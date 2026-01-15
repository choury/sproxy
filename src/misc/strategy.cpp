#include "strategy.h"
#include "net.h"
#include "config.h"
#include "common/common.h"
#include "util.h"
#include "trie.h"
#include "prot/http/http_header.h"
#include <set>
#include <map>
#include <sstream>

#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <limits.h>

#include <openssl/hmac.h>
#include <openssl/evp.h>

#ifdef __ANDROID__
#include <stdlib.h>
#endif
#ifdef __APPLE__
#include <sys/param.h>
#define HOST_NAME_MAX  MAXHOSTNAMELEN
#endif


using std::string;
using std::stringstream;

static Trie<string, strategy> domains;
static Trie<char, strategy> ipv4s;
static Trie<char, strategy> ipv6s;
static std::map<std::string, std::string> aliases;

string toLower(const string &s);

static std::string getrawip(const char* ipstr) {
    if(ipstr[0] != '['){
        return ipstr;
    }
    //for ipv6, we should drop '[]'
    char name[URLLIMIT]={0};
    int l = snprintf(name, sizeof(name), "%s", ipstr + 1);
    name[l - 1] = 0;
    return name;
}

static const TrieType<strategy>* ipfind(const char* ipstr, int prefix = -1){
    in_addr ip4;
    in6_addr ip6;

    if (inet_pton(AF_INET, ipstr, &ip4) == 1) {
        return ipv4s.find(split(ip4, prefix));
    }
    if (inet_pton(AF_INET6, getrawip(ipstr).c_str(), &ip6) == 1) {
        return ipv6s.find(split(ip6, prefix));
    }
    return nullptr;
}


bool ipinsert(const char* ipstr, const strategy& stra, int prefix = -1){
    in_addr ip4;
    in6_addr ip6;

    if (inet_pton(AF_INET, ipstr, &ip4) == 1) {
        ipv4s.insert(split(ip4, prefix), stra);
        return true;
    }
    if (inet_pton(AF_INET6, getrawip(ipstr).c_str(), &ip6) == 1) {
        ipv6s.insert(split(ip6, prefix), stra);
        return true;
    }
    return false;
}

bool ipremove(const char* ipstr, bool& found, int prefix = -1) {
    in_addr ip4;
    in6_addr ip6;

    if (inet_pton(AF_INET, ipstr, &ip4) == 1) {
        ipv4s.remove(split(ip4, prefix), found);
        return true;
    }
    if (inet_pton(AF_INET6, getrawip(ipstr).c_str(), &ip6) == 1) {
        ipv6s.remove(split(ip6, prefix), found);
        return true;
    }
    return false;
}


static bool mergestrategy(const string& host, const string& strategy_str, const string& ext){
    Strategy s;
    if(strategy_str == "direct"){
        s = Strategy::direct;
    }else if(strategy_str == "proxy"){
        s = Strategy::proxy;
    }else if(strategy_str == "local"){
        s = Strategy::local;
    }else if(strategy_str == "block"){
        s = Strategy::block;
    }else if(strategy_str == "forward"){
        s = Strategy::forward;
    }else if(strategy_str == "rewrite"){
        s = Strategy::rewrite;
    }else if(strategy_str == "alias"){
        s = Strategy::alias;
    }else{
        return false;
    }

    if (s == Strategy::alias) {
        aliases[host] = ext;
        return true;
    }

    strategy stra{s, ext};
    auto mask_pos = host.find_first_of('/');
    if(mask_pos != string::npos){
        string ip = host.substr(0, mask_pos);
#ifdef __ANDROID__
        int prefix = atoi(host.substr(mask_pos+1).c_str());
#else
        int prefix = stoi(host.substr(mask_pos+1));
#endif
        return ipinsert(ip.c_str(), stra, prefix);
    }else if(ipinsert(host.c_str(), stra)){
        return true;
    } else if(stra.s == Strategy::block){
        try{
            std::regex reg(ext);
        }catch(std::regex_error&) {
            return false;
        }
        domains.insert(split(toLower(host)), stra, ext);
        return true;
    } else {
        domains.insert(split(toLower(host)), stra);
        return true;
    }
}

void reloadstrategy() {
    ipv4s.clear();
    ipv6s.clear();
    domains.clear();
    aliases.clear();

    //default strategy
    for(auto ips=getlocalip(); ips->ss_family ; ips++){
        if(ips->ss_family == AF_INET){
            ipv4s.insert(split(ips), strategy{Strategy::local, GEN_TIP});
        }
        if(ips->ss_family == AF_INET6){
            ipv6s.insert(split(ips), strategy{Strategy::local, GEN_TIP});
        }
    }
    char hostname[HOST_NAME_MAX];
    gethostname(hostname, sizeof(hostname));
    domains.insert(split(hostname), strategy{Strategy::local, GEN_TIP});
    domains.insert(split("localhost"), strategy{Strategy::local, GEN_TIP});
    domains.insert(split("fake_ip"), strategy{Strategy::block, GEN_TIP});
    if (opt.policy_read && fseek(opt.policy_read, 0L, SEEK_SET) == 0){
        int lineNum = 0;
        char* line = nullptr;
        size_t len = 0;
        while (getline(&line, &len, opt.policy_read) > 0) {
            lineNum ++;
            if(len == 0 || line[0] == '#' || line[0] == '\n'){
                continue;
            }
            stringstream ss(line);
            string site, strategy, ext;
            ss >> site >> strategy >> ext;
            if(!mergestrategy(site, strategy, ext)){
                LOGE("Wrong config line %d:%s\n", lineNum, line);
            }
        }
        free(line);
    }
}

void savesites(){
#ifndef __ANDROID__
    if(!opt.policy_write || fseek(opt.policy_write, 0L, SEEK_SET)){
        return;
    }
    auto list = getallstrategy();
    for (const auto& i:list) {
        if(i.second.ext == GEN_TIP){
            continue;
        }

        if(fprintf(opt.policy_write,
            "%s %s %s\n", i.first.c_str(),
            getstrategystring(i.second.s),
            i.second.ext.c_str()) <= 0)
        {
            LOGE("failed to update policy: %s\n", strerror(errno));
        }
    }
    (void)!ftruncate(fileno(opt.policy_write), ftell(opt.policy_write));
    fflush(opt.policy_write);
#endif
}


bool addstrategy(const char* host, const char* strategy, const char* ext) {
    if(mergestrategy(host, strategy, ext)){
        savesites();
        return true;
    }
    return false;
}

bool delstrategy(const char* host_) {
    if(host_[0] == '@' && aliases.erase(host_ + 1)){
        return true;
    }
    bool found  = false;
    string host = host_;
    auto mask_pos = host.find_first_of('/');
    if(mask_pos != string::npos){
        string ip = host.substr(0, mask_pos);
#ifdef __ANDROID__
        int prefix = atoi(host.substr(mask_pos+1).c_str());
#else
        int prefix = stoi(host.substr(mask_pos+1));
#endif
        ipremove(ip.c_str(), found, prefix);
    }else if(!ipremove(host.c_str(), found)){
        domains.remove(split(toLower(host)), found);
    }
    if(found){
        savesites();
    }
    return found;
}

strategy getstrategy(const char *host_, const char* path){
    const TrieType<strategy> *v = nullptr;
    string host = host_;
    auto mask_pos = host.find_first_of('/');
    if(mask_pos != string::npos){
        string ip = host.substr(0, mask_pos);
        string prefix_str = host.substr(mask_pos+1);
        char* pos = nullptr;
        int prefix = (int)strtol(prefix_str.c_str(), &pos, 10);
        if(*pos != '\0'  || prefix < 0 || prefix > 128) {
            return strategy{Strategy::block, ""};
        }
        v = ipfind(ip.c_str(), prefix);
    }else if((v = ipfind(host.c_str())) == nullptr){
        v = domains.find(split(toLower(host)), path);
    }
    if(!v) {
        return strategy{Strategy::direct, ""};
    }
    strategy s = v->value;
    if(s.s != Strategy::alias && !s.ext.empty() && s.ext[0] == '@'){
        if(aliases.count(s.ext.substr(1))){
             s.ext = aliases[s.ext.substr(1)];
        } else {
            return strategy{Strategy::none, ""};
        }
    }
    return s;
}

bool mayBeBlocked(const char* host) {
    auto strategies = domains.findAll(split(toLower(host)));
    return std::any_of(strategies.begin(), strategies.end(), [](const TrieType<strategy>* s){
        return s->value.s == Strategy::block;
    });
}

const char* getstrategystring(Strategy s) {
    switch(s){
    case Strategy::direct:
        return "direct";
    case Strategy::forward:
        return "forward";
    case Strategy::rewrite:
        return "rewrite";
    case Strategy::proxy:
        return "proxy";
    case Strategy::local:
        return "local";
    case Strategy::block:
        return "block";
    case Strategy::alias:
        return "alias";
    case Strategy::none:
        return "null";
    }
    return nullptr;
}

std::list<std::pair<std::string, strategy>> getallstrategy(){
    std::list<std::pair<std::string, strategy>> slist;
    for(const auto& i: aliases){
        slist.emplace_back(i.first, strategy{Strategy::alias, i.second});
    }
    std::list<char> i4list;
    auto ip4list = ipv4s.dump(i4list);
    for(const auto& i: ip4list){
        slist.emplace_back(join(AF_INET, i.first), i.second);
    }
    std::list<char> i6list;
    auto ip6list = ipv6s.dump(i6list);
    for(const auto& i: ip6list){
        slist.emplace_back(join(AF_INET6, i.first), i.second);
    }
    std::list<string> hlist;
    auto domainlist = domains.dump(hlist);
    for(const auto& i: domainlist){
        slist.emplace_back(join(i.first), i.second);
    }
    return slist;
}

static std::set<string> secrets;
static std::set<string> authips{"127.0.0.1", "[::1]", "localhost"};

void addsecret(const char* secret) {
    secrets.emplace(secret);
    for(auto ips=getlocalip(); ips->ss_family ; ips++){
        char buff[INET6_ADDRSTRLEN + 3] = {0};
        const char* dst = nullptr;
        if(ips->ss_family == AF_INET){
            dst = inet_ntop(AF_INET, &((sockaddr_in*)ips)->sin_addr, buff, sizeof(buff));
        }else if(ips->ss_family == AF_INET6){
            buff[0] = '[';
            dst = inet_ntop(AF_INET6, &((sockaddr_in6*)ips)->sin6_addr, buff + 1, sizeof(buff) - 2);
            buff[strlen(buff)] = ']';
        }
        if (dst) {
            authips.insert(buff);
        }
    }
    //add vpn address
    authips.insert(VPNADDR);
    authips.insert("[" VPNADDR6 "]");
}

static std::string hmac_sha256(const void* key, size_t key_len, const unsigned char* data, size_t data_len) {
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;
    HMAC(EVP_sha256(), key, key_len, data, data_len, hash, &hash_len);
    return std::string((char*)hash, hash_len);
}

// Token format: Base64(timestamp(8 bytes) + signature(32 bytes))
std::string gen_token() {
    uint64_t now = time(NULL); // seconds
    unsigned char now_be[8];
    set64(now_be, now);
    std::string signature;

    // Priority: cert key -> ca key -> secrets
    if (opt.cert.key) {
        BIO *bio = BIO_new(BIO_s_mem());
        PEM_write_bio_PrivateKey(bio, opt.cert.key, NULL, NULL, 0, NULL, NULL);
        char *key_data;
        long key_len = BIO_get_mem_data(bio, &key_data);
        signature = hmac_sha256(key_data, key_len, now_be, sizeof(now_be));
        BIO_free(bio);
    } else if (opt.ca.key) {
        BIO *bio = BIO_new(BIO_s_mem());
        PEM_write_bio_PrivateKey(bio, opt.ca.key, NULL, NULL, 0, NULL, NULL);
        char *key_data;
        long key_len = BIO_get_mem_data(bio, &key_data);
        signature = hmac_sha256(key_data, key_len, now_be, sizeof(now_be));
        BIO_free(bio);
    } else if (!secrets.empty()) {
        const std::string& secret = *secrets.begin(); // Use the first secret
        signature = hmac_sha256(secret.c_str(), secret.length(), now_be, sizeof(now_be));
    } else {
        return ""; // No auth required
    }

    std::string token_data;
    token_data.append((char*)now_be, sizeof(now_be));
    token_data.append(signature);

    char encoded[128]; // ample space
    Base64EnUrl(token_data.c_str(), token_data.length(), encoded);
    return std::string(encoded);
}

bool checktoken(const char* token) {
    if (token == nullptr || *token == '\0') return false;

    char decoded[128];
    size_t len = Base64DeUrl(token, strlen(token), decoded);
    if (len != 8 + 32) return false; // 8 bytes timestamp + 32 bytes SHA256

    uint64_t ts = get64(decoded);
    uint64_t now = time(NULL);

    // Valid for 30 days
    if (now < ts || now - ts > 30ULL * 24 * 3600) {
        return false;
    }

    unsigned char ts_be[8];
    set64(ts_be, ts);
    std::string provided_sig(decoded + 8, 32);

    // Try cert key
    if (opt.cert.key) {
        BIO *bio = BIO_new(BIO_s_mem());
        PEM_write_bio_PrivateKey(bio, opt.cert.key, NULL, NULL, 0, NULL, NULL);
        char *key_data;
        long key_len = BIO_get_mem_data(bio, &key_data);
        std::string sig = hmac_sha256(key_data, key_len, ts_be, sizeof(ts_be));
        BIO_free(bio);
        return sig == provided_sig;
    }

    // Try CA key
    if (opt.ca.key) {
        BIO *bio = BIO_new(BIO_s_mem());
        PEM_write_bio_PrivateKey(bio, opt.ca.key, NULL, NULL, 0, NULL, NULL);
        char *key_data;
        long key_len = BIO_get_mem_data(bio, &key_data);
        std::string sig = hmac_sha256(key_data, key_len, ts_be, sizeof(ts_be));
        BIO_free(bio);
        return sig == provided_sig;
    }

    // Try secrets
    for (const auto& secret : secrets) {
        std::string sig = hmac_sha256(secret.c_str(), secret.length(), ts_be, sizeof(ts_be));
        if(sig == provided_sig) return true;
    }

    return false;
}

bool checksecret(const char* ip, const char* secret){
    if(secrets.empty())
        return true;
    if(authips.count(ip) > 0){
        return true;
    }

    sockaddr_storage addr;
    if(storage_aton(ip, 0, &addr)  && isFakeAddress(&addr)) {
        return true;
    }
    if(secret == nullptr){
        return false;
    }
    if(strncmp(secret, "Basic ", 6) == 0){
        secret = secret + 6;
    }
    if(secrets.count(secret) > 0) {
        authips.insert(ip);
        return true;
    }
    return false;
}

bool checkauth(const char* ip, std::shared_ptr<const HttpReqHeader> req) {
    if (checksecret(ip, req->get("Proxy-Authorization")) || checksecret(ip, req->get("Authorization"))) {
        return true;
    }
    auto cookies = req->getcookies();
    if (cookies.count("sproxy_token")) {
        return checktoken(cookies.at("sproxy_token").c_str());
    }
    return false;
}
