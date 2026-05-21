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
#include <vector>

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

static std::map<uint16_t, Trie<string, strategy>> domains_map;
static std::map<uint16_t, Trie<char, strategy>> ipv4s_map;
static std::map<uint16_t, Trie<char, strategy>> ipv6s_map;
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

static const TrieType<strategy>* ipfind(const char* ipstr, int prefix = -1, uint16_t port = 0){
    in_addr ip4;
    in6_addr ip6;

    if (inet_pton(AF_INET, ipstr, &ip4) == 1) {
        auto it = ipv4s_map.find(port);
        if (it != ipv4s_map.end()) {
            return it->second.find(split(ip4, prefix));
        }
        return nullptr;
    }
    if (inet_pton(AF_INET6, getrawip(ipstr).c_str(), &ip6) == 1) {
        auto it = ipv6s_map.find(port);
        if (it != ipv6s_map.end()) {
            return it->second.find(split(ip6, prefix));
        }
        return nullptr;
    }
    return nullptr;
}


bool ipinsert(const char* ipstr, const strategy& stra, int prefix = -1, uint16_t port = 0){
    in_addr ip4;
    in6_addr ip6;

    if (inet_pton(AF_INET, ipstr, &ip4) == 1) {
        ipv4s_map[port].insert(split(ip4, prefix), stra);
        return true;
    }
    if (inet_pton(AF_INET6, getrawip(ipstr).c_str(), &ip6) == 1) {
        ipv6s_map[port].insert(split(ip6, prefix), stra);
        return true;
    }
    return false;
}

bool ipremove(const char* ipstr, bool& found, int prefix = -1, uint16_t port = 0) {
    in_addr ip4;
    in6_addr ip6;

    if (inet_pton(AF_INET, ipstr, &ip4) == 1) {
        auto it = ipv4s_map.find(port);
        if (it != ipv4s_map.end()) {
            it->second.remove(split(ip4, prefix), found);
        }
        return true;
    }
    if (inet_pton(AF_INET6, getrawip(ipstr).c_str(), &ip6) == 1) {
        auto it = ipv6s_map.find(port);
        if (it != ipv6s_map.end()) {
            it->second.remove(split(ip6, prefix), found);
        }
        return true;
    }
    return false;
}

// Extract port from host:port or [ipv6]:port via spliturl, modifies host in place
static uint16_t splitport(string& host) {
    Destination dest = {};
    if (spliturl(host.c_str(), &dest, nullptr) == 0) {
        host = dest.hostname;
        if (host.size() >= 2 && host.front() == '[' && host.back() == ']')
            host = host.substr(1, host.size() - 2);
        return dest.port;
    }
    return 0;
}

// Extract port from CIDR suffix (e.g. "24:8080" → port=8080, prefix_str="24")
static uint16_t splitport_cidr(string& prefix_str) {
    auto colon_pos = prefix_str.find(':');
    if (colon_pos == string::npos) {
        return 0;
    }
    int port = atoi(prefix_str.substr(colon_pos + 1).c_str());
    if (port > 0 && port <= 65535) {
        prefix_str = prefix_str.substr(0, colon_pos);
        return (uint16_t)port;
    }
    return 0;
}

static bool mergestrategy(const string& host_, const string& strategy_str, const string& ext){
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
        aliases[host_] = ext;
        return true;
    }

    string host = host_;
    strategy stra{s, ext};
    auto mask_pos = host.find_first_of('/');
    if(mask_pos != string::npos){
        string ip = host.substr(0, mask_pos);
        string prefix_str = host.substr(mask_pos+1);
        uint16_t port = splitport_cidr(prefix_str);
#ifdef __ANDROID__
        int prefix = atoi(prefix_str.c_str());
#else
        int prefix = stoi(prefix_str);
#endif
        return ipinsert(ip.c_str(), stra, prefix, port);
    }
    uint16_t port = splitport(host);
    if(ipinsert(host.c_str(), stra, -1, port)){
        return true;
    } else if(stra.s == Strategy::block){
        try{
            std::regex reg(ext);
        }catch(std::regex_error&) {
            return false;
        }
        domains_map[port].insert(split(toLower(host)), stra, ext);
        return true;
    } else {
        domains_map[port].insert(split(toLower(host)), stra);
        return true;
    }
}

void reloadstrategy() {
    ipv4s_map.clear();
    ipv6s_map.clear();
    domains_map.clear();
    aliases.clear();

    //default strategy
    for(auto ips=getlocalip(); ips->ss_family ; ips++){
        if(ips->ss_family == AF_INET){
            ipv4s_map[0].insert(split(ips), strategy{Strategy::local, GEN_TIP});
        }
        if(ips->ss_family == AF_INET6){
            ipv6s_map[0].insert(split(ips), strategy{Strategy::local, GEN_TIP});
        }
    }
    char hostname[HOST_NAME_MAX];
    gethostname(hostname, sizeof(hostname));
    domains_map[0].insert(split(hostname), strategy{Strategy::local, GEN_TIP});
    domains_map[0].insert(split("localhost"), strategy{Strategy::local, GEN_TIP});
    domains_map[0].insert(split("fake_ip"), strategy{Strategy::block, GEN_TIP});
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
        string prefix_str = host.substr(mask_pos+1);
        uint16_t port = splitport_cidr(prefix_str);
#ifdef __ANDROID__
        int prefix = atoi(prefix_str.c_str());
#else
        int prefix = stoi(prefix_str);
#endif
        ipremove(ip.c_str(), found, prefix, port);
    }else{
        uint16_t port = splitport(host);
        if(!ipremove(host.c_str(), found, -1, port)){
            auto it = domains_map.find(port);
            if(it != domains_map.end()) {
                it->second.remove(split(toLower(host)), found);
            }
        }
    }
    if(found){
        savesites();
    }
    return found;
}

strategy getstrategy(const char *host_, uint16_t port, const char* path){
    const TrieType<strategy> *v = nullptr;
    string host = host_;
    auto mask_pos = host.find_first_of('/');
    int prefix = -1;
    string ip;
    if(mask_pos != string::npos){
        ip = host.substr(0, mask_pos);
        string prefix_str = host.substr(mask_pos+1);
        char* pos = nullptr;
        prefix = (int)strtol(prefix_str.c_str(), &pos, 10);
        if(*pos != '\0'  || prefix < 0 || prefix > 128) {
            return strategy{Strategy::block, ""};
        }
    }
    // Try port-specific lookup first
    if(port > 0) {
        if(mask_pos != string::npos){
            v = ipfind(ip.c_str(), prefix, port);
        }else if((v = ipfind(host.c_str(), -1, port)) == nullptr){
            auto it = domains_map.find(port);
            if(it != domains_map.end()) {
                v = it->second.find(split(toLower(host)), path);
            }
        }
    }
    // Fall back to general (port=0)
    if(!v) {
        if(mask_pos != string::npos){
            v = ipfind(ip.c_str(), prefix);
        }else if((v = ipfind(host.c_str())) == nullptr){
            auto it = domains_map.find((uint16_t)0);
            if(it != domains_map.end()) {
                v = it->second.find(split(toLower(host)), path);
            }
        }
    }
    if(!v) {
        return strategy{Strategy::direct, ""};
    }
    strategy s = v->value;
    if(s.s != Strategy::alias && !s.ext.empty() && s.ext[0] == '@'){
        if(getalias(s.ext.substr(1), s.ext)){
            return s;
        }
        return strategy{Strategy::none, ""};
    }
    return s;
}

bool getalias(const std::string& name, std::string& target) {
    if (aliases.count(name)) {
        target = aliases[name];
        return true;
    }
    return false;
}

bool mayBeBlocked(const char* host, uint16_t port) {
    auto check = [&](uint16_t p) -> bool {
        auto it = domains_map.find(p);
        if(it == domains_map.end()) return false;
        auto strategies = it->second.findAll(split(toLower(host)));
        return std::any_of(strategies.begin(), strategies.end(), [](const TrieType<strategy>* s){
            return s->value.s == Strategy::block;
        });
    };
    if(port != 0 && check(port)) return true;
    return check(0);
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
    for(auto& [port, trie]: ipv4s_map){
        std::list<char> i4list;
        auto ip4list = trie.dump(i4list);
        for(const auto& i: ip4list){
            string host = join(AF_INET, i.first);
            if(port) host += ":" + std::to_string(port);
            slist.emplace_back(host, i.second);
        }
    }
    for(auto& [port, trie]: ipv6s_map){
        std::list<char> i6list;
        auto ip6list = trie.dump(i6list);
        for(const auto& i: ip6list){
            string host = join(AF_INET6, i.first);
            if(port){
                auto slash_pos = host.find('/');
                if(slash_pos != string::npos){
                    host = "[" + host.substr(0, slash_pos) + "]" + host.substr(slash_pos) + ":" + std::to_string(port);
                }else{
                    host = "[" + host + "]:" + std::to_string(port);
                }
            }
            slist.emplace_back(host, i.second);
        }
    }
    for(auto& [port, trie]: domains_map){
        std::list<string> hlist;
        auto domainlist = trie.dump(hlist);
        for(const auto& i: domainlist){
            string host = join(i.first);
            if(port) host += ":" + std::to_string(port);
            slist.emplace_back(host, i.second);
        }
    }
    return slist;
}

static std::map<string, string> secrets;
static std::set<string> authips{"127.0.0.1", "[::1]", "localhost"};

void addsecret(const char* secret) {
    Credit cr{};
    if (parse_user_pass(secret, strlen(secret), &cr) == 0) {
        secrets[cr.user] = cr.pass;
    }
    if(!authips.empty()) {
        return;
    }
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
        const auto& [user, pass] = *secrets.begin(); // Use the first secret
        const std::string& secret = user + ':' + pass;
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
    for (const auto& [user, pass] : secrets) {
        const std::string& secret = user + ':' + pass;
        std::string sig = hmac_sha256(secret.c_str(), secret.length(), ts_be, sizeof(ts_be));
        if(sig == provided_sig) return true;
    }

    return false;
}

bool decodeauth(const char* auth, struct Credit* credit){
    if(strncmp(auth, "Basic ", 6) == 0){
        auth = auth + 6;
    }

    size_t len = strlen(auth);
    std::vector<char> decoded(len + 1);
    size_t decoded_len = Base64Decode(auth, len, decoded.data());
    if (decoded_len == 0) {
        return false;
    }
    decoded[decoded_len] = 0;

    return parse_user_pass(decoded.data(), decoded_len, credit) == 0;
}

bool checksecret(const char* auth, const struct Credit* cr){
    if(secrets.empty())
        return true;

    if(auth == nullptr && cr == nullptr){
        return false;
    }
    struct Credit local;
    if(cr == nullptr){
        if (!decodeauth(auth, &local)) {
            return false;
        }
    } else {
        local = *cr;
    }
    char* plus = strchr(local.user, '+');
    if (plus) {
        *plus = 0;
    }
    if (secrets.count(local.user) && secrets.at(local.user) == local.pass) {
        return true;
    }
    return false;
}

bool checkauth(const char* ip, std::shared_ptr<const HttpReqHeader> req) {
    if(authips.count(ip) > 0){
        return true;
    }
    if (req->has("Skip-Authorize", "1")) {
        return true;
    }
    sockaddr_storage addr;
    if(storage_aton(ip, 0, &addr)  && isFakeAddress(&addr)) {
        return true;
    }

    if (checksecret(req->get("Proxy-Authorization"), nullptr) || checksecret(req->get("Authorization"), nullptr)) {
        return true;
    }
    auto cookies = req->getcookies();
    if (cookies.count("sproxy_token")) {
        return checktoken(cookies.at("sproxy_token").c_str());
    }
    return false;
}
