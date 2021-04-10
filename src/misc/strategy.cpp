#include "strategy.h"
#include "net.h"
#include "config.h"
#include "common/common.h"
#include "trie.h"
#include "defer.h"
#include <set>
#include <sstream>

#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <limits.h>

#ifdef __ANDROID__
#include <stdlib.h>
#endif
#ifdef __APPLE__
#include <sys/param.h>
#define HOST_NAME_MAX  MAXHOSTNAMELEN
#endif

#define GEN_TIP  "GENERATED"

using std::string;
using std::stringstream;

static Trie<string, strategy> domains;
static Trie<char, strategy> ipv4s;
static Trie<char, strategy> ipv6s;

string toLower(const string &s);

static const Trie<char, strategy>* ipfind(const char* ipstr, int prefix = -1){
    in_addr ip4;
    in6_addr ip6;

    if (inet_pton(AF_INET, ipstr, &ip4) == 1) {
        return ipv4s.find(split(ip4, prefix));
    }else if (inet_pton(AF_INET6, ipstr, &ip6) == 1) {
        return ipv6s.find(split(ip6, prefix));
    }
    return nullptr;
}

bool ipinsert(const char* ipstr, strategy stra, int prefix = -1){
    in_addr ip4;
    in6_addr ip6;

    if (inet_pton(AF_INET, ipstr, &ip4) == 1) {
        ipv4s.insert(split(ip4, prefix), stra);
        return true;
    }
    if (inet_pton(AF_INET6, ipstr, &ip6) == 1) {
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
    if (inet_pton(AF_INET6, ipstr, &ip6) == 1) {
        ipv6s.remove(split(ip6, prefix), found);
        return true;
    }
    return false;
}


static bool mergestrategy(const string& host, const string& strategy_str, string ext){
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
    }else{
        return false;
    }
    strategy stra{s, std::move(ext)};
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
    } else{
        domains.insert(split(toLower(host)), stra);
        return true;
    }
}

std::string getExternalFilesDir();

void reloadstrategy() {
    ipv4s.clear();
    ipv6s.clear();
    domains.clear();

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
    if (opt.policy_read && fseek(opt.policy_read, 0L, SEEK_SET) == 0){
        int lineNum = 0;
        char* line = nullptr;
        size_t len = 0;
        while (getline(&line, &len, opt.policy_read) > 0) {
            defer([&line]{
                free(line);
                line = nullptr;
            });
            lineNum ++;
            if(len == 0 || line[0] == '#'){
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

    addauth("127.0.0.1");
    addauth("[::1]");
}

void savesites(){
#ifndef __ANDROID__
    if(!opt.policy_write || fseek(opt.policy_write, 0L, SEEK_SET)){
        return;
    }
    auto list = getallstrategy();
    for (auto i:list) {
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
    ftruncate(fileno(opt.policy_write), ftell(opt.policy_write));
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

strategy getstrategy(const char *host_){
    const TrieType<strategy> *v = nullptr;
    string host = host_;
    auto mask_pos = host.find_first_of('/');
    if(mask_pos != string::npos){
        string ip = host.substr(0, mask_pos);
#ifdef __ANDROID__
        int prefix = atoi(host.substr(mask_pos+1).c_str());
#else
        int prefix = stoi(host.substr(mask_pos+1));
#endif
        v = ipfind(ip.c_str(), prefix);
    }else if((v = ipfind(host.c_str())) == nullptr){
        v = domains.find(split(toLower(host)));
    }
    return v? v->value : strategy{Strategy::direct, ""};
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
    case Strategy::none:
        return "null";
    }
    return nullptr;
}

std::list<std::pair<std::string, strategy>> getallstrategy(){
    std::list<std::pair<std::string, strategy>> slist;
    std::list<char> i4list;
    auto ip4list = ipv4s.dump(i4list);
    for(auto i: ip4list){
        slist.emplace_back(join(AF_INET, i.first), i.second);
    }
    std::list<char> i6list;
    auto ip6list = ipv6s.dump(i6list);
    for(auto i: ip6list){
        slist.emplace_back(join(AF_INET6, i.first), i.second);
    }
    std::list<string> hlist;
    auto domainlist = domains.dump(hlist);
    for(auto i: domainlist){
        slist.emplace_back(join(i.first), i.second);
    }
    return slist;
}

static std::set<string> authips;
void addauth(const char *ip) {
    authips.insert(ip);
}

bool checkauth(const char *ip) {
    if(strlen(opt.auth_string) == 0)
        return true;
    return authips.count(ip) > 0;
}
