#include "strategy.h"
#include "net.h"
#include "config.h"
#include "common.h"
#include "trie.h"
#include <set>
#include <fstream>

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
using std::ifstream;
using std::ofstream;

static Trie<string, strategy> domains;
static Trie<char, strategy> ipv4s;
static Trie<char, strategy> ipv6s;

string toLower(const string &s);

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
    sockaddr_un addr;
    if(mask_pos != string::npos){
        string ip = host.substr(0, mask_pos);
#ifdef __ANDROID__
        int prefix = atoi(host.substr(mask_pos+1).c_str());
#else
        int prefix = stoi(host.substr(mask_pos+1));
#endif
        if (inet_pton(AF_INET, ip.c_str(), &addr.addr_in.sin_addr) == 1) {
            ipv4s.insert(split(addr.addr_in.sin_addr, (uint32_t)prefix), stra);
            return true;
        }
        if (inet_pton(AF_INET6, ip.c_str(), &addr.addr_in6.sin6_addr) == 1) {
            ipv6s.insert(split(addr.addr_in6.sin6_addr, (uint32_t)prefix), stra);
            return true;
        }
        return false;
    }else if(inet_pton(AF_INET, host.c_str(), &addr.addr_in.sin_addr) == 1){
        ipv4s.insert(split(addr.addr_in.sin_addr), stra);
        return true;
    }else if(inet_pton(AF_INET6, host.c_str(), &addr.addr_in6.sin6_addr) == 1){
        ipv6s.insert(split(addr.addr_in6.sin6_addr), stra);
        return false;
    } else{
        domains.insert(split(toLower(host)), stra);
        return true;
    }
}

std::string getExternalFilesDir();

void reloadstrategy() {
    ipv4s.clear();
    domains.clear();

    //default strategy
    for(auto ips=getlocalip(); ips->addr_in.sin_family ; ips++){
        if(ips->addr.sa_family == AF_INET){
            ipv4s.insert(split(ips->addr_in.sin_addr), strategy{Strategy::local, GEN_TIP});
        }
        if(ips->addr.sa_family == AF_INET6){
            ipv6s.insert(split(ips->addr_in6.sin6_addr), strategy{Strategy::local, GEN_TIP});
        }
    }
    char hostname[HOST_NAME_MAX];
    gethostname(hostname, sizeof(hostname));
    domains.insert(split(hostname), strategy{Strategy::local, GEN_TIP});
    domains.insert(split("localhost"), strategy{Strategy::local, GEN_TIP});
    ifstream sitesfile(opt.policy_file);
    if (sitesfile.good()) {
        int lineNum = 0;
        string line;
        while (std::getline(sitesfile, line)) {
            lineNum ++;
            if(line[0] == '#'){
                continue;
            }

            char site[DOMAINLIMIT];
            char strategy[20];
            char ext[DOMAINLIMIT] = {0};
            int ret = sscanf(line.c_str(), "%s %s %s", site, strategy, ext);

            if(line.length() && (ret < 2 || !mergestrategy(site, strategy, ext))){
                LOGE("Wrong config line %d:%s\n", lineNum, line.c_str());
            }
        }

        sitesfile.close();
    } else {
        LOGE("read policy file %s failed!\n", opt.policy_file);
    }

    addauth("::ffff:127.0.0.1");
    addauth("::1");
}

void savesites(){
#ifndef __ANDROID__
    ofstream sitesfile(opt.policy_file);
    auto list = getallstrategy();
    for (auto i:list) {
        if(i.second.ext == GEN_TIP){
            continue;
        }
        sitesfile <<i.first<<' '<<getstrategystring(i.second.s)<<' '<<i.second.ext<< std::endl;
    }
    sitesfile.close();
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
    sockaddr_un addr;
    if(mask_pos != string::npos){
        string ip = host.substr(0, mask_pos);
#ifdef __ANDROID__
        int prefix = atoi(host.substr(mask_pos+1).c_str());
#else
        int prefix = stoi(host.substr(mask_pos+1));
#endif
        if (inet_pton(AF_INET, ip.c_str(), &addr.addr_in.sin_addr) == 1) {
            ipv4s.remove(split(addr.addr_in.sin_addr, (uint32_t)prefix), found);
        }else if (inet_pton(AF_INET6, ip.c_str(), &addr.addr_in6.sin6_addr) == 1) {
            ipv6s.remove(split(addr.addr_in6.sin6_addr, (uint32_t)prefix), found);
        }
    }else if(inet_pton(AF_INET, host.c_str(), &addr.addr_in.sin_addr) == 1){
        ipv4s.remove(split(addr.addr_in.sin_addr), found);
    }else if(inet_pton(AF_INET6, host.c_str(), &addr.addr_in6.sin6_addr) == 1){
        ipv6s.remove(split(addr.addr_in6.sin6_addr), found);
    } else{
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
    sockaddr_un addr;
    if(mask_pos != string::npos){
        string ip = host.substr(0, mask_pos);
#ifdef __ANDROID__
        int prefix = atoi(host.substr(mask_pos+1).c_str());
#else
        int prefix = stoi(host.substr(mask_pos+1));
#endif
        if (inet_pton(AF_INET, ip.c_str(), &addr.addr_in.sin_addr) == 1) {
            v = ipv4s.find(split(addr.addr_in.sin_addr, (uint32_t)prefix));
        }else if (inet_pton(AF_INET6, ip.c_str(), &addr.addr_in6.sin6_addr) == 1) {
            v = ipv6s.find(split(addr.addr_in6.sin6_addr, (uint32_t)prefix));
        }
    }else if(inet_pton(AF_INET, host.c_str(), &addr.addr_in.sin_addr) == 1){
        v = ipv4s.find(split(addr.addr_in.sin_addr));
    }else if(inet_pton(AF_INET6, host.c_str(), &addr.addr_in6.sin6_addr) == 1){
        v = ipv6s.find(split(addr.addr_in6.sin6_addr));
    } else{
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
