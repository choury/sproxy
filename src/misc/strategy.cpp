#include "strategy.h"
#include "net.h"
#include "config.h"
#include "common.h"
#include <map>
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

#define LISTFILE "sites.list"
#define GEN_TIP  "GENERATED"

using std::string;
using std::map;
using std::ifstream;
using std::ofstream;

/*
static string reverse(string str){
    string::size_type split = 0;
    string result;
    while((split = str.find_last_of('.')) != string::npos){
        result += str.substr(split+1) + '.';
        str = str.substr(0, split);
    }
    result += str;
    return result;
}
*/

static string trimdomain(string host){
    string domain;
    auto pos = host.find_first_of('.');
    if(pos != string::npos){
        domain = host.substr(pos+1);
    }
    return domain;
}

static string joinhost(string host, string domain){
    if(host.empty()){
        return domain;
    }
    if(domain.empty()){
        return host;
    }
    return host + '.' + domain;
}

class Ipv4Stra{
    map<uint64_t, strategy> strategies;
public:
    void insert(in_addr ip, uint32_t prefix, const strategy& s){
        assert(prefix <= 32);
        uint64_t prefix_mask =  (((uint64_t)1 << prefix) - 1) << (32 - prefix);
        strategies[((uint64_t)ntohl(ip.s_addr) & prefix_mask) << 32u | prefix_mask] = s;
    }
    strategy find(in_addr ip){
        for(const auto& i: strategies){
            uint32_t mask = i.first & 0xffffffff;
            uint32_t net = i.first >> 32u;
            if((net & mask ) == (ntohl(ip.s_addr) & mask)){
                return i.second;
            }
        }
        return {Strategy::none, ""};
    }
    bool remove(in_addr ip){
        for(auto i = strategies.begin(); i!= strategies.end(); i++ ){
            uint32_t mask = i->first & 0xffffffff;
            uint32_t net = i->first >> 32u;
            if((net & mask ) == (ntohl(ip.s_addr) & mask)){
                strategies.erase(i);
                return true;
            }
        }
        return false;
    }
    void clear(){
        strategies.clear();
    }
    void stats(){
        for(const auto& i: strategies){
            int prefix = 0;
            uint32_t mask = i.first&0xffffffff;
            while(mask){
                prefix ++;
                mask <<= 1u;
            }
            uint64_t net = i.first >> 32u;
            LOG("%s/%d: %s %s\n", 
                inet_ntoa(in_addr{htonl(net)}), 
                prefix, 
                getstrategystring(i.second.s),
                i.second.ext.c_str());
        }
    }
    void dump(std::list<std::pair<std::string, strategy>>& slist){
        for(auto i: strategies){
            int prefix = 0;
            uint32_t mask = i.first&0xffffffff;
            while(mask){
                prefix ++;
                mask <<= 1u;
            }
            uint64_t net = i.first >> 32u;
            char ip_prefix[100];
            snprintf(ip_prefix, 100, "%s/%d", inet_ntoa(in_addr{htonl(net)}), prefix);
            slist.emplace_back(ip_prefix, i.second);
        }
    }
}ipv4s;

class DomainStra{
    map<string, strategy> children;
public:
    void insert(const string& host, const strategy& stra){
        assert(stra.s != Strategy::none);
        children[host] = stra;
    }
    const strategy find(const string& host){
        assert(!host.empty());
        if(children.count(host)){
            return children[host];
        }
        string domain = host;
        do{
            domain = trimdomain(domain);
            string wildhost = joinhost("*", domain);
            if(children.count(wildhost)){
                return children[wildhost];
            }
        }while(!domain.empty());
        return {Strategy::none, ""};
    }
    bool remove(const string& host){
        return children.erase(host) > 0;
    }
    void clear(){
        children.clear();
    }
    void stats(){
        for(auto i: children){
            if(i.second.ext.empty()){
                LOG("%s %s\n", i.first.c_str(), getstrategystring(i.second.s));
            }else{
                LOG("%s %s[%s]\n", i.first.c_str(), getstrategystring(i.second.s), i.second.ext.c_str());
            }
        }
    }
    std::list<std::pair<string, strategy>> dump(){
        std::list<std::pair<string, strategy>>slist;
        for(auto i: children){
            slist.emplace_back(i);
        }
        return slist;
    }
}domains;

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
            ipv4s.insert(addr.addr_in.sin_addr, (uint32_t)prefix, stra);
            return true;
        }
        if (inet_pton(AF_INET6, ip.c_str(), &addr.addr_in6.sin6_addr) == 1) {
            //TODO: xxx
            return false;
        }
        return false;
    }else if(inet_pton(AF_INET, host.c_str(), &addr.addr_in.sin_addr) == 1){
        ipv4s.insert(addr.addr_in.sin_addr, 32, stra);
        return true;
    }else if(inet_pton(AF_INET6, host.c_str(), &addr.addr_in.sin_addr) == 1){
        //TODO: xxx
        return false;
    } else{
        domains.insert(host, stra);
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
            ipv4s.insert(ips->addr_in.sin_addr, 32, strategy{Strategy::local, GEN_TIP});
        }
        if(ips->addr.sa_family == AF_INET6){
            //TDDO: xxx
        }
    }
    char hostname[HOST_NAME_MAX];
    gethostname(hostname, sizeof(hostname));
    domains.insert(hostname, strategy{Strategy::local, GEN_TIP});
    domains.insert("localhost", strategy{Strategy::local, GEN_TIP});
#ifdef __ANDROID__
    ifstream sitesfile(getExternalFilesDir() + "/" + LISTFILE);
    LOG("load sites from: %s\n", getExternalFilesDir().c_str());
#else
    ifstream sitesfile(LISTFILE);
#endif
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
        LOGE("There is no %s !\n", LISTFILE);
    }

    addauth("::ffff:127.0.0.1");
    addauth("::1");
    //ipv4s.stats();
    //domains.stats();
}

void savesites(){
#ifndef __ANDROID__
    ofstream sitesfile(LISTFILE);
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

bool delstrategy(const char* host) {
    bool found  = false;
    sockaddr_un addr;
    if(host[0] == '_'){
        found = true;
    }else if (inet_pton(AF_INET, host, &addr.addr_in.sin_addr) == 1) {
        found = ipv4s.remove(addr.addr_in.sin_addr);
    }else if (inet_pton(AF_INET6, host, &addr.addr_in6.sin6_addr) == 1) {
        //TODO
        found = false;
    }else{
        found = domains.remove(host);
    }
    if(found){
        savesites();
    }
    return found;
}

strategy getstrategy(const char *host){
    strategy stra{Strategy::none, ""};
    sockaddr_un addr;
    if (inet_pton(AF_INET, host, &addr.addr_in.sin_addr) == 1) {
        stra = ipv4s.find(addr.addr_in.sin_addr);
    }else if (inet_pton(AF_INET6, host, &addr.addr_in6.sin6_addr) == 1) {
        //TODO
    }else {
        stra = domains.find(host);
    }
    if(stra.s == Strategy::none){
        stra = {Strategy::direct, ""};
    }
    return stra;
}

const char* getstrategystring(Strategy s) {
    switch(s){
    case Strategy::direct:
        return "direct";
    case Strategy::forward:
        return "forward";
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
    ipv4s.dump(slist);
    auto domainlist = domains.dump();
    for(auto i: domainlist){
        slist.emplace_back(i.first, i.second);
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
