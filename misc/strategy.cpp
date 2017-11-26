#include "strategy.h"
#include "net.h"
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

#define LISTFILE "sites.list"

using std::string;
using std::map;
using std::ifstream;
using std::ofstream;

static string reverse(string str){
    string::size_type split = 0;
    string result;
    while((split = str.find_last_of(".")) != string::npos){
        result += str.substr(split+1) + '.';
        str = str.substr(0, split);
    }
    result += str;
    return result;
}


class Stra{
    Strategy strategy = Strategy::none;
    string ext;
    map<string, Stra> domains;
    map<uint64_t, Strategy> ip4s;
    void insert(string host, Strategy strategy, string ext);
    Strategy find(string host, string& ext);
    bool remove(string host);
    bool purge(Strategy strategy);
public:
    void add(const char* host, Strategy strategy, string ext){
        string domain = host;
        auto mask_pos = domain.find_first_of("/");
        string ip = domain.substr(0, mask_pos);
        uint32_t ipv4 = inet_addr(ip.c_str());
        if(ipv4 != INADDR_NONE){
            uint32_t mask = 0xffffffff;
            if(mask_pos != string::npos){
#ifdef __ANDROID__
                int prefix = atoi(domain.substr(mask_pos+1).c_str());
#else
                int prefix = stoi(domain.substr(mask_pos+1));
#endif
                mask =  ((uint64_t)1 << prefix) - 1;
            }
            ip4s[(uint64_t)ipv4 << 32 | mask] = strategy;
            return;
        }
        if(host[0] == '_'){
            this->strategy = strategy;
        }
        return insert(reverse(host), strategy, ext);
    }
    Strategy get(const char* host, string& ext){
        uint32_t ipv4 = inet_addr(host);
        if(ipv4 != INADDR_NONE){
            for(auto i: ip4s){
                uint32_t mask = i.first & 0xffffffff;
                uint32_t net = i.first >> 32;
                if((net & mask ) == (ipv4 & mask)){
                    ext = this->ext;
                    return i.second;
                }
            }
            return strategy;
        }
        return find(reverse(host), ext);
    }
    bool del(const char *host){
        uint32_t ipv4 = inet_addr(host);
        if(ipv4 != INADDR_NONE){
            for(auto i: ip4s){
                uint32_t mask = i.first & 0xffffffff;
                uint32_t net = i.first >> 32;
                if((net & mask ) == (ipv4 & mask)){
                    ip4s.erase(i.first);
                    return true;
                }
            }
            return false;
        }
        if(host[0] == '_'){
            strategy = Strategy::direct;
        }
        return remove(reverse(host));
    }
    void clear();
    void stats(int tab);
    std::list<std::tuple<string, string, string>> dump();
}sites;

void Stra::insert(string host, Strategy strategy, string ext){
    assert(strategy != Strategy::none);
    auto pos = host.find_first_of(".");
    if(pos == string::npos){
        domains[host].strategy =  strategy;
        domains[host].ext = ext;
        domains[host].purge(strategy);
        return;
    }else{
        domains[host.substr(0, pos)].insert(host.substr(pos+1), strategy, ext);
    }
}

bool Stra::purge(Strategy strategy){
    for(auto i= domains.begin();i != domains.end();){
        if(i->second.purge(strategy)){
            i = domains.erase(i);
        }else{
            i++;
        }
    }
    return (domains.empty() &&
        (this->strategy == strategy || this->strategy == Strategy::none));
}

Strategy Stra::find(string host, string& ext) {
    if(host == ""){
        ext = this->ext;
        return strategy;
    }
    string subhost;
    auto pos = host.find_first_of(".");
    if(pos == string::npos){
        subhost = "";
    }else{
        subhost = host.substr(pos+1);
    }
    Strategy s = Strategy::none;
    if(domains.count(host.substr(0, pos)))
        s= domains[host.substr(0, pos)].find(subhost, ext);
    if(s != Strategy::none)
        return s;
    ext = this->ext;
    return strategy;
}

void Stra::clear() {
    ip4s.clear();
    domains.clear();
}


bool Stra::remove(string host) {
    auto pos = host.find_first_of(".");
    if(pos == string::npos){
        if(domains.count(host)){
            if(domains[host].strategy == Strategy::none){
                return false;
            }
            if(domains[host].domains.empty()){
                domains.erase(host);
            }else{
                domains[host].strategy = Strategy::none;
            }
            return true;
        }else{
            return false;
        }
    }else{
        string subhost = host.substr(pos+1);
        if(domains.count(host.substr(0, pos))){
            return domains[host.substr(0, pos)].remove(subhost);
        }else{
            return false;
        }
    }
}

void Stra::stats(int tab){
    for(auto i: ip4s){
        int prefix = 0;
        uint32_t mask = i.first&0xffffffff;
        while(mask){
            prefix ++;
            mask >>= 1;
        }
        uint32_t net = i.first >> 32;
        LOG("%s/%d: %s\n", inet_ntoa(in_addr{net}), prefix, getstrategystring(i.second));
    }
    char tabs[100]= {0};
    for(int i = 0; i<tab; i++){
        tabs[i]='\t';
    }
    if(domains.size()){
        if(strategy != Strategy::none){
            LOG("[%zu] %s\n", domains.size(), getstrategystring(strategy));
        }else{
            LOG("[%zu]\n", domains.size());
        }
        for(auto i: domains){
            LOG("%s %s", tabs, i.first.c_str());
            i.second.stats(tab+1);
        }
    }else{
        LOG(" %s\n", getstrategystring(strategy));
    }
}


std::list<std::tuple<string, string, string>> Stra::dump(){
    std::list<std::tuple<string, string, string>>slist;
    for(auto i: ip4s){
        uint32_t net = i.first >> 32;
        uint32_t mask = i.first&0xffffffff;
        char ipv4_string[100];
        if(mask != 0xffffffff){
            int prefix = 0;
            while(mask){
                prefix ++;
                mask >>= 1;
            }
            sprintf(ipv4_string, "%s/%d", inet_ntoa(in_addr{net}), prefix);
        }else{
            sprintf(ipv4_string, "%s", inet_ntoa(in_addr{net}));
        }
        slist.push_back(std::make_tuple(ipv4_string, getstrategystring(i.second), ext));
    }
    if(domains.size()){
        for(auto i: domains){
            auto submap =  i.second.dump();
            for(auto j:submap){
                if(std::get<0>(j) != ""){
                    slist.push_back(std::make_tuple(std::get<0>(j)+'.'+i.first,  std::get<1>(j), std::get<2>(j)));
                }else{
                    slist.push_back(std::make_tuple(i.first, std::get<1>(j), std::get<2>(j)));
                }
            }
        }
    }
    if(strategy != Strategy::none){
        slist.push_back(std::make_tuple("",  getstrategystring(strategy), ext));
    }
    return slist;
}

static bool mergestrategy(const char* host, const char* strategy, string ext){
    Strategy s;
    if(strcmp(strategy, "direct") == 0){
        s = Strategy::direct;
    }else if(strcmp(strategy, "proxy") == 0){
        s = Strategy::proxy;
    }else if(strcmp(strategy, "local") == 0){
        s = Strategy::local;
    }else if(strcmp(strategy, "block") == 0){
        s = Strategy::block;
    }else if(strcmp(strategy, "forward") == 0){
        s = Strategy::forward;
    }else{
        return false;
    }
    sites.add(host, s, ext);
    return true;
}

std::string getExternalFilesDir();

void reloadstrategy() {
    sites.clear();

    //default strategy
    for(const char *ips=getlocalip(); ips && strlen(ips); ips+=INET6_ADDRSTRLEN){
        sites.add(ips, Strategy::local, "");
    }
    char hostname[HOST_NAME_MAX];
    gethostname(hostname, sizeof(hostname));
    sites.add(hostname, Strategy::local, "");
    sites.add("localhost", Strategy::local, "");
    sites.add("_", Strategy::direct, "");

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
//    sites.stats(0);
}

void savesites(){
#ifndef __ANDROID__
    ofstream sitesfile(LISTFILE);
    auto list = getallstrategy();
    for (auto i:list) {
        if(std::get<0>(i) == ""){
            sitesfile <<"_ "<<std::get<1>(i)<<' '<<std::get<2>(i)<< std::endl;
        }else{
            sitesfile <<std::get<0>(i)<<' '<<std::get<1>(i)<<' '<<std::get<2>(i)<< std::endl;
        }
    }
    sitesfile.close();
#endif
}


bool addstrategy(const char* host, const char* strategy, string ext) {
    if(mergestrategy(host, strategy, ext)){
        savesites();
        return true;
    }
    return false;
}

bool delstrategy(const char* host) {
    if(sites.del(host)){
        savesites();
        return true;
    }else{
        return false;
    }
}



Strategy getstrategy(const char *host, string& ext){
    return sites.get(host, ext);
}

const char* getstrategystring(Strategy s)
{
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

std::list<std::tuple<std::string, std::string, std::string>> getallstrategy(){
    return sites.dump();
}

static std::set<string> authips;
void addauth(const char *ip) {
    authips.insert(ip);
}

bool checkauth(const char *ip) {
    if(strlen(auth_string) == 0)
        return true;
    return authips.count(ip);
}
