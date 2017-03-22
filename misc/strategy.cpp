#include "strategy.h"
#include "net.h"
#include "common.h"
#include <string>
#include <unordered_map>
#include <set>
#include <fstream>

#include <string.h>
#include <bits/local_lim.h>
#include <unistd.h>

#define LISTFILE "sites.list"

using std::string;
using std::unordered_map;
using std::ifstream;
using std::ofstream;

static std::set<string> authips;

static unordered_map<string, Strategy> sites;



void loadsites() {
    sites.clear();

    //default strategy
    for(const char *ips=getlocalip(); strlen(ips); ips+=INET6_ADDRSTRLEN){
        sites[ips] = Strategy::local;
    }
    char hostname[HOST_NAME_MAX];
    gethostname(hostname, sizeof(hostname));
    sites[hostname] = Strategy::local;
    sites["localhost"] = Strategy::local;

    ifstream sitesfile(LISTFILE);
    if (sitesfile.good()) {
        string line;
        while (std::getline(sitesfile, line)) {
            if(line[0] == '#'){
                continue;
            }

            char site[DOMAINLIMIT];
            char strategy[20];
            char proxy[DOMAINLIMIT];
            sscanf(line.c_str(), "%s %s %s", site, strategy, proxy);

            if(strcmp(strategy, "direct") == 0){
                sites[site] = Strategy::direct;
            }else if(strcmp(strategy, "proxy") == 0){
                sites[site] = Strategy::proxy;
            }else if(strcmp(strategy, "local") == 0){
                sites[site] = Strategy::local;
            }else if(strcmp(strategy, "block") == 0){
                sites[site] = Strategy::block;
            }else if(line.length()){
                LOGE("Wrong config line:%s\n",line.c_str());
            }
        }

        sitesfile.close();
    } else {
        LOGE("There is no %s !\n", LISTFILE);
    }

    addauth("::ffff:127.0.0.1");
    addauth("::1");

}

void savesites(){
    ofstream sitesfile(LISTFILE);

    for (auto i : sites) {
        switch(i.second){
        case Strategy::direct:
            sitesfile <<i.first<<":direct"<< std::endl;
            break;
        case Strategy::proxy:
            sitesfile <<i.first<<":proxy"<< std::endl;
            break;
        case Strategy::local:
            sitesfile <<i.first<<":local"<< std::endl;
            break;
        case Strategy::block:
            sitesfile <<i.first<<":block"<< std::endl;
            break;
        }
    }
    sitesfile.close();
}

bool addstrategy(const char* host, const char* strategy) {
    if(strcmp(strategy, "direct") == 0){
        sites[host] = Strategy::direct;
        return true;
    }else if(strcmp(strategy, "proxy") == 0){
        sites[host] = Strategy::proxy;
        return true;
    }else if(strcmp(strategy, "local") == 0){
        sites[host] = Strategy::local;
        return true;
    }else if(strcmp(strategy, "block") == 0){
        sites[host] = Strategy::block;
        return true;
    }else{
        return false;
    }
}

bool delstrategy(const char* host) {
    if(sites.count(host)){
        sites.erase(host);
        return true;
    }else{
        return false;
    }
}



Strategy getstrategy(const char *host){
    if (inet_addr(host) != INADDR_NONE){
        //ip address should not be split
        if(sites.count("*.*.*.*")) {
            return sites["*.*.*.*"];
        }else if(sites.count(host)){
            return sites[host];
        }else{
            return sites["_"];
        }
    }
    const char* subhost = host;

    while (subhost) {
        if (subhost[0] == '.') {
            subhost++;
        }

        if (sites.count(subhost)) {
            return sites[subhost];
        }
        subhost = strpbrk(subhost, ".");
    }
    return sites["_"];
}

const char* getstrategystring(Strategy s)
{
    switch(s){
    case Strategy::direct:
        return "direct";
    case Strategy::proxy:
        return "proxy";
    case Strategy::local:
        return "local";
    case Strategy::block:
        return "block";
    }
    return nullptr;
}

std::map<std::string, std::string> getallstrategy(){
    std::map<std::string, std::string> smap;
    for(auto i:sites){
        smap[i.first] = getstrategystring(i.second);
    }
    return smap;
}

void addauth(const char *ip) {
    authips.insert(ip);
}

bool checkauth(const char *ip) {
    return authips.count(ip);
}
