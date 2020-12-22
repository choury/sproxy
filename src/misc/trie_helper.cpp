#include <string>
#include <list>
#include <netdb.h>
#include <assert.h>
#include <string.h>
#include <arpa/inet.h>
#include "net.h"

std::list<std::string> split(std::string s){
    std::list<std::string> tokens;
    std::string::size_type split = 0;
    while((split = s.find_last_of('.')) != std::string::npos){
        tokens.emplace_back(s.substr(split+1));
        s = s.substr(0, split);
    }
    tokens.emplace_back(s);
    return tokens;
}

std::string join(std::list<std::string> tokens) {
    if(tokens.empty()){
        return "";
    }
    std::string s;
    for(auto i = tokens.rbegin(); i != tokens.rend(); i++){
        s += ".";
        s += *i;
    }
    return s.substr(1);
}


std::list<char> split(in_addr ip, int prefix = -1) {
    prefix = prefix < 0 ? 32 : prefix;
    assert(prefix <= 32 && prefix >= 0);
    std::list<char> ipbytes;
    uint32_t iph = ntohl(ip.s_addr);
    for(int i = 0; i < prefix ; i++){
        char bytes = (iph >> (31-i)) & 1;
        ipbytes.push_back(bytes + '0');
    }
    if(prefix < 32) {
        ipbytes.push_back('*');
    }
    return ipbytes;
}

static const char *dumpip(const sockaddr_storage *addr_){
    sockaddr* addr = (sockaddr*)addr_;
    static char buff[100];
    if(addr->sa_family == AF_INET6){
        sockaddr_in6* ip6 = (sockaddr_in6*)addr;
        inet_ntop(AF_INET6, &ip6->sin6_addr, buff, sizeof(buff));
    }
    if(addr->sa_family == AF_INET){
        sockaddr_in* ip = (sockaddr_in*)addr;
        inet_ntop(AF_INET, &ip->sin_addr, buff, sizeof(buff));
    }
    return buff;
}


std::string join(int type, std::list<char> tokens){
    int prefix = 0;
    if(type == AF_INET){
        sockaddr_in ip4;
        ip4.sin_family = AF_INET;
        uint32_t ipn = 0;
        for(auto c : tokens){
            if(c == '*') {
                break;
            }
            ipn |= (c-'0') << (31 - prefix);
            prefix ++; 
        }
        ip4.sin_addr.s_addr = ntohl(ipn);
        std::string ip = dumpip((sockaddr_storage*)&ip4);
        if(prefix == 32){
            return ip;
        }else{
            return ip + "/" + std::to_string(prefix);
        }
    }
    if(type == AF_INET6){
        sockaddr_in6 ip6;
        memset(&ip6, 0, sizeof(ip6));
        ip6.sin6_family = AF_INET6;
        for(auto c : tokens){
            if(c == '*') {
                break;
            }
            ip6.sin6_addr.s6_addr[prefix/8] |= (c-'0') << (7 - prefix%8);
            prefix ++; 
        }
        std::string ip = dumpip((sockaddr_storage*)&ip6);
        if(prefix == 128){
            return ip;
        }else{
            return ip + "/" + std::to_string(prefix);
        }
    }
    return "";
}

std::list<char> split(in6_addr ip6, int prefix = -1) {
    prefix = prefix < 0 ? 128 : prefix;
    assert(prefix <= 128 && prefix >= 0);
    std::list<char> ipbytes;
    for(int i = 0; i < prefix; i++) {
        char bytes = (ip6.s6_addr[i/8] >> (7 - i%8)) & 1;
        ipbytes.push_back(bytes + '0');
    }
    if(prefix < 128) {
        ipbytes.push_back('*');
    }
    return ipbytes;
}

std::list<char> split(const sockaddr_storage* ip, int prefix){
    if(ip->ss_family == AF_INET6){
        sockaddr_in6* ip6 = (sockaddr_in6*)ip;
        return split(ip6->sin6_addr, prefix<0?128:prefix);
    }else{
        sockaddr_in* ip4 = (sockaddr_in*)ip;
        return split(ip4->sin_addr, prefix<0?32:prefix);
    }
}