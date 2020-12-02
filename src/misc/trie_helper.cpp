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


std::list<char> split(in_addr ip, uint32_t prefix = 32) {
    assert(prefix <= 32);
    std::list<char> ipbytes;
    uint32_t iph = ntohl(ip.s_addr);
    for(uint32_t i = 0; i < prefix ; i++){
        char bytes = (iph >> (31-i)) & 1;
        ipbytes.push_back(bytes + '0');
    }
    if(prefix < 32) {
        ipbytes.push_back('*');
    }
    return ipbytes;
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
        std::string ip = getaddrstring((sockaddr_un*)&ip4);
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
        std::string ip = getaddrstring((sockaddr_un*)&ip6);
        if(prefix == 128){
            return ip;
        }else{
            return ip + "/" + std::to_string(prefix);
        }
    }
    return "";
}

std::list<char> split(in6_addr ip6, uint32_t prefix = 128) {
    assert(prefix <= 128);
    std::list<char> ipbytes;
    for(uint32_t i = 0; i < prefix; i++) {
        char bytes = (ip6.s6_addr[i/8] >> (7 - i%8)) & 1;
        ipbytes.push_back(bytes + '0');
    }
    if(prefix < 128) {
        ipbytes.push_back('*');
    }
    return ipbytes;
}