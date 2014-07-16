#include <map>
#include <string>
#include <string.h>
#include <fstream>
#include <iostream>
#include <unordered_set>

#include <arpa/inet.h>

#include "parse.h"

#define H302FORMAT "HTTP/1.1 302 Found" CRLF "Location: %s" CRLF CRLF

#define PROXYFILE "proxy.list"

using namespace std;

static int loadedsite = 0;
static unordered_set<string> proxylist;

int loadproxysite()
{
    loadedsite = 1;
    proxylist.clear();
    ifstream proxyfile(PROXYFILE);
    if (proxyfile.good()) {
        while (!proxyfile.eof()) {
            string site;
            proxyfile >> site;
            if(!site.empty()){
                proxylist.insert(site);
            }
        }
        proxyfile.close();
        return proxylist.size();
    } else {
        cerr << "There is no "<<PROXYFILE<<"!" << endl;
        return -1;
    }
}


void addpsite(const char* host){
    proxylist.insert(host);
    ofstream proxyfile(PROXYFILE);
    for(auto i:proxylist){
        proxyfile<<i<<endl;
    }
}


int checkproxy(const char* host)
{
    if (!loadedsite) {
        loadproxysite();
    }
    
    //如果proxylist里面有*.*.*.* 那么ip地址直接代理
    if(inet_addr(host)!=INADDR_NONE && 
        proxylist.find("*.*.*.*") != proxylist.end()){
        return 1;
    }
    
    const char *subhost = host;
    while (subhost) {
        if(subhost[0] == '.'){
            subhost++;
        }
        if (proxylist.find(subhost) != proxylist.end()) {
            return 1;
        }
        subhost = strpbrk(subhost, ".");
    }

    return 0;
}

int parse(char* header)
{
    map<string, string> hmap;
    strcpy(header, header);
    for (char* str = header; ; str = NULL) {
        char* p = strtok(str, CRLF);
        if (p == NULL)
            break;
        char* sp = strpbrk(p, ":");
        hmap[string(p, sp - p)] = string(sp + 1);
    }

    int p = 0;
    for (auto i : hmap) {
        int len;
        sprintf(header + p, "%s:%s" CRLF "%n", i.first.c_str(), i.second.c_str(), &len);
        p += len;
    }
    sprintf(header + p, CRLF);
    cout<<header;
    
    if(hmap.find("ccept") != hmap.end()){
        return 1;
    }else {
        return 0;
    }

}

size_t parse302(const char* location, char* buff){
    sprintf(buff,H302FORMAT,location);
    return strlen(buff);
}

