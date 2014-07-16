#include <map>
#include <string>
#include <string.h>
#include <fstream>
#include <iostream>
#include <unordered_set>

#include <arpa/inet.h>

#include "parse.h"

#define H302FORMAT "HTTP/1.1 302 Found" CRLF "Location: %s" CRLF CRLF

using namespace std;

static int loadedsite = 0;
static unordered_set<string> blocklist;

int loadproxysite()
{
    loadedsite = 1;
    blocklist.clear();
    ifstream blockfile("proxy.list");
    if (blockfile.good()) {
        while (!blockfile.eof()) {
            string site;
            blockfile >> site;
            if(!site.empty()){
                blocklist.insert(site);
            }
        }
        blockfile.close();
        return blocklist.size();
    } else {
        cerr << "There is no blocked.list!" << endl;
        return -1;
    }
}


void addpsite(const char* host){
    blocklist.insert(host);
    ofstream blockfile("blocked.list");
    for(auto i:blocklist){
        blockfile<<i<<endl;
    }
}


int checkproxy(const char* host)
{
    if (!loadedsite) {
        loadproxysite();
    }
    
    //如果blocklist里面有*.*.*.* 那么ip地址直接代理
    if(inet_addr(host)!=INADDR_NONE && 
        blocklist.find("*.*.*.*") != blocklist.end()){
        return 1;
    }
    
    const char *subhost = host;
    while (subhost) {
        if(subhost[0] == '.'){
            subhost++;
        }
        if (blocklist.find(subhost) != blocklist.end()) {
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
    return p+sizeof(CRLF);

}

int parse302(const char* location, char* buff){
    sprintf(buff,H302FORMAT,location);
    return strlen(buff);
}

