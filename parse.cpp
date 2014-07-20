#include <string.h>
#include <fstream>
#include <iostream>
#include <algorithm>
#include <unordered_set>

#include <arpa/inet.h>

#include "parse.h"

#define H302FORMAT "HTTP/1.1 302 Found" CRLF "Location: %s" CRLF "Content-Length: 0" CRLF CRLF
#define H200FORMAT "HTTP/1.1 200 OK" CRLF "Content-Length: %d" CRLF CRLF

#define PROXYFILE "proxy.list"

using namespace std;

static int loadedsite = 0;
static unordered_set<string> proxylist;


// trim from start
static inline string& ltrim(std::string && s) {
    s.erase(s.begin(), find_if(s.begin(), s.end(), std::not1(std::ptr_fun<int, int>(std::isspace))));
    return s;
}


int loadproxysite() {
    loadedsite = 1;
    proxylist.clear();
    ifstream proxyfile(PROXYFILE);

    if (proxyfile.good()) {
        while (!proxyfile.eof()) {
            string site;
            proxyfile >> site;

            if(!site.empty()) {
                proxylist.insert(site);
            }
        }

        proxyfile.close();
        return proxylist.size();
    } else {
        cerr << "There is no " << PROXYFILE << "!" << endl;
        return -1;
    }
}


void addpsite(const string& host) {
    proxylist.insert(host);
    ofstream proxyfile(PROXYFILE);

    for(auto i : proxylist) {
        proxyfile << i << endl;
    }
}


int checkproxy(const char* host) {
    if (!loadedsite) {
        loadproxysite();
    }

    //如果proxylist里面有*.*.*.* 那么ip地址直接代理
    if(inet_addr(host) != INADDR_NONE &&
       proxylist.find("*.*.*.*") != proxylist.end()) {
        return 1;
    }

    const char* subhost = host;

    while (subhost) {
        if(subhost[0] == '.') {
            subhost++;
        }

        if (proxylist.find(subhost) != proxylist.end()) {
            return 1;
        }

        subhost = strpbrk(subhost, ".");
    }

    return 0;
}

char* toUpper(char* s) {
    char* p=s;

    while(*p) {
        *p=toupper(*p);
        p++;
    }

    return s;
}


map<string, string> parse(char* header) {

    *(strstr(header, CRLF CRLF) + strlen(CRLF)) = 0;

    map<string, string> hmap;
    char method[20];
    char url[URLLIMIT] = {0};
    sscanf(header, "%s%*[ ]%[^\r\n ]", method, url);

    hmap["method"] = toUpper(method);
    hmap["url"] = url;

    for (char* str = strstr(header, CRLF) + strlen(CRLF); ; str = NULL) {
        char* p = strtok(str, CRLF);

        if (p == NULL)
            break;

        char* sp = strpbrk(p, ":");
        hmap[string(p, sp - p)] = ltrim(string(sp + 1));
    }

    return hmap;
}

int gheaderstring(map< string, string >& header, char* buff) {
    int p;
    if(!header["pmethod"].empty()) {
        sprintf(buff, "%s %s HTTP/1.1" CRLF "%n",
                header["pmethod"].c_str(), header["url"].c_str(), &p);
    } else {
        sprintf(buff, "%s %s HTTP/1.1" CRLF "%n",
                header["method"].c_str(), header["path"].c_str(), &p);
    }

    for (auto i : header) {
        int len;
        sprintf(buff + p, "%s:%s" CRLF "%n", i.first.c_str(), i.second.c_str(), &len);
        p += len;
    }

    sprintf(buff + p, CRLF);
    return p + strlen(CRLF);
}


size_t parse302(const char* location, char* buff) {
    sprintf(buff, H302FORMAT, location);
    return strlen(buff);
}

size_t parse200(int length, char* buff) {
    sprintf(buff, H200FORMAT, length);
    return strlen(buff);
}



int spliturl(const char* url, char* hostname, char* path , int* port) {
    const char* addrsplit;
    char tmpaddr[DOMAINLIMIT];
    int urllen = strlen(url);
    int copylen;
    bzero(hostname, DOMAINLIMIT);
    bzero(path, urllen);

    if (strncasecmp(url, "https://", 8) == 0) {
        url += 8;
        urllen -= 8;
        *port = HTTPSPORT;
    } else if (strncasecmp(url, "http://", 7) == 0) {
        url += 7;
        urllen -= 7;
        *port = HTTPPORT;
    } else if (!strstr(url, "://")) {
        *port = HTTPPORT;
    } else {
        return -1;
    }

    if ((addrsplit = strpbrk(url, "/"))) {
        copylen = url + urllen - addrsplit < (URLLIMIT - 1) ? url + urllen - addrsplit : (URLLIMIT - 1);
        memcpy(path, addrsplit, copylen);
        copylen = addrsplit - url < (DOMAINLIMIT - 1) ? addrsplit - url : (DOMAINLIMIT - 1);
        strncpy(tmpaddr, url, copylen);
        tmpaddr[copylen] = 0;
    } else {
        copylen = urllen < (DOMAINLIMIT - 1) ? urllen : (DOMAINLIMIT - 1);
        strncpy(tmpaddr, url, copylen);
        strcpy(path, "/");
        tmpaddr[copylen] = 0;
    }

    if (tmpaddr[0] == '[') {                                //this is a ipv6 address
        if (!(addrsplit = strpbrk(tmpaddr, "]"))) {
            return -1;
        }

        strncpy(hostname, tmpaddr + 1, addrsplit - tmpaddr - 1);

        if (addrsplit[1] == ':') {
            if(sscanf(addrsplit + 2, "%d", port) != 1)
                return -1;
        } else if (addrsplit[1] != 0) {
            return -1;
        }
    } else {
        if ((addrsplit = strpbrk(tmpaddr, ":"))) {
            strncpy(hostname, url, addrsplit - tmpaddr);

            if(sscanf(addrsplit + 1, "%d", port) != 1)
                return -1;
        } else {
            strcpy(hostname, tmpaddr);
        }
    }

    return 0;
}
