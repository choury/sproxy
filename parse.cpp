#include <string.h>
#include <fstream>
#include <iostream>
#include <algorithm>
#include <unordered_set>

#include <arpa/inet.h>

#include "parse.h"
#include "common.h"


#define PROXYFILE "proxy.list"

using namespace std;

static int loadedsite = 0;
static int GLOBALPROXY = 0;
static unordered_set<string> proxylist;


// trim from start
static inline string& ltrim(std::string && s) {
    s.erase(0,s.find_first_not_of(" "));
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
    proxyfile.close();
}

int delpsite(const string& host) {
    if(proxylist.find(host)==proxylist.end()) {
        return 0;
    }
    proxylist.erase(host);
    ofstream proxyfile(PROXYFILE);

    for(auto i : proxylist) {
        proxyfile << i << endl;
    }
    proxyfile.close();
    return 1;
}

int globalproxy() {
    GLOBALPROXY= !GLOBALPROXY;
    return GLOBALPROXY;
}

bool checkproxy(const char *hostname) {
    if (!loadedsite) {
        loadproxysite();
    }

    if(GLOBALPROXY) {
        return true;
    }

    //如果proxylist里面有*.*.*.* 那么ip地址直接代理
    if(inet_addr(hostname) != INADDR_NONE &&
            proxylist.find("*.*.*.*") != proxylist.end()) {
        return true;
    }

    const char* subhost = hostname;

    while (subhost) {
        if(subhost[0] == '.') {
            subhost++;
        }

        if (proxylist.find(subhost) != proxylist.end()) {
            return true;
        }

        subhost = strpbrk(subhost, ".");
    }

    return false;
}

char* toUpper(char* s) {
    char* p=s;

    while(*p) {
        *p=toupper(*p);
        p++;
    }

    return s;
}

char* toLower(char* s) {
    char* p=s;

    while(*p) {
        *p=tolower(*p);
        p++;
    }

    return s;
}


int spliturl(const char* url, char* hostname, char* path , uint16_t* port) {
    const char* addrsplit;
    char tmpaddr[DOMAINLIMIT];
    int urllen = strlen(url);
    int copylen;
    bzero(hostname, DOMAINLIMIT);
    if(path) {
        bzero(path, urllen);
    }

    if (strncasecmp(url, "https://", 8) == 0) {
        url += 8;
        urllen -= 8;
        *port = HTTPSPORT;
    } else if (strncasecmp(url, "http://", 7) == 0) {
        url += 7;
        urllen -= 7;
        *port = HTTPPORT;
    } else if (strstr(url, "://") != 0) {
        return -1;
    }

    if ((addrsplit = strpbrk(url, "/"))) {
        copylen = url + urllen - addrsplit < (URLLIMIT - 1) ? url + urllen - addrsplit : (URLLIMIT - 1);
        if(path) {
            memcpy(path, addrsplit, copylen);
        }
        copylen = addrsplit - url < (DOMAINLIMIT - 1) ? addrsplit - url : (DOMAINLIMIT - 1);
        strncpy(tmpaddr, url, copylen);
        tmpaddr[copylen] = 0;
    } else {
        copylen = urllen < (DOMAINLIMIT - 1) ? urllen : (DOMAINLIMIT - 1);
        strncpy(tmpaddr, url, copylen);
        if(path) {
            strcpy(path, "/");
        }
        tmpaddr[copylen] = 0;
    }

    if (tmpaddr[0] == '[') {                                //this is a ipv6 address
        if (!(addrsplit = strpbrk(tmpaddr, "]"))) {
            return -1;
        }

        strncpy(hostname, tmpaddr + 1, addrsplit - tmpaddr - 1);

        if (addrsplit[1] == ':') {
            if(sscanf(addrsplit + 2, "%hd", port) != 1)
                return -1;
        } else if (addrsplit[1] != 0) {
            return -1;
        }
    } else {
        if ((addrsplit = strpbrk(tmpaddr, ":"))) {
            strncpy(hostname, url, addrsplit - tmpaddr);

            if(sscanf(addrsplit + 1, "%hd", port) != 1)
                return -1;
        } else {
            strcpy(hostname, tmpaddr);
        }
    }

    return 0;
}


HttpReqHeader::HttpReqHeader(char* header)throw (int) {
    if(header[0]){   //第一个字节不为0，说明是一个HTTP/1.x头部
        *(strstr(header, CRLF CRLF) + strlen(CRLF)) = 0;
        memset(path,0,sizeof(path));
        memset(url,0,sizeof(url));
        sscanf(header, "%s%*[ ]%[^\r\n ]", method, url);
        toUpper(method);
        port=80;

        if(spliturl(url,hostname,path,&port)) {
            LOGE("wrong url format:%s\n",url);
            throw 0;
        }


        for (char* str = strstr(header, CRLF) + strlen(CRLF); ; str = NULL) {
            char* p = strtok(str, CRLF);

            if (p == NULL)
                break;

            char* sp = strpbrk(p, ":");
            if(sp==NULL) {
                LOGE("wrong header format:%s\n",p);
                throw 0;
            }
            this->header[string(p, sp - p)] = ltrim(string(sp + 1));
        }

        this->header.erase("Proxy-Connection");
        this->header.erase("Host");
    }else{
        uint32_t *p=(uint32_t *)header;
        uint32_t c=ntohl(*p++);
        for(size_t i=0; i<c; ++i) {
            uint32_t nlen=ntohl(*p++);
            char *np=(char *)p;
            p=(uint32_t*)(np+nlen);
            uint32_t vlen=ntohl(*p++);
            char *vp=(char *)p;
            p=(uint32_t *)((char *)p+vlen);
            this->header[string(np,nlen)] = string(vp,vlen);
        }
        sprintf(url,"%s://%s%s",
                this->header[":scheme"].c_str(),
                this->header[":host"].c_str(),
                this->header[":path"].c_str());
        spliturl(url,hostname,path,&port);
        strcpy(method,this->header[":method"].c_str());
        for(auto i=this->header.begin(); i!=this->header.end();) {
            if(i->first[0]==':') {
                this->header.erase(i++);
            } else {
                i++;
            }
        }
    }

}

int HttpReqHeader::getstring( char* buff) {
    int p;
    if(checkproxy(hostname)) {
        sprintf(buff, "%s %s HTTP/1.1" CRLF "%n",
                method,url, &p);
    } else {
        if(strcmp(method,"CONNECT")==0){
            return 0;
        }
        sprintf(buff, "%s %s HTTP/1.1" CRLF "%n",
                method, path, &p);
    }
    int len;
    sprintf(buff+p,"Host: %s" CRLF "%n",hostname,&len);
    p+=len;
    for (auto i : header) {
        int len;
        sprintf(buff + p, "%s: %s" CRLF "%n", i.first.c_str(), i.second.c_str(), &len);
        p += len;
    }

    sprintf(buff + p, CRLF);
    return p + strlen(CRLF);
}

string HttpReqHeader::getval(const char* key) {
    return header[key];
}


bool HttpReqHeader::ismethod(const char* method) {
    return strcmp(this->method,method)==0;
}


HttpResHeader::HttpResHeader(const char* status) {
    strcpy(this->status,status);
}


void HttpResHeader::add(const char* header, const char* value) {
    this->header[header]=value;
}

int HttpResHeader::getstring(char* buff, protocol proto) {
    switch(proto) {
    case HTTP:
        int p;
        sprintf(buff, "%s HTTP/1.1" CRLF "%n",status, &p);
        for (auto i : header) {
            int len;
            sprintf(buff + p, "%s: %s" CRLF "%n", i.first.c_str(), i.second.c_str(), &len);
            p += len;
        }

        sprintf(buff + p, CRLF);
        return p + strlen(CRLF);
    case SPDY:
        uint32_t *q=(uint32_t *)buff;
        *q++=htonl(header.size()+2);
        
        //for ":status" => "200 OK" etc
        int nlen=7;
        *q++=htonl(nlen);
        memcpy(q,":status",nlen);
        q=(uint32_t *)(((char *)q)+nlen);
        int vlen=strlen(status);
        *q++=htonl(vlen);
        memcpy(q,status,vlen);
        q=(uint32_t *)(((char *)q)+vlen);
        
        //for ":version" => "HTTP/1.1"
        nlen=8;
        *q++=htonl(nlen);
        memcpy(q,":version",nlen);
        q=(uint32_t *)(((char *)q)+nlen);
        vlen=strlen("HTTP/1.1");
        *q++=htonl(vlen);
        memcpy(q,"HTTP/1.1",vlen);
        q=(uint32_t *)(((char *)q)+vlen);
        for (auto i : header) {
            nlen=i.first.length();
            *q++=htonl(nlen);
            memcpy(q,i.first.data(),nlen);
            q=(uint32_t *)(((char *)q)+nlen);
            vlen=i.second.length();
            *q++=htonl(vlen);
            memcpy(q,i.second.data(),vlen);
            q=(uint32_t *)(((char *)q)+vlen);
        }
        return (char *)q-buff;
    }
    return 0;
}
