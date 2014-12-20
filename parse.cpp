#include <string.h>
#include <fstream>
#include <iostream>
#include <algorithm>
#include <unordered_set>

#include <arpa/inet.h>

#include "common.h"
#include "parse.h"



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
    if(proxylist.count(host)==0) {
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

    if(GLOBALPROXY || proxylist.count("*")) {
        return true;
    }

    //如果proxylist里面有*.*.*.* 那么ip地址直接代理
    if(inet_addr(hostname) != INADDR_NONE && proxylist.count("*.*.*.*")) {
        return true;
    }

    const char* subhost = hostname;

    while (subhost) {
        if(subhost[0] == '.') {
            subhost++;
        }

        if (proxylist.count(subhost)) {
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

string toLower(const string &s) {
    string str=s;
    std::transform(str.begin(), str.end(), str.begin(), ::tolower);
    return str;
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


HttpReqHeader::HttpReqHeader(){

}



HttpReqHeader::HttpReqHeader(void* header){
    char *httpheader=(char *)header;
    *(strstr(httpheader, CRLF CRLF) + strlen(CRLF)) = 0;
    memset(path,0,sizeof(path));
    memset(url,0,sizeof(url));
    sscanf(httpheader, "%s%*[ ]%[^\r\n ]", method, url);
    toUpper(method);
    port=80;

    if(spliturl(url,hostname,path,&port)) {
        LOGE("wrong url format:%s\n",url);
        throw 0;
    }

    for (char* str = strstr(httpheader, CRLF) + strlen(CRLF); ; str = NULL) {
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
}

HttpReqHeader::HttpReqHeader(syn_frame* sframe, z_stream* instream) {
    size_t len=get24(sframe->head.length);
    char tmpbuff[HEADLENLIMIT];
    if(spdy_inflate(instream,sframe+1,len-sizeof(syn_frame)+sizeof(spdy_head),tmpbuff,sizeof(tmpbuff))<0)
        throw 0;
    uint32_t *p=(uint32_t *)tmpbuff;
    uint32_t c=ntohl(*p++);
    for(size_t i=0; i<c; ++i) {
        uint32_t nlen=ntohl(*p++);
        char *np=(char *)p;
        p=(uint32_t*)(np+nlen);
        if((char *)p-tmpbuff>=HEADLENLIMIT)
            throw 0;
        uint32_t vlen=ntohl(*p++);
        char *vp=(char *)p;
        p=(uint32_t *)((char *)p+vlen);
        if((char *)p-tmpbuff>=HEADLENLIMIT)
            throw 0;
        header[string(np,nlen)] = string(vp,vlen);
    }
    strcpy(method,header[":method"].c_str());
    
    if(ismethod("CONNECT")){
        strcpy(url,header[":path"].c_str());
    }else{
        sprintf(url,"%s://%s%s",header[":scheme"].c_str(),
                header[":host"].c_str(),header[":path"].c_str());
    }
    spliturl(url,hostname,path,&port);
    for(auto i=header.begin(); i!=header.end();) {
        if(i->first[0]==':') {
            header.erase(i++);
        } else {
            i++;
        }
    }
}


bool HttpReqHeader::ismethod(const char* method) {
    return strcmp(this->method,method)==0;
}

char *addnv(void *buff,const char *name,size_t nlen,const char *val,size_t vlen) {
    uint32_t *p=(uint32_t *)buff;
    *p++=htonl(nlen);
    char *q=(char *)p;
    while(nlen--) {
        *q++=tolower(*name++);
    }
    p=(uint32_t *)q;
    *p++=htonl(vlen);
    q=(char *)p;
    while(vlen--) {
        *q++=*val++;
    }
    return q;
}


const char* HttpReqHeader::getval(const char* key) {
    if(header.count(key)) {
        return header[key].c_str();
    } else {
        return nullptr;
    }
}

int HttpReqHeader::getstring(void* outbuff) {
    char *buff=(char *)outbuff;
    int p;
    if(checkproxy(hostname)) {
        sprintf(buff, "%s %s HTTP/1.1" CRLF "%n",
                method,url, &p);
    } else {
        if(strcmp(method,"CONNECT")==0) {
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


int HttpReqHeader::getframe(void* buff, z_stream* destream, size_t id) {
    syn_frame* sframe=(syn_frame *)buff;
    memset(sframe,0,sizeof(*sframe));
    sframe->head.magic = CTRL_MAGIC;
    sframe->head.type=htons(SYN_TYPE);
    if(strcmp(method,"POST")) {
        sframe->head.flag = FLAG_FIN;
    }

    sframe->id=htonl(id);
    sframe->priority=3;
    char tmpbuff[HEADLENLIMIT];


    char *p=tmpbuff;
    *(uint32_t *)p=htonl(header.size()+5);
    p += 4;
    p=addnv(p,":method",7,method,strlen(method));
    p=addnv(p,":version",8,"HTTP/1.1",8);
    p=addnv(p,":host",5,hostname,strlen(hostname));
    if(strcmp(method,"CONNECT")==0) {
        p=addnv(p,":path",5,url,strlen(url));
    } else {
        p=addnv(p,":path",5,path,strlen(path));
        p=addnv(p,":scheme",7,"http",4);
    }
    for(auto i:header) {
        p=addnv(p,i.first.data(),i.first.length(),i.second.data(),i.second.length());
    }
    int len=p-tmpbuff;
    len=sizeof(syn_frame)-sizeof(spdy_head)+
        spdy_deflate(destream,tmpbuff,len,sframe+1,0);
    set24(sframe->head.length,len);
    return len+sizeof(spdy_head);
}



HttpResHeader::HttpResHeader(void* header) {
    *(strstr((char *)header, CRLF CRLF) + strlen(CRLF)) = 0;
    memset(version,0,sizeof(version));
    memset(status,0,sizeof(status));
    sscanf((char *)header, "%s%*[ ]%[^\r\n]", version, status);

    for (char* str = strstr((char *)header, CRLF) + strlen(CRLF); ; str = NULL) {
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

}

HttpResHeader::HttpResHeader(syn_reply_frame* sframe, z_stream* instream) {
    int len=get24(sframe->head.length);
    char buff[HEADLENLIMIT];
    spdy_inflate(instream,sframe+1,len-(sizeof(*sframe)-sizeof(spdy_head)),buff,sizeof(buff));

    uint32_t *p=(uint32_t *)buff;
    uint32_t c=ntohl(*p++);
    for(size_t i=0; i<c; ++i) {
        uint32_t nlen=ntohl(*p++);
        char *np=(char *)p;
        *np=toupper(*np);
        p=(uint32_t*)(np+nlen);
        uint32_t vlen=ntohl(*p++);
        char *vp=(char *)p;
        p=(uint32_t *)((char *)p+vlen);
        this->header[string(np,nlen)] = string(vp,vlen);
    }

    strcpy(version,this->header[":version"].c_str());
    strcpy(status,this->header[":status"].c_str());
    for(auto i=this->header.begin(); i!=this->header.end();) {
        if(i->first[0]==':') {
            this->header.erase(i++);
        } else {
            i++;
        }
    }
}



void HttpResHeader::add(const char* header, const char* value) {
    this->header[header]=value;
}

void HttpResHeader::del(const char* header) {
    this->header.erase(header);
}


const char* HttpResHeader::getval(const char* key) {
    if(header.count(key)) {
        return header[key].c_str();
    } else {
        return nullptr;
    }
}

int HttpResHeader::getstring(void* buff) {
    int p;
    sprintf((char *)buff, "HTTP/1.1 %s" CRLF "%n",status, &p);
    for (auto i : header) {
        int len;
        sprintf((char *)buff + p, "%s: %s" CRLF "%n", i.first.c_str(), i.second.c_str(), &len);
        p += len;
    }

    sprintf((char *)buff + p, CRLF);
    return p + strlen(CRLF);

}


int HttpResHeader::getframe(void* buff, z_stream* destream, size_t id) {
    syn_reply_frame *srframe=(syn_reply_frame *)buff;
    memset(srframe,0,sizeof(*srframe));
    srframe->head.magic=CTRL_MAGIC;
    srframe->head.type=htons(SYN_REPLY_TYPE);
    srframe->id=htonl(id);

    char headbuff[HEADLENLIMIT];

    char *p=headbuff;
    *(uint32_t *)p=htonl(header.size()+2);
    p += 4;
    p=addnv(p,":status",7,status,strlen(status));
    p=addnv(p,":version",8,"HTTP/1.1",8);

    for (auto i : header) {
        p=addnv(p,i.first.data(),i.first.length(),i.second.data(),i.second.length());
    }
    int len=p-(char *)headbuff;
    len=sizeof(syn_reply_frame)-sizeof(spdy_head)+
        spdy_deflate(destream,headbuff,len,srframe+1,0);
    set24(srframe->head.length,len);
    return len+sizeof(spdy_head);
}
