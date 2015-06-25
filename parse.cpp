#include "parse.h"
#include "net.h"
#include "http2.h"

#include <fstream>
#include <iostream>
#include <algorithm>
#include <unordered_set>

#include <string.h>
#include <unistd.h>

#define PROXYFILE "proxy.list"
#define BLOCKFILE "block.list"

using std::unordered_set;
using std::ifstream;
using std::ofstream;

static int loadedsites = 0;
static int GLOBALPROXY = 0;
static unordered_set<string> proxylist;
static unordered_set<string> blocklist;

// trim from start
static inline string& ltrim(std::string && s) {
    s.erase(0, s.find_first_not_of(" "));
    return s;
}


void loadsites() {
    loadedsites = 1;
    proxylist.clear();
    ifstream proxyfile(PROXYFILE);

    if (proxyfile.good()) {
        while (!proxyfile.eof()) {
            string site;
            proxyfile >> site;

            if (!site.empty()) {
                proxylist.insert(site);
            }
        }

        proxyfile.close();
    } else {
        LOGE("There is no %s !\n", PROXYFILE);
    }

    ifstream blockfile(BLOCKFILE);
    if (blockfile.good()) {
        while (!blockfile.eof()) {
            string site;
            blockfile >> site;

            if (!site.empty()) {
                blocklist.insert(site);
            }
        }

        blockfile.close();
    } else {
        LOGE("There is no %s !\n", BLOCKFILE);
    }
}


void addpsite(const char * host) {
    proxylist.insert(host);
    ofstream proxyfile(PROXYFILE);

    for (auto i : proxylist) {
        proxyfile << i << std::endl;
    }
    proxyfile.close();
}

void addbsite(const char * host) {
    blocklist.insert(host);
    ofstream blockfile(BLOCKFILE);

    for (auto i : blocklist) {
        blockfile << i << std::endl;
    }
    blockfile.close();
}

int delpsite(const char * host) {
    if (proxylist.count(host) == 0) {
        return 0;
    }
    proxylist.erase(host);
    ofstream proxyfile(PROXYFILE);

    for (auto i : proxylist) {
        proxyfile << i << std::endl;
    }
    proxyfile.close();
    return 1;
}

int delbsite(const char * host) {
    if (blocklist.count(host) == 0) {
        return 0;
    }
    blocklist.erase(host);
    ofstream blockfile(BLOCKFILE);

    for (auto i : blocklist) {
        blockfile << i << std::endl;
    }
    blockfile.close();
    return 1;
}

int globalproxy() {
    GLOBALPROXY = !GLOBALPROXY;
    return GLOBALPROXY;
}

bool checkproxy(const char *hostname) {
#ifdef CLIENT
    if (!loadedsites) {
        loadsites();
    }

    if (GLOBALPROXY || proxylist.count("*")) {
        return true;
    }

    // 如果proxylist里面有*.*.*.* 那么ip地址直接代理
    if (inet_addr(hostname) != INADDR_NONE && proxylist.count("*.*.*.*")) {
        return true;
    }

    const char* subhost = hostname;

    while (subhost) {
        if (subhost[0] == '.') {
            subhost++;
        }

        if (proxylist.count(subhost)) {
            return true;
        }

        subhost = strpbrk(subhost, ".");
    }
#endif
    return false;
}


bool checkblock(const char *hostname) {
#ifdef CLIENT
    if (!loadedsites) {
        loadsites();
    }

    // 如果list文件里面有*.*.*.* 那么匹配ip地址
    if (inet_addr(hostname) != INADDR_NONE && blocklist.count("*.*.*.*")) {
        return true;
    }

    const char* subhost = hostname;

    while (subhost) {
        if (subhost[0] == '.') {
            subhost++;
        }

        if (blocklist.count(subhost)) {
            return true;
        }

        subhost = strpbrk(subhost, ".");
    }
#endif
    return false;
}

char* toUpper(char* s) {
    char* p = s;

    while (*p) {
        *p = toupper(*p);
        p++;
    }

    return s;
}

char* toLower(char* s) {
    char* p = s;

    while (*p) {
        *p = tolower(*p);
        p++;
    }

    return s;
}

string toLower(const string &s) {
    string str = s;
    std::transform(str.begin(), str.end(), str.begin(), ::tolower);
    return str;
}

int spliturl(const char* url, char* hostname, char* path , uint16_t* port) {
    const char* addrsplit;
    char tmpaddr[DOMAINLIMIT];
    int urllen = strlen(url);
    int copylen;
    bzero(hostname, DOMAINLIMIT);
    if (path) {
        bzero(path, urllen);
    }
    if (url[0] == '/' && path) {
        strcpy(path, url);
        return 0;
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
    } else {
        *port = HTTPPORT;
    }

    if ((addrsplit = strpbrk(url, "/"))) {
        copylen = Min(url+urllen-addrsplit, (URLLIMIT-1));
        if (path) {
            memcpy(path, addrsplit, copylen);
        }
        copylen = addrsplit - url < (DOMAINLIMIT - 1) ? addrsplit - url : (DOMAINLIMIT - 1);
        strncpy(tmpaddr, url, copylen);
        tmpaddr[copylen] = 0;
    } else {
        copylen = urllen < (DOMAINLIMIT - 1) ? urllen : (DOMAINLIMIT - 1);
        strncpy(tmpaddr, url, copylen);
        if (path) {
            strcpy(path, "/");
        }
        tmpaddr[copylen] = 0;
    }

    if (tmpaddr[0] == '[') {                        // this is a ipv6 address
        if (!(addrsplit = strpbrk(tmpaddr, "]"))) {
            return -1;
        }

        strncpy(hostname, tmpaddr + 1, addrsplit - tmpaddr - 1);

        if (addrsplit[1] == ':') {
            if (sscanf(addrsplit + 2, "%hd", port) != 1)
                return -1;
        } else if (addrsplit[1] != 0) {
            return -1;
        }
    } else {
        if ((addrsplit = strpbrk(tmpaddr, ":"))) {
            strncpy(hostname, url, addrsplit - tmpaddr);

            if (sscanf(addrsplit + 1, "%hd", port) != 1)
                return -1;
        } else {
            strcpy(hostname, tmpaddr);
        }
    }

    return 0;
}


HttpReqHeader::HttpReqHeader(const char* header) {
    char httpheader[HEADLENLIMIT];
    snprintf(httpheader, sizeof(httpheader), "%s", header);
    *(strstr(httpheader, CRLF CRLF) + strlen(CRLF)) = 0;
    memset(path, 0, sizeof(path));
    memset(url, 0, sizeof(url));
    sscanf(httpheader, "%s%*[ ]%[^\r\n ]", method, url);
    toUpper(method);
    port = 80;

    if (spliturl(url, hostname, path, &port)) {
        LOGE("wrong url format:%s\n", url);
        throw 0;
    }

    for (char* str = strstr(httpheader, CRLF) + strlen(CRLF); ; str = NULL) {
        char* p = strtok(str, CRLF);

        if (p == NULL)
            break;

        char* sp = strpbrk(p, ":");
        if (sp == NULL) {
            LOGE("wrong header format:%s\n", p);
            throw 0;
        }
        headers.push_back(std::make_pair(string(p, sp - p), ltrim(string(sp + 1))));
    }
    
    
    if (!hostname[0] && get("Host")) {
        if(spliturl(get("Host"), hostname, nullptr, &port))
        {
            LOGE("wrong host format:%s\n", get("Host"));
            throw 0;
        }
    }
    
    del("Proxy-Connection");
}


HttpReqHeader::HttpReqHeader(std::list< std::pair< string, string > >&& headers):headers(headers) {
    snprintf(method, sizeof(method), "%s", get(":method"));
    snprintf(path, sizeof(path), get(":path"));
    
    if (get(":authority")){
        if (ismethod("CONNECT")) {
            snprintf(url, sizeof(url), "%s", get(":authority"));
        } else {
            snprintf(url, sizeof(url), "%s://%s%s", get(":scheme"),
                        get(":authority"), get(":path"));
        }
        spliturl(get(":authority"), hostname, nullptr, &port);
    } else {
        snprintf(url, sizeof(url), path);
        hostname[0] = 0;
    }
    for (auto i = this->headers.begin(); i!= this->headers.end();) {
        if (i->first[0] == ':') {
            this->headers.erase(i++);
        } else {
            i++;
        }
    }
}


int HttpReqHeader::parse() {
    char paramsbuff[URLLIMIT];
    if(URLDecode(path,paramsbuff) == 0){
        return -1;
    }
    char *p=paramsbuff;
    while (*p && *++p != '?');
    memset(filename, 0, sizeof(filename));
    filename[0]='.';
    memcpy(filename+1,paramsbuff,p-paramsbuff);
    char *q=p-1;
    while (q != paramsbuff) {
        if (*q == '.' || *q == '/')
            break;
        q--;
    }
    memset(extname, 0, sizeof(extname));
    if (*q != '/') {
        if (p-q >= 20)
            return -1;
        memcpy(extname, q, p-q);
    }
    if(*p++){
        for (; ; p = NULL) {
            q = strtok(p, "&");

            if (q == NULL)
                break;

            char* sp = strpbrk(q, "=");
            if (sp) {
                params[string(q, sp - q)] = sp + 1;
            } else {
                params[q] = "";
            }
        }
    }
    return 0;
}


bool HttpReqHeader::ismethod(const char* method) {
    return strcmp(this->method, method) == 0;
}

char *addnv(void *buff, const char *name, size_t nlen, const char *val, size_t vlen) {
    uint32_t *p = (uint32_t *)buff;
    *p++= htonl(nlen);
    char *q = (char *)p;
    while (nlen--) {
        *q++= tolower(*name++);
    }
    p = (uint32_t *)q;
    *p++= htonl(vlen);
    q = (char *)p;
    while (vlen--) {
        *q++= *val++;
    }
    return q;
}


void HttpReqHeader::add(const char* header, const char* value) {
    headers.push_back(std::make_pair(header, value));
}

void HttpReqHeader::del(const char* header) {
    for(auto i=headers.begin();i != headers.end();) {
        if(strcasecmp(i->first.c_str(),header)==0)
            headers.erase(i++);
        else
            ++i;
    }
}

const char* HttpReqHeader::get(const char* header) {
    for(auto i=headers.begin();i != headers.end(); ++i) {
        if(strcasecmp(i->first.c_str(),header)==0)
            return i->second.c_str();
    }
    return nullptr;
}

int HttpReqHeader::getstring(void* outbuff) {
    char *buff = (char *)outbuff;
    int p;
    if (checkproxy(hostname)) {
        sprintf(buff, "%s %s HTTP/1.1" CRLF "%n",
                method, url, &p);
    } else {
        if (strcmp(method, "CONNECT") == 0) {
            return 0;
        }
        if (get("Host") == nullptr && hostname[0] == 0) {
            sprintf(buff, "%s %s HTTP/1.0" CRLF "%n",
                        method, path, &p);
            
        }else{
            sprintf(buff, "%s %s HTTP/1.1" CRLF "%n",
                    method, path, &p);
        }
    }
    
    if(get("Host") == nullptr && hostname[0]){
        char buff[DOMAINLIMIT];
        snprintf(buff, sizeof(buff), "%s:%d", hostname, port);
        headers.push_back(std::make_pair("Host", buff));
    }

    for (auto i : headers) {
        int len;
        sprintf(buff + p, "%s: %s" CRLF "%n",
                i.first.c_str(), i.second.c_str(), &len);
        p += len;
    }

    sprintf(buff + p, CRLF);
    return p + strlen(CRLF);
}


#if 0

int HttpReqHeader::getframe(void* buff, z_stream* destream) {
    syn_frame* sframe = (syn_frame *)buff;
    memset(sframe, 0, sizeof(*sframe));
    sframe->head.magic = CTRL_MAGIC;
    sframe->head.type = htons(SYN_TYPE);
    if (strcmp(method, "POST")) {
        sframe->head.flag = FLAG_FIN;
    }

    sframe->id = htonl(id);
    sframe->priority = 3;
    char tmpbuff[HEADLENLIMIT];


    char *p = tmpbuff;
    *(uint32_t *)p = htonl(headers.size()+5);
    p += 4;
    p = addnv(p, ":method", 7, method, strlen(method));
    p = addnv(p, ":version", 8, "HTTP/1.1", 8);
    p = addnv(p, ":host", 5, hostname, strlen(hostname));
    if (strcmp(method, "CONNECT") == 0) {
        p = addnv(p, ":path", 5, url, strlen(url));
    } else {
        p = addnv(p, ":path", 5, path, strlen(path));
        p = addnv(p, ":scheme", 7, "http", 4);
    }
    for (auto i:headers) {
        p = addnv(p, i.first.data(), i.first.length(),
                  i.second.data(), i.second.length());
    }
    int len = p-tmpbuff;
    len = sizeof(syn_frame)-sizeof(spdy_head)+
        spdy_deflate(destream, tmpbuff, len, sframe+1, 0);
    set24(sframe->head.length, len);
    return len+sizeof(spdy_head);
}

#endif

HttpResHeader::HttpResHeader(const char* header, int fd):fd(fd) {
    char httpheader[HEADLENLIMIT];
    snprintf(httpheader, sizeof(httpheader), "%s", header);
    *(strstr((char *)httpheader, CRLF CRLF) + strlen(CRLF)) = 0;
    memset(version, 0, sizeof(version));
    memset(status, 0, sizeof(status));
    sscanf((char *)httpheader, "%s%*[ ]%s", version, status);

    for (char* str = strstr((char *)httpheader, CRLF)+strlen(CRLF); ; str = NULL) {
        char* p = strtok(str, CRLF);

        if (p == NULL)
            break;

        char* sp = strpbrk(p, ":");
        if (sp == NULL) {
            LOGE("wrong header format:%s\n", p);
            throw 0;
        }
        headers.push_back(std::make_pair(string(p, sp - p), ltrim(string(sp + 1))));
    }
}

#if 0
HttpResHeader::HttpResHeader(const syn_reply_frame* sframe, z_stream* instream) {
    id = ntohl(sframe->id);
    int len = get24(sframe->head.length);
    char buff[HEADLENLIMIT];
    spdy_inflate(instream, sframe+1, len-(sizeof(*sframe)-sizeof(spdy_head)),
                 buff, sizeof(buff));

    uint32_t *p = (uint32_t *)buff;
    uint32_t c = ntohl(*p++);
    for (size_t i = 0; i < c; ++i) {
        uint32_t nlen = ntohl(*p++);
        char *np = (char *)p;
        *np = toupper(*np);
        p = (uint32_t*)(np+nlen);
        uint32_t vlen = ntohl(*p++);
        char *vp = (char *)p;
        p = (uint32_t *)((char *)p+vlen);
        this->headers[string(np, nlen)] = string(vp, vlen);
    }

    snprintf(version, sizeof(version), "%s", this->headers[":version"].c_str());
    snprintf(status, sizeof(status), "%s", this->headers[":status"].c_str());
    for (auto i = this->headers.begin(); i!= this->headers.end();) {
        if (i->first[0] == ':') {
            this->headers.erase(i++);
        } else {
            i++;
        }
    }
}

#endif
void HttpResHeader::add(const char* header, const char* value) {
    headers.push_back(std::make_pair(header, value));
}

void HttpResHeader::del(const char* header) {
    for(auto i=headers.begin();i != headers.end();) {
        if(strcasecmp(i->first.c_str(),header)==0)
            headers.erase(i++);
        else
            ++i;
    }
}

const char* HttpResHeader::get(const char* header) {
    for(auto i=headers.begin();i != headers.end(); ++i) {
        if(strcasecmp(i->first.c_str(),header)==0)
            return i->second.c_str();
    }
    return nullptr;
}


int HttpResHeader::getstring(void* buff) {
    int p;
    sprintf((char *)buff, "HTTP/1.1 %s" CRLF "%n", status, &p);
    for (auto i : headers) {
        int len;
        sprintf((char *)buff + p, "%s: %s" CRLF "%n",
                i.first.c_str(), i.second.c_str(), &len);
        p += len;
    }

    sprintf((char *)buff + p, CRLF);
    return p + strlen(CRLF);
}


int HttpResHeader::getframe(void* outbuff, Index_table* index_table) {
    Http2_header *header = (Http2_header *)outbuff;
    memset(header, 0, sizeof(*header));
    header->type = HEADERS_TYPE;
    header->flags = END_HEADERS_F;
    set32(header->id, id);

    char *p = (char *)(header + 1);
    p += index_table->hpack_encode(p, ":status", status);
    p += index_table->hpack_encode(p, headers);
    
    set24(header->length, p-(char *)(header + 1));
    
//    index_table->hpack_decode((char *)(header+1), get24(header->length));
    return p - (char *)outbuff;
}


int HttpResHeader::sendheader() {
    char buff[HEADLENLIMIT];
    return ::write(fd, buff, getstring(buff));
}


int HttpResHeader::write(const void* buff, size_t size) {
    char chunkbuf[100];
    int chunklen;
    snprintf(chunkbuf, sizeof(chunkbuf), "%x" CRLF "%n", (uint32_t)size, &chunklen);
    ::write(fd, chunkbuf, chunklen);
    size = ::write(fd, buff, size);
    ::write(fd, CRLF, strlen(CRLF));
    return size;
}
