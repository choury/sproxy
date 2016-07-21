#include "parse.h"
#include "net.h"
#include "http2.h"
#include "cgi.h"

#include <fstream>
//#include <iostream>
#include <algorithm>
#include <unordered_set>

#include <string.h>
#include <unistd.h>
#include <bits/local_lim.h>

#define LISTFILE "sites.list"

using std::string;
using std::unordered_set;
using std::ifstream;
using std::ofstream;

static int GLOBALPROXY = 0;
static unordered_set<string> proxylist;
static unordered_set<string> blocklist;
static unordered_set<string> locallist;

static unordered_set<string> authips;

static char *cgi_addnv(char *p, const istring &name, const string &value);
static char *cgi_getnv(char *p, istring &name, string &value);

void loadsites() {
#ifdef CLIENT
    proxylist.clear();
    blocklist.clear();
    ifstream sitefile(LISTFILE);

    if (sitefile.good()) {
        while (!sitefile.eof()) {
            string site;
            sitefile >> site;

            int split = site.find(':');
            if(site.substr(0, split) == "proxy"){
                proxylist.insert(site.substr(split+1));
            }else if(site.substr(0, split) == "block"){
                blocklist.insert(site.substr(split+1));
            }else if(site.length()){
                LOGE("Wrong config line:%s\n",site.c_str());
            }
        }

        sitefile.close();
    } else {
        LOGE("There is no %s !\n", LISTFILE);
    }

    addauth("::ffff:127.0.0.1");
    addauth("::1");
#endif

    for(const char *ips=getlocalip(); strlen(ips); ips+=INET6_ADDRSTRLEN){
       locallist.insert(ips);
    }
    char hostname[HOST_NAME_MAX];
    gethostname(hostname, sizeof(hostname));
    locallist.insert(hostname);
}

void savesites(){
    ofstream listfile(LISTFILE);

    for (auto i : proxylist) {
        listfile <<"proxy:"<< i << std::endl;
    }
    for (auto i : blocklist) {
        listfile <<"block:"<< i << std::endl;
    }
    listfile.close();
}


void addpsite(const char * host) {
    proxylist.insert(host);
    savesites();
}

void addbsite(const char * host) {
    blocklist.insert(host);
    savesites();
}

void addauth(const char *ip) {
    authips.insert(ip);
}

int delpsite(const char * host) {
    if (proxylist.count(host) == 0) {
        return 0;
    }
    proxylist.erase(host);
    savesites();
    return 1;
}

int delbsite(const char * host) {
    if (blocklist.count(host) == 0) {
        return 0;
    }
    blocklist.erase(host);
    savesites();
    return 1;
}


int globalproxy() {
    GLOBALPROXY = !GLOBALPROXY;
    return GLOBALPROXY;
}

bool checkproxy(const char *hostname) {
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
    return false;
}


bool checkblock(const char *hostname) {
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
    return false;
}

bool checklocal(const char *hostname) {
    return locallist.count(hostname);
}

bool checkauth(const char *ip) {
    return authips.count(ip);
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

HttpHeader::HttpHeader(Ptr&& src):src(src){
}

/*
HttpHeader::HttpHeader(mulmap< string, string > headers, Ptr&& src):
               headers(headers), src(src)
{

}
*/

Ptr HttpHeader::getsrc() {
    return src;
}


void HttpHeader::add(const istring& header, const string& value) {
    headers.insert(std::make_pair(header, value));
}

void HttpHeader::add(const istring& header, int value) {
    headers.insert(std::make_pair(header, std::to_string(value)));
}

void HttpHeader::append(const istring& header, const string& value){
    if(headers.count(header)){
        string old_value = headers[header];
        add(header, old_value + ", " + value);
    }else{
        add(header, value);
    }
}

void HttpHeader::del(const istring& header) {
    headers.erase(header);
}

const char* HttpHeader::get(const char* header) const{
    if(headers.count(header)) {
        return headers.at(header).c_str();
    }
    return nullptr;
}

/*
std::set< string > HttpHeader::getall(const char *header) const{
    std::set<string> sets;
    for(auto i:headers) {
        if(strcasecmp(i.first.c_str(),header)==0)
            sets.insert(i.second);
    }
    return sets;
}
*/


HttpReqHeader::HttpReqHeader(const char* header, Ptr&& src):
                   HttpHeader(std::move(src))
{
    if(header == nullptr){
        return;
    }
    char httpheader[HEADLENLIMIT];
    snprintf(httpheader, sizeof(httpheader), "%s", header);
    *(strstr(httpheader, CRLF CRLF) + strlen(CRLF)) = 0;
    memset(path, 0, sizeof(path));
    memset(url, 0, sizeof(url));
    sscanf(httpheader, "%19s%*[ ]%4095[^\r\n ]", method, url);
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
        istring name = string(p, sp-p);
        if(name == "cookie"){
            char *cp = sp +1;
            for(char *p = strsep(&cp, ";");p;
                p = strsep(&cp, ";"))
            {
                cookies.insert(ltrim(string(p)));
            }
        }else{
            add(string(p, sp - p), ltrim(string(sp + 1)));
        }
    }
    
    
    if (!hostname[0] && get("Host")) {
        if(spliturl(get("Host"), hostname, nullptr, &port))
        {
            LOGE("wrong host format:%s\n", get("Host"));
            throw 0;
        }
    }
    getfile();
}


HttpReqHeader::HttpReqHeader(std::multimap<istring, string>&& headers, Ptr&& src):
                   HttpHeader(std::move(src))
{
    for(auto i: headers){
        if(i.first == "cookie"){
            char cookiebuff[URLLIMIT];
            strcpy(cookiebuff, i.second.c_str()); 
            char *cp=cookiebuff;
            for(char *p = strsep(&cp, ";");p;
                p = strsep(&cp, ";"))
            {
                cookies.insert(ltrim(string(p)));
            }
        }else{
            add(i.first, i.second);
        }
    }
    snprintf(method, sizeof(method), "%s", get(":method"));
    snprintf(path, sizeof(path), "%s", get(":path"));
    port = 80;
    
    if (get(":authority")){
        if (ismethod("CONNECT") || ismethod("SEND")) {
            snprintf(url, sizeof(url), "%s", get(":authority"));
        } else {
            snprintf(url, sizeof(url), "%s://%s%s", get(":scheme"),
                        get(":authority"), get(":path"));
        }
        spliturl(get(":authority"), hostname, nullptr, &port);
        add("host", get(":authority"));
    } else {
        snprintf(url, sizeof(url), "%s", path);
        hostname[0] = 0;
    }
    for (auto i = this->headers.begin(); i!= this->headers.end();) {
        if (i->first[0] == ':') {
            this->headers.erase(i++);
        } else {
            i++;
        }
    }
    getfile();
}

HttpReqHeader::HttpReqHeader(CGI_Header *headers, Ptr&& src):
                   HttpHeader(std::move(src))
{
    if(headers->type != CGI_REQUEST)
    {
        LOGE("wrong CGI header");
        throw 1;
    }
    cgi_id = ntohl(headers->requestId);
   
    char *p = (char *)(headers +1);
    uint32_t len = ntohs(headers->contentLength);
    while(uint32_t(p - (char *)(headers +1)) < len){
        istring name;
        string value;
        p = cgi_getnv(p, name, value);
        if(name == ":method"){
            strcpy(method, value.c_str());
            continue;
        }
        if(name == ":path"){
            strcpy(path, value.c_str());
            continue;
        }
        if(name == "cookie"){
            cookies.insert(value);
            continue;
        }
        add(name, value);
    }
    getfile();
}


void HttpReqHeader::getfile() {
    char *p=path;
    while (*p && *++p != '?');
    memset(filename, 0, sizeof(filename));
    filename[0]='.';
    memcpy(filename+1,path,p-path);
/*
    char *q=p-1;
    while (q != path) {
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
    return 0; */
}


bool HttpReqHeader::ismethod(const char* method) const{
    return strcmp(this->method, method) == 0;
}

char *HttpReqHeader::getstring(size_t &len) const{
    char *buff = (char *)malloc(BUF_LEN);
    len = 0;
    if (should_proxy) {
        len += sprintf(buff, "%s %s HTTP/1.1" CRLF, method, url);
    } else if (strcmp(method, "CONNECT") == 0 || 
               strcmp(method, "SEND") == 0)
    {
        free(buff);
        return 0;
    }else{
        len += sprintf(buff, "%s %s HTTP/1.1" CRLF, method, path);
    }
    
    if(get("Host") == nullptr && hostname[0]){
        if(port == HTTPPORT){
            len += sprintf(buff + len, "Host: %s" CRLF, hostname);
        }else{
            char host_buff[DOMAINLIMIT];
            snprintf(host_buff, sizeof(host_buff), "%s:%d", hostname, port);
            len += sprintf(buff + len, "Host: %s" CRLF, host_buff);
        }
    }

    for (auto i : headers) {
        len += sprintf(buff + len, "%s: %s" CRLF,
                i.first.c_str(), i.second.c_str());
    }
    if(!cookies.empty()){
        string cookie_str;
        for(auto i : cookies){
            cookie_str += "; ";
            cookie_str += i;
        }
        len += sprintf(buff + len, "Cookie: %s" CRLF, 
                cookie_str.substr(2).c_str());
    }

    len += sprintf(buff + len, CRLF);
    assert(len < BUF_LEN);
    return buff;
}

bool HttpReqHeader::no_left() const {
    if(!ismethod("POST") && 
       !ismethod("PUT") &&
       !ismethod("PATCH") &&
       !ismethod("CONNECT") &&
       !ismethod("SEND"))
    {
        return true;
    }
    if(get("content-length") &&
       strcmp("0", get("content-length"))==0)
    {
        return true;
    }
    return false;
}


Http2_header *HttpReqHeader::getframe(Index_table *index_table) const{
    Http2_header *header = (Http2_header *)malloc(BUF_LEN);
    memset(header, 0, sizeof(*header));
    header->type = HEADERS_TYPE;
    header->flags = END_HEADERS_F;
    if(no_left()){
        header->flags |= END_STREAM_F;
    }
    set32(header->id, http_id);

    char *p = (char *)(header + 1);
    p += index_table->hpack_encode(p, ":method", method);
    if(get("host") && !ismethod("CONNECT")){
        p += index_table->hpack_encode(p, ":authority" ,get("host"));
    }else{
        char authority[URLLIMIT];
        snprintf(authority, sizeof(authority), "%s:%d", hostname, port);
        p += index_table->hpack_encode(p, ":authority" ,authority);
    }
    
    if(!ismethod("CONNECT") && !ismethod("SEND")){
        p += index_table->hpack_encode(p, ":scheme", "http");
        p += index_table->hpack_encode(p, ":path", path);
    }
    for(auto i: cookies){
        p += index_table->hpack_encode(p, "cookie", i.c_str());
    }
    
    p += index_table->hpack_encode(p, headers);
    set24(header->length, p-(char *)(header + 1));
    assert(get24(header->length) < BUF_LEN);
    return header;
}


CGI_Header *HttpReqHeader::getcgi() const{
    CGI_Header *cgi = (CGI_Header *)malloc(BUF_LEN);
    cgi->type = CGI_REQUEST;
    cgi->flag = 0;
    cgi->requestId = htonl(cgi_id);
    
    if(no_left()){
        cgi->flag |= CGI_FLAG_END;
    }
    char *p = (char *)(cgi + 1);
    p = cgi_addnv(p, ":method", method);
    p = cgi_addnv(p, ":path", path);
    for(auto i: headers){
        p = cgi_addnv(p, i.first, i.second);
    }
    for(auto i: cookies){
        p = cgi_addnv(p, "cookie", i);
    }
    cgi->contentLength = htons(p - (char *)(cgi + 1));
    assert(ntohs(cgi->contentLength) < BUF_LEN);
    return cgi;
}

const char *HttpReqHeader::getparamstring() const {
    const char *p = path;
    while (*p && *p++ != '?');
    return p;
}

std::map< string, string > HttpReqHeader::getcookies() const {
    std::map<string, string> cookie;
    for(auto i:cookies){
        const char *p = i.c_str();
        const char* sp = strpbrk(p, "=");
        if (sp) {
            cookie[ltrim(string(p, sp - p))] = sp + 1;
        } else {
            cookie[p] = "";
        }
    }
    return cookie;
}



HttpResHeader::HttpResHeader(const char* header, Ptr&& src):
                   HttpHeader(std::move(src))
{
    char httpheader[HEADLENLIMIT];
    snprintf(httpheader, sizeof(httpheader), "%s", header);
    *(strstr((char *)httpheader, CRLF CRLF) + strlen(CRLF)) = 0;
    memset(status, 0, sizeof(status));
    sscanf((char *)httpheader, "%*s%*[ ]%99[^\r\n]", status);

    for (char* str = strstr((char *)httpheader, CRLF)+strlen(CRLF); ; str = NULL) {
        char* p = strtok(str, CRLF);

        if (p == NULL)
            break;

        char* sp = strpbrk(p, ":");
        if (sp == NULL) {
            LOGE("wrong header format:%s\n", p);
            throw 0;
        }
        istring name = istring(p, sp-p);
        string value = ltrim(string(sp + 1));
        if(name == "set-cookie"){
            cookies.insert(value);
        }else{
            add(name, value);
        }
    }
}

HttpResHeader::HttpResHeader(std::multimap<istring, string>&& headers, Ptr&& src):
                   HttpHeader(std::move(src))
{
    for(auto i: headers){
        if(i.first == "set-cookies"){
            cookies.insert(i.second);
        }else{
            add(i.first, i.second);
        }
    }

    snprintf(status, sizeof(status), "%s", get(":status"));
    for (auto i = this->headers.begin(); i!= this->headers.end();) {
        if (i->first[0] == ':') {
            this->headers.erase(i++);
        } else {
            i++;
        }
    }
}

HttpResHeader::HttpResHeader(CGI_Header *headers, Ptr&& src):
                   HttpHeader(std::move(src))
{
    if(headers->type != CGI_RESPONSE)
    {
        LOGE("wrong CGI header");
        throw 1;
    }
    cgi_id = ntohl(headers->requestId);
   
    char *p = (char *)(headers +1);
    uint32_t len = ntohs(headers->contentLength);
    while(uint32_t(p - (char *)(headers +1)) < len){
        istring name;
        string value;
        p = cgi_getnv(p, name, value);
        if(name == ":status"){
            strcpy(status, value.c_str());
            continue;
        }
        if(name == "set-cookie"){
            cookies.insert(value);
            continue;
        }
        add(name, value);
   }
}

bool HttpResHeader::no_left() const {
    if(memcmp(status, "204", 3) == 0||
       memcmp(status, "205", 3) == 0||
       memcmp(status, "304", 3) == 0)
    {
       return true;
    }
             
    if(get("content-length") &&
       memcmp("0", get("content-length"), 2)==0)
    {
        return true;
    }
        
    return false;
}


char * HttpResHeader::getstring(size_t &len) const{
    char * buff = (char *)malloc(BUF_LEN);
    len = 0;
    if(get("Content-Length") || get("Transfer-Encoding")){
        len += sprintf(buff, "HTTP/1.1 %s" CRLF, status);
    }else {
        len += sprintf(buff, "HTTP/1.0 %s" CRLF, status);
    }
    for (auto i : headers) {
        len += sprintf(buff + len, "%s: %s" CRLF,
                i.first.c_str(), i.second.c_str());
    }
    for (auto i : cookies) {
        len += sprintf(buff + len, "Set-Cookie: %s" CRLF, i.c_str());
    }

    len += sprintf(buff + len, CRLF);
    assert(len < BUF_LEN);
    return buff;
}


Http2_header *HttpResHeader::getframe(Index_table* index_table) const{
    Http2_header *header = (Http2_header *)malloc(BUF_LEN);
    memset(header, 0, sizeof(*header));
    header->type = HEADERS_TYPE;
    header->flags = END_HEADERS_F;
    if(no_left()) {
        header->flags |= END_STREAM_F;
    }
    set32(header->id, http_id);

    char *p = (char *)(header + 1);
    char status_h2[100];
    sscanf(status,"%99s",status_h2);
    p += index_table->hpack_encode(p, ":status", status_h2);
    for (auto i : cookies) {
        p += index_table->hpack_encode(p, "set-cookie", i.c_str());
    }
    p += index_table->hpack_encode(p, headers);
    
    set24(header->length, p-(char *)(header + 1));
    assert(get24(header->length) < BUF_LEN);
    return header;
}

CGI_Header *HttpResHeader::getcgi()const {
    CGI_Header *cgi = (CGI_Header *)malloc(BUF_LEN);
    cgi->type = CGI_RESPONSE;
    cgi->flag = 0;
    cgi->requestId = htonl(cgi_id);
    
    if(no_left()) {
        cgi->flag |= CGI_FLAG_END;
    }
    char *p = (char *)(cgi + 1);
    p = cgi_addnv(p, ":status", status);
    for(auto i: headers){
        p = cgi_addnv(p, i.first, i.second);
    }
    for(auto i: cookies){
        p = cgi_addnv(p, "set-cookie", i);
    }
    cgi->contentLength = htons(p - (char *)(cgi + 1));
    assert(ntohs(cgi->contentLength) < BUF_LEN);
    return cgi;
}


static char *cgi_addnv(char *p, const istring &name, const string &value) {
    CGI_NVLenPair *cgi_pairs = (CGI_NVLenPair *) p;
    cgi_pairs->nameLength = htons(name.size());
    cgi_pairs->valueLength = htons(value.size());
    p = (char *)(cgi_pairs +1);
    memcpy(p, name.c_str(), name.size());
    p += name.size();
    memcpy(p, value.c_str(), value.size());
    return p + value.size();
}

static char *cgi_getnv(char* p, istring& name, string& value) {
    CGI_NVLenPair *cgi_pairs = (CGI_NVLenPair *)p;
    uint32_t name_len = ntohs(cgi_pairs->nameLength);
    uint32_t value_len = ntohs(cgi_pairs->valueLength);
    p = (char *)(cgi_pairs + 1);
    name = istring(p, name_len);
    p += name_len;
    value = string(p, value_len);
    return p + value_len;
}
