#include "parse.h"
#include "net.h"
#include "http2.h"
#include "cgi.h"

#include <fstream>
#include <algorithm>
#include <unordered_set>
#include <unordered_map>

#include <string.h>
#include <unistd.h>
#include <bits/local_lim.h>

#define LISTFILE "sites.list"

using std::string;
using std::unordered_set;
using std::unordered_map;
using std::ifstream;
using std::ofstream;

static unordered_set<string> authips;

static unordered_map<string, Strategy> sites; 

static char *cgi_addnv(char *p, const istring &name, const string &value);
static char *cgi_getnv(char *p, istring &name, string &value);

void loadsites() {
    sites.clear();

    //default strategy
    for(const char *ips=getlocalip(); strlen(ips); ips+=INET6_ADDRSTRLEN){
        sites[ips] = Strategy::local;
    }
    char hostname[HOST_NAME_MAX];
    gethostname(hostname, sizeof(hostname));
    sites[hostname] = Strategy::local;

    ifstream sitesfile(LISTFILE);
    if (sitesfile.good()) {


        while (!sitesfile.eof()) {
            string line;
            sitesfile >> line;

            int split = line.find(':');
            if(line[0] == '#'){
                continue;
            }
            string site = line.substr(0, split);
            if(line.substr(split+1) == "direct"){
                sites[site] = Strategy::direct;
            }else if(line.substr(split+1) == "proxy"){
                sites[site] = Strategy::proxy;
            }else if(line.substr(split+1) == "local"){
                sites[site] = Strategy::local;
            }else if(line.substr(split+1) == "block"){
                sites[site] = Strategy::block;
            }else if(site.length()){
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

const char *getstrategystring(const char *host){
    switch(getstrategy(host)){
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

void addauth(const char *ip) {
    authips.insert(ip);
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


HttpHeader::HttpHeader(Object* src):src(src){
}

HttpHeader::~HttpHeader() {
}


/*
HttpHeader::HttpHeader(mulmap< string, string > headers, Ptr&& src):
               headers(headers), src(src)
{

}
*/


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


HttpReqHeader::HttpReqHeader(const char* header, Object* src):
               HttpHeader(src)
{
    if(header == nullptr)
        return;
    
    char httpheader[HEADLENLIMIT];
    snprintf(httpheader, sizeof(httpheader), "%s", header);
    *(strstr(httpheader, CRLF CRLF) + strlen(CRLF)) = 0;
    memset(path, 0, sizeof(path));
    memset(url, 0, sizeof(url));
    sscanf(httpheader, "%19s%*[ ]%4095[^\r\n ]", method, url);
    toUpper(method);

    if (spliturl(url, protocol, hostname, path, &port)) {
        LOGE("wrong url format:%s\n", url);
        throw 0;
    }
    if(strcasecmp(protocol, "https") == 0){
        port = port?port:HTTPSPORT;
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
        if(spliturl(get("Host"), nullptr, hostname, nullptr, &port))
        {
            LOGE("wrong host format:%s\n", get("Host"));
            throw 0;
        }
    }
    if(url[0] == '/'){
        snprintf(url, sizeof(url), "http://%s%s", hostname, path);
    }
    getfile();
}


HttpReqHeader::HttpReqHeader(std::multimap<istring, string>&& headers, Object* src):
               HttpHeader(src)
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
    snprintf(protocol, sizeof(protocol), "%s", get(":scheme"));
    snprintf(method, sizeof(method), "%s", get(":method"));
    snprintf(path, sizeof(path), "%s", get(":path"));
    
    if (get(":authority")){
        if (ismethod("CONNECT") || ismethod("SEND")) {
            snprintf(url, sizeof(url), "%s", get(":authority"));
        } else {
            snprintf(url, sizeof(url), "%s://%s%s",
                     protocol, get(":authority"), path);
        }
        spliturl(get(":authority"), nullptr, hostname, nullptr, &port);
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

HttpReqHeader::HttpReqHeader(CGI_Header *headers, Object* src):
               HttpHeader(src)
{
    if(headers->type != CGI_REQUEST)
    {
        LOGE("wrong CGI header");
        throw 1;
    }
//    cgi_id = ntohl(headers->requestId);
   
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
    char *buff = nullptr;
    len = 0;
    if (should_proxy) {
        buff= (char *)p_malloc(BUF_LEN);
        len += sprintf(buff, "%s %s HTTP/1.1" CRLF, method, url);
    } else if (strcmp(method, "CONNECT") == 0 || 
               strcmp(method, "SEND") == 0)
    {
        return 0;
    }else{
        buff= (char *)p_malloc(BUF_LEN);
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

bool HttpReqHeader::no_body() const {
    if(!ismethod("POST") && 
       !ismethod("PUT") &&
       !ismethod("PATCH") &&
       !ismethod("CONNECT") &&
       !ismethod("SEND"))
    {
        return true;
    }
    if(get("content-length") &&
       strcmp("0", get("content-length"))==0 &&
       !ismethod("CONNECT"))
    {
        return true;
    }
    return false;
}


Http2_header *HttpReqHeader::getframe(Index_table *index_table) const{
    Http2_header *header = (Http2_header *)p_malloc(BUF_LEN);
    memset(header, 0, sizeof(*header));
    header->type = HEADERS_TYPE;
    header->flags = END_HEADERS_F;
    if(no_body()){
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


CGI_Header *HttpReqHeader::getcgi(uint32_t cgi_id) const{
    CGI_Header *cgi = (CGI_Header *)p_malloc(BUF_LEN);
    cgi->type = CGI_REQUEST;
    cgi->flag = 0;
    cgi->requestId = htonl(cgi_id);
    
    if(no_body()){
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



HttpResHeader::HttpResHeader(const char* header, Object* src):
               HttpHeader(src)
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

HttpResHeader::HttpResHeader(std::multimap<istring, string>&& headers, Object* src):
               HttpHeader(src)
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

HttpResHeader::HttpResHeader(CGI_Header *headers, Object* src):
               HttpHeader(src)
{
    if(headers->type != CGI_RESPONSE)
    {
        LOGE("wrong CGI header");
        throw 1;
    }
//    cgi_id = ntohl(headers->requestId);
   
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

bool HttpResHeader::no_body() const {
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
    char * buff = (char *)p_malloc(BUF_LEN);
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
    Http2_header *header = (Http2_header *)p_malloc(BUF_LEN);
    memset(header, 0, sizeof(*header));
    header->type = HEADERS_TYPE;
    header->flags = END_HEADERS_F;
    if(no_body()) {
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

CGI_Header *HttpResHeader::getcgi(uint32_t cgi_id)const {
    CGI_Header *cgi = (CGI_Header *)p_malloc(BUF_LEN);
    cgi->type = CGI_RESPONSE;
    cgi->flag = 0;
    cgi->requestId = htonl(cgi_id);
    
    if(no_body()) {
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


bool HttpReqHeader::getrange() {
    const char *range_str = get("Range");
    if(range_str == nullptr){
        return  true;
    }
    if(strncasecmp(range_str,"bytes=",6) != 0) {
        return false;
    }
    range_str += 6;
    enum class Status{
        start,testtail,first,testsecond,second
    }status= Status::start;
    ssize_t begin = -1,end = -1;
    while (1){
        switch (status){
        case Status::start:
            begin = end = -1;
            if (*range_str == '-') {
                range_str ++;
                status = Status::testtail;
            } else if (isdigit(*range_str)) {
                begin = 0;
                status = Status::first;
            } else {
                return false;
            }
            break;
        case Status::testtail:
            if (isdigit(*range_str)) {
                end = 0;
                status = Status::second;
            } else {
                return false;
            }
            break;
        case Status::first:
            if (*range_str == '-' ) {
                range_str ++;
                status = Status::testsecond;
            } else if (isdigit(*range_str)) {
                begin *= 10;
                begin += *range_str - '0';
                range_str ++;
            } else {
                return false;
            }
            break;
        case Status::testsecond:
            if (*range_str == 0) {
                ranges.push_back(Range{begin,end});
                return true;
            } else if (*range_str == ',') {
                ranges.push_back(Range{begin,end});
                range_str ++;
                status = Status::start;
            } else if(isdigit(*range_str)) {
                end = 0;
                status = Status::second;
            }
            break;
        case Status::second:
            if (*range_str == 0) {
                ranges.push_back(Range{begin,end});
                return true;
            } else if (*range_str == ',') {
                ranges.push_back(Range{begin,end});
                range_str ++;
                status = Status::start;
            } else if (isdigit(*range_str)){
                end *= 10 ;
                end += *range_str - '0';
                range_str ++;
            } else {
                return false;
            }
            break;
        }
    }
}



HttpBody::HttpBody() {
}


HttpBody::HttpBody(HttpBody && copy):data(copy.data) {
    while(!copy.data.empty()){
        copy.data.pop();
    }
}


size_t HttpBody::push(const void* buff, size_t len) {
    return push(p_memdup(buff, len), len);
}

size_t HttpBody::push(void* buff, size_t len) {
    if(len){
        data.push(std::make_pair(buff, len));
        content_size += len;
    }else{
        p_free(buff);
        data.push(std::make_pair(nullptr, 0));
    }
    return len;
}

std::pair<void*, size_t> HttpBody::pop(){
    if(data.empty()){
        return std::make_pair(nullptr, 0);
    }else{
        auto ret = data.front();
        data.pop();
        content_size -= ret.second;
        return ret;
    }
}

size_t HttpBody::size() {
    return content_size;
}



HttpBody::~HttpBody() {
    while(data.size()){
       p_free(data.front().first);
       data.pop();
    }
}
