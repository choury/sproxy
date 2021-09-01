#include "http_header.h"
#include "misc/config.h"
#include "misc/util.h"

#include <algorithm>
#include <atomic>
#include <sstream>
#include <list>

#include <assert.h>
#include <string.h>


using std::string;

static std::atomic<uint64_t> id_gen(100000);

std::string toLower(const std::string &s) {
    std::string str = s;
    std::transform(str.begin(), str.end(), str.begin(), ::tolower);
    return str;
}

void HttpHeader::set(const std::string& header, const string& value) {
    headers[toLower(header)] = value;
}

#ifdef __ANDROID__
#include <sstream>
template <typename T>
std::string to_string(T value)
{
    std::ostringstream os;
    os << value ;
    return os.str() ;
}
#else
using std::to_string;
#endif


void HttpHeader::set(const std::string& header, uint64_t value) {
    set(header, to_string(value));
}

void HttpHeader::append(const std::string& header, const string& value){
    if(get(header)){
        string old_value = get(header);
        set(header, old_value + ", " + value);
    }else{
        set(header, value);
    }
}

void HttpHeader::del(const std::string& header) {
    headers.erase(toLower(header));
}

const char* HttpHeader::get(const std::string& header) const{
    if(headers.count(toLower(header))) {
        return headers.at(toLower(header)).c_str();
    }
    return nullptr;
}

const std::map<std::string, std::string>& HttpHeader::getall() const {
    return headers;
}

/*
HttpReqHeader::HttpReqHeader(const char* header, size_t len) {
    assert(header);
    assert(len < HEADLENLIMIT);
    char httpheader[HEADLENLIMIT];
    memcpy(httpheader, header, len);
    *(strstr((char *)httpheader, CRLF CRLF) + strlen(CRLF)) = 0;
    char url[URLLIMIT] = {0};
    sscanf(httpheader, "%19s%*[ ]%4095[^\r\n ]", method, url);
    toUpper(method);

    memset(&Dest, 0, sizeof(Dest));
    if (spliturl(url, &Dest, path)) {
        LOGE("wrong url format:%s\n", url);
        throw PROTOCOL_ERR;
    }
    for (char* str = strstr(httpheader, CRLF) + strlen(CRLF); ; str = nullptr) {
        char* p = strtok(str, CRLF);

        if (p == nullptr)
            break;

        char* sp = strpbrk(p, ":");
        if (sp == nullptr) {
            //tolerate malformed header here for obfuscation
            break;
        }
        string name = toLower(string(p, sp-p));
        if(name == "cookie"){
            char *cp = sp +1;
            for(char *p = strsep(&cp, ";");p;
                p = strsep(&cp, ";"))
            {
                cookies.insert(ltrim(string(p)));
            }
        }else{
            set(name, ltrim(string(sp + 1)));
        }
    }
    
    
    if (!Dest.hostname[0] && get("Host")) {
        if(spliturl(get("Host"), &Dest, nullptr))
        {
            LOGE("wrong host format:%s\n", get("Host"));
            throw PROTOCOL_ERR;
        }
    }
    postparse();
}

HttpReqHeader::HttpReqHeader(const CGI_Header *headers) {
    if(headers->type != CGI_REQUEST)
    {
        LOGE("wrong CGI header");
        throw HTTP2_ERR_PROTOCOL_ERROR;
    }
    request_id = ntohl(headers->requestId);
    memset(&Dest, 0, sizeof(Dest));
    char *p = (char *)(headers +1);
    uint32_t len = ntohs(headers->contentLength);
    while(uint32_t(p - (char *)(headers +1)) < len){
        string name, value;
        p = cgi_getnv(p, name, value);
        if(name == ":method"){
            strcpy(method, value.c_str());
            continue;
        }
        if(name == ":path"){
            strcpy(path, value.c_str());
            continue;
        }
        if(name == ":authority"){
            strcpy(Dest.hostname, value.c_str());
            continue;
        }
        if(name == "cookie"){
            cookies.insert(value);
            continue;
        }
        set(name, value);
    }
    postparse();
}
 */


HttpReqHeader::HttpReqHeader(std::multimap<std::string, string>&& headers) {
    for(const auto& i: headers){
        if(toLower(i.first) == "cookie"){
            char cookiebuff[URLLIMIT];
            strcpy(cookiebuff, i.second.c_str()); 
            char *cp=cookiebuff;
            for(char *p = strsep(&cp, ";");p;
                p = strsep(&cp, ";"))
            {
                cookies.insert(ltrim(string(p)));
            }
        }else{
            set(i.first, i.second);
        }
    }

    snprintf(method, sizeof(method), "%s", get(":method"));
    memset(&Dest, 0, sizeof(Dest));
    if (get(":authority")){
        spliturl(get(":authority"), &Dest, nullptr);
    }
    if(get(":scheme")){
        snprintf(Dest.scheme, sizeof(Dest.scheme), "%s", get(":scheme"));
    }
    if(get(":path")){
        snprintf(path, sizeof(path), "%s", get(":path"));
    }
    if(!path[0]){
        strcpy(path, "/");
    }

    for (auto i = this->headers.begin(); i!= this->headers.end();) {
        if (i->first[0] == ':') {
            this->headers.erase(i++);
        } else {
            i++;
        }
    }
    postparse();
}

bool HttpReqHeader::http_method() const {
    return ismethod("GET") ||
        ismethod("POST") ||
        ismethod("PUT") ||
        ismethod("HEAD") ||
        ismethod("DELETE") ||
        ismethod("OPTIONS");
}

bool HttpReqHeader::normal_method() const {
    return http_method() ||
        ismethod("CONNECT") ||
        ismethod("SEND") ||
        ismethod("PING");
}

void HttpReqHeader::postparse() {
    char *start = path;
    while (*start && *++start == '/');
    char *end=start;
    while (*end ){
        if(*end == '?'){
            break;
        }
        end++;
    }
    string filepath = string(start, end-start);
    if(filepath.empty()){
        filename = "/";
    }else{
        char buff[URLLIMIT * 3];
        URLDecode(buff, filepath.c_str(), filepath.length());
        filename = buff;
    }
    if(get(AlterMethod)){
        strcpy(method, get(AlterMethod));
        del(AlterMethod);
    }
    if(!normal_method()){
        return;
    }
    if(!Dest.scheme[0] && ismethod("SEND")){
        strcpy(Dest.scheme, "udp");
    }
    if(Dest.port == 0 && !ismethod("CONNECT") && !ismethod("SEND") && !ismethod("PING")){
        Dest.port = HTTPPORT;
    }
    if(request_id == 0) {
        request_id = id_gen++;
    }
}

std::string HttpReqHeader::geturl() const {
    char url[URLLIMIT]={0};
    int pos = dumpDestToBuffer(&Dest, url, sizeof(url));
    assert(path[0] == '/');
    if(!ismethod("CONNECT") || path[1] ){
        snprintf(url + pos, sizeof(url) - pos, "%s", path);
    }
    return url;
}


bool HttpReqHeader::ismethod(const char* method) const{
    return strcasecmp(this->method, method) == 0;
}

/*
char *HttpReqHeader::getstring(size_t &len) const{
    char *buff = nullptr;
    len = 0;
    if(!should_proxy && (ismethod("CONNECT")|| ismethod("SEND"))){
        //本地请求，自己处理connect和send方法
        return (char *)p_malloc(0);
    }
    std::list<string> AppendHeaders;
    char method[20];
    if(opt.alter_method){
        strcpy(method, "GET");
        AppendHeaders.push_back(string(AlterMethod)+": " + this->method);
    }else{
        strcpy(method, this->method);
    }
    for(auto p = opt.request_headers.next; p != nullptr; p = p->next){
        AppendHeaders.push_back(p->arg);
    }
    if(should_proxy){
        if (ismethod("CONNECT")|| ismethod("SEND")){
            buff= (char *)p_malloc(BUF_LEN);
            len += sprintf(buff, "%s %s:%d HTTP/1.1" CRLF, method, Dest.hostname, Dest.port);
        }else{
            buff= (char *)p_malloc(BUF_LEN);
            len += sprintf(buff, "%s %s HTTP/1.1" CRLF, method, geturl().c_str());
        }
    }else{
        buff= (char *)p_malloc(BUF_LEN);
        len += sprintf(buff, "%s %s HTTP/1.1" CRLF, method, path);
    }
    
    if(get("Host") == nullptr && Dest.hostname[0]){
        if(Dest.port == HTTPPORT){
            len += sprintf(buff + len, "Host: %s" CRLF, Dest.hostname);
        }else{
            char host_buff[DOMAINLIMIT+20];
            snprintf(host_buff, sizeof(host_buff), "%s:%d", Dest.hostname, Dest.port);
            len += sprintf(buff + len, "Host: %s" CRLF, host_buff);
        }
    }

    for (const auto& i : headers) {
        len += sprintf(buff + len, "%s: %s" CRLF, toUpHeader(i.first).c_str(), i.second.c_str());
    }
    if(!cookies.empty()){
        string cookie_str;
        for(const auto& i : cookies){
            cookie_str += "; ";
            cookie_str += i;
        }
        len += sprintf(buff + len, "Cookie: %s" CRLF, 
                cookie_str.substr(2).c_str());
    }

    for(const auto& i: AppendHeaders){
        len += sprintf(buff + len, "%s" CRLF, i.c_str());
    }

    len += sprintf(buff + len, CRLF);
    assert(len < BUF_LEN);
    return buff;
}

Http2_header *HttpReqHeader::getframe(Hpack_encoder *hpack_encoder, uint32_t http_id) const{
    Http2_header* const header = (Http2_header *)p_malloc(BUF_LEN);
    memset(header, 0, sizeof(*header));
    header->type = HTTP2_STREAM_HEADERS;
    header->flags = END_HEADERS_F;
    set32(header->id, http_id);

    unsigned char *p = (unsigned char *)(header + 1);
    p += hpack_encoder->encode(p, ":method", method);
    if(get("host") && !ismethod("CONNECT") && !ismethod("SEND")){
        p += hpack_encoder->encode(p, ":authority", get("host"));
    }else{
        char authority[URLLIMIT];
        snprintf(authority, sizeof(authority), "%s:%d", Dest.hostname, Dest.port);
        p += hpack_encoder->encode(p, ":authority", authority);
    }
    
    if(!ismethod("CONNECT") && !ismethod("SEND") && !ismethod("PING")){
        p += hpack_encoder->encode(p, ":scheme", Dest.scheme[0] ? Dest.scheme : "http");
        p += hpack_encoder->encode(p, ":path", path);
    }
    for(const auto& i: cookies){
        p += hpack_encoder->encode(p, "cookie", i.c_str());
    }

    p += hpack_encoder->encode(p, headers);
    set24(header->length, p-(unsigned char *)(header + 1));
    assert(get24(header->length) < BUF_LEN);
    return header;
}


CGI_Header *HttpReqHeader::getcgi() const{
    CGI_Header* const cgi = (CGI_Header *)p_malloc(BUF_LEN);
    cgi->type = CGI_REQUEST;
    cgi->flag = 0;
    cgi->requestId = htonl(request_id);
    
    char *p = (char *)(cgi + 1);
    p = cgi_addnv(p, ":method", method);
    p = cgi_addnv(p, ":path", path);
    p = cgi_addnv(p, ":authority", Dest.hostname);
    for(const auto& i: headers){
        p = cgi_addnv(p, i.first, i.second);
    }
    for(const auto& i: cookies){
        p = cgi_addnv(p, "cookie", i);
    }
    cgi->contentLength = htons(p - (char *)(cgi + 1));
    assert(ntohs(cgi->contentLength) < BUF_LEN);
    return cgi;
}
 */

bool HttpReqHeader::no_body() const {
    if(get("Upgrade")){
        return false;
    }
    if(get("Transfer-Encoding")){
        return false;
    }
    if(get("Content-Length")){
        return strcmp("0", get("Content-Length")) == 0;
    }
    return !(ismethod("CONNECT") ||
    ismethod("SEND") ||
    ismethod("PING"));
}


std::multimap<std::string, std::string> HttpReqHeader::Normalize() const {
    std::multimap<std::string, std::string> normalization;
    normalization.emplace(":method", method);
    normalization.emplace(":authority", dumpAuthority(&Dest));

    if(!ismethod("CONNECT") && !ismethod("SEND") && !ismethod("PING")){
        normalization.emplace(":scheme", Dest.scheme[0] ? Dest.scheme : "http");
        normalization.emplace(":path", path);
    }
    for(const auto& i: cookies){
        normalization.emplace("cookie", i.c_str());
    }

    for(const auto& i: headers){
        normalization.emplace(i.first, i.second);
    }
    //rfc7540#section.8.1.2.2 && http3
    normalization.erase("connection");
    normalization.erase("keep-alive");
    normalization.erase("proxy-connection");
    normalization.erase("transfer-encoding");
    normalization.erase("upgrade");
    return normalization;
}

const char *HttpReqHeader::getparamstring() const {
    const char *p = path;
    while (*p && *p++ != '?');
    return p;
}

std::map<std::string, std::string> HttpReqHeader::getparamsmap()const{
	return ::getparamsmap(getparamstring());
}

std::map<string, string> HttpReqHeader::getcookies() const {
    std::map<string, string> cookie;
    for(const auto& i:cookies){
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


/*
HttpResHeader::HttpResHeader(const char* header, size_t len) {
    assert(header);
    if(len == 0){
        //add one for \0
        len = strlen(header) + 1;
    }
    char httpheader[HEADLENLIMIT];
    memcpy(httpheader, header, len);
    *(strstr((char *)httpheader, CRLF CRLF) + strlen(CRLF)) = 0;
    memset(status, 0, sizeof(status));
    sscanf((char *)httpheader, "%*s%*[ ]%99[^\r\n]", status);

    for (char* str = strstr((char *)httpheader, CRLF)+strlen(CRLF); ; str = nullptr) {
        char* p = strtok(str, CRLF);

        if (p == nullptr)
            break;

        char* sp = strpbrk(p, ":");
        if (sp == nullptr) {
            LOGE("wrong header format:%s\n", p);
            throw PROTOCOL_ERR;
        }
        string name = toLower(string(p, sp-p));
        string value = ltrim(string(sp + 1));
        if(name == "set-cookie"){
            cookies.insert(value);
        }else{
            set(name, value);
        }
    }
}

HttpResHeader::HttpResHeader(const CGI_Header* headers)
{
    if(headers->type != CGI_RESPONSE)
    {
        LOGE("wrong CGI header");
        throw HTTP2_ERR_PROTOCOL_ERROR;
    }
    request_id = ntohl(headers->requestId);
    char *p = (char *)(headers +1);
    uint32_t len = ntohs(headers->contentLength);
    while(uint32_t(p - (char *)(headers +1)) < len){
        string name, value;
        p = cgi_getnv(p, name, value);
        if(name == ":status"){
            strcpy(status, value.c_str());
            continue;
        }
        if(name == "set-cookie"){
            cookies.insert(value);
            continue;
        }
        set(name, value);
   }
}
 */


HttpResHeader::HttpResHeader(std::multimap<string, string>&& headers) {
    for(const auto& i: headers){
        if(toLower(i.first) == "set-cookie"){
            cookies.insert(i.second);
        }else{
            set(i.first, i.second);
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

bool HttpResHeader::no_body() const {
    if(memcmp(status, "204", 3) == 0||
       memcmp(status, "304", 3) == 0)
    {
       return true;
    }

    return get("content-length") &&
           memcmp("0", get("content-length"), 2) == 0;
}

/*
char* HttpResHeader::getstring(size_t &len) const{
    char* const buff = (char *)p_malloc(BUF_LEN);
    len = 0;
    if(get("Content-Length") || get("Transfer-Encoding") || no_body() || get("Upgrade")){
        len += sprintf(buff, "HTTP/1.1 %s" CRLF, status);
    }else {
        len += sprintf(buff, "HTTP/1.0 %s" CRLF, status);
    }
    for (const auto& i : headers) {
        len += sprintf(buff + len, "%s: %s" CRLF,
                toUpHeader(i.first).c_str(), i.second.c_str());
    }
    for (const auto& i : cookies) {
        len += sprintf(buff + len, "Set-Cookie: %s" CRLF, i.c_str());
    }

    len += sprintf(buff + len, CRLF);
    assert(len < BUF_LEN);
    return buff;
}

Http2_header *HttpResHeader::getframe(Hpack_encoder* hpack_encoder, uint32_t http_id) const{
    Http2_header* const header = (Http2_header *)p_malloc(BUF_LEN);
    memset(header, 0, sizeof(*header));
    header->type = HTTP2_STREAM_HEADERS;
    header->flags = END_HEADERS_F;
    set32(header->id, http_id);

    unsigned char *p = (unsigned char *)(header + 1);
    char status_h2[100];
    sscanf(status,"%99s",status_h2);
    p += hpack_encoder->encode(p, ":status", status_h2);
    for (const auto& i : cookies) {
        p += hpack_encoder->encode(p, "set-cookie", i.c_str());
    }
    p += hpack_encoder->encode(p, headers);
    
    set24(header->length, p-(unsigned char *)(header + 1));
    assert(get24(header->length) < BUF_LEN);
    return header;
}

CGI_Header *HttpResHeader::getcgi() const{
    CGI_Header* const cgi = (CGI_Header *)p_malloc(BUF_LEN);
    cgi->type = CGI_RESPONSE;
    cgi->flag = 0;
    cgi->requestId = htonl(request_id);
    
    char *p = (char *)(cgi + 1);
    p = cgi_addnv(p, ":status", status);
    for(const auto& i: headers){
        p = cgi_addnv(p, i.first, i.second);
    }
    for(const auto& i: cookies){
        p = cgi_addnv(p, "set-cookie", i);
    }
    cgi->contentLength = htons(p - (char *)(cgi + 1));
    assert(ntohs(cgi->contentLength) < BUF_LEN);
    return cgi;
}
*/

std::multimap<std::string, std::string> HttpResHeader::Normalize() const {
    std::multimap<std::string, std::string> normalization;
    char status_h2[100];
    sscanf(status,"%99s",status_h2);
    normalization.emplace(":status", status_h2);
    for(const auto& i : cookies) {
        normalization.emplace("set-cookie", i.c_str());
    }
    for(const auto& i : headers){
        normalization.emplace(i.first, i.second);
    }
    return normalization;
}

void HttpResHeader::addcookie(const Cookie &cookie) {
    std::stringstream cookiestream;
    cookiestream << cookie.name <<'='<<cookie.value;
    if(cookie.path) {
        cookiestream << "; path="<< cookie.path;
    }
    if(cookie.domain) {
        cookiestream << "; domain="<< cookie.domain;
    }
    if(cookie.maxage) {
        cookiestream << "; max-age="<< cookie.maxage;
    }
    cookies.insert(cookiestream.str());
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
    while (true){
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


std::map<string, string> getparamsmap(const char* param) {
    return getparamsmap(param, strlen(param));
}


std::map<string, string> getparamsmap(const char *param, size_t len) {
    std::map<string, string> params;
    if(len == 0) {
        return params;
    }
    char paramsbuff[URLLIMIT];
    URLDecode(paramsbuff, param, len);
    char *p=paramsbuff;
    if(*p) {
        for (; ; p = nullptr) {
            char *q = strtok(p, "&");
            if (q == nullptr)
                break;

            char* sp = strpbrk(q, "=");
            if (sp) {
                params[string(q, sp - q)] = sp + 1;
            } else {
                params[q] = "";
            }
        }
    }
    return params;
}
