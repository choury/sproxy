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

std::string toLower(const std::string &s) {
    std::string str = s;
    std::transform(str.begin(), str.end(), str.begin(), ::tolower);
    return str;
}

HttpHeader::HttpHeader() {
    ctime = getmtime();
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

size_t HttpHeader::mem_usage() {
    size_t usage = headers.size() * sizeof(std::string) * 2;
    for(const auto& i : headers) {
        usage += i.first.length();
        usage += i.second.length();
    }
    usage += cookies.size() * sizeof(std::string);
    for(const auto& cookie: cookies) {
        usage += cookie.length();
    }
    return usage;
}

HttpReqHeader::HttpReqHeader(HeaderMap&& headers) {
    for(const auto& i: headers){
        if(toLower(i.first) == "cookie"){
            std::string cookiebuff = i.second;
            std::istringstream iss(cookiebuff);
            std::string token;

            while (std::getline(iss, token, ';')) {
                cookies.insert(ltrim(token));
            }
        }else{
            set(i.first, i.second);
        }
    }

    memset(&Dest, 0, sizeof(Dest));
    if (get(":authority")){
        spliturl(get(":authority"), &Dest, nullptr);
    }
    if(get(":scheme")){
        snprintf(Dest.scheme, sizeof(Dest.scheme), "%s", get(":scheme"));
    }
    if(get(":protocol")){
        snprintf(Dest.protocol, sizeof(Dest.protocol), "%s", get(":protocol"));
    }
    if(get(":path")){
        snprintf(path, sizeof(path), "%s", get(":path"));
    }else{
        strcpy(path, "/");
    }
    if(strcmp(Dest.protocol, "websocket") == 0) {
        strcpy(method, "GET");
    } else {
        snprintf(method, sizeof(method), "%s", get(":method"));
    }

    for (auto i = this->headers.begin(); i!= this->headers.end();) {
        if (i->first[0] == ':') {
            i = this->headers.erase(i);
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

bool HttpReqHeader::valid_method() const {
    return http_method() || ismethod("CONNECT");
}

void HttpReqHeader::postparse() {
    const char *start = path;
    while (*start && *++start == '/');
    const char *end=start;
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
    if(request_id == 0) {
        request_id = nextId();
    }
    if(http_method()){
        if(Dest.protocol[0]){
            //do nothing
        }else if(strcasecmp(Dest.scheme, "https") == 0) {
            strcpy(Dest.protocol, "ssl");
        }else if(strcasecmp(Dest.scheme, "http") == 0){
            strcpy(Dest.protocol, "tcp");
        }
    }else if(ismethod("CONNECT")){
        Dest.scheme[0] = 0;
        if(!Dest.protocol[0]) {
            strcpy(Dest.protocol, "tcp");
        }
    // keep SEND and Ping method for compatibility
    }else if(ismethod("SEND")){
        strcpy(method, "CONNECT");
        Dest.scheme[0] = 0;
        strcpy(Dest.protocol, "udp");
    }else if(ismethod("PING")) {
        strcpy(method, "CONNECT");
        Dest.scheme[0] = 0;
        strcpy(Dest.protocol, "icmp");
    }
}

uint16_t HttpReqHeader::getDport() const {
    if(Dest.port || ismethod("CONNECT")){
        //这些方法必须指定端口，否则无法解析
        return Dest.port;
    }
    if(strcasecmp(Dest.scheme, "http") == 0) {
        return HTTPPORT;
    }
    if(strcasecmp(Dest.scheme, "https") == 0) {
        return HTTPSPORT;
    }
    return HTTPPORT;
}

std::string HttpReqHeader::geturl() const {
    std::string url = dumpDest(&Dest);
    assert(path[0] == '/');
    if(path[1]){
        url += path;
    }
    return url;
}


bool HttpReqHeader::ismethod(const char* method) const{
    return strcmp(this->method, method) == 0;
}

bool HttpReqHeader::no_body() const {
    if(ismethod("CONNECT")){
        return false;
    }
    if(get("Transfer-Encoding")){
        return false;
    }
    if(get("Content-Length")){
        return strcmp("0", get("Content-Length")) == 0;
    }
    if(strcmp(Dest.protocol, "websocket") == 0) {
        return false;
    }
    return true;
}

bool HttpReqHeader::no_end() const {
    if(no_body()){
        return false;
    }
    if(get("Transfer-Encoding")){
        return false;
    }
    if(get("Content-Length")){
        return false;
    }
    return true;
}

std::multimap<std::string, std::string> HttpReqHeader::Normalize() const {
    std::multimap<std::string, std::string> normalization;
    bool isWebsocket = strcmp(Dest.protocol, "websocket") == 0;
    if(isWebsocket) {
        normalization.emplace(":method", "CONNECT");
    }else {
        normalization.emplace(":method", method);
    }
    normalization.emplace(":authority", dumpAuthority(&Dest));
    if(chain_proxy || isWebsocket) {
        normalization.emplace(":protocol", Dest.protocol);
    }

    if(!ismethod("CONNECT")){
        normalization.emplace(":scheme", Dest.scheme[0] ? Dest.scheme : "http");
    }
    if(path[1] || http_method()) {
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
    normalization.erase("sec-websocket-key");
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

size_t HttpReqHeader::mem_usage() {
    return HttpHeader::mem_usage() + sizeof(*this) + ranges.size() * sizeof(Range);
}

HttpResHeader::HttpResHeader(const char *status, size_t len) {
    snprintf(this->status, sizeof(this->status), "%.*s", (int)len, status);
}

HttpResHeader::HttpResHeader(HeaderMap&& headers) {
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

bool HttpResHeader::no_end() const {
    if(no_body()){
        return false;
    }
    if(get("transfer-encoding")){
        return false;
    }
    if(get("content-length")){
        return false;
    }
    if(status[0] == '1' && memcmp(status, "101", 3) != 0){
        return false;
    }
    return true;
}

std::multimap<std::string, std::string> HttpResHeader::Normalize() const {
    std::multimap<std::string, std::string> normalization;
    char status_h2[100];
    if(isWebsocket && memcmp(status, "101", 3) == 0) {
        strcpy(status_h2, "200");
    }else {
        sscanf(status,"%99s",status_h2);
    }
    normalization.emplace(":status", status_h2);
    for(const auto& i : cookies) {
        normalization.emplace("set-cookie", i.c_str());
    }
    for(const auto& i : headers){
        normalization.emplace(i.first, i.second);
    }
    //rfc7540#section.8.1.2.2 && http3
    normalization.erase("connection");
    normalization.erase("keep-alive");
    normalization.erase("proxy-connection");
    normalization.erase("transfer-encoding");
    normalization.erase("upgrade");
    normalization.erase("sec-websocket-accept");
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

void HttpResHeader::markWebsocket(const char* key) {
    isWebsocket = true;
    if(key) {
        websocketKey = key;
    }
    if(memcmp(status, "200", 3) == 0) {
        strcpy(status, "101 Switching Protocols");
    }
}

void HttpResHeader::markTunnel(){
    isTunnel = true;
    if(memcmp(status, "200", 3) == 0) {
        strcpy(status, "200 Connection established");
    }
}

std::shared_ptr<HttpResHeader> HttpResHeader::create(const char *status, size_t len, uint64_t id) {
    auto res = std::make_shared<HttpResHeader>(status, len);
    res->request_id = id;
    return res;
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
