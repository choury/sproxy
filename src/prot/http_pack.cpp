#include "http_pack.h"
#include "http2.h"
#include "res/cgi.h"
#include "req/requester.h"
#include "misc/net.h"
#include "misc/util.h"

#include <algorithm>

#include <assert.h>

using std::string;

static char *cgi_addnv(char *p, const string &name, const string &value);
static char *cgi_getnv(char *p, string &name, string &value);

static char* toUpper(char* s) {
    char* p = s;

    while (*p) {
        *p = toupper(*p);
        p++;
    }

    return s;
}

static char* toLower(char* s) {
    char* p = s;

    while (*p) {
        *p = tolower(*p);
        p++;
    }

    return s;
}

static string toLower(const string &s) {
    string str = s;
    std::transform(str.begin(), str.end(), str.begin(), ::tolower);
    return str;
}

static string toUpHeader(const string &s){
    string str = s;
    str[0] = toupper(str[0]);
    for(size_t i = 0; i < str.length(); i++){
        if(str[i] == '-' && i != str.length() - 1){
            str[i+1] = toupper(str[i+1]);
        }
    }
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


HttpReqHeader::HttpReqHeader(const char* header, size_t len, std::weak_ptr<RwObject> src):
                             src(std::dynamic_pointer_cast<Requester>(src.lock()))
{
    assert(header);
    assert(!src.expired());
    assert(len < HEADLENLIMIT);
    memset(&Dest, 0, sizeof(Dest));
    
    char httpheader[HEADLENLIMIT];
    memcpy(httpheader, header, len);
    *(strstr((char *)httpheader, CRLF CRLF) + strlen(CRLF)) = 0;
    char url[URLLIMIT] = {0};
    sscanf(httpheader, "%19s%*[ ]%4095[^\r\n ]", method, url);
    toUpper(method);

    if (spliturl(url, &Dest, path)) {
        LOGE("wrong url format:%s\n", url);
        throw ERR_PROTOCOL_ERROR;
    }
    for (char* str = strstr(httpheader, CRLF) + strlen(CRLF); ; str = nullptr) {
        char* p = strtok(str, CRLF);

        if (p == nullptr)
            break;

        char* sp = strpbrk(p, ":");
        if (sp == nullptr) {
            LOGE("wrong header format:%s\n", p);
            throw ERR_PROTOCOL_ERROR;
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
            throw ERR_PROTOCOL_ERROR;
        }
    }
    postparse();
}


HttpReqHeader::HttpReqHeader(std::multimap<std::string, string>&& headers, std::weak_ptr<RwObject> src):
               src(std::dynamic_pointer_cast<Requester>(src.lock()))
{
    assert(!src.expired());
    if(!headers.count(":method")){
        LOGE("wrong http2 request\n");
        throw ERR_PROTOCOL_ERROR;
    }
    memset(&Dest, 0, sizeof(Dest));
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
            set(i.first, i.second);
        }
    }
    snprintf(method, sizeof(method), "%s", get(":method"));
    if(get(":scheme")){
        snprintf(Dest.schema, sizeof(Dest.schema), "%s", get(":scheme"));
    }
    if(get(":path")){
        snprintf(path, sizeof(path), "%s", get(":path"));
        if(!path[0]){
            throw ERR_PROTOCOL_ERROR;
        }
    }else{
        strcpy(path, "/");
    }
    
    if (get(":authority")){
        spliturl(get(":authority"), &Dest, nullptr);
        set("host", get(":authority"));
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

HttpReqHeader::HttpReqHeader(const CGI_Header *headers): src(std::weak_ptr<Requester>()) {
    if(headers->type != CGI_REQUEST)
    {
        LOGE("wrong CGI header");
        throw ERR_PROTOCOL_ERROR;
    }
   
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
    if(!normal_method()){
        return;
    }
    if(!Dest.schema[0]){
        if(ismethod("SEND")){
            strcpy(Dest.schema, "udp");
        }else{
            strcpy(Dest.schema, "http");
        }
    }
    if(Dest.port == 0 && !ismethod("CONNECT") && !ismethod("SEND")){
        Dest.port = HTTPPORT;
    }
}

std::string HttpReqHeader::geturl() const {
    char url[URLLIMIT]={0};
    int pos = dumpDestToBuffer(&Dest, url, sizeof(url));
    assert(path[0] == '/');
    if(path[1]){
        snprintf(url + pos, sizeof(url) - pos, "%s", path);
    }
    return url;
}


bool HttpReqHeader::ismethod(const char* method) const{
    return strcasecmp(this->method, method) == 0;
}

char *HttpReqHeader::getstring(size_t &len) const{
    char *buff = nullptr;
    len = 0;
    if (ismethod("CONNECT")|| ismethod("SEND")){
        if(should_proxy){
            buff= (char *)p_malloc(BUF_LEN);
            len += sprintf(buff, "%s %s:%d HTTP/1.1" CRLF, method, Dest.hostname, Dest.port);
        }else{
            //本地请求，自己处理connect和send方法
            len = 0;
            return (char *)p_malloc(0);
        }
    }else{
        if(should_proxy){
            buff= (char *)p_malloc(BUF_LEN);
            len += sprintf(buff, "%s %s HTTP/1.1" CRLF, method, geturl().c_str());
        }else{
            buff= (char *)p_malloc(BUF_LEN);
            len += sprintf(buff, "%s %s HTTP/1.1" CRLF, method, path);
        }
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
        len += sprintf(buff + len, "%s: %s" CRLF,
                toUpHeader(i.first).c_str(), i.second.c_str());
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

    len += sprintf(buff + len, CRLF);
    assert(len < BUF_LEN);
    return buff;
}

bool HttpReqHeader::no_body() const {
    if(ismethod("GET") ||
       ismethod("DELETE") ||
       ismethod("HEAD"))
    {
        return true;
    }
    if(ismethod("CONNECT") ||
       ismethod("SEND"))
    {
        return false;
    }
    if(get("content-length") &&
       strcmp("0", get("content-length"))==0)
    {
        return true;
    }
    return !(ismethod("POST") ||
             ismethod("PUT") ||
             ismethod("OPTIONS") ||
             ismethod("PING"));
}


Http2_header *HttpReqHeader::getframe(Hpack_index_table *index_table, uint32_t http_id) const{
    Http2_header* const header = (Http2_header *)p_malloc(BUF_LEN);
    memset(header, 0, sizeof(*header));
    header->type = HEADERS_TYPE;
    header->flags = END_HEADERS_F;
    set32(header->id, http_id);

    unsigned char *p = (unsigned char *)(header + 1);
    p += index_table->hpack_encode(p, ":method", method);
    if(get("host") && !ismethod("CONNECT") && !ismethod("SEND")){
        p += index_table->hpack_encode(p, ":authority" ,get("host"));
    }else{
        char authority[URLLIMIT];
        snprintf(authority, sizeof(authority), "%s:%d", Dest.hostname, Dest.port);
        p += index_table->hpack_encode(p, ":authority" ,authority);
    }
    
    if(!ismethod("CONNECT") && !ismethod("SEND") && !ismethod("PING")){
        p += index_table->hpack_encode(p, ":scheme", Dest.schema[0]?Dest.schema:"http");
        p += index_table->hpack_encode(p, ":path", path);
    }
    for(auto i: cookies){
        p += index_table->hpack_encode(p, "cookie", i.c_str());
    }
    
    p += index_table->hpack_encode(p, headers);
    set24(header->length, p-(unsigned char *)(header + 1));
    assert(get24(header->length) < BUF_LEN);
    return header;
}


CGI_Header *HttpReqHeader::getcgi(uint32_t cgi_id) const{
    CGI_Header* const cgi = (CGI_Header *)p_malloc(BUF_LEN);
    cgi->type = CGI_REQUEST;
    cgi->flag = 0;
    cgi->requestId = htonl(cgi_id);
    
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

const char *HttpReqHeader::getparamstring() const {
    const char *p = path;
    while (*p && *p++ != '?');
    return p;
}

std::map<std::string, std::string> HttpReqHeader::getparamsmap()const{
	return ::getparamsmap(getparamstring());
}

std::map< string, string > HttpReqHeader::getcookies() const {
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



HttpResHeader::HttpResHeader(const char* header, size_t len) {
    assert(header);
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
            throw ERR_PROTOCOL_ERROR;
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

HttpResHeader::HttpResHeader(std::multimap<string, string>&& headers) {
    for(const auto& i: headers){
        if(i.first == "set-cookies"){
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

HttpResHeader::HttpResHeader(const CGI_Header* headers)
{
    if(headers->type != CGI_RESPONSE)
    {
        LOGE("wrong CGI header");
        throw ERR_PROTOCOL_ERROR;
    }
   
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

bool HttpResHeader::no_body() const {
    if(memcmp(status, "204", 3) == 0||
       memcmp(status, "304", 3) == 0)
    {
       return true;
    }

    return get("content-length") &&
           memcmp("0", get("content-length"), 2) == 0;
}


char * HttpResHeader::getstring(size_t &len) const{
    char* const buff = (char *)p_malloc(BUF_LEN);
    len = 0;
    if(get("Content-Length") || get("Transfer-Encoding") || no_body()){
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


Http2_header *HttpResHeader::getframe(Hpack_index_table* index_table, uint32_t http_id) const{
    Http2_header* const header = (Http2_header *)p_malloc(BUF_LEN);
    memset(header, 0, sizeof(*header));
    header->type = HEADERS_TYPE;
    header->flags = END_HEADERS_F;
    set32(header->id, http_id);

    unsigned char *p = (unsigned char *)(header + 1);
    char status_h2[100];
    sscanf(status,"%99s",status_h2);
    p += index_table->hpack_encode(p, ":status", status_h2);
    for (const auto& i : cookies) {
        p += index_table->hpack_encode(p, "set-cookie", i.c_str());
    }
    p += index_table->hpack_encode(p, headers);
    
    set24(header->length, p-(unsigned char *)(header + 1));
    assert(get24(header->length) < BUF_LEN);
    return header;
}

CGI_Header *HttpResHeader::getcgi(uint32_t cgi_id) const{
    CGI_Header* const cgi = (CGI_Header *)p_malloc(BUF_LEN);
    cgi->type = CGI_RESPONSE;
    cgi->flag = 0;
    cgi->requestId = htonl(cgi_id);
    
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


static char *cgi_addnv(char *p, const string &name, const string &value) {
    CGI_NVLenPair *cgi_pairs = (CGI_NVLenPair *) p;
    cgi_pairs->nameLength = htons(name.size());
    cgi_pairs->valueLength = htons(value.size());
    p = (char *)(cgi_pairs +1);
    memcpy(p, name.c_str(), name.size());
    p += name.size();
    memcpy(p, value.c_str(), value.size());
    return p + value.size();
}

static char *cgi_getnv(char* p, string& name, string& value) {
    CGI_NVLenPair *cgi_pairs = (CGI_NVLenPair *)p;
    uint32_t name_len = ntohs(cgi_pairs->nameLength);
    uint32_t value_len = ntohs(cgi_pairs->valueLength);
    p = (char *)(cgi_pairs + 1);
    name = string(p, name_len);
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

#if 0

HttpBody::HttpBody() {
}


HttpBody::HttpBody(HttpBody && copy){
    while(copy.size()){
       this->push(copy.pop());
    }
}

void HttpBody::push(const void* buff, size_t len) {
    return push(p_memdup(buff, len), len);
}

void HttpBody::push(void* buff, size_t len) {
    assert(len);
    content_size += len;
    data.push(write_block{buff, len, 0});
}

void HttpBody::push(const write_block& wb) {
    assert(wb.buff);
    assert(wb.len);
    content_size += (wb.len - wb.wlen);
    return data.push(wb);
}



write_block HttpBody::pop(){
    assert(data.size());
    auto ret = data.front();
    data.pop();
    content_size -= (ret.len - ret.wlen);
    return ret;
}

size_t& HttpBody::size() {
    assert(bool(content_size) ==  !data.empty() ||
          (content_size == 0 && data.size() == 1 && data.back().wlen == data.back().len));
    return content_size;
}

HttpBody::~HttpBody() {
    while(data.size()){
       p_free(pop().buff);
    }
}

HttpReq::~HttpReq() {
    p_free(header_buff);
    delete header;
}

HttpReq::HttpReq(HttpReq && copy):body(std::move(copy.body)){
    header_buff = copy.header_buff;
    header_len = copy.header_len;
    header_sent = copy.header_sent;
    header = copy.header;

    copy.header_buff = nullptr;
    copy.header = nullptr;
}


ssize_t HttpReq::Write_string(std::function<ssize_t (const void *, size_t)> write_func){
    if(header_buff == nullptr){
        header_buff = header->getstring(header_len);
    }
    ssize_t writed = 0;
    assert(header_sent <= header_len);
    while(header_sent <  header_len){
        ssize_t ret = write_func((char *)header_buff + header_sent, header_len - header_sent);
        if(ret <= 0){
            return ret;
        }
        header_sent += ret;
        writed += ret;
    }
    while(body.size()){
        write_block& wb = body.data.front();
        ssize_t ret = write_func((char *)wb.buff + wb.wlen, wb.len - wb.wlen);
        if (ret <= 0) {
            return ret;
        }

        writed += true;
        body.size() -= ret;
        assert(ret + wb.wlen <= wb.len);
        if ((size_t)ret + wb.wlen == wb.len) {
            p_free(wb.buff);
            body.data.pop();
        } else {
            wb.wlen += ret;
            break;
        }
    }
    return writed;
}

size_t HttpReq::size(){
    if(header_buff == nullptr){
        return body.size() + BUF_LEN;
    }else{
        return body.size() + header_len - header_sent;
    }
}
#endif