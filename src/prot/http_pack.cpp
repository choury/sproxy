#include "http_pack.h"
#include "http2.h"
#include "res/cgi.h"
#include "misc/net.h"
#include "misc/util.h"

#include <algorithm>
#include <utility>
#include <atomic>

#include <assert.h>
#include <inttypes.h>

using std::string;

static std::atomic<uint64_t> id_gen(10000);
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

string toLower(const string &s) {
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

// trim from start
static std::string& ltrim(std::string && s) {
    s.erase(0, s.find_first_not_of(" "));
    return s;
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


HttpReqHeader::HttpReqHeader(std::multimap<std::string, string>&& headers) {
    if(!headers.count(":method")){
        LOGE("wrong http2 request\n");
        throw ERR_PROTOCOL_ERROR;
    }
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

    memset(&Dest, 0, sizeof(Dest));
    if (get(":authority")){
        spliturl(get(":authority"), &Dest, nullptr);
        set("host", get(":authority"));
    }
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

    for (auto i = this->headers.begin(); i!= this->headers.end();) {
        if (i->first[0] == ':') {
            this->headers.erase(i++);
        } else {
            i++;
        }
    }
    postparse();
}

HttpReqHeader::HttpReqHeader(const CGI_Header *headers) {
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
    if(!Dest.schema[0] && ismethod("SEND")){
        strcpy(Dest.schema, "udp");
    }
    if(Dest.port == 0 && !ismethod("CONNECT") && !ismethod("SEND") && !ismethod("PING")){
        Dest.port = HTTPPORT;
    }
    request_id = id_gen++;
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

Channel::Channel(more_data_t need_more): need_more(std::move(need_more)){
}

Channel::~Channel() {
    free(data);
}

int Channel::cap(){
    if(cap_cb){
        ssize_t ret = cap_cb() - len;
        return Max(ret, 0);
    }
    return DATALEN - len;
}


bool Channel::eatData(void *buf, size_t size) {
    assert((int)size <= cap());
    if(recv_cb){
        recv_cb(buf, size);
        return true;
    }
    if(recv_const_cb){
        recv_const_cb(buf, size);
        p_free(buf);
        return true;
    }
    return false;
}

bool Channel::eatData(const void* buf, size_t size) {
    assert((int)size <= cap());
    if(recv_const_cb){
        recv_const_cb(buf, size);
        return true;
    }
    if(recv_cb){
        recv_cb(p_memdup(buf, size), size);
        return true;
    }
    if(size == 0){
        eof = true;
        return true;
    }
    return false;
}



void Channel::send(void *buf, size_t size) {
    assert(!eof && size);
    if(len){
        goto innerCopy;
    }
    assert((int)size <= cap());
    if(eatData(buf, size)){
        return;
    }
    assert(data == nullptr);
    data = (uchar*)malloc(DATALEN);
innerCopy:
    if(len + size > DATALEN){
        abort();
    }
    memcpy(data+len, buf, size);
    len += size;
    p_free(buf);
}

void Channel::send(const void* buf, size_t size){
    assert(!eof || !size);
    if(len){
        goto innerCopy;
    }
    assert((int)size <= cap());
    if(eatData(buf, size)){
        return;
    }
    assert(data == nullptr);
    data = (uchar*)malloc(DATALEN);
innerCopy:
    if(len + size > DATALEN){
        abort();
    }
    memcpy(data+len, buf, size);
    len += size;
}

void Channel::trigger(Channel::signal s) {
    if(handler)
        handler(s);
}

void Channel::more(){
    int left = cap();
    if(left <= 0){
        return;
    }
    if(len){
        size_t l = Min(len, left);
        eatData((const void *) data, l);
        len -= l;
        left -= l;
        memmove(data, data + l, len);
    }
    if(len == 0){
        if(eof){
            eatData((const void *) nullptr, 0);
        }else if(left > 0) {
            need_more();
        }
    }
}

void Channel::attach(recv_t recv_cb, cap_t cap_cb) {
    this->recv_cb = std::move(recv_cb);
    this->cap_cb = std::move(cap_cb);
    more();
}

void Channel::attach(recv_const_t recv_cb, cap_t cap_cb) {
    this->recv_const_cb = std::move(recv_cb);
    this->cap_cb = std::move(cap_cb);
    more();
}

void Channel::setHandler(handler_t handler) {
    this->handler = std::move(handler);
}

void Channel::detach() {
    this->recv_cb = nullptr;
    this->recv_const_cb = nullptr;
    this->cap_cb = []{return 0;};
    this->handler = nullptr;
}

HttpRes::HttpRes(HttpResHeader* header, more_data_t more): Channel(std::move(more)), header(header) {
}

HttpRes::HttpRes(HttpResHeader *header): HttpRes(header, []{}) {
}

HttpRes::HttpRes(HttpResHeader *header, const char *body): HttpRes(header, []{
})
{
    len = strlen(body);
    if(len) {
        data = (uchar *) malloc(DATALEN);
        memcpy(data, body, len);
    }
    eof = true;
    header->set("Content-Length", len);
}

HttpRes::~HttpRes() {
    delete header;
}

HttpReq::HttpReq(HttpReqHeader* header, HttpReq::res_cb response, more_data_t more):
    Channel(std::move(more)), header(header), response(std::move(response))
{
}

HttpReq::~HttpReq() {
    delete header;
}


void HttpLog(const char* src, const HttpReq* req, const HttpRes* res){
    char status[100];
    sscanf(res->header->status, "%s", status);
    LOG("%s [%" PRIu64 "] %s %s [%s] %s [%s]\n", src,
        req->header->request_id,
        req->header->method,
        req->header->geturl().c_str(),
        req->header->get("Strategy"),
        status,
        req->header->get("User-Agent"));
}

