#include "http.h"
#include "misc/util.h"
#include "misc/config.h"

#include <string.h>
#include <stdlib.h>
#include <assert.h>

static size_t hextoint(const char* str){
    size_t size = 0;
    for(; *str ; str++){
        if(*str >= '0' && *str <= '9'){
            size *= 16;
            size += *str - '0';
        }else if(*str >= 'a' && *str <= 'f'){
            size *= 16;
            size += *str - 'a' + 10;
        }else if(*str >= 'A' && *str <= 'F'){
            size *= 16;
            size += *str - 'A' + 10;
        }else{
            break;
        }
    }
    return size;
}

size_t HttpBase::ChunkLProc(const char* buffer, size_t len) {
    if (const char* headerend = strnstr(buffer, CRLF, len)) {
        headerend += strlen(CRLF);
        size_t headerlen = headerend - buffer;
        http_expectlen = hextoint(buffer);
        if (!http_expectlen) {
            http_flag |= HTTP_CHUNK_END_F;
        }
        Http_Proc = &HttpBase::ChunkBProc;
        return headerlen;
    } else {
        return 0;
    }
}

size_t HttpBase::ChunkBProc(const char* buffer, size_t len) {
    if (http_expectlen == 0) {
        if (len >= strlen(CRLF)){
            if(memcmp(buffer, CRLF, strlen(CRLF)) != 0) {
                LOGD(DHTTP, "buffer: %X %X\n", buffer[0], buffer[1]);
                ErrProc();
                return 0;
            }
            if(http_flag & HTTP_CHUNK_END_F){
                Http_Proc = &HttpBase::HeaderProc;
                http_flag &= ~HTTP_CHUNK_END_F;
                EndProc();
            }else{
                Http_Proc = &HttpBase::ChunkLProc;
            }
            return strlen(CRLF);
        }
        return 0;
    } else {
        if (len == 0) {
            return 0;
        }
        ssize_t ret = DataProc(buffer, Min(len, http_expectlen));
        if (ret < 0) {
            return 0;
        }
        http_expectlen -= ret;
        return ret;
    }
}

size_t HttpBase::FixLenProc(const char* buffer, size_t len) {
    if (len == 0) {
        return 0;
    }
    ssize_t ret = DataProc(buffer, Min(len, http_expectlen));
    if (ret < 0) {
        return 0;
    }
    http_expectlen -= ret;
    if (http_expectlen == 0) {
        Http_Proc = &HttpBase::HeaderProc;
        EndProc();
    }
    return ret;
}

size_t HttpBase::AlwaysProc(const char* buffer, size_t len) {
    if (len == 0) {
        return 0;
    }
    ssize_t ret = DataProc(buffer, len);
    if (ret <= 0) {
        return 0;
    }
    return ret;
}

size_t HttpResponser::HeaderProc(const char* buffer, size_t len) {
    if (const char* headerend = strnstr(buffer, CRLF CRLF, len)) {
        headerend += strlen(CRLF CRLF);
        size_t headerlen = headerend - buffer;
        std::shared_ptr<HttpReqHeader> req = UnpackHttpReq(buffer, headerlen);
        if(req == nullptr){
            ErrProc();
            return 0;
        }
        if(req->no_body()){
            http_flag |= HTTP_IGNORE_BODY_F;
        }else if(req->get("Transfer-Encoding")!= nullptr) {
            Http_Proc = &HttpResponser::ChunkLProc;
        }else if (req->get("Content-Length") != nullptr){
            Http_Proc = &HttpResponser::FixLenProc;
            http_expectlen = strtoull(req->get("Content-Length"), nullptr, 10);
        }else {
            Http_Proc = &HttpResponser::AlwaysProc;
        }
        ReqProc(req);
        if(http_flag & HTTP_IGNORE_BODY_F){
            EndProc();
            http_flag &= ~HTTP_IGNORE_BODY_F;
            Http_Proc = (size_t (HttpBase::*)(const char*, size_t))&HttpResponser::HeaderProc;
        }
        return headerlen;
    } else {
        return 0;
    }
}


size_t HttpRequester::HeaderProc(const char* buffer, size_t len) {
    if (const char* headerend = strnstr(buffer, CRLF CRLF, len)) {
        headerend += strlen(CRLF CRLF);
        size_t headerlen = headerend - buffer;
        std::shared_ptr<HttpResHeader> res = UnpackHttpRes(buffer, headerlen);
        if(res == nullptr){
            ErrProc();
            return 0;
        }
        if(res->no_body()){
            http_flag |= HTTP_IGNORE_BODY_F;
        }else if(res->status[0] == '1') {
            http_flag |= HTTP_STATUS_1XX;
        }else if(res->get("Transfer-Encoding")!= nullptr) {
            Http_Proc = &HttpRequester::ChunkLProc;
        }else if(res->get("Content-Length") == nullptr) {
            Http_Proc = &HttpRequester::AlwaysProc;
        }else{
            Http_Proc = &HttpRequester::FixLenProc;
            http_expectlen = strtoull(res->get("Content-Length"), nullptr, 10);
        }

        if(memcmp(res->status, "101", 3) == 0){
            //treat Switching Protocols as raw tcp
            http_flag &= ~HTTP_STATUS_1XX;
            Http_Proc = &HttpRequester::AlwaysProc;
        }
        ResProc(res);
        if (http_flag & HTTP_IGNORE_BODY_F) {
            http_flag &= ~HTTP_IGNORE_BODY_F;
            Http_Proc = (size_t (HttpBase::*)(const char*, size_t))&HttpRequester::HeaderProc;
            EndProc();
        }else if(http_flag & HTTP_STATUS_1XX){
            http_flag &= ~HTTP_STATUS_1XX;
            Http_Proc = (size_t (HttpBase::*)(const char*, size_t))&HttpRequester::HeaderProc;
        }
        return headerlen;
    } else {
        return 0;
    }
}

std::shared_ptr<HttpReqHeader> UnpackHttpReq(const void* header, size_t len){
    if(header == nullptr){
        return nullptr;
    }
    if(len == 0) len = strlen((char*)header);
    std::string httpheader((const char*)header, len);
    *(strstr(&httpheader[0], CRLF CRLF) + strlen(CRLF)) = 0;

    std::multimap<std::string, std::string> headers;
    for (char* str = strstr(&httpheader[0], CRLF) + strlen(CRLF); ; str = nullptr) {
        char* p = strtok(str, CRLF);

        if (p == nullptr)
            break;

        char* sp = strpbrk(p, ":");
        if (sp == nullptr) {
            //tolerate malformed header here for obfuscation
            break;
        }
        std::string name = std::string(p, sp-p);
        headers.emplace(name, ltrim(std::string(sp + 1)));
    }

    char method[20] = {0};
    std::string url, path;
    url.resize(URLLIMIT);
    path.resize(URLLIMIT);
    sscanf(httpheader.c_str(), "%19s%*[ ]%4095[^" CRLF " ]", method, &url[0]);
    headers.emplace(":method", method);

    Destination dest;
    memset(&dest, 0, sizeof(dest));
    if (spliturl(url.c_str(), &dest, &path[0])) {
        LOGE("wrong url format:%s\n", url.c_str());
        return nullptr;
    }
    headers.emplace(":path", path.c_str());
    if(dest.scheme[0]){
        headers.emplace(":scheme", dest.scheme);
    }
    if(dest.hostname[0]){
        headers.emplace(":authority", dumpAuthority(&dest));
    }else if(headers.count("Host")){
        headers.emplace(":authority", headers.find("Host")->second);
    }
    headers.erase("Host");
    return std::make_shared<HttpReqHeader>(std::move(headers));
}

std::shared_ptr<HttpResHeader> UnpackHttpRes(const void* header, size_t len) {
    if(header == nullptr){
        return nullptr;
    }
    if(len == 0) len = strlen((char*)header);
    std::string httpheader((const char*)header, len);

    *(strstr(&httpheader[0], CRLF CRLF) + strlen(CRLF)) = 0;

    char status[100] = {0};
    sscanf(httpheader.c_str(), "%*s%*[ ]%99[^\r\n]", status);

    std::multimap<std::string, std::string> headers;
    headers.emplace(":status", status);

    for (char* str = strstr(&httpheader[0], CRLF)+strlen(CRLF); ; str = nullptr) {
        char* p = strtok(str, CRLF);

        if (p == nullptr)
            break;

        char* sp = strpbrk(p, ":");
        if (sp == nullptr) {
            LOGE("wrong header format:%s\n", p);
            return nullptr;
        }
        std::string name = std::string(p, sp-p);
        std::string value = ltrim(std::string(sp + 1));
        headers.emplace(name, value);
    }
    return std::make_shared<HttpResHeader>(std::move(headers));
}

static std::string toUpHeader(const std::string &s){
    std::string str = s;
    str[0] = toupper(str[0]);
    for(size_t i = 0; i < str.length(); i++){
        if(str[i] == '-' && i != str.length() - 1){
            str[i+1] = toupper(str[i+1]);
        }
    }
    return str;
}

size_t PackHttpReq(std::shared_ptr<const HttpReqHeader> req, void* data, size_t size){
    if(!req->should_proxy && (req->ismethod("CONNECT") || req->ismethod("SEND"))){
        //本地请求，自己处理connect和send方法
        return 0;
    }
    char *buff = (char*) data;
    std::list<std::string> AppendHeaders;
    char method[20];
    if(opt.alter_method){
        strcpy(method, "GET");
        AppendHeaders.push_back(std::string(AlterMethod)+": " + req->method);
    }else{
        strcpy(method, req->method);
    }
    for(auto p = opt.request_headers.next; p != nullptr; p = p->next){
        AppendHeaders.emplace_back(p->arg);
    }
    size_t len = 0;
    if(req->should_proxy){
        if (req->ismethod("CONNECT")|| req->ismethod("SEND")){
            len += sprintf(buff, "%s %s:%d HTTP/1.1" CRLF, method, req->Dest.hostname, req->Dest.port);
        }else{
            len += sprintf(buff, "%s %s HTTP/1.1" CRLF, method, req->geturl().c_str());
        }
    }else{
        len += sprintf(buff, "%s %s HTTP/1.1" CRLF, method, req->path);
    }

    if(req->get("Host") == nullptr && req->Dest.hostname[0]){
        len += sprintf(buff + len, "Host: %s" CRLF, dumpAuthority(&req->Dest));
    }

    for (const auto& i : req->getall()) {
        len += sprintf(buff + len, "%s: %s" CRLF, toUpHeader(i.first).c_str(), i.second.c_str());
    }
    if(!req->cookies.empty()){
        std::string cookie_str;
        for(const auto& i : req->cookies){
            cookie_str += "; ";
            cookie_str += i;
        }
        len += sprintf(buff + len, "Cookie: %s" CRLF, cookie_str.substr(2).c_str());
    }

    for(const auto& i: AppendHeaders){
        len += sprintf(buff + len, "%s" CRLF, i.c_str());
    }

    len += sprintf(buff + len, CRLF);
    assert(len < size);
    (void)size;
    return len;
}

size_t PackHttpRes(std::shared_ptr<const HttpResHeader> res, void* data, size_t size) {
    char* const buff = (char *)data;
    size_t len = 0;
    if(res->get("Content-Length") || res->get("Transfer-Encoding")
        || res->no_body() || res->get("Upgrade"))
    {
        len += sprintf(buff, "HTTP/1.1 %s" CRLF, res->status);
    }else {
        len += sprintf(buff, "HTTP/1.0 %s" CRLF, res->status);
    }
    for (const auto& i : res->getall()) {
        len += sprintf(buff + len, "%s: %s" CRLF, toUpHeader(i.first).c_str(), i.second.c_str());
    }
    for (const auto& i : res->cookies) {
        len += sprintf(buff + len, "Set-Cookie: %s" CRLF, i.c_str());
    }

    len += sprintf(buff + len, CRLF);
    assert(len < size);
    (void)size;
    return len;
}
