#include "http.h"
#include "misc/util.h"
#include "misc/buffer.h"
#include "misc/config.h"

#include <string.h>
#include <stdlib.h>
#include <assert.h>

#include <list>

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

bool HttpBase::ChunkLProc(Buffer& bb) {
    if (const char* headerend = strnstr((const char*)bb.data(), CRLF, bb.len)) {
        headerend += strlen(CRLF);
        size_t headerlen = headerend - (const char*)bb.data();
        http_expectlen = hextoint((const char*)bb.data());
        if (!http_expectlen) {
            http_flag |= HTTP_CHUNK_END_F;
        }
        Http_Proc = &HttpBase::ChunkBProc;
        bb.reserve(headerlen);
        return true;
    } else {
        return false;
    }
}

bool HttpBase::ChunkBProc(Buffer& bb) {
    if (http_expectlen == 0) {
        if (bb.len < strlen(CRLF)) {
            return false;
        }
        if(memcmp(bb.data(), CRLF, strlen(CRLF)) != 0) {
            LOGD(DHTTP, "buffer: %X %X\n", ((char*)bb.data())[0], ((char*)bb.data())[1]);
            ErrProc(bb.id);
            return false;
        }
        if(http_flag & HTTP_CHUNK_END_F){
            EndProc(bb.id);

            http_flag &= ~HTTP_CHUNK_END_F;
            Http_Proc = &HttpBase::HeaderProc;
        }else{
            Http_Proc = &HttpBase::ChunkLProc;
        }
        bb.reserve(strlen(CRLF));
        return true;
    } else {
        if (bb.len == 0) {
            return false;
        }
        if(http_expectlen < bb.len) {
            auto cbb = bb;
            cbb.truncate(http_expectlen);
            ssize_t ret = DataProc(cbb);
            if (ret < 0) {
                return false;
            }
            http_expectlen -= ret;
            bb.reserve(ret);
        }else {
            ssize_t ret = DataProc(bb);
            if (ret < 0) {
                return false;
            }
            http_expectlen -= ret;
        }
        return true;
    }
}

bool HttpBase::FixLenProc(Buffer& bb) {
    if (bb.len == 0) {
        return false;
    }
    if(http_expectlen < bb.len) {
        auto cbb = bb;
        cbb.truncate(http_expectlen);
        ssize_t ret = DataProc(cbb);
        if (ret < 0) {
            return false;
        }
        http_expectlen -= ret;
        bb.reserve(ret);
    } else {
        ssize_t ret = DataProc(bb);
        if (ret < 0) {
            return false;
        }
        http_expectlen -= ret;
    }
    if (http_expectlen == 0) {
        EndProc(bb.id);
        Http_Proc = &HttpBase::HeaderProc;
    }
    return true;
}

bool HttpBase::AlwaysProc(Buffer& bb) {
    if (bb.len == 0) {
        return false;
    }
    return DataProc(bb) > 0;
}

bool HttpResponser::HeaderProc(Buffer& bb) {
    if (const char* headerend = strnstr((const char*)bb.data(), CRLF CRLF, bb.len)) {
        headerend += strlen(CRLF CRLF);
        size_t headerlen = headerend - (const char*)bb.data();
        std::shared_ptr<HttpReqHeader> req = UnpackHttpReq(bb.data(), headerlen);
        if(req == nullptr){
            ErrProc(bb.id);
            return false;
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
        ReqProc(bb.id, req);
        if(http_flag & HTTP_IGNORE_BODY_F){
            EndProc(bb.id);
            http_flag &= ~HTTP_IGNORE_BODY_F;
            Http_Proc = (bool (HttpBase::*)(Buffer&))&HttpResponser::HeaderProc;
        }
        bb.reserve(headerlen);
        return true;
    } else {
        return false;
    }
}


bool HttpRequester::HeaderProc(Buffer& bb) {
    if (const char* headerend = strnstr((const char*)bb.data(), CRLF CRLF, bb.len)) {
        headerend += strlen(CRLF CRLF);
        size_t headerlen = headerend - (const char*)bb.data();
        std::shared_ptr<HttpResHeader> res = UnpackHttpRes(bb.data(), headerlen);
        if(res == nullptr){
            ErrProc(bb.id);
            return false;
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
        ResProc(bb.id, res);
        if (http_flag & HTTP_IGNORE_BODY_F) {
            EndProc(bb.id);

            http_flag &= ~HTTP_IGNORE_BODY_F;
            Http_Proc = (bool (HttpBase::*)(Buffer&))&HttpRequester::HeaderProc;
        }else if(http_flag & HTTP_STATUS_1XX){
            http_flag &= ~HTTP_STATUS_1XX;
            Http_Proc = (bool (HttpBase::*)(Buffer&))&HttpRequester::HeaderProc;
        }
        bb.reserve(headerlen);
        return true;
    } else {
        return false;
    }
}

std::shared_ptr<HttpReqHeader> UnpackHttpReq(const void* header, size_t len){
    if(header == nullptr){
        return nullptr;
    }
    if(len == 0) len = strlen((char*)header);
    std::string httpheader((const char*)header, len);
    *(strstr(&httpheader[0], CRLF CRLF) + strlen(CRLF)) = 0;

    HeaderMap headers;
    for (char* str = strstr(&httpheader[0], CRLF) + strlen(CRLF); ; str = nullptr) {
        char* p = strtok(str, CRLF);

        if (p == nullptr)
            break;

        const char* sp = strpbrk(p, ":");
        if (sp == nullptr) {
            //tolerate malformed header here for obfuscation
            continue;
        }
        std::string name = std::string(p, sp-p);
        headers.emplace(name, ltrim(std::string(sp + 1)));
    }

    char method[20] = {0};
    std::string url, path;
    url.resize(URLLIMIT);
    path.resize(URLLIMIT);
    sscanf(httpheader.c_str(), "%19s%*[ ]%8192[^" CRLF " ]", method, &url[0]);
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
    if (headers.count("Protocol")) {
        headers.emplace(":protocol", headers.find("Protocol")->second);
        headers.erase("Protocol");
    }
    if (headers.count("Upgrade") && headers.find("Upgrade")->second == "websocket") {
        headers.emplace(":protocol", "websocket");
        if(headers.count("Sec-WebSocket-Key") == 0) {
            //从http2/http3 转过来的websocket请求没有 Sec-WebSocket-Key，但是http1 需要有
            char nonce[16];
            for(int i = 0; i < 16; i++){
                nonce[i] = rand() % 256;
            }
            char key[25];
            Base64Encode(nonce, 16, key);
            headers.emplace("Sec-WebSocket-Key", key);
        }
    }
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

    HeaderMap headers;
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
    char *buff = (char*) data;
    std::list<std::string> AppendHeaders;
    char method[20];
    if(opt.alter_method){
        strcpy(method, "GET");
        AppendHeaders.push_back(std::string(AlterMethod)+": " + req->method);
    } else {
        strcpy(method, req->method);
    }
    size_t len = 0;
    if (strcmp(method, "CONNECT") == 0){
        assert(req->chain_proxy);
        len += snprintf(buff, size, "%s %s:%d HTTP/1.1" CRLF, method, req->Dest.hostname, req->Dest.port);
    }else if(req->chain_proxy){
        len += snprintf(buff, size, "%s %s HTTP/1.1" CRLF, method, req->geturl().c_str());
    }else{
        len += snprintf(buff, size, "%s %s HTTP/1.1" CRLF, method, req->path);
    }

    if(req->get("Host") == nullptr && req->Dest.hostname[0]){
        len += snprintf(buff + len, size-len, "Host: %s" CRLF, dumpAuthority(&req->Dest));
    }
    if(req->chain_proxy) {
        len += snprintf(buff + len, size - len, "Protocol: %s" CRLF, req->Dest.protocol);
    }
    for (const auto& i : req->getall()) {
        if (i.first == "proxy-connection" || i.first == "connection" || i.first == "upgrade"){
            continue;
        }
        len += snprintf(buff + len, size-len, "%s: %s" CRLF, toUpHeader(i.first).c_str(), i.second.c_str());
    }
    if(strcmp(req->Dest.protocol, "websocket") == 0){
        len += snprintf(buff + len, size-len, "Upgrade: websocket" CRLF "Connection: Upgrade" CRLF);
        if(req->get("Sec-WebSocket-Key") == nullptr) {
            //从http2/http3 转过来的websocket请求没有 Sec-WebSocket-Key，但是http1 要求有
            char nonce[16];
            for(int i = 0; i < 16; i++){
                nonce[i] = rand() % 256;
            }
            char key[25];
            Base64Encode(nonce, 16, key);
            len += snprintf(buff + len, size-len, "Sec-WebSocket-Key: %24s" CRLF, key);
        }
    }
    if(!req->cookies.empty()){
        std::string cookie_str;
        for(const auto& i : req->cookies){
            cookie_str += "; ";
            cookie_str += i;
        }
        len += snprintf(buff + len, size-len, "Cookie: %s" CRLF, cookie_str.substr(2).c_str());
    }

    for(const auto& i: AppendHeaders){
        len += snprintf(buff + len, size-len, "%s" CRLF, i.c_str());
    }

    len += snprintf(buff + len, size-len, CRLF);
    assert(len < size);
    return len;
}

size_t PackHttpRes(std::shared_ptr<const HttpResHeader> res, void* data, size_t size) {
    char* const buff = (char *)data;
    size_t len = 0;
    if(res->get("Content-Length") || res->get("Transfer-Encoding")
        || res->no_body() || res->get("Upgrade"))
    {
        len += snprintf(buff, size, "HTTP/1.1 %s" CRLF, res->status);
        len += snprintf(buff + len, size-len, "Connection: keep-alive" CRLF);
    }else {
        len += snprintf(buff, size, "HTTP/1.0 %s" CRLF, res->status);
        len += snprintf(buff + len, size-len, "Connection: close" CRLF);
    }
    for (const auto& i : res->getall()) {
        if(i.first == "upgrade" || i.first == "connection") {
            continue;
        }
        if(res->isTunnel && i.first == "transfer-encoding") {
            continue;
        }
        len += snprintf(buff + len, size-len, "%s: %s" CRLF, toUpHeader(i.first).c_str(), i.second.c_str());
    }
    if(res->isWebsocket && memcmp(res->status, "101", 3) == 0) {
        if(res->get("Sec-WebSocket-Accept") == nullptr) {
            assert(res->websocketKey.length());
            std::string key = res->websocketKey + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
            char sha1[20];
            SHA1((const unsigned char*)key.c_str(), key.length(), (unsigned char*)sha1);
            char accept[30];
            Base64Encode(sha1, 20, accept);
            len += snprintf(buff + len, size-len, "Sec-WebSocket-Accept: %s" CRLF, accept);
        }
        len += snprintf(buff + len, size-len, "Upgrade: websocket" CRLF "Connection: Upgrade" CRLF);
    }
    for (const auto& i : res->cookies) {
        len += snprintf(buff + len, size-len, "Set-Cookie: %s" CRLF, i.c_str());
    }

    len += snprintf(buff + len, size-len, CRLF);
    assert(len < size);
    return len;
}
