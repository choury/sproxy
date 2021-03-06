#include "http.h"
#include "misc/net.h"
#include "misc/util.h"

#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <cinttypes>

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
    if (http_expectlen == 0) {
        Http_Proc = &HttpBase::HeaderProc;
        EndProc();
        return HeaderProc(buffer, len);
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
        try {
            HttpReqHeader* req = new HttpReqHeader(buffer, headerlen);
            if(req->no_body()){
                http_flag |= HTTP_IGNORE_BODY_F;
            }else if (req->get("Content-Length") == nullptr ||
                      req->ismethod("CONNECT"))
            {
                Http_Proc = &HttpResponser::AlwaysProc;
            }else{
                Http_Proc = &HttpResponser::FixLenProc;
                http_expectlen = strtoull(req->get("Content-Length"), nullptr, 10);
            }
            ReqProc(req);
            if(http_flag & HTTP_IGNORE_BODY_F){
                EndProc();
                http_flag &= ~HTTP_IGNORE_BODY_F;
                Http_Proc = (size_t (HttpBase::*)(const char*, size_t))&HttpResponser::HeaderProc;
            }
        }catch(...) {
            ErrProc();
            return 0;
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
        try {
            HttpResHeader* res = new HttpResHeader(buffer, headerlen);
            if(res->no_body()){
                http_flag |= HTTP_IGNORE_BODY_F;
            }else if(res->status[0] == '1'){
                http_flag |= HTTP_STATUS_1XX;
            }else if(res->get("Transfer-Encoding")!= nullptr) {
                Http_Proc = &HttpRequester::ChunkLProc;
            }else if(res->get("Content-Length") == nullptr) {
                Http_Proc = &HttpRequester::AlwaysProc;
            }else{
                Http_Proc = &HttpRequester::FixLenProc;
                http_expectlen = strtoull(res->get("Content-Length"), nullptr, 10);
            }

            if(res->get("Upgrade") && strcmp(res->get("Upgrade"), "websocket") == 0){
                //treat websocket as raw tcp
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
        }catch(...) {
            ErrProc();
            return 0;
        }
        return headerlen;
    } else {
        return 0;
    }
}
