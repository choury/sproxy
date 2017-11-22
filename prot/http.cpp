#include "http.h"
#include "misc/net.h"
#include "misc/util.h"

#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <cinttypes>

void HttpBase::ChunkLProc() {
    if (char* headerend = strnstr(http_buff, CRLF, http_getlen)) {
        headerend += strlen(CRLF);
        size_t headerlen = headerend - http_buff;
        sscanf(http_buff, "%" SCNx64, &http_expectlen);
        if (!http_expectlen) {
            http_flag |= HTTP_CHUNK_END_F;
        }
        Http_Proc = &HttpBase::ChunkBProc;
        if (headerlen != http_getlen) {
            memmove(http_buff, http_buff+headerlen, http_getlen-headerlen);
        }
        http_getlen-= headerlen;
    } else {
        if (http_getlen == sizeof(http_buff)) {
            ErrProc(HEAD_TOO_LONG_ERR);
            return;
        }
        ssize_t readlen = Read(http_buff+http_getlen, sizeof(http_buff)-http_getlen);
        if (readlen <= 0) {
            ErrProc(readlen);
            return;
        } else {
            http_getlen += readlen;
        }
    }
    (this->*Http_Proc)();
}

void HttpBase::ChunkBProc() {
    if (http_expectlen == 0) {
        if (http_getlen >= strlen(CRLF)){
            if(memcmp(http_buff, CRLF, strlen(CRLF))) {
                ErrProc(HTTP_PROTOCOL_ERR);
                return;
            }
            http_getlen-= strlen(CRLF);
            memmove(http_buff, http_buff+strlen(CRLF), http_getlen);
            if(http_flag & HTTP_CHUNK_END_F){
                Http_Proc = &HttpBase::HeaderProc;
                http_flag &= ~HTTP_CHUNK_END_F;
                if(!EndProc()){
                    return;
                }
            }else{
                Http_Proc = &HttpBase::ChunkLProc;
            }
        }else{
            ssize_t readlen = Read(http_buff+http_getlen, sizeof(http_buff)-http_getlen);
            if (readlen <= 0) {
                ErrProc(readlen);
                return;
            }
            http_getlen += readlen;
        }
    } else {
        if (http_getlen == 0) {
            ssize_t readlen = Read(http_buff, sizeof(http_buff));
            if (readlen <= 0) {
                ErrProc(readlen);
                return;
            }
            http_getlen = readlen;
        }
        ssize_t len = DataProc(http_buff, Min(http_getlen, http_expectlen));
        if (len < 0) {
            return;
        } else {
            memmove(http_buff, http_buff+len, http_getlen-len);
            http_expectlen -= len;
            http_getlen    -= len;
        }
    }
    (this->*Http_Proc)();
}

void HttpBase::FixLenProc() {
    if (http_expectlen == 0) {
        Http_Proc = &HttpBase::HeaderProc;
        if(!EndProc()){
            return;
        }
    } else {
        if (http_getlen == 0) {
            ssize_t readlen = Read(http_buff, sizeof(http_buff));
            if (readlen <= 0) {
                ErrProc(readlen);
                return;
            }
            http_getlen = readlen;
        }

        ssize_t len = DataProc(http_buff, Min(http_getlen, http_expectlen));
        if (len <= 0) {
            return;
        } else {
            memmove(http_buff, http_buff+len, http_getlen-len);
            http_expectlen -= len;
            http_getlen    -= len;
        }
    }
    (this->*Http_Proc)();
}

void HttpBase::AlwaysProc() {
    if (http_getlen == 0) {
        ssize_t readlen = Read(http_buff, sizeof(http_buff));
        if(readlen == 0){
            EndProc();
        }
        if(readlen <= 0) {
            ErrProc(readlen);
            return;
        }
        http_getlen = readlen;
    }
    ssize_t len = DataProc(http_buff, http_getlen);
    if (len <= 0) {
        return;
    } else {
        memmove(http_buff, http_buff+len, http_getlen-len);
        http_getlen    -= len;
    }
    AlwaysProc();
}

void HttpResponser::HeaderProc() {
    bool proc = true;
    if (char* headerend = strnstr(http_buff, CRLF CRLF, http_getlen)) {
        headerend += strlen(CRLF CRLF);
        size_t headerlen = headerend - http_buff;
        try {
            HttpReqHeader* req = new HttpReqHeader(http_buff, this);
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
                proc = EndProc();
                http_flag &= ~HTTP_IGNORE_BODY_F;
                Http_Proc = (void (HttpBase::*)())&HttpResponser::HeaderProc;
            }
        }catch(...) {
            ErrProc(HTTP_PROTOCOL_ERR);
            return;
        }
        if (headerlen != http_getlen) {
            //TODO 待优化为环形buff
            memmove(http_buff, http_buff+headerlen, http_getlen-headerlen);
        }
        http_getlen-= headerlen;
    } else {
        if (http_getlen == sizeof(http_buff)) {
            ErrProc(HEAD_TOO_LONG_ERR);
            return;
        }
        ssize_t readlen = Read(http_buff+http_getlen, sizeof(http_buff)-http_getlen);
        if (readlen <= 0) {
            ErrProc(readlen);
            return;
        } else {
            http_getlen += readlen;
        }
    }
    if(!proc){
        return;
    }
    (this->*Http_Proc)();
}


void HttpRequester::HeaderProc() {
    if (char* headerend = strnstr(http_buff, CRLF CRLF, http_getlen)) {
        headerend += strlen(CRLF CRLF);
        size_t headerlen = headerend - http_buff;
        try {
            HttpResHeader* res = new HttpResHeader(http_buff);
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
            ResProc(res);
            if (http_flag & HTTP_IGNORE_BODY_F) {
                http_flag &= ~HTTP_IGNORE_BODY_F;
                Http_Proc = (void (HttpBase::*)())&HttpRequester::HeaderProc;
                if(!EndProc()){
                    return;
                }
            }else if(http_flag & HTTP_STATUS_1XX){
                http_flag &= ~HTTP_STATUS_1XX;
                Http_Proc = (void (HttpBase::*)())&HttpRequester::HeaderProc;
            }
        }catch(...) {
            ErrProc(HTTP_PROTOCOL_ERR);
            return;
        }
        if (headerlen != http_getlen) {
            assert(headerlen < http_getlen);
            //TODO 待优化为环形buff
            memmove(http_buff, http_buff+headerlen, http_getlen-headerlen);
        }
        http_getlen-= headerlen;
    } else {
        if (http_getlen == sizeof(http_buff)) {
            ErrProc(HEAD_TOO_LONG_ERR);
            return;
        }
        ssize_t readlen = Read(http_buff+http_getlen, sizeof(http_buff)-http_getlen);
        if (readlen <= 0) {
            ErrProc(readlen);
            return;
        } else {
            http_getlen += readlen;
        }
    }
    (this->*Http_Proc)();
}
