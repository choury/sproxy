#include "http.h"
#include "net.h"

#include <string.h>
#include <inttypes.h>

void HttpBase::ChunkLProc() {
    if (char* headerend = strnstr(http_buff, CRLF, http_getlen)) {
        headerend += strlen(CRLF);
        size_t headerlen = headerend - http_buff;
        sscanf(http_buff, "%" SCNx64, &http_expectlen);
        if (!http_expectlen) {
            http_flag |= HTTP_CHUNK_END;
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
            if(http_flag & HTTP_CHUNK_END){
                DataProc(http_buff, 0);
                Http_Proc = &HttpBase::HeaderProc;
                http_flag &= ~HTTP_CHUNK_END;
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
        DataProc(http_buff, 0);
        Http_Proc = &HttpBase::HeaderProc;
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
        if (readlen <= 0) {
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


void HttpRes::HeaderProc() {
    if (char* headerend = strnstr(http_buff, CRLF CRLF, http_getlen)) {
        headerend += strlen(CRLF CRLF);
        size_t headerlen = headerend - http_buff;
        try {
            HttpReqHeader req(http_buff, shared_from_this());
            if (req.ismethod("POST") || 
                req.ismethod("PUT") || 
                req.ismethod("PATCH") ||
                req.ismethod("SEND")
            ) {
                if (req.get("Content-Length")!= nullptr) {
                    sscanf(req.get("Content-Length"), "%" SCNu64, &http_expectlen);
                    if(http_expectlen){
                        Http_Proc = &HttpRes::FixLenProc;
                    }
                } else {
                    Http_Proc = &HttpRes::AlwaysProc;
                }
            } else if (req.ismethod("CONNECT")) {
                Http_Proc = &HttpRes::AlwaysProc;
            }
            ReqProc(req);
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
    (this->*Http_Proc)();
}


void HttpReq::HeaderProc() {
    if (char* headerend = strnstr(http_buff, CRLF CRLF, http_getlen)) {
        headerend += strlen(CRLF CRLF);
        size_t headerlen = headerend - http_buff;
        try {
            HttpResHeader res(http_buff, shared_from_this());
            if (res.get("Transfer-Encoding")!= nullptr) {
                Http_Proc = &HttpReq::ChunkLProc;
            } else if (res.get("Content-Length")!= nullptr) {
                sscanf(res.get("Content-Length"), "%" SCNu64, &http_expectlen);
                if(http_expectlen){
                    Http_Proc = &HttpReq::FixLenProc;
                }
            } else {
                Http_Proc = &HttpReq::AlwaysProc;
            }
            if(memcmp(res.status, "204", 3) == 0||
               memcmp(res.status, "205", 3) == 0||
               memcmp(res.status, "304", 3) == 0)
               http_flag |= HTTP_IGNORE_BODY;
            ResProc(res);
            if (http_flag & HTTP_IGNORE_BODY) {
                Http_Proc = (void (HttpBase::*)())&HttpReq::HeaderProc;
                DataProc(http_buff, 0);
                http_flag &= ~HTTP_IGNORE_BODY;
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
