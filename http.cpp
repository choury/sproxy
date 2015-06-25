#include "http.h"
#include "net.h"

#include <string.h>

Http::Http(bool transparent) {
    if(transparent) {
        Http_Proc = &Http::AlwaysProc;
    } else {
        Http_Proc = &Http::HeaderProc;
    }
}


void Http::ReqProc(HttpReqHeader& req) {
    LOG("Get a http request\n");
}

void Http::ResProc(HttpResHeader& res) {
    LOG("Get a http response\n");
}


void Http::HeaderProc() {
    if (char* headerend = strnstr(http_buff, CRLF CRLF, http_getlen)) {
        headerend += strlen(CRLF CRLF);
        size_t headerlen = headerend - http_buff;
        try {
            if (memcmp(http_buff, "HTTP", 4) == 0) {
                HttpResHeader res(http_buff);
                if (res.get("Transfer-Encoding")!= nullptr) {
                    Http_Proc = &Http::ChunkLProc;
                } else if (res.get("Content-Length")!= nullptr) {
                    sscanf(res.get("Content-Length"), "%lu", &http_expectlen);
                    Http_Proc = &Http::FixLenProc;
                } else {
                    Http_Proc = &Http::AlwaysProc;
                }
                ResProc(res);
                if (ignore_body) {
                    Http_Proc = &Http::HeaderProc;
                    DataProc(http_buff, 0);
                    ignore_body = false;
                }
            } else {
                HttpReqHeader req(http_buff);
                if (req.ismethod("POST")) {
                    if (req.get("Content-Length")!= nullptr) {
                        sscanf(req.get("Content-Length"), "%lu", &http_expectlen);
                        Http_Proc = &Http::FixLenProc;
                    } else {
                        Http_Proc = &Http::ChunkLProc;
                    }
                } else if (req.ismethod("CONNECT")) {
                    Http_Proc = &Http::AlwaysProc;
                }
                ReqProc(req);
            }
        }catch(...) {
            ErrProc(0);
            return;
        }
        if (headerlen != http_getlen) {
            //TODO 待优化为环形buff
            memmove(http_buff, http_buff+headerlen, http_getlen-headerlen);
        }
        http_getlen-= headerlen;

    } else {
        if (http_getlen == sizeof(http_buff)) {
            ErrProc(HEAD_TOO_LAGER);
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

void Http::ChunkLProc() {
    if (char* headerend = strnstr(http_buff, CRLF, http_getlen)) {
        headerend += strlen(CRLF);
        size_t headerlen = headerend - http_buff;
        sscanf(http_buff, "%lx", &http_expectlen);
        if (http_expectlen) {
            Http_Proc = &Http::ChunkBProc;
        } else {
            DataProc(http_buff, 0);
            Http_Proc = &Http::HeaderProc;
            headerlen += strlen(CRLF);
        }
        if (headerlen != http_getlen) {
            memmove(http_buff, http_buff+headerlen, http_getlen-headerlen);
        }
        http_getlen-= headerlen;
    } else {
        if (http_getlen == sizeof(http_buff)) {
            ErrProc(HEAD_TOO_LAGER);
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

void Http::ChunkBProc() {
    if (http_expectlen == 0) {
        if (memcmp(http_buff, CRLF, strlen(CRLF))) {
            ErrProc(HTTP_ERROR);
            return;
        }
        http_getlen-= strlen(CRLF);
        memmove(http_buff, http_buff+strlen(CRLF), http_getlen);
        Http_Proc = &Http::ChunkLProc;
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

void Http::FixLenProc() {
    if (http_expectlen == 0) {
        DataProc(http_buff, 0);
        Http_Proc = &Http::HeaderProc;
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

void Http::AlwaysProc() {
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
