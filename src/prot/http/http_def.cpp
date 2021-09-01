#include "http_def.h"
#include "misc/util.h"

#include <assert.h>
#include <inttypes.h>

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
    return DATALEN - (int)len;
}


size_t Channel::eatData(const void* buf, size_t size) {
    if(size == 0){
        eof = true;
    }
    int rsize = std::min((int)size, cap());
    if(rsize <= 0 && !eof){
        return 0;
    }
    if(recv_const_cb){
        recv_const_cb(buf, rsize);
        return rsize;
    }
    if(recv_cb){
        recv_cb(p_memdup(buf, rsize), rsize);
        return rsize;
    }
    return 0;
}

void Channel::send(const void* buf, size_t size){
    assert((!eof || !size) && !closed);
    size_t rsize = 0;
    if(len){
        goto innerCopy;
    }
    rsize = eatData(buf, size);
    if(rsize == size){
        return;
    }
    size -= rsize;
    buf = (const char*)buf + rsize;
    if(data == nullptr) {
        data = (uchar *) malloc(DATALEN);
    }
innerCopy:
    if(len + size > DATALEN){
        abort();
    }
    memcpy(data+len, buf, size);
    len += size;
}

void Channel::trigger(Channel::signal s) {
    if (s == CHANNEL_ABORT || s == CHANNEL_CLOSED){
        closed = true;
    }
    if(handler){
        handler(s);
    }
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
        if(!eof && !closed && left > 0) {
            need_more();
            return;
        }
        if(eof){
            eatData((const void *) nullptr, 0);
        }
        if(closed){
            trigger(Channel::CHANNEL_CLOSED);
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

HttpRes::HttpRes(HttpResHeader *header, const char *body): HttpRes(header, []{}) {
    len = strlen(body);
    if(len) {
        data = (uchar *) malloc(DATALEN);
        memcpy(data, body, len);
    }
    eof = true;
    closed = true;
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
    LOG("%s [%" PRIu32 "] %s %s [%s] %s [%s]\n", src,
        req->header->request_id,
        req->header->method,
        req->header->geturl().c_str(),
        req->header->get("Strategy"),
        status,
        req->header->get("User-Agent"));
}

