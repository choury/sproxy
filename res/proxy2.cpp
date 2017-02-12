#include "proxy2.h"
#include "req/requester.h"
#include "misc/job.h"


Proxy2* proxy2 = nullptr;

void Proxy2::ping_check(Proxy2 *p){
    if(proxy2 != p && p->statusmap.empty()){
        p->clean(NOERROR, 0);
        return;
    }
    char buff[8];
    set64(buff, getutime());
    p->Ping(buff);
#ifndef NDEBUG
    LOGD(DHTTP2, "window size global: %d/%d\n", p->localwinsize, p->remotewinsize);
#endif
    add_job((job_func)ping_check, p, 5000);
}

void Proxy2::ping_timeout(Proxy2 *p){
    LOGE("[Proxy2] %p the ping timeout, so close it\n", p);
    p->clean(PEER_LOST_ERR, 0);
}

Proxy2::Proxy2(int fd, SSL_CTX *ctx, Ssl *ssl): ctx(ctx), ssl(ssl) {
    this->fd = fd;
    remotewinsize = remoteframewindowsize;
    localwinsize  = localframewindowsize;
    updateEpoll(EPOLLIN | EPOLLOUT);
    handleEvent = (void (Con::*)(uint32_t))&Proxy2::defaultHE;
}

Proxy2::~Proxy2() {
    delete ssl;
    SSL_CTX_free(ctx);
    del_job((job_func)ping_check, this);
    del_job((job_func)ping_timeout, this);
}


ssize_t Proxy2::Read(void* buff, size_t len) {
    return ssl->read(buff, len);
}


ssize_t Proxy2::Write(const void *buff, size_t len) {
    return ssl->write(buff, len);
}

ssize_t Proxy2::Write(void* buff, size_t size, void* index) {
    uint32_t id = (uint32_t)(long)index;
    assert(statusmap.count(id));
    size = Min(size, FRAMEBODYLIMIT);
    Http2_header *header=(Http2_header *)p_move(buff, -(char)sizeof(Http2_header));
    memset(header, 0, sizeof(Http2_header));
    set32(header->id, id);
    set24(header->length, size);
    if(size == 0) {
        header->flags = END_STREAM_F;
    }
    PushFrame(header);
    this->remotewinsize -= size;
    statusmap[id].remotewinsize -= size;
    return size;
}

void Proxy2::PushFrame(Http2_header *header){
    updateEpoll(EPOLLIN | EPOLLOUT);
    return Http2Base::PushFrame(header);
}


int32_t Proxy2::bufleft(void* index) {
    if(index)
        return Min(statusmap.at((uint32_t)(long)index).remotewinsize, this->remotewinsize);
    else
        return this->remotewinsize;
}


void Proxy2::defaultHE(uint32_t events) {
    if (events & EPOLLERR || events & EPOLLHUP) {
        int       error = 0;
        socklen_t errlen = sizeof(error);

        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, (void*)&error, &errlen) == 0) {
            LOGE("proxy2 error: %s\n", strerror(error));
        }
        clean(INTERNAL_ERR, 0);
        return;
    }
    if (events & EPOLLIN) {
        add_job((job_func)ping_check, this, 20000);
        add_job((job_func)ping_timeout, this, 30000);
        (this->*Http2_Proc)();
        if(inited && localwinsize < 50 *1024 *1024){
            localwinsize += ExpandWindowSize(0, 50*1024*1024);
        }
    }

    if (events & EPOLLOUT) {
        int ret = SendFrame();
        if(ret <=0 && showerrinfo(ret, "proxy2 write error")) {
            clean(WRITE_ERR, 0);
            return;
        }else{
            for(auto i = waitlist.begin(); i!= waitlist.end(); ){
                assert(statusmap.count(*i));
                ReqStatus& status = statusmap.at(*i);
                if(status.remotewinsize > 0){
                    status.req_ptr->writedcb(status.req_index);
                    i = waitlist.erase(i);
                }else{
                    i++;
                }
            }
        }
        if (framequeue.empty()) {
            updateEpoll(EPOLLIN);
        }
    }
}


void Proxy2::DataProc(const Http2_header* header) {
    uint32_t id = get32(header->id);
    ssize_t len = get24(header->length);
    if(statusmap.count(id)){
        ReqStatus& status = statusmap[id];
        Requester* requester = status.req_ptr;
        if(len > status.localwinsize){
            Reset(id, ERR_FLOW_CONTROL_ERROR);
            requester->clean(ERR_FLOW_CONTROL_ERROR, status.req_index);
            LOGE("(%s) :[%d] window size error\n", requester->getsrc(), id);
            statusmap.erase(id);
            waitlist.erase(id);
            return;
        }
        requester->Write(header+1, len, status.req_index);
        if(header->flags & END_STREAM_F){
            if(len)
                requester->Write((const void*)nullptr, 0, status.req_index);
        }else{
            status.localwinsize -= len;
        }
    }else{
        Reset(id, ERR_STREAM_CLOSED);
    }
    localwinsize -= len;
}

void Proxy2::ErrProc(int errcode) {
    if (showerrinfo(errcode, "Proxy2 Http2 error")){
        clean(errcode, 0);
    }
}

void Proxy2::RstProc(uint32_t id, uint32_t errcode) {
    if(statusmap.count(id)){
        ReqStatus& status = statusmap[id];
        if(errcode){
            LOGE("(%s) [%d]: stream reseted: %d\n",
                 status.req_ptr->getsrc(), id, errcode);
        }
        status.req_ptr->Write((const void*)nullptr, 0, status.req_index);  //for http/1.0
        status.req_ptr->clean(errcode, status.req_index);
        statusmap.erase(id);
        waitlist.erase(id);
    }
}

void Proxy2::WindowUpdateProc(uint32_t id, uint32_t size){
    if(id){
        if(statusmap.count(id)){
            ReqStatus& status = statusmap[id];
#ifndef NDEBUG
            LOGD(DHTTP2, "window size updated [%d]: %d+%d\n", id, status.remotewinsize, size);
#endif
            status.remotewinsize += size;
            status.req_ptr->writedcb(status.req_index);
            waitlist.erase(id);
#ifndef NDEBUG
        }else{
            LOGD(DHTTP2, "window size updated [%d]: not found\n", id);
#endif
        }
    }else{
#ifndef NDEBUG
        LOGD(DHTTP2, "window size updated global: %d+%d\n", remotewinsize, size);
#endif
        remotewinsize += size;
    }
}

void Proxy2::PingProc(Http2_header *header){
    if(header->flags & ACK_F){
        double diff = (getutime()-get64(header+1))/1000.0;
        LOG("[Proxy2] Get a ping time=%.3fms\n", diff);
        if(diff >= 5000){
            LOGE("[Proxy2] The ping time too long, close it.\n");
            clean(PEER_LOST_ERR, 0);
        }
 
    }
    Http2Base::PingProc(header);
}


void* Proxy2::request(HttpReqHeader&& req) {
    statusmap[curid] = ReqStatus{
       req.src,
       req.index,
       (int32_t)remoteframewindowsize,
       localframewindowsize
    };
    req.index = reinterpret_cast<void*>(curid);  //change to proxy server's id
    curid += 2;
    PushFrame(req.getframe(&request_table, (uint32_t)(long)req.index));
    return req.index;
}

void Proxy2::ResProc(HttpResHeader&& res) {
    uint32_t id = (uint32_t)(long)res.index;
    if(statusmap.count(id)){
        ReqStatus& status = statusmap[id];
        if((res.flags & END_STREAM_F) == 0 &&
           !res.get("Content-Length") &&
           res.status[0] != '1')  //1xx should not have body
        {
            res.add("Transfer-Encoding", "chunked");
        }
        res.index = status.req_index;  //change back to req's id
        status.req_ptr->response(std::move(res));
    }else{
        Reset(id, ERR_STREAM_CLOSED);
    }
}

void Proxy2::AdjustInitalFrameWindowSize(ssize_t diff) {
    for(auto i: statusmap){
       i.second.remotewinsize += diff;
    }
    remotewinsize += diff;
}

void Proxy2::clean(uint32_t errcode, void* index) {
    if(index == nullptr) {
        proxy2 = (proxy2 == this) ? nullptr: proxy2;
        for(auto i: statusmap){
            i.second.req_ptr->clean(errcode, i.second.req_index);
        }
        statusmap.clear();
        return Peer::clean(errcode, 0);
    }else{
        uint32_t id = (uint32_t)(long)index;
        assert(statusmap.count(id));
        Reset(id, errcode>30?ERR_INTERNAL_ERROR:errcode);
        statusmap.erase(id);
        waitlist.erase(id);
    }
}

void Proxy2::wait(void* index) {
    waitlist.insert((uint32_t)(long)index);
}

void Proxy2::writedcb(void* index){
    uint32_t id = (uint32_t)(long)index;
    if(statusmap.count(id)){
        ReqStatus& status = statusmap[id];
        size_t len = localframewindowsize - status.localwinsize;
        if(len < localframewindowsize/5)
            return;
        status.localwinsize += ExpandWindowSize(id, len);
    }
}

void flushproxy2() {
    if(proxy2)
        proxy2 = nullptr;
}
