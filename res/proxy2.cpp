#include "proxy2.h"
#include "req/requester.h"
#include "misc/job.h"


Proxy2* proxy2 = nullptr;


int Proxy2::connection_lost(Proxy2 *p){
    LOGE("[Proxy2] %p the ping timeout, so close it\n", p);
    p->deleteLater(PEER_LOST_ERR);
    return 0;
}

int Proxy2::ping_check(Proxy2 *p){
    char buff[8];
    set64(buff, getutime());
    p->Ping(buff);
    LOGD(DHTTP2, "window size global: %d/%d\n", p->localwinsize, p->remotewinsize);
    add_delayjob((job_func)connection_lost, p, 3000);
    return 0;
}


Proxy2::Proxy2(int fd, SSL_CTX *ctx, Ssl *ssl): ctx(ctx), ssl(ssl) {
    this->fd = fd;
    updateEpoll(EPOLLIN | EPOLLOUT);
    handleEvent = (void (Con::*)(uint32_t))&Proxy2::defaultHE;
#ifdef __ANDROID__
    receive_time = getmtime();
    ping_time = getmtime();
#endif
}

Proxy2::~Proxy2() {
    delete ssl;
    SSL_CTX_free(ctx);
    del_delayjob((job_func)ping_check, this);
    del_delayjob((job_func)connection_lost, this);
    proxy2 = (proxy2 == this) ? nullptr: proxy2;
}


ssize_t Proxy2::Read(void* buff, size_t len) {
    auto ret = ssl->read(buff, len);
    if(ret > 0){
#ifndef __ANDROID__
        add_delayjob((job_func)ping_check, this, 30000);
#else
        receive_time = getmtime();
#endif
    }
    return ret;
}


ssize_t Proxy2::Write(const void *buff, size_t len) {
    return ssl->write(buff, len);
}

int32_t Proxy2::bufleft(void* index) {
    int32_t globalwindow = Min(1024*1024 - (int32_t)framelen, this->remotewinsize);
    if(index)
        return Min(statusmap.at((uint32_t)(long)index).remotewinsize, globalwindow);
    else
        return globalwindow;
}


ssize_t Proxy2::Send(void* buff, size_t size, void* index) {
    uint32_t id = (uint32_t)(long)index;
    assert(statusmap.count(id));
    assert((statusmap[id].req_flags & STREAM_WRITE_CLOSED) == 0);
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
#ifdef __ANDROID__
    uint32_t now = getmtime();
    if(now - receive_time >=30000 && now - ping_time >=5000){
        ping_time = now;
        ping_check(this);
    }
#endif
    return Http2Base::PushFrame(header);
}

void Proxy2::defaultHE(uint32_t events) {
    if (events & EPOLLERR || events & EPOLLHUP) {
        int       error = 0;
        socklen_t errlen = sizeof(error);

        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, (void*)&error, &errlen) == 0) {
            LOGE("proxy2 error: %s\n", strerror(error));
        }
        deleteLater(INTERNAL_ERR);
        return;
    }

    if (events & EPOLLOUT) {
        if(framelen >= 1024*1024){
            LOGD(DHTTP2, "active all frame because of framelen\n");
            for(auto i: statusmap){
                ReqStatus& status = i.second;
                if(status.remotewinsize > 0){
                    status.req_ptr->writedcb(status.req_index);
                }
            }
        }
        int ret = SendFrame();
        if(ret < 0 && showerrinfo(ret, "proxy2 write error")) {
            deleteLater(WRITE_ERR);
            return;
        }
        if(framequeue.empty()){
            updateEpoll(this->events & ~EPOLLOUT);
        }
    }
    
    if (events & EPOLLIN) {
        (this->*Http2_Proc)();
        if((http2_flag & HTTP2_FLAG_INITED)  && localwinsize < 50 *1024 *1024){
            localwinsize += ExpandWindowSize(0, 50*1024*1024);
        }
    }
    
    if(proxy2 != this && statusmap.empty()){
        LOG("this is not the proxy2 and no clients, close it.\n");
        deleteLater(PEER_LOST_ERR);
    }
}

void Proxy2::closeHE(uint32_t events) {
    int ret = SendFrame();
    if (framequeue.empty() ||
        (ret <= 0 && showerrinfo(ret, "write error while closing"))) {
        delete this;
        return;
    }
}


void Proxy2::ResProc(HttpResHeader* res) {
    uint32_t id = (uint32_t)(long)res->index;
    if(statusmap.count(id)){
        ReqStatus& status = statusmap[id];
        if(!res->no_body() && res->status[0] != '1' &&  //1xx should not have body
           !res->get("Content-Length"))
        {
            res->add("Transfer-Encoding", "chunked");
        }
        res->index = status.req_index;  //change back to req's id
        status.req_ptr->response(res);
    }else{
        delete res;
        Reset(id, ERR_STREAM_CLOSED);
    }
}


void Proxy2::DataProc(uint32_t id, const void* data, size_t len) {
    if( len == 0)
        return;
    if(statusmap.count(id)){
        ReqStatus& status = statusmap[id];
        Requester* requester = status.req_ptr;
        if(len > (size_t)status.localwinsize){
            Reset(id, ERR_FLOW_CONTROL_ERROR);
            LOGE("(%s) :[%d] window size error\n", requester->getsrc(status.req_index), id);
            requester->finish(ERR_FLOW_CONTROL_ERROR, status.req_index);
            statusmap.erase(id);
            return;
        }
        requester->Send(data, len, status.req_index);
        status.localwinsize -= len;
    }
    localwinsize -= len;
}

void Proxy2::EndProc(uint32_t id){
    if(statusmap.count(id)) {
        ReqStatus &status = statusmap[id];
        if(status.req_flags & STREAM_WRITE_CLOSED){
            status.req_ptr->finish(NOERROR | DISCONNECT_FLAG, status.req_index);
            statusmap.erase(id);
        }else{
            status.req_ptr->finish(NOERROR, status.req_index);
            status.req_flags |= STREAM_READ_CLOSED;
        }
    }
}


void Proxy2::ErrProc(int errcode) {
    if (showerrinfo(errcode, "Proxy2 Http2 error")){
        if(errcode > ERR_HTTP_1_1_REQUIRED){
            deleteLater(ERR_INTERNAL_ERROR);
        }else if(errcode == 0){
            deleteLater(PEER_LOST_ERR);
        }else{
            deleteLater(errcode);
        }
    }
}

void Proxy2::RstProc(uint32_t id, uint32_t errcode) {
    if(statusmap.count(id)){
        ReqStatus& status = statusmap[id];
        if(errcode){
            LOGE("(%s) [%d]: stream reseted: %d\n",
                 status.req_ptr->getsrc(status.req_index), id, errcode);
        }
        status.req_ptr->finish(errcode?errcode:PEER_LOST_ERR, status.req_index);
        statusmap.erase(id);
    }
}

void Proxy2::WindowUpdateProc(uint32_t id, uint32_t size){
    if(id){
        if(statusmap.count(id)){
            ReqStatus& status = statusmap[id];
            LOGD(DHTTP2, "window size updated [%d]: %d+%d\n", id, status.remotewinsize, size);
            if((uint64_t)status.remotewinsize + size >= (uint64_t)1<<31){
                Reset(id, ERR_FLOW_CONTROL_ERROR);
                return;
            }
            status.remotewinsize += size;
            status.req_ptr->writedcb(status.req_index);
        }else{
            LOGD(DHTTP2, "window size updated [%d]: not found\n", id);
        }
    }else{
        LOGD(DHTTP2, "window size updated global: %d+%d\n", remotewinsize, size);
        if((uint64_t)remotewinsize + size >= (uint64_t)1<<31){
            ErrProc(ERR_FLOW_CONTROL_ERROR);
            return;
        }
        remotewinsize += size;
        if(remotewinsize == (int32_t)size){
            LOGD(DHTTP2, "active all frame\n");
            for(auto i: statusmap){
                ReqStatus& status = i.second;
                if(status.remotewinsize > 0){
                    status.req_ptr->writedcb(status.req_index);
                }
            }
        }
    }
}

void Proxy2::PingProc(Http2_header *header){
    if(header->flags & ACK_F){
        del_delayjob((job_func)connection_lost, this);
        double diff = (getutime()-get64(header+1))/1000.0;
        LOG("[Proxy2] Get a ping time=%.3fms\n", diff);
        if(diff >= 5000){
            LOGE("[Proxy2] The ping time too long!\n");
        }
    }
    Http2Base::PingProc(header);
}


void* Proxy2::request(HttpReqHeader* req) {
    assert(req->src && req->index);
    uint32_t id = GetSendId();
    statusmap[id] = ReqStatus{
       req->src,
       req->index,
       (int32_t)remoteframewindowsize,
       localframewindowsize,
       0,
    };
    void *index =reinterpret_cast<void*>(id);  //change to proxy server's id
    req->index = index;
    PushFrame(req->getframe(&request_table, (uint32_t)(long)index));
    delete req;
    return index;
}


void Proxy2::GoawayProc(Http2_header* header){
    Goaway_Frame* goaway = (Goaway_Frame *)(header+1);
    uint32_t errcode = get32(goaway->errcode);
    errcode = errcode ? errcode:PEER_LOST_ERR;
    proxy2 = (proxy2 == this) ? nullptr: proxy2;
    for(auto i: statusmap){
        i.second.req_ptr->finish(errcode, i.second.req_index);
    }
    statusmap.clear();
    return Peer::deleteLater(errcode);
}


void Proxy2::AdjustInitalFrameWindowSize(ssize_t diff) {
    for(auto i: statusmap){
       i.second.remotewinsize += diff;
    }
}

bool Proxy2::finish(uint32_t flags, void* index) {
    uint32_t id = (uint32_t)(long)index;
    assert(statusmap.count(id));
    ReqStatus& status = statusmap[id];
    uint8_t errcode = flags & ERROR_MASK;
    if(errcode == VPN_AGED_ERR){
        status.req_ptr->finish(errcode, status.req_index);
        Reset(id, ERR_CANCEL);
        statusmap.erase(id);
        return false;
    }
    if(errcode == 0 && (status.req_flags & STREAM_WRITE_CLOSED) == 0){
        Peer::Send((const void*)nullptr, 0, index);
        status.req_flags |= STREAM_WRITE_CLOSED;
    }
    if(status.req_flags & STREAM_READ_CLOSED){
        statusmap.erase(id);
        return false;
    }
    if(errcode || (flags & DISCONNECT_FLAG)){
        Reset(id, errcode>30?ERR_INTERNAL_ERROR:errcode);
        statusmap.erase(id);
        return false;
    }
    return true;
}

void Proxy2::deleteLater(uint32_t errcode){
    proxy2 = (proxy2 == this) ? nullptr: proxy2;
    for(auto i: statusmap){
        i.second.req_ptr->finish(errcode, i.second.req_index);
    }
    statusmap.clear();
    if((http2_flag & HTTP2_FLAG_GOAWAYED) == 0){
        http2_flag |= HTTP2_FLAG_GOAWAYED;
        Goaway(-1, errcode);
    }
    return Peer::deleteLater(errcode);
}


void Proxy2::writedcb(void* index){
    uint32_t id = (uint32_t)(long)index;
    if(statusmap.count(id)){
        ReqStatus& status = statusmap[id];
        auto len = status.req_ptr->bufleft(status.req_index);
        if(len <= status.localwinsize ||
           (len - status.localwinsize < FRAMEBODYLIMIT &&
            status.localwinsize >= FRAMEBODYLIMIT))
            return;
        status.localwinsize += ExpandWindowSize(id, len - status.localwinsize);
    }
}

void Proxy2::dump_stat() {
    LOG("Proxy2 %p, id:%d: %s\n", this, sendid, this==proxy2?"[M]":"");
    for(auto i: statusmap){
        LOG("0x%x: %p, %p (%d/%d)\n",
            i.first, i.second.req_ptr, i.second.req_index,
            i.second.remotewinsize, i.second.localwinsize);
    }
}

void flushproxy2() {
    if(proxy2)
        proxy2 = nullptr;
}
