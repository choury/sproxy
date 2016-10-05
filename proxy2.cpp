#include "proxy2.h"
#include "requester.h"
#include "dtls.h"

Proxy2* proxy2 = nullptr;

void proxy2tick(Proxy2 *p){
    p->check_alive();
}

Proxy2::Proxy2(int fd, SSL_CTX *ctx, Ssl *ssl): ctx(ctx), ssl(ssl) {
    this->fd = fd;
    remotewinsize = remoteframewindowsize;
    localwinsize  = localframewindowsize;
    updateEpoll(EPOLLIN | EPOLLOUT);
    handleEvent = (void (Con::*)(uint32_t))&Proxy2::defaultHE;
    add_tick_func((void (*)(void *))proxy2tick, this);
}

Proxy2::~Proxy2() {
    delete ssl;
    SSL_CTX_free(ctx);
}


ssize_t Proxy2::Read(void* buff, size_t len) {
    return ssl->read(buff, len);
}


ssize_t Proxy2::Write(const void *buff, size_t len) {
    return ssl->write(buff, len);
}

ssize_t Proxy2::Write(void* buff, size_t size, Peer *who, uint32_t id) {
    Requester *requester = dynamic_cast<Requester *>(who);
    if(!id){
        if(idmap.count(requester)){
            id = idmap.at(requester);
        }else{
            who->clean(PEER_LOST_ERR, this);
            return -1;
        }
    }
    size = Min(size, FRAMEBODYLIMIT);
    Http2_header *header=(Http2_header *)p_move(buff, -(char)sizeof(Http2_header));
    memset(header, 0, sizeof(Http2_header));
    set32(header->id, id);
    set24(header->length, size);
    if(size == 0) {
        header->flags = END_STREAM_F;
    }
    SendFrame(header);
    this->remotewinsize -= size;
    who->remotewinsize -= size;
    return size;
}

void Proxy2::SendFrame(Http2_header *header){
    updateEpoll(EPOLLIN | EPOLLOUT);
    return Http2Base::SendFrame(header);
}


int32_t Proxy2::bufleft(Peer* peer) {
    if(peer)
        return Min(peer->remotewinsize, this->remotewinsize);
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
        clean(INTERNAL_ERR, this);
        return;
    }
    if (events & EPOLLIN) {
        (this->*Http2_Proc)();
        if(inited && localwinsize < 50 *1024 *1024){
            localwinsize += ExpandWindowSize(0, 50*1024*1024);
        }
        lastrecv = getmtime();
    }

    if (events & EPOLLOUT) {
        int ret = Write_Proc();
        if(ret <=0 && showerrinfo(ret, "proxy2 write error")) {
            clean(WRITE_ERR, this);
            return;
        }else{
            for(auto i = waitlist.begin(); i!= waitlist.end(); ){
                if(bufleft(*i)){
                    (*i)->writedcb(this);
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
    if(idmap.count(id)){
        Requester *requester = idmap.at(id);
        int32_t len = get24(header->length);
        if(len > requester->localwinsize){
            Reset(id, ERR_FLOW_CONTROL_ERROR);
            idmap.erase(id);
            waitlist.erase(requester);
            requester->clean(ERR_FLOW_CONTROL_ERROR, this, id);
            LOGE("[%d]: window size error\n", id);
            return;
        }
        requester->Write(header+1, len, this, id);
        if(header->flags & END_STREAM_F){
            if(len){
                requester->Write((const void*)nullptr, 0, this, id);
            }
            idmap.erase(id);
            requester->ResetResponser(nullptr);
        }
        requester->localwinsize -= len; 
        localwinsize -= len;
    }else{
        Reset(id, ERR_STREAM_CLOSED);
    }
}

void Proxy2::ErrProc(int errcode) {
    if (errcode > 0){
        LOGE("Proxy2 Http2 error: %d\n", errcode);
        clean(errcode, this);
    }
}

void Proxy2::RstProc(uint32_t id, uint32_t errcode) {
    if(idmap.count(id)){
        Peer *requester = idmap.at(id);
        if(errcode){
            LOGE("Requester reset stream [%d]: %d\n", id, errcode);
        }
        idmap.erase(id);
        waitlist.erase(requester);
        requester->Write((const void*)nullptr, 0, this, id);  //for http/1.0
        requester->clean(errcode, this, id);
    }
}

void Proxy2::WindowUpdateProc(uint32_t id, uint32_t size){
    if(id){
        if(idmap.count(id)){
            Peer *requester = idmap.at(id);
            requester->remotewinsize += size;
            requester->writedcb(this);
            waitlist.erase(requester);
        }
    }else{
        remotewinsize += size;
    }
}

void Proxy2::PingProc(Http2_header *header){
    if(header->flags & ACK_F){
        double diff = (getutime()-get64(header+1))/1000.0;
        LOG("[Proxy2] Get a ping time=%.3fms\n", diff);
        if(diff >= 5000){
            LOGE("[Proxy2] The ping time too long, close it.\n");
            clean(PEER_LOST_ERR, this);
        }
 
    }
    Http2Base::PingProc(header);
}


void Proxy2::request(HttpReqHeader& req) {
    Requester *requester = dynamic_cast<Requester *>(req.src);
    if(requester == nullptr)
        return;
    idmap.erase(requester);
    idmap.insert(requester, curid);
    req.http_id = curid;
    curid += 2;
    requester->remotewinsize = remoteframewindowsize;
    requester->localwinsize = localframewindowsize;
    if(req.ismethod("CONNECT")){
        requester->flag |= ISPERSISTENT_F;
    }
    
    SendFrame(req.getframe(&request_table));
}

void Proxy2::ResProc(HttpResHeader& res) {
    if(idmap.count(res.http_id)){
        Requester *requester = dynamic_cast<Requester *>(idmap.at(res.http_id));
        
        if(requester->flag & ISPERSISTENT_F) {
            if(memcmp(res.status, "200", 4) == 0)
                strcpy(res.status, "200 Connection established");
        }else if((res.flags & END_STREAM_F) == 0 &&
           !res.get("Content-Length"))
        {
            res.add("Transfer-Encoding", "chunked");
        }
        requester->response(res);
    }else{
        Reset(res.http_id, ERR_STREAM_CLOSED);
    }
}

void Proxy2::AdjustInitalFrameWindowSize(ssize_t diff) {
    for(auto i: idmap.Left()){
       i.first->remotewinsize += diff; 
    }
    remotewinsize += diff;
}


void Proxy2::clean(uint32_t errcode, Peer *who, uint32_t) {
    Requester *requester = dynamic_cast<Requester *>(who);
    if(who == this) {
        proxy2 = (proxy2 == this) ? nullptr: proxy2;
        for(auto i: idmap.Left()){
            i.first->clean(errcode, this, i.second);
        }
        idmap.clear();
        del_tick_func((void (*)(void *))proxy2tick, this);
        return Peer::clean(errcode, this);
    }else if(idmap.count(requester)){
        Reset(idmap.at(requester), errcode>30?ERR_INTERNAL_ERROR:errcode);
        idmap.erase(requester);
        waitlist.erase(who);
    }else{
      assert(0);
    }
}

void Proxy2::wait(Peer *who) {
    waitlist.insert(who);
    Peer::wait(who);
}

void Proxy2::writedcb(Peer *who){
    Requester *requester = dynamic_cast<Requester *>(who);
    if(idmap.count(requester)){
        size_t len = localframewindowsize - who->localwinsize;
        if(len < localframewindowsize/5)
            return;
        requester->localwinsize += ExpandWindowSize(idmap.at(requester), len);
    }
}

int Proxy2::showerrinfo(int ret, const char* s) {
    if(errno == EAGAIN){
        return 0;
    }
    LOGE("%s:%m\n", s);
    return 1;
}

void Proxy2::check_alive() {
    Dtls *dtls = dynamic_cast<Dtls*>(ssl);
    if(dtls && dtls->send() < 0){
        clean(PEER_LOST_ERR, this);
        return;
    }
    if(proxy2 && proxy2 != this && idmap.empty()){
        clean(NOERROR, this);
        return;
    }
    if(!lastrecv)
        return;
    uint32_t now = getmtime();
    if(now - lastrecv >= 20000 && now - lastping >= 5000){ //超过20秒就发ping包检测
        char buff[8];
        set64(buff, getutime());
        Ping(buff);
        lastping = now;
    }
    if(now - lastrecv >= 30000){ //超过30秒没收到报文，认为连接断开
        LOGE("[Proxy2] the ping timeout, so close it\n");
        clean(PEER_LOST_ERR, this);
    }
}

void flushproxy2() {
    if(proxy2)
        proxy2 = nullptr;
}
