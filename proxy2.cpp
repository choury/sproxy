#include "proxy2.h"

Proxy2* proxy2 = nullptr;

Proxy2::Proxy2(Proxy *const copy): Proxy(copy) {
    struct epoll_event event;
    event.data.ptr = this;
    event.events = EPOLLIN | EPOLLOUT;
    epoll_ctl(efd, EPOLL_CTL_MOD, fd, &event);
    handleEvent = (void (Con::*)(uint32_t))&Proxy2::defaultHE;
}



ssize_t Proxy2::Read(void* buff, size_t len) {
    return Proxy::Read(buff, len);
}


ssize_t Proxy2::Write(const void *buff, size_t len) {
    return Proxy::Write(buff, len);
}


ssize_t Proxy2::Write(const void* buff, size_t size, Peer *who, uint32_t) {
    Http2_header header;
    memset(&header, 0, sizeof(header));
    Guest *guest = dynamic_cast<Guest*>(who);
    if(idmap.count(guest)){
        set32(header.id, idmap.at(guest));
    }else{
        who->clean(PEER_LOST_ERR, this);
        return -1;
    }
    size = size > FRAMEBODYLIMIT ? FRAMEBODYLIMIT:size;
    set24(header.length, size);
    if(size == 0) {
        header.flags = END_STREAM_F;
    }
    SendFrame(&header, 0);
    int ret = Peer::Write(buff, size, this, get32(header.id));
    this->windowsize -= ret;
    who->windowsize -= ret;
    return ret;
}

Http2_header *Proxy2::SendFrame(const Http2_header *header, size_t addlen){
    struct epoll_event event;
    event.data.ptr = this;
    event.events = EPOLLIN | EPOLLOUT;
    epoll_ctl(efd, EPOLL_CTL_MOD, fd, &event);
    return Http2Base::SendFrame(header, addlen);
}


int32_t Proxy2::bufleft(Peer* peer) {
    int32_t windowsize = Min(peer->windowsize, this->windowsize);
    return Min(windowsize, Peer::bufleft(peer));
}


void Proxy2::defaultHE(u_int32_t events) {
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
        if(windowleft < 50 *1024 *1024){
            windowleft += ExpandWindowSize(0, 50*1024*1024);
        }
        lastrecv = getutime();
    }

    if (events & EPOLLOUT) {
        int ret = Write_Proc(wbuff, writelen);
        if(ret){ 
            for(auto i = waitlist.begin(); i!= waitlist.end(); ){
                if(bufleft(*i)){
                    (*i)->writedcb(this);
                    i = waitlist.erase(i);
                }else{
                    i++;
                }
            }      
        }else if(showerrinfo(ret, "proxy2 write error")) {
            clean(WRITE_ERR, this);
            return;
        }
        if (ret == 2) {
            struct epoll_event event;
            event.data.ptr = this;
            event.events = EPOLLIN;
            epoll_ctl(efd, EPOLL_CTL_MOD, fd, &event);
        }
    }
}


void Proxy2::DataProc(Http2_header* header) {
    uint32_t id = get32(header->id);
    if(idmap.count(id)){
        Guest *guest = idmap.at(id);
        int32_t len = get24(header->length);
        if(len > guest->bufleft(this)){
            Reset(id, ERR_FLOW_CONTROL_ERROR);
            idmap.erase(id);
            waitlist.erase(guest);
            guest->clean(ERR_FLOW_CONTROL_ERROR, this, id);
            LOGE("[%d]: window size error\n", id);
            return;
        }
        if((header->flags & END_STREAM_F) && len) {
            guest->Write("", 0, this, id);
        }else{
            guest->Write(header+1, len, this, id);
        }
        if(header->flags & END_STREAM_F){
            idmap.erase(id);
        }
        guest->windowleft -= len; 
        windowleft -= len;
    }else{
        Reset(id, ERR_STREAM_CLOSED);
    }
}

void Proxy2::ErrProc(int errcode) {
    Proxy::ErrProc(errcode);
}


void Proxy2::RstProc(uint32_t id, uint32_t errcode) {
    if(idmap.count(id)){
        Guest *guest = idmap.at(id);
        if(errcode){
            LOGE("Guest reset stream [%d]: %d\n", id, errcode);
        }
        idmap.erase(id);
        waitlist.erase(guest);
        guest->Write("", 0, this, id);  //for http/1.0
        guest->clean(errcode, this, id);
    }
}

void Proxy2::WindowUpdateProc(uint32_t id, uint32_t size){
    if(id){
        if(idmap.count(id)){
            Guest *guest = idmap.at(id);
            guest->windowsize += size;
            guest->writedcb(this);
            waitlist.erase(guest);
        }
    }else{
        windowsize += size;
    }
}

void Proxy2::PingProc(Http2_header *header){
    if(header->flags & ACK_F){
        double diff = (getutime()-get64(header+1))/1000.0;
        LOG("[Proxy2] Get a ping time=%.3fms\n", diff);
        if(diff >= 20000){
            LOGE("[Proxy2] The ping time too long, close it.");
            clean(PEER_LOST_ERR, this);
        }
 
    }
    Http2Base::PingProc(header);
}


void Proxy2::Request(Guest* guest, HttpReqHeader& req, bool) {
    ::connect(guest, this);
    idmap.erase(guest);
    idmap.insert(guest, curid);
    req.http_id = curid;
    curid += 2;
    guest->windowsize = initalframewindowsize;
    guest->windowleft = 512 *1024;
    if(req.ismethod("CONNECT")){
        guest->flag = ISCONNECT_F;
    }else{
        guest->flag = 0;
    }
    
    char buff[FRAMELENLIMIT];
    SendFrame((Http2_header *)buff, req.getframe(buff, &request_table));
}

void Proxy2::ResProc(HttpResHeader& res) {
    if(idmap.count(res.http_id)){
        Guest *guest = idmap.at(res.http_id);
        
        if(guest->flag & ISCONNECT_F) {
            strcpy(res.status, "200 Connection established");
        }else if(!res.get("Content-Length")){
            res.add("Transfer-Encoding", "chunked");
        }
        guest->Response(res, this);
    }else{
        Reset(res.http_id, ERR_STREAM_CLOSED);
    }
}

void Proxy2::AdjustInitalFrameWindowSize(ssize_t diff) {
    for(auto&& i: idmap.pairs()){
       i.first->windowsize += diff; 
    }

}


void Proxy2::clean(uint32_t errcode, Peer *who, uint32_t) {
    Guest *guest = dynamic_cast<Guest*>(who);
    if(who == this) {
        proxy2 = (proxy2 == this) ? nullptr: proxy2;
        return Peer::clean(errcode, this);
    }else if(idmap.count(guest)){
        Reset(idmap.at(guest), errcode>30?ERR_INTERNAL_ERROR:errcode);
        idmap.erase(guest);
    }
    disconnect(guest, this);
	waitlist.erase(who);
}

void Proxy2::wait(Peer *who) {
    waitlist.insert(who);
    Peer::wait(who);
}

void Proxy2::writedcb(Peer *who){
    Guest *guest = dynamic_cast<Guest*>(who);
    if(idmap.count(guest)){
        if(guest->bufleft(this) > 512*1024){
            size_t len = Min(512*1024 - guest->windowleft, guest->bufleft(this) - 512*1024);
            if(len < 10240)
                return;
            guest->windowleft += ExpandWindowSize(idmap.at(guest), len);
        }
    }
}


int Proxy2::showstatus(char *buff, Peer *who){
    Guest *guest = dynamic_cast<Guest*>(who);
    int len = 0;
    if(guest){
        if(idmap.count(guest)){
            len =sprintf(buff, "id:[%u] buffleft(%d) windowsize :%d, windowleft: %d #(proxy2)\n",
                    idmap.at(guest), guest->bufleft(this),
                    guest->windowsize, guest->windowleft);
        }else{
            len =sprintf(buff, "null #(proxy2)\n");
        }
    }
    return len;
}

void Proxy2::Pingcheck() {
    if(!lastrecv)
        return;
    uint64_t now = getutime();
    if(now - lastrecv >= 10000000 && now - lastping >= 5000000){ //超过10秒就发ping包检测
        char buff[8];
        set64(buff, now);
        Ping(buff);
        lastping = now;
    }
    if(now - lastrecv >= 20000000){ //超过20秒没收到报文，认为链接断开
        LOGE("[Proxy2] the ping timeout, so close it\n");
        clean(PEER_LOST_ERR, this);
    }
}


void proxy2tick() {
    if(proxy2){
        proxy2->Pingcheck();
    }
}

