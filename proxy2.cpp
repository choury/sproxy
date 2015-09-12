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


ssize_t Proxy2::Write(Peer* who, const void* buff, size_t size) {
    Http2_header header;
    memset(&header, 0, sizeof(header));
    Guest *guest = dynamic_cast<Guest*>(who);
    if(idmap.left.count(guest)){
        set32(header.id, idmap.left.find(guest)->second);
    }else{
        who->clean(this, PEER_LOST_ERR);
        return -1;
    }
    size = size > FRAMEBODYLIMIT ? FRAMEBODYLIMIT:size;
    set24(header.length, size);
    if(size == 0) {
        header.flags = END_STREAM_F;
    }
    SendFrame(&header, 0);
    int ret = Peer::Write(who, buff, size);
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
        clean(this, INTERNAL_ERR);
        return;
    }
    
    if (events & EPOLLIN) {
        (this->*Http2_Proc)();
        if(windowleft < 50 *1024 *1024){
            windowleft += ExpandWindowSize(0, 50*1024*1024);
        }
    }

    if (events & EPOLLOUT) {
        int ret = Write_Proc(wbuff, writelen);
        if (ret <= 0 && showerrinfo(ret, "proxy2 write error")) {
            clean(this, WRITE_ERR);
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
    if(idmap.right.count(id)){
        Guest *guest = idmap.right.find(id)->second;
        int32_t len = get24(header->length);
        if(len > guest->bufleft(this)){
            Reset(id, ERR_FLOW_CONTROL_ERROR);
            idmap.right.erase(id);
            guest->clean(this, ERR_FLOW_CONTROL_ERROR);
            return;
        }
        if(guest->flag & ISCHUNKED_F){
            char chunkbuf[100];
            int chunklen;
            snprintf(chunkbuf, sizeof(chunkbuf), "%x" CRLF "%n", (uint32_t)get24(header->length), &chunklen);
            guest->Write(this, chunkbuf, chunklen);
            guest->Write(this, header+1, get24(header->length));
            guest->Write(this, CRLF, strlen(CRLF));
            
            if((header->flags & END_STREAM_F) && get24(header->length)) {
                guest->Write(this, CHUNCKEND, strlen(CHUNCKEND));
            }
        }else{
            guest->Write(this, header+1, get24(header->length));
        }
        if(header->flags & END_STREAM_F){
            guest->flag |= ISCLOSED_F;
            idmap.right.erase(id);
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
    if(idmap.right.count(id)){
        Guest *guest = idmap.right.find(id)->second;
        idmap.right.erase(id);
        if(errcode){
            LOGE("Guest reset stream [%d]: %d\n", id, errcode);
        }else if((guest->flag & ISCHUNKED_F) && (guest->flag & ISCLOSED_F) == 0){ //for http/1.0
            guest->Write(this, CHUNCKEND, strlen(CHUNCKEND));
        }
        guest->clean(this, errcode);
    }
}

void Proxy2::WindowUpdateProc(uint32_t id, uint32_t size){
    if(id){
        if(idmap.right.count(id)){
            Guest *guest = idmap.right.find(id)->second;
            guest->windowsize += size;
            guest->writedcb(this);
            waitlist.erase(guest);
        }
    }else{
        windowsize += size;
    }
}


void Proxy2::Request(Guest* guest, HttpReqHeader& req, bool) {
    ::connect(guest, this);
    idmap.insert(decltype(idmap)::value_type(guest, curid));
    req.id = curid;
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
    if(idmap.right.count(res.id)){
        Guest *guest = idmap.right.find(res.id)->second;
        
        if(guest->flag & ISCONNECT_F) {
            strcpy(res.status, "200 Connection established");
        }else if(!res.get("Content-Length")){
            guest->flag |= ISCHUNKED_F;
            res.add("Transfer-Encoding", "chunked");
        }
        guest->Response(this, res);
    }else{
        Reset(res.id, ERR_STREAM_CLOSED);
    }
}

void Proxy2::AdjustInitalFrameWindowSize(ssize_t diff) {
    for(auto i: idmap.left){
       i.first->windowsize += diff; 
    }

}


void Proxy2::clean(Peer* who, uint32_t errcode) {
    Guest *guest = dynamic_cast<Guest*>(who);
    if(who == this) {
        proxy2 = (proxy2 == this) ? nullptr: proxy2;
        Peer::clean(who, errcode);
    }else if(idmap.left.count(guest)){
        Reset(idmap.left.find(guest)->second, errcode>30?ERR_INTERNAL_ERROR:errcode);
        idmap.left.erase(guest);
    }
	waitlist.erase(who);
}

void Proxy2::wait(Peer *who) {
    waitlist.insert(who);
    Peer::wait(who);
}

void Proxy2::writedcb(Peer *who){
    Guest *guest = dynamic_cast<Guest*>(who);
    if(idmap.left.count(guest)){
        if(guest->bufleft(this) > 512*1024){
            size_t len = Min(512*1024 - guest->windowleft, guest->bufleft(this) - 512*1024);
            guest->windowleft += ExpandWindowSize(idmap.left.find(guest)->second, len);
        }
    }else{
        who->clean(this, PEER_LOST_ERR);
    }
}


int Proxy2::showstatus(Peer *who, char *buff){
    Guest *guest = dynamic_cast<Guest*>(who);
    int len = 0;
    if(guest){
        if(idmap.left.count(guest)){
            sprintf(buff, "id:[%u] buffleft(%d) windowsize :%d, windowleft: %d #(proxy2)\n%n",
                    idmap.left.find(guest)->second, guest->bufleft(this),
                    guest->windowsize, guest->windowleft, &len);
        }else{
            sprintf(buff, "null #(proxy2)\n%n", &len);
        }
    }else{
        int wlen;
        sprintf(buff, "Proxy2 buffleft(%d): windowsize: %d, windowleft: %d\n"
                      "waitlist: \n%n",
                       (int32_t)(sizeof(wbuff)-writelen), windowsize, windowleft, &wlen);
        len+= wlen;
        for(auto i:waitlist){
            sprintf(buff+len, "[%d] buffleft(%d): windowsize: %d, windowleft: %d\r\n%n",
                    idmap.left.find(static_cast<Guest *>(i))->second, i->bufleft(this),
                    i->windowsize, i->windowleft, &wlen);
        }
    }
    return len;
}

