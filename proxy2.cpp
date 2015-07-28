#include "proxy2.h"

Proxy2* proxy2 = nullptr;

Proxy2::Proxy2(int fd, SSL* ssl, SSL_CTX* ctx): Proxy(fd, ssl, ctx) {
    struct epoll_event event;
    event.data.ptr = this;
    event.events = EPOLLIN | EPOLLOUT;
    epoll_ctl(efd, EPOLL_CTL_MOD, fd, &event);
    handleEvent = (void (Con::*)(uint32_t))&Proxy2::defaultHE;
}



ssize_t Proxy2::Read(void* buff, size_t len) {
    return Proxy::Read(buff, len);
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
    Peer::Write(who, &header, sizeof(header));
    return Peer::Write(who, buff, size);
}


ssize_t Proxy2::Write2(const void* buff, size_t len) {
    return Peer::Write(this, buff, len);
}

size_t Proxy2::bufleft(Peer*) {
    if(sizeof(wbuff) - writelen < FRAMELENLIMIT){
        return 0;
    }else{
        return sizeof(wbuff) -writelen - FRAMELENLIMIT;
    }
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
    }

    if (events & EPOLLOUT) {
        if (writelen) {
            int ret = Proxy::Write();
            if (ret <= 0) {
                if (showerrinfo(ret, "proxy2 write error")) {
                    clean(this, WRITE_ERR);
                }
                return;
            }
        }
        if (writelen == 0) {
            struct epoll_event event;
            event.data.ptr = this;
            event.events = EPOLLIN;
            epoll_ctl(efd, EPOLL_CTL_MOD, fd, &event);
        }
    }
}


void Proxy2::DataProc2(Http2_header* header) {
    uint32_t id = get32(header->id);
    if(idmap.right.count(id)){
        Guest *guest = idmap.right.find(id)->second;
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
    }else{
        Reset(id, ERR_STREAM_CLOSED);
    }
}

void Proxy2::ErrProc(int errcode) {
    Proxy::ErrProc(errcode);
}


void Proxy2::RstProc(Http2_header* header) {
    uint32_t id = get32(header->id);
    uint32_t code = get32(header+1);
    if(idmap.right.count(id)){
        Guest *guest = idmap.right.find(id)->second;
        idmap.right.erase(id);
        if(code){
            LOGE("Guest reset stream [%d]: %d\n", id, code);
        }else if((guest->flag & ISCHUNKED_F) && (guest->flag & ISCLOSED_F) == 0){ //for http/1.0
            guest->Write(this, CHUNCKEND, strlen(CHUNCKEND));
        }
        guest->clean(this, code);
    }
}


void Proxy2::Request(Guest* guest, HttpReqHeader& req, bool) {
    ::connect(guest, this);
    idmap.insert(decltype(idmap)::value_type(guest, curid));
    req.id = curid;
    writelen+= req.getframe(wbuff+writelen, &request_table);
    struct epoll_event event;
    event.data.ptr = this;
    event.events = EPOLLIN | EPOLLOUT;
    epoll_ctl(efd, EPOLL_CTL_MOD, fd, &event);
    curid += 2;
    guest->flag = 0;
    
    if(req.ismethod("CONNECT")){
        guest->flag = ISCONNECT_F;
    }
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

void Proxy2::clean(Peer* who, uint32_t errcode) {
    Guest *guest = dynamic_cast<Guest*>(who);
    if(who == this) {
        proxy2 = nullptr;
        Peer::clean(who, errcode);
    }else if(idmap.left.count(guest)){
        Reset(idmap.left.find(guest)->second, errcode>30?ERR_INTERNAL_ERROR:errcode);
        idmap.left.erase(guest);
    }
}


