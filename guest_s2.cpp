#include "guest_s2.h"
#include "host.h"
#include "file.h"
#include "cgi.h"

#include <limits.h>

Guest_s2::Guest_s2(Guest_s *const copy): Guest_s(copy) {
    struct epoll_event event;
    event.data.ptr = this;
    event.events = EPOLLIN | EPOLLOUT;
    epoll_ctl(efd, EPOLL_CTL_MOD, fd, &event);
    handleEvent = (void (Con::*)(uint32_t))&Guest_s2::defaultHE;
}


ssize_t Guest_s2::Read(void *buff, size_t size) {
    return Guest_s::Read(buff, size);
}


ssize_t Guest_s2::Write(const void *buff, size_t size) {
    return Guest_s::Write(buff, size);
}


ssize_t Guest_s2::Write(const void *buff, size_t size, Peer *who, uint32_t id)
{
    if(!id){
        if(idmap.count(who)){
            id = idmap.at(who);
        }else{
            who->clean(PEER_LOST_ERR, this);
            return -1;
        }
    }
    size = Min(size, FRAMEBODYLIMIT);
    Http2_header *header=(Http2_header *)malloc(sizeof(Http2_header)+size);
    memset(header, 0, sizeof(Http2_header));
    set32(header->id, id);
    set24(header->length, size);
    if(size == 0) {
        header->flags = END_STREAM_F;
        idmap.erase(who);
        waitlist.erase(who);
        who->clean(NOERROR, this, id);
    }
    memcpy(header+1, buff, size);
    SendFrame(header);
    this->remotewinsize -= size;
    who->remotewinsize -= size;
    return size;
}



void Guest_s2::SendFrame(Http2_header *header) {
    struct epoll_event event;
    event.data.ptr = this;
    event.events = EPOLLIN | EPOLLOUT;
    epoll_ctl(efd, EPOLL_CTL_MOD, fd, &event);
    return Http2Res::SendFrame(header);
}


void Guest_s2::DataProc(Http2_header* header) {
    uint32_t id = get32(header->id);
    if(idmap.count(id)){
        Peer *host = idmap.at(id);
        ssize_t len = get24(header->length);
        if(len > host->bufleft(this)){
            Reset(id, ERR_FLOW_CONTROL_ERROR);
            idmap.erase(id);
            waitlist.erase(host);
            host->clean(ERR_FLOW_CONTROL_ERROR, this, id);
            LOGE("(%s:[%d]):[%d] window size error\n", sourceip, sourceport, id);
            return;
        }
        host->Write((const void *)(header+1), len, this, id);
        host->localwinsize -= len;
        localwinsize -= len;
    }else{
        Reset(get32(header->id), ERR_STREAM_CLOSED);
    }
}

void Guest_s2::ReqProc(HttpReqHeader &req)
{
    LOG("([%s]:%d):[%d] %s %s\n", sourceip, sourceport, req.http_id, req.method, req.url);
    Peer *peer;
    if(!checklocal(req.hostname)){
        peer = new Host(req, this);
    }else {
        req.getfile();
        if (endwith(req.filename,".so")) {
            peer = Cgi::getcgi(req, this);
        } else {
            peer = File::getfile(req,this);
        }
    }
    peer->remotewinsize = remoteframewindowsize;
    peer->localwinsize = localframewindowsize;
    idmap.insert(peer, req.http_id);
}



void Guest_s2::Response(HttpResHeader &res, Peer *who)
{
    if(res.http_id == 0){
        if(idmap.count(who)){
            res.http_id = idmap.at(who);
        }else{
            who->clean(PEER_LOST_ERR, who);
            return;
        }
    }
    res.del("Transfer-Encoding");
    res.del("Connection");
    SendFrame(res.getframe(&request_table));
}


void Guest_s2::defaultHE(uint32_t events)
{
    if (events & EPOLLERR || events & EPOLLHUP) {
        int       error = 0;
        socklen_t errlen = sizeof(error);

        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, (void*)&error, &errlen) == 0) {
            LOGE("([%s]:%d): guest_s error:%s\n",
                  sourceip, sourceport, strerror(error));
        }
        clean(INTERNAL_ERR, this);
        return;
    }
    
    if (events & EPOLLIN) {
        (this->*Http2_Proc)();
        if(localwinsize < 50 *1024 *1024){
            localwinsize += ExpandWindowSize(0, 50*1024*1024);
        }
    }

    if (events & EPOLLOUT) {
        int ret = Write_Proc();
        if(ret){ 
            for(auto i = waitlist.begin(); i!= waitlist.end(); ){
                if(bufleft(*i)){
                    (*i)->writedcb(this);
                    i = waitlist.erase(i);
                }else{
                    i++;
                }
            }      
        }else if(ret <= 0 && showerrinfo(ret, "guest_s2 write error")) {
            clean(WRITE_ERR, this);
            return;
        }

        if (framequeue.empty()) {
            struct epoll_event event;
            event.data.ptr = this;
            event.events = EPOLLIN;
            epoll_ctl(efd, EPOLL_CTL_MOD, fd, &event);
        }
    }
}


void Guest_s2::RstProc(uint32_t id, uint32_t errcode) {
    if(idmap.count(id)){
        if(errcode)
            LOGE("([%s]:%d): reset stream [%d]: %d\n", sourceip, sourceport, id, errcode);
        Peer *who = idmap.at(id);
        idmap.erase(id);
        waitlist.erase(who);
        who->clean(errcode, this, id);
    }
}


void Guest_s2::WindowUpdateProc(uint32_t id, uint32_t size) {
    if(id){
        if(idmap.count(id)){
            Peer *peer = idmap.at(id);
            peer->remotewinsize += size;
            peer->writedcb(this);
            waitlist.erase(peer);
        }
    }else{
        remotewinsize += size;
    }
}


void Guest_s2::GoawayProc(Http2_header* header) {
    clean(get32(header+1), this);
}

void Guest_s2::ErrProc(int errcode) {
    Guest::ErrProc(errcode);
}

void Guest_s2::AdjustInitalFrameWindowSize(ssize_t diff) {
    for(auto&& i: idmap.pairs()){
       i.first->remotewinsize += diff; 
    }
}

void Guest_s2::clean(uint32_t errcode, Peer *who, uint32_t id) {
    if(who == this) {
        return Peer::clean(errcode, this);
    }
    if(id == 0 && idmap.count(who)){
        id = idmap.at(who);
    }
    if(id){
        Reset(id, errcode>30?ERR_INTERNAL_ERROR:errcode);
        idmap.erase(who, id);
    }
    disconnect(this, who);
    waitlist.erase(who);
}

int32_t Guest_s2::bufleft(Peer *peer) {
    if(peer)
        return Min(peer->remotewinsize, this->remotewinsize);
    else
        return this->remotewinsize;
}

void Guest_s2::wait(Peer *who){
    waitlist.insert(who);
    Peer::wait(who);
}

void Guest_s2::writedcb(Peer *who){
    if(idmap.count(who)){
        size_t len = localframewindowsize - who->localwinsize;
        if(len < localframewindowsize/2)
            return;
        who->localwinsize += ExpandWindowSize(idmap.at(who), len);
    }
}

/*
int Guest_s2::showstatus(char *buff, Peer *who) {
    int wlen,len=0;
    sprintf(buff, "Guest_s2([%s]:%d) buffleft:%d: remotewinsize: %d, localwinsize: %d\n%n",
                   sourceip, sourceport, (int32_t)(sizeof(wbuff)-writelen), remotewinsize, localwinsize, &wlen);
    len += wlen;
    for(auto&& i: idmap.pairs()){
        Peer *peer = i.first;
        sprintf(buff+len,"[%d] buffleft:%d: remotewinsize: %d, localwinsize:%d : %n",
                i.second, peer->bufleft(this), peer->remotewinsize, peer->localwinsize, &wlen);
        len += wlen;
        len += i.first->showstatus(buff+len, this);
    }
    sprintf(buff+len, "waitlist:\r\n%n", &wlen);
    len += wlen;
    for(auto i:waitlist){
        sprintf(buff+len, "[%d] buffleft(%d): remotewinsize: %d, localwinsize: %d\r\n%n",
                idmap.at(i), i->bufleft(this),
                i->remotewinsize, i->localwinsize, &wlen);
        len += wlen;
    }
    sprintf(buff+len, "\r\n%n", &wlen);
    len += wlen;
    return len;
}
*/
