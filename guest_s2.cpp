#include "guest_s2.h"
#include "responser.h"

#include <limits.h>

void guest2tick(Guest_s2 *g){
    g->check_alive();
}

Guest_s2::Guest_s2(int fd, const char* ip, uint16_t port, Ssl* ssl):
        Requester(fd, ip, port), ssl(ssl)
{
    remotewinsize = remoteframewindowsize;
    localwinsize  = localframewindowsize;
    updateEpoll(EPOLLIN | EPOLLOUT);
    handleEvent = (void (Con::*)(uint32_t))&Guest_s2::defaultHE;
    last_interactive = getmtime();
    add_tick_func((void (*)(void *))guest2tick, this);
}

Guest_s2::Guest_s2(int fd, struct sockaddr_in6* myaddr, Ssl* ssl):
        Requester(fd, myaddr),ssl(ssl)
{
    remotewinsize = remoteframewindowsize;
    localwinsize  = localframewindowsize;
    updateEpoll(EPOLLIN | EPOLLOUT);
    handleEvent = (void (Con::*)(uint32_t))&Guest_s2::defaultHE;
    last_interactive = getmtime();
    add_tick_func((void (*)(void *))guest2tick, this);
}

Guest_s2::~Guest_s2() {
    delete ssl;
}


ssize_t Guest_s2::Read(void *buff, size_t size) {
    return ssl->read(buff, size);
}

ssize_t Guest_s2::Write(const void *buff, size_t size) {
    return ssl->write(buff, size);
}

ssize_t Guest_s2::Write(void *buff, size_t size, Peer *who, uint32_t id) {
    Responser* responser = dynamic_cast<Responser *>(who);
    if(!id){
        if(idmap.count(responser)){
            id = idmap.at(responser);
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
//        idmap.erase(responser);
//        waitlist.erase(who);
//        who->clean(NOERROR, this, id);
    }
    SendFrame(header);
    this->remotewinsize -= size;
    who->remotewinsize -= size;
    return size;
}

void Guest_s2::SendFrame(Http2_header *header) {
    updateEpoll(EPOLLIN | EPOLLOUT);
    return Http2Res::SendFrame(header);
}

void Guest_s2::DataProc(const Http2_header* header)
{
    uint32_t id = get32(header->id);
    if(idmap.count(id)){
        Responser *host = idmap.at(id);
        ssize_t len = get24(header->length);
        if(len > host->localwinsize){
            Reset(id, ERR_FLOW_CONTROL_ERROR);
            idmap.erase(id);
            waitlist.erase(host);
            host->clean(ERR_FLOW_CONTROL_ERROR, this, id);
            LOGE("(%s):[%d] window size error\n", getsrc(), id);
            return;
        }
        host->Write(header+1, len, this, id);
        if((header->flags & END_STREAM_F) && len != 0){
            host->Write((const void*)nullptr, 0, this, id);
            host->ResetRequester(nullptr);
        }
        host->localwinsize -= len;
        localwinsize -= len;
    }else{
        Reset(get32(header->id), ERR_STREAM_CLOSED);
    }
}

void Guest_s2::ReqProc(HttpReqHeader &req)
{
    Responser *responser = distribute(req, nullptr);
    if(responser){
        responser->remotewinsize = remoteframewindowsize;
        responser->localwinsize = localframewindowsize;
        idmap.insert(responser, req.http_id);
    }
}

void Guest_s2::response(HttpResHeader &res) {
    Responser *responser = dynamic_cast<Responser *>(res.src);
    if(res.http_id == 0){
        if(idmap.count(responser)){
            res.http_id = idmap.at(responser);
        }else{
            responser->clean(PEER_LOST_ERR, this);
            return;
        }
    }
    res.del("Transfer-Encoding");
    res.del("Connection");
    SendFrame(res.getframe(&request_table));
}


void Guest_s2::defaultHE(uint32_t events) {
    if (events & EPOLLERR || events & EPOLLHUP) {
        int       error = 0;
        socklen_t errlen = sizeof(error);

        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, (void*)&error, &errlen) == 0) {
            LOGE("(%s): guest_s error:%s\n", getsrc(), strerror(error));
        }
        clean(INTERNAL_ERR, this);
        return;
    }
    if (events & EPOLLIN) {
        (this->*Http2_Proc)();
        if(inited && localwinsize < 50 *1024 *1024){
            localwinsize += ExpandWindowSize(0, 50*1024*1024);
        }
        last_interactive = getmtime();
    }

    if (events & EPOLLOUT) {
        int ret = Write_Proc();
        if(ret <= 0 && showerrinfo(ret, "guest_s2 write error")) {
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
            last_interactive = getmtime();
        }
        if (framequeue.empty()) {
            updateEpoll(EPOLLIN);
        }
    }
}

void Guest_s2::RstProc(uint32_t id, uint32_t errcode) {
    if(idmap.count(id)){
        if(errcode)
            LOGE("(%s) [%d]: stream  reseted: %d\n", getsrc(), id, errcode);
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
    if(showerrinfo(errcode, "Guest_s2-Http2 error")){
        clean(errcode, this);
    }
}

void Guest_s2::AdjustInitalFrameWindowSize(ssize_t diff) {
    for(auto i: idmap.Left()){
       i.first->remotewinsize += diff; 
    }
    remotewinsize += diff;
}

void Guest_s2::clean(uint32_t errcode, Peer *who, uint32_t id) {
    Responser *responser = dynamic_cast<Responser *>(who);
    if(who == this) {
        for(auto i: idmap.Left()){
            i.first->clean(errcode, this, i.second);
        }
        idmap.clear();
        del_tick_func((void (*)(void *))guest2tick, this);
        return Peer::clean(errcode, this);
    }else{
        if(id == 0 && idmap.count(responser)){
            id = idmap.at(responser);
        }
        if(id){
            Reset(id, errcode>30?ERR_INTERNAL_ERROR:errcode);
            idmap.erase(responser, id);
        }else{
            assert(0);
        }
        waitlist.erase(who);
    }
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
    Responser* responser = dynamic_cast<Responser *>(who);
    if(idmap.count(responser)){
        size_t len = localframewindowsize - who->localwinsize;
        if(len < localframewindowsize/5)
            return;
        responser->localwinsize += ExpandWindowSize(idmap.at(responser), len);
    }
}


void Guest_s2::check_alive() {
    if(ssl->is_dtls()){
        dtls_tick(ssl);
    }
    if(getmtime() - last_interactive >= 30000){ //超过30秒交互数据，认为连接断开
        LOGE("(%s): [Guest_s2] Nothing got too long, so close it\n", getsrc());
        clean(PEER_LOST_ERR, this);
    }
}
