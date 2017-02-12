#include "guest_s2.h"
#include "res/responser.h"
#include "misc/job.h"

#include <limits.h>

void Guest_s2::peer_lost(Guest_s2 *g){
    LOGE("(%s): [Guest_s2] Nothing got too long, so close it\n", g->getsrc());
    g->clean(PEER_LOST_ERR, 0);
}

Guest_s2::Guest_s2(int fd, const char* ip, uint16_t port, Ssl* ssl):
        Requester(fd, ip, port), ssl(ssl)
{
    remotewinsize = remoteframewindowsize;
    localwinsize  = localframewindowsize;
    updateEpoll(EPOLLIN | EPOLLOUT);
    handleEvent = (void (Con::*)(uint32_t))&Guest_s2::defaultHE;
}

Guest_s2::Guest_s2(int fd, struct sockaddr_in6* myaddr, Ssl* ssl):
        Requester(fd, myaddr),ssl(ssl)
{
    remotewinsize = remoteframewindowsize;
    localwinsize  = localframewindowsize;
    updateEpoll(EPOLLIN | EPOLLOUT);
    handleEvent = (void (Con::*)(uint32_t))&Guest_s2::defaultHE;
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

ssize_t Guest_s2::Write(void *buff, size_t size, void* index) {
    uint32_t id = (uint32_t)(long)index;
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
    if(statusmap.count(id))
        statusmap.at(id).remotewinsize -= size;
    return size;
}

void Guest_s2::PushFrame(Http2_header *header) {
    updateEpoll(events | EPOLLOUT);
    return Http2Base::PushFrame(header);
}

void Guest_s2::DataProc(const Http2_header* header) {
    uint32_t id = get32(header->id);
    ssize_t len = get24(header->length);
    if(statusmap.count(id)){
        ResStatus& status = statusmap[id];
        Responser* responser = status.res_ptr;
        if(len > status.localwinsize){
            Reset(id, ERR_FLOW_CONTROL_ERROR);
            responser->clean(ERR_FLOW_CONTROL_ERROR, status.res_index);
            LOGE("(%s) :[%d] window size error\n", getsrc(), id);
            statusmap.erase(id);
            waitlist.erase(id);
            return;
        }
        responser->Write(header+1, len, status.res_index);
        if(header->flags & END_STREAM_F){
            if(len)
                responser->Write((const void*)nullptr, 0, status.res_index);
        }else{
            status.localwinsize -= len;
        }
    }else{
        Reset(id, ERR_STREAM_CLOSED);
    }
    localwinsize -= len;
}

void Guest_s2::ReqProc(HttpReqHeader&& req) {
    Responser *responser = distribute(req, nullptr);
    uint32_t id = (uint32_t)(long)req.index;
    if(responser){
        statusmap[id]=ResStatus{
            responser,
            responser->request(std::move(req)),
            (int32_t)remoteframewindowsize,
            localframewindowsize
        };
    }
}

void Guest_s2::response(HttpResHeader&& res) {
    assert(res.index);
    res.del("Transfer-Encoding");
    res.del("Connection");
    PushFrame(res.getframe(&request_table, (uint32_t)(long)res.index));
}


void Guest_s2::defaultHE(uint32_t events) {
    if (events & EPOLLERR || events & EPOLLHUP) {
        int       error = 0;
        socklen_t errlen = sizeof(error);

        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, (void*)&error, &errlen) == 0) {
            LOGE("(%s): guest_s error:%s\n", getsrc(), strerror(error));
        }
        clean(INTERNAL_ERR, 0);
        return;
    }
    if (events & EPOLLIN) {
        add_job((job_func)peer_lost, this, 30000);
        (this->*Http2_Proc)();
        if(inited && localwinsize < 50 *1024 *1024){
            localwinsize += ExpandWindowSize(0, 50*1024*1024);
        }
    }

    if (events & EPOLLOUT) {
        int ret = SendFrame();
        if(ret <= 0 && showerrinfo(ret, "guest_s2 write error")) {
            clean(WRITE_ERR, 0);
            return;
        }else{
            for(auto i = waitlist.begin(); i!= waitlist.end(); ){
                if(bufleft(reinterpret_cast<void *>(*i))){
                    statusmap.at(*i).res_ptr->writedcb(reinterpret_cast<void*>(*i));
                    i = waitlist.erase(i);
                }else{
                    i++;
                }
            }
            add_job((job_func)peer_lost, this, 30000);
        }
        if (framequeue.empty()) {
            updateEpoll(EPOLLIN);
        }
    }
}

void Guest_s2::RstProc(uint32_t id, uint32_t errcode) {
    if(statusmap.count(id)){
        if(errcode)
            LOGE("(%s) [%d]: stream  reseted: %d\n", getsrc(), id, errcode);
        ResStatus& status = statusmap[id];
        status.res_ptr->clean(errcode,  status.res_index);
        statusmap.erase(id);
        waitlist.erase(id);
    }
}


void Guest_s2::WindowUpdateProc(uint32_t id, uint32_t size) {
    if(id){
        if(statusmap.count(id)){
            ResStatus& status = statusmap[id];
#ifndef NDEBUG
            LOGD(DHTTP2, "window size updated [%d]: %d+%d\n", id, status.remotewinsize, size);
#endif
            status.remotewinsize += size;
            status.res_ptr->writedcb(status.res_index);
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


void Guest_s2::GoawayProc(Http2_header* header) {
    clean(get32(header+1), 0);
}

void Guest_s2::ErrProc(int errcode) {
    if(showerrinfo(errcode, "Guest_s2-Http2 error")){
        clean(errcode, 0);
    }
}

void Guest_s2::AdjustInitalFrameWindowSize(ssize_t diff) {
    for(auto i: statusmap){
       i.second.remotewinsize += diff;
    }
    remotewinsize += diff;
}

void Guest_s2::ResetResponser(Responser* r, void* index) {
    uint32_t id = (uint32_t)(long)index;
    assert(statusmap.count(id));
    if(r){
        statusmap[id].res_ptr = r;
    }else{
        statusmap.erase(id);
    }
}


void Guest_s2::clean(uint32_t errcode, void* index) {
    uint32_t id = (uint32_t)(long)index;
    if(id == 0) {
        for(auto i: statusmap){
            i.second.res_ptr->clean(errcode, i.second.res_index);
        }
        statusmap.clear();
        del_job((job_func)peer_lost, this);
        return Peer::clean(errcode, 0);
    }else{
        Reset(id, errcode>30?ERR_INTERNAL_ERROR:errcode);
        statusmap.erase(id);
        waitlist.erase(id);
    }
}

int32_t Guest_s2::bufleft(void* index) {
    if(index){
        assert(statusmap.count((uint32_t)(long)index));
        return Min(statusmap[(uint32_t)(long)index].remotewinsize, this->remotewinsize);
    }else
        return this->remotewinsize;
}

void Guest_s2::wait(void* index){
    waitlist.insert((uint32_t)(long)index);
}

void Guest_s2::writedcb(void* index){
    uint32_t id = (uint32_t)(long)index;
    if(statusmap.count(id)){
        ResStatus& status = statusmap[id];
        size_t len = localframewindowsize - status.localwinsize;
        if(len < localframewindowsize/5)
            return;
        status.localwinsize += ExpandWindowSize(id, len);
    }
}

#ifndef NDEBUG
void Guest_s2::PingProc(Http2_header *header){
    LOGD(DHTTP2, "window size global: %d/%d\n", localwinsize, remotewinsize);
    return Http2Base::PingProc(header);
}
#endif

