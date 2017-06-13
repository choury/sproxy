#include "guest_s2.h"
#include "res/responser.h"
#include "misc/job.h"

//#include <limits.h>

void Guest_s2::connection_lost(Guest_s2 *g){
    LOGE("(%s): [Guest_s2] Nothing got too long, so close it\n", g->getsrc(nullptr));
    g->clean(PEER_LOST_ERR, 0);
}

Guest_s2::Guest_s2(int fd, const char* ip, uint16_t port, Ssl* ssl):
        Requester(fd, ip, port), ssl(ssl)
{
    updateEpoll(EPOLLIN | EPOLLOUT);
    handleEvent = (void (Con::*)(uint32_t))&Guest_s2::defaultHE;
}

Guest_s2::Guest_s2(int fd, struct sockaddr_in6* myaddr, Ssl* ssl):
        Requester(fd, myaddr),ssl(ssl)
{
    updateEpoll(EPOLLIN | EPOLLOUT);
    handleEvent = (void (Con::*)(uint32_t))&Guest_s2::defaultHE;
}

Guest_s2::~Guest_s2() {
    del_job((job_func)connection_lost, this);
    delete ssl;
}

ssize_t Guest_s2::Read(void *buff, size_t size) {
    auto ret = ssl->read(buff, size);
    if(ret > 0){
        add_job((job_func)connection_lost, this, 90000);
    }
    return ret;
}

ssize_t Guest_s2::Write(const void *buff, size_t size) {
    auto ret =  ssl->write(buff, size);
    if(ret > 0){
        add_job((job_func)connection_lost, this, 90000);
    }
    return ret;
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
            LOGE("(%s) :[%d] window size error\n", getsrc(nullptr), id);
            statusmap.erase(id);
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
            LOGE("(%s): guest_s error:%s\n", getsrc(nullptr), strerror(error));
        }
        clean(INTERNAL_ERR, 0);
        return;
    }
    if (events & EPOLLIN) {
        (this->*Http2_Proc)();
        if(inited && localwinsize < 50 *1024 *1024){
            localwinsize += ExpandWindowSize(0, 50*1024*1024);
        }
    }

    if (events & EPOLLOUT) {
        if(framelen >= 1024*1024){
            LOGD(DHTTP2, "active all frame because of framelen\n");
            for(auto i: statusmap){
                ResStatus& status = i.second;
                if(status.remotewinsize > 0){
                    status.res_ptr->writedcb(status.res_index);
                }
            }
        }
        int ret = SendFrame();
        if(ret <= 0  && showerrinfo(ret, "guest_s2 write error")) {
            clean(WRITE_ERR, 0);
            return;
        }
        if (framequeue.empty()) {
            updateEpoll(EPOLLIN);
        }
    }
}

void Guest_s2::RstProc(uint32_t id, uint32_t errcode) {
    if(statusmap.count(id)){
        if(errcode)
            LOGE("(%s) [%d]: stream  reseted: %d\n", getsrc(nullptr), id, errcode);
        ResStatus& status = statusmap[id];
        status.res_ptr->clean(errcode,  status.res_index);
        statusmap.erase(id);
    }
}


void Guest_s2::WindowUpdateProc(uint32_t id, uint32_t size) {
    if(id){
        if(statusmap.count(id)){
            ResStatus& status = statusmap[id];
            LOGD(DHTTP2, "window size updated [%d]: %d+%d\n", id, status.remotewinsize, size);
            status.remotewinsize += size;
            status.res_ptr->writedcb(status.res_index);
        }else{
            LOGD(DHTTP2, "window size updated [%d]: not found\n", id);
        }
    }else{
        LOGD(DHTTP2, "window size updated global: %d+%d\n", remotewinsize, size);
        remotewinsize += size;
        if(remotewinsize == (int32_t)size){
            LOGD(DHTTP2, "get global window active all frame\n");
            for(auto i: statusmap){
                ResStatus& status = i.second;
                if(status.remotewinsize > 0){
                    status.res_ptr->writedcb(status.res_index);
                }
            }
        }
    }
}


void Guest_s2::GoawayProc(Http2_header* header) {
    Goaway_Frame* goaway = (Goaway_Frame *)(header+1);
    clean(get32(goaway->errcode), nullptr);
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
}

void Guest_s2::clean(uint32_t errcode, void* index) {
    uint32_t id = (uint32_t)(long)index;
    if(id == 0) {
        for(auto i: statusmap){
            i.second.res_ptr->clean(errcode, i.second.res_index);
        }
        statusmap.clear();
        Goaway(-1, errcode);
        return Peer::clean(errcode, 0);
    }else{
        Reset(id, errcode>30?ERR_INTERNAL_ERROR:errcode);
        statusmap.erase(id);
    }
}

int32_t Guest_s2::bufleft(void* index) {
    int32_t globalwindow = Min(1024*1024 - (int32_t)framelen, this->remotewinsize);
    if(index){
        assert(statusmap.count((uint32_t)(long)index));
        return Min(statusmap[(uint32_t)(long)index].remotewinsize, globalwindow);
    }else
        return globalwindow;
}

void Guest_s2::writedcb(void* index){
    uint32_t id = (uint32_t)(long)index;
    if(statusmap.count(id)){
        ResStatus& status = statusmap[id];
        auto len = status.res_ptr->bufleft(status.res_index);
        if(len <= status.localwinsize ||
           (len - status.localwinsize < FRAMEBODYLIMIT &&
            status.localwinsize >= FRAMEBODYLIMIT))
            return;
        status.localwinsize += ExpandWindowSize(id, len - status.localwinsize);
    }
}

const char * Guest_s2::getsrc(void* index){
    static char src[DOMAINLIMIT];
    if(index == nullptr){
        sprintf(src, "%s:%d", sourceip, sourceport);
    }else{
        sprintf(src, "%s:%d [%u]", sourceip, sourceport, (uint32_t)(long)index);
    }
    return src;
}


void Guest_s2::dump_stat() {
    LOG("Guest_s2 %p %s:\n", this, getsrc(nullptr));
    for(auto i: statusmap){
        LOG("0x%x: %p, %p", i.first, i.second.res_ptr, i.second.res_index);
    }
}


#ifndef NDEBUG
void Guest_s2::PingProc(Http2_header *header){
    LOGD(DHTTP2, "window size global: %d/%d\n", localwinsize, remotewinsize);
    return Http2Base::PingProc(header);
}
#endif

