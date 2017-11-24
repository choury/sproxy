#include "guest_s2.h"
#include "res/responser.h"
#include "misc/job.h"

//#include <limits.h>

int Guest_s2::connection_lost(Guest_s2 *g){
    LOGE("(%s): [Guest_s2] Nothing got too long, so close it\n", g->getsrc(nullptr));
    g->deleteLater(PEER_LOST_ERR);
    return 0;
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
    del_delayjob((job_func)connection_lost, this);
    delete ssl;
}

ssize_t Guest_s2::Read(void *buff, size_t size) {
    auto ret = ssl->read(buff, size);
    if(ret > 0){
        add_delayjob((job_func)connection_lost, this, 1800000);
    }
    return ret;
}

ssize_t Guest_s2::Write(const void *buff, size_t size) {
    auto ret =  ssl->write(buff, size);
    if(ret > 0){
        add_delayjob((job_func)connection_lost, this, 1800000);
    }
    return ret;
}

int32_t Guest_s2::bufleft(void* index) {
    int32_t globalwindow = Min(1024*1024 - (int32_t)framelen, this->remotewinsize);
    if(index){
        assert(statusmap.count((uint32_t)(long)index));
        return Min(statusmap[(uint32_t)(long)index].remotewinsize, globalwindow);
    }else
        return globalwindow;
}

ssize_t Guest_s2::Send(void *buff, size_t size, void* index) {
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
    if(statusmap.count(id)){
        assert((statusmap[id].res_flags & STREAM_WRITE_CLOSED) == 0);
        statusmap[id].remotewinsize -= size;
    }
    return size;
}

void Guest_s2::PushFrame(Http2_header *header) {
    updateEpoll(events | EPOLLOUT);
    return Http2Base::PushFrame(header);
}

void Guest_s2::ReqProc(HttpReqHeader* req) {
    Responser *responser = distribute(req, nullptr);
    uint32_t id = (uint32_t)(long)req->index;
    if(statusmap.count(id)){
        delete req;
        Reset(id, ERR_STREAM_CLOSED);
        return;
    }
    if(id <= maxid || (id&1) == 0){
        delete req;
        ErrProc(ERR_STREAM_CLOSED);
        return;
    }
    maxid = id;
    if(responser){
        statusmap[id]=ResStatus{
            responser,
            responser->request(req),
            (int32_t)remoteframewindowsize,
            localframewindowsize,
            0,
        };
    }else{
        finish(0, req->index);
        delete req;
    }
}

void Guest_s2::DataProc(uint32_t id, const void* data, size_t len) {
    if(len == 0)
        return;
    if(statusmap.count(id)){
        ResStatus& status = statusmap[id];
        Responser* responser = status.res_ptr;
        if(len > (size_t)status.localwinsize){
            Reset(id, ERR_FLOW_CONTROL_ERROR);
            responser->finish(ERR_FLOW_CONTROL_ERROR, status.res_index);
            LOGE("(%s) :[%d] window size error\n", getsrc(nullptr), id);
            statusmap.erase(id);
            return;
        }
        responser->Send(data, len, status.res_index);
        status.localwinsize -= len;
    }else{
        ErrProc(ERR_PROTOCOL_ERROR);
    }
    localwinsize -= len;
}

void Guest_s2::EndProc(uint32_t id) {
    if(statusmap.count(id)){
        ResStatus& status = statusmap[id];
        if(status.res_flags & STREAM_WRITE_CLOSED){
            status.res_ptr->finish(NOERROR | DISCONNECT_FLAG, status.res_index);
            statusmap.erase(id);
        }else{
            status.res_ptr->finish(NOERROR, status.res_index);
            status.res_flags |= STREAM_READ_CLOSED;
        }
    }
}


void Guest_s2::response(HttpResHeader* res) {
    assert(res->index);
    res->del("Transfer-Encoding");
    res->del("Connection");
    PushFrame(res->getframe(&request_table, (uint32_t)(long)res->index));
    delete res;
}

void Guest_s2::transfer(void* index, Responser* res_ptr, void* res_index) {
    uint32_t id = (uint32_t)(long)index;
    assert(statusmap.count(id));
    ResStatus& status = statusmap[id];
    status.res_ptr = res_ptr;
    status.res_index = res_index;
}



void Guest_s2::defaultHE(uint32_t events) {
    if (events & EPOLLERR || events & EPOLLHUP) {
        int       error = 0;
        socklen_t errlen = sizeof(error);

        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, (void*)&error, &errlen) == 0) {
            LOGE("(%s): guest_s error:%s\n", getsrc(nullptr), strerror(error));
        }
        deleteLater(INTERNAL_ERR);
        return;
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
        if(ret < 0  && showerrinfo(ret, "guest_s2 write error")) {
            deleteLater(WRITE_ERR);
            return;
        }
        if(framequeue.empty()) {
            updateEpoll(this->events & ~EPOLLOUT);
        }
    }
    
    if (events & EPOLLIN) {
        (this->*Http2_Proc)();
        if((http2_flag & HTTP2_FLAG_INITED) && localwinsize < 50 *1024 *1024){
            localwinsize += ExpandWindowSize(0, 50*1024*1024);
        }
    }

}

void Guest_s2::closeHE(uint32_t events) {
    int ret = SendFrame();
    if (framequeue.empty() ||
        (ret <= 0 && showerrinfo(ret, "write error while closing"))) {
        delete this;
        return;
    }
}


void Guest_s2::RstProc(uint32_t id, uint32_t errcode) {
    if(statusmap.count(id)){
        if(errcode)
            LOGE("(%s) [%d]: stream  reseted: %d\n", getsrc(nullptr), id, errcode);
        ResStatus& status = statusmap[id];
        status.res_ptr->finish(errcode?errcode:PEER_LOST_ERR,  status.res_index);
        statusmap.erase(id);
    }else{
        ErrProc(ERR_PROTOCOL_ERROR);
    }
}


void Guest_s2::WindowUpdateProc(uint32_t id, uint32_t size) {
    if(id){
        if(statusmap.count(id)){
            ResStatus& status = statusmap[id];
            LOGD(DHTTP2, "window size updated [%d]: %d+%d\n", id, status.remotewinsize, size);
            if((uint64_t)status.remotewinsize + size >= (uint64_t)1<<31){
                Reset(id, ERR_FLOW_CONTROL_ERROR);
                return;
            }
            status.remotewinsize += size;
            status.res_ptr->writedcb(status.res_index);
        }else{
            LOGD(DHTTP2, "window size updated [%d]: not found\n", id);
            ErrProc(ERR_PROTOCOL_ERROR);
        }
    }else{
        LOGD(DHTTP2, "window size updated global: %d+%d\n", remotewinsize, size);
        if((uint64_t)remotewinsize + size >= (uint64_t)1<<31){
            ErrProc(ERR_FLOW_CONTROL_ERROR);
            return;
        }
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
    uint32_t errcode = get32(goaway->errcode);
    http2_flag |= HTTP2_FLAG_GOAWAYED;
    deleteLater(errcode ? errcode:PEER_LOST_ERR);
}

void Guest_s2::ErrProc(int errcode) {
    if(showerrinfo(errcode, "Guest_s2-Http2 error")){
        deleteLater(errcode > ERR_HTTP_1_1_REQUIRED ? ERR_INTERNAL_ERROR: errcode);
    }
}

void Guest_s2::AdjustInitalFrameWindowSize(ssize_t diff) {
    for(auto i: statusmap){
       i.second.remotewinsize += diff;
    }
}

bool Guest_s2::finish(uint32_t flags, void* index) {
    uint32_t id = (uint32_t)(long)index;
    if(statusmap.count(id) == 0){
        Peer::Send((const void*)nullptr, 0, index);
        return false;
    }
    ResStatus& status = statusmap[id];
    uint8_t errcode = flags & ERROR_MASK;
    if(errcode == 0 && (status.res_flags & STREAM_WRITE_CLOSED) == 0){
        Peer::Send((const void*)nullptr, 0, index);
        status.res_flags |= STREAM_WRITE_CLOSED;
    }
    if(status.res_flags & STREAM_READ_CLOSED){
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

void Guest_s2::deleteLater(uint32_t errcode){
    for(auto i: statusmap){
        i.second.res_ptr->finish(errcode, i.second.res_index);
    }
    statusmap.clear();
    if((http2_flag & HTTP2_FLAG_GOAWAYED) == 0){
        http2_flag |= HTTP2_FLAG_GOAWAYED;
        Goaway(-1, errcode);
    }
    return Peer::deleteLater(errcode);
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
        LOG("0x%x: %p, %p (%d/%d)\n",
            i.first, i.second.res_ptr, i.second.res_index,
            i.second.remotewinsize, i.second.localwinsize);
    }
}


#ifndef NDEBUG
void Guest_s2::PingProc(Http2_header *header){
    LOGD(DHTTP2, "window size global: %d/%d\n", localwinsize, remotewinsize);
    return Http2Base::PingProc(header);
}
#endif

