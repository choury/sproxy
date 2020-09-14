#include "guest2.h"
#include "res/responser.h"
#include "misc/util.h"

#include <assert.h>
#include <inttypes.h>

void Guest2::connection_lost(){
    LOGE("(%s): <guest2> Nothing got too long, so close it\n", getsrc());
    deleteLater(PEER_LOST_ERR);
}

bool Guest2::wantmore(const ReqStatus& status) {
    if(!status.res){
        return false;
    }
    if((status.flags&HTTP_RES_COMPLETED) || (status.flags&HTTP_RES_EOF)){
        return false;
    }
    return status.remotewinsize > 0;
}


Guest2::Guest2(RWer* rwer): Requester(rwer) {
    rwer->SetErrorCB(std::bind(&Guest2::Error, this, _1, _2));
    rwer->SetReadCB([this](size_t len){
        const char* data = this->rwer->rdata();
        size_t consumed = 0;
        size_t ret = 0;
        while((ret = (this->*Http2_Proc)((uchar*)data+consumed, len-consumed))){
            consumed += ret;
        }
        assert(consumed <= len);
        this->rwer->consume(data, consumed);
        if((http2_flag & HTTP2_FLAG_INITED) && localwinsize < 50 *1024 *1024){
            localwinsize += ExpandWindowSize(0, 50*1024*1024);
        }
        this->connection_lost_job = this->rwer->updatejob(
                this->connection_lost_job,
                std::bind(&Guest2::connection_lost, this), 1800000);
    });
    rwer->SetWriteCB([this](size_t){
        auto statusmap_copy = statusmap;
        for(auto& i: statusmap_copy){
            ReqStatus& status = i.second;
            if(status.res == nullptr){
                continue;
            }
            if((status.flags&HTTP_REQ_COMPLETED) && (status.flags&HTTP_RES_COMPLETED)){
                Clean(i.first, i.second, NOERROR);
                continue;
            }
            if(wantmore(status)){
                status.res->more();
            }
        }
    });
}


Guest2::~Guest2() {
    for(auto i: statusmap){
        delete i.second.req;
        delete i.second.res;
    }
    statusmap.clear();
}

void Guest2::Error(int ret, int code){
    if((ret == READ_ERR || ret == SOCKET_ERR) && code == 0){
        return deleteLater(NOERROR);
    }
    LOGE("guest2 error: %d/%d\n", ret, code);
    deleteLater(ret);
}

int Guest2::bufleft(uint32_t id) {
    int32_t globalwindow = Min(1024*1024 - rwer->wlength(), this->remotewinsize);
    return Min(statusmap.at(id).remotewinsize, globalwindow);
}

void Guest2::Send(uint32_t id, const void* buff, size_t size){
    if(statusmap.count(id)){
        ReqStatus& status = statusmap[id];
        assert((status.flags & HTTP_RES_COMPLETED) == 0);
        assert((status.flags & HTTP_RES_EOF) == 0);
        status.remotewinsize -= size;
        assert(status.remotewinsize >= 0);
        if(size == 0){
            status.flags |= HTTP_RES_COMPLETED;
            LOGD(DHTTP2, "<guest2> %" PRIu64 " send data [%d]: EOF/%d\n",
                    status.req->header->request_id, id,
                    status.remotewinsize);
        }else{
            LOGD(DHTTP2, "<guest2> %" PRIu64 " send data [%d]: %zu/%d\n",
                    status.req->header->request_id, id,
                    size, status.remotewinsize);
        }
    }
    remotewinsize -= size;
    PushData(id, buff, size);
}

void Guest2::ReqProc(uint32_t id, HttpReqHeader* header) {
    LOGD(DHTTP2, "guest %" PRIu64 " [%s] ReqProc %s\n", header->request_id, getsrc(), header->geturl().c_str());
    if(statusmap.count(id)){
        delete header;
        LOGD(DHTTP2, "<guest2> ReqProc dup id: %d\n", id);
        Reset(id, ERR_STREAM_CLOSED);
        return;
    }

    statusmap[id] = ReqStatus{
        nullptr,
        nullptr,
        (int32_t)remoteframewindowsize,
        localframewindowsize,
        0,
    };
    ReqStatus& status = statusmap[id];

    status.req = new HttpReq(header,
    std::bind(&Guest2::response, this, (void*)(long)id, _1),
    [this, &status, id] () mutable{
        auto len = status.req->cap();
        if(len < status.localwinsize){
            LOGE("http2 [%d] shrunken local window: %d/%d\n", id, len, status.localwinsize);
        }else{
            if(len - status.localwinsize > 2*FRAMEBODYLIMIT){
                status.localwinsize += ExpandWindowSize(id, len - status.localwinsize - FRAMEBODYLIMIT);
                return;
            }
            if(status.localwinsize < FRAMEBODYLIMIT && len > status.localwinsize){
                status.localwinsize += ExpandWindowSize(id, len - status.localwinsize);
            }
        }
    });
    distribute(status.req, this);
}

void Guest2::DataProc(uint32_t id, const void* data, size_t len) {
    if(len == 0)
        return;
    localwinsize -= len;
    if(statusmap.count(id)){
        ReqStatus& status = statusmap[id];
        assert((status.flags & HTTP_REQ_EOF) == 0);
        assert((status.flags & HTTP_REQ_COMPLETED) == 0);
        if(len > (size_t)status.localwinsize){
            LOGE("(%s): <guest2> [%d] window size error %zu/%d\n", getsrc(), id, len, status.localwinsize);
            Clean(id, status, ERR_FLOW_CONTROL_ERROR);
            return;
        }
        status.req->send(data, len);
        status.localwinsize -= len;
    }else{
        LOGD(DHTTP2, "<guest2> DateProc not found id: %d\n", id);
        Reset(id, ERR_STREAM_CLOSED);
    }
}

void Guest2::EndProc(uint32_t id) {
    LOGD(DHTTP2, "<guest2> [%d]: end of stream\n", id);
    if(statusmap.count(id)){
        ReqStatus& status = statusmap[id];
        assert((status.flags & HTTP_REQ_EOF) == 0);
        status.req->send((const void*)nullptr, 0);
        status.flags |= HTTP_REQ_COMPLETED;
        if(status.flags & HTTP_RES_COMPLETED) {
            Clean(id, status, NOERROR);
        }
    }
}


void Guest2::response(void* index, HttpRes* res) {
    uint32_t id = (uint32_t)(long)index;
    assert(statusmap.count(id));
    ReqStatus& status = statusmap[id];
    LOGD(DHTTP2, "<guest2> get response [%d]: %s\n", id, res->header->status);
    HttpLog(getsrc(), status.req, res);
    res->header->del("Transfer-Encoding");
    res->header->del("Connection");
    status.res = res;
    PushFrame(res->header->getframe(&request_table, id));
    res->setHandler([this, id](Channel::signal s){
        ReqStatus& status = statusmap[id];
        switch(s){
        case Channel::CHANNEL_SHUTDOWN:
            assert((status.flags & HTTP_REQ_EOF) == 0);
            status.flags |= HTTP_RES_EOF;
            if(http2_flag & HTTP2_SUPPORT_SHUTDOWN) {
                LOGD(DHTTP2, "<guest2> send shutdown frame: %d\n", id);
                Shutdown(id);
            }else{
                LOGD(DHTTP2, "<guest2> send reset frame: %d\n", id);
                Clean(id, status, ERR_CANCEL);
            }
            break;
        case Channel::CHANNEL_CLOSED:
            status.flags |= HTTP_CLOSED_F;
            return Clean(id, status, NOERROR);
        case Channel::CHANNEL_ABORT:
            status.flags |= HTTP_CLOSED_F;
            return Clean(id, status, ERR_INTERNAL_ERROR);
        }
    });
    res->attach((Channel::recv_const_t)std::bind(&Guest2::Send, this, id, _1, _2),
                std::bind(&Guest2::bufleft, this, id));
}

void Guest2::Clean(uint32_t id, ReqStatus &status, uint32_t errcode) {
    assert(statusmap[id].req == status.req);

    if((status.flags&HTTP_REQ_COMPLETED) == 0 || (status.flags&HTTP_RES_COMPLETED) == 0){
        Reset(id, errcode);
    }
    if((status.flags & HTTP_CLOSED_F) == 0){
        status.req->trigger(errcode ? Channel::CHANNEL_ABORT : Channel::CHANNEL_CLOSED);
    }
    delete status.req;
    delete status.res;
    statusmap.erase(id);
}

void Guest2::RstProc(uint32_t id, uint32_t errcode) {
    if(statusmap.count(id)){
        ReqStatus& status = statusmap[id];
        if(errcode){
            LOGE("(%s) <guest2> [%d]: stream  reseted: %d\n", getsrc(), id, errcode);
        }
        status.flags |= HTTP_REQ_COMPLETED | HTTP_RES_COMPLETED; //make clean not send reset back
        Clean(id, status, errcode);
    }
}


void Guest2::WindowUpdateProc(uint32_t id, uint32_t size) {
    if(id){
        if(statusmap.count(id)){
            ReqStatus& status = statusmap[id];
            LOGD(DHTTP2, "<guest2> window size updated [%d]: %d+%d\n", id, status.remotewinsize, size);
            if((uint64_t)status.remotewinsize + size >= (uint64_t)1<<31u){
                Clean(id, status, ERR_FLOW_CONTROL_ERROR);
                return;
            }
            status.remotewinsize += size;
            if(wantmore(status)){
                status.res->more();
            }
        }else{
            LOGD(DHTTP2, "<guest2> window size updated [%d]: not found\n", id);
        }
    }else{
        LOGD(DHTTP2, "<guest2> window size updated global: %d+%d\n", remotewinsize, size);
        if((uint64_t)remotewinsize + size >= (uint64_t)1<<31u){
            ErrProc(ERR_FLOW_CONTROL_ERROR);
            return;
        }
        remotewinsize += size;
        if(remotewinsize == (int32_t)size){
            LOGD(DHTTP2, "<guest2> get global window active all frame\n");
            auto statusmap_copy = statusmap;
            for(auto& i: statusmap_copy){
                ReqStatus& status = i.second;
                if(wantmore(status)){
                    status.res->more();
                }
            }
        }
    }
}

void Guest2::ShutdownProc(uint32_t id) {
    if(statusmap.count(id) == 0){
        return;
    }
    LOGD(DHTTP2, "<guest2> get shutdown frame from frame %d\n", id);
    ReqStatus& status = statusmap[id];
    status.flags |= HTTP_REQ_EOF;
    if(status.flags & HTTP_RES_EOF){
        Clean(id, status, ERR_STREAM_CLOSED);
    }else{
        status.req->trigger(Channel::CHANNEL_SHUTDOWN);
    }
}

void Guest2::GoawayProc(const Http2_header* header) {
    Goaway_Frame* goaway = (Goaway_Frame *)(header+1);
    uint32_t errcode = get32(goaway->errcode);
    deleteLater(errcode);
}

void Guest2::ErrProc(int errcode) {
    LOGE("Guest2 http2 error:0x%08x\n", errcode);
    deleteLater(errcode);
}

void Guest2::AdjustInitalFrameWindowSize(ssize_t diff) {
    for(auto& i: statusmap){
       i.second.remotewinsize += diff;
    }
}

std::list<write_block>::insert_iterator Guest2::queue_head() {
    return rwer->buffer_head();
}

std::list<write_block>::insert_iterator Guest2::queue_end() {
    return rwer->buffer_end();
}

void Guest2::queue_insert(std::list<write_block>::insert_iterator where, const write_block& wb) {
    rwer->buffer_insert(where, wb);
}

void Guest2::deleteLater(uint32_t errcode){
    for(auto& i: statusmap){
        if((i.second.flags & HTTP_CLOSED_F) == 0) {
            i.second.req->trigger(errcode ? Channel::CHANNEL_ABORT : Channel::CHANNEL_CLOSED);
        }
        i.second.flags |= HTTP_CLOSED_F;
    }
    if((http2_flag & HTTP2_FLAG_GOAWAYED) == 0){
        Goaway(-1, errcode & ERROR_MASK);
    }
    return Server::deleteLater(errcode);
}


void Guest2::dump_stat(Dumper dp, void* param) {
    dp(param, "Guest2 %p, id:%d %s (%d/%d)\n",
            this, sendid, getsrc(),
            this->remotewinsize, this->localwinsize);
    dp(param, "  rwer: rlength:%zu, rleft:%zu, wlength:%zu, stats:%d, event:%s\n",
            rwer->rlength(), rwer->rleft(), rwer->wlength(),
            (int)rwer->getStats(), events_string[(int)rwer->getEvents()]);
    for(auto& i: statusmap){
        dp(param, "0x%x [%" PRIu64 "]: %s %s (%d/%d)\n",
                i.first, i.second.req->header->request_id,
                i.second.req->header->method,
                i.second.req->header->geturl().c_str(),
                i.second.remotewinsize, i.second.localwinsize);
    }
}


#ifndef NDEBUG
void Guest2::PingProc(const Http2_header *header){
    LOGD(DHTTP2, "<guest2> ping: window size global: %d/%d\n", localwinsize, remotewinsize);
    return Http2Base::PingProc(header);
}
#endif
