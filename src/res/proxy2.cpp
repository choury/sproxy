#include "proxy2.h"
#include "req/requester.h"
#include "misc/util.h"
#include "misc/net.h"
#include "misc/config.h"

#include <assert.h>
#include <inttypes.h>

Proxy2* proxy2 = nullptr;

void Proxy2::connection_lost(){
    LOGE("<proxy2> %p the ping timeout, so close it\n", this);
    deleteLater(PEER_LOST_ERR);
}

void Proxy2::ping_check(){
    char buff[8];
    set64(buff, getutime());
    Ping(buff);
    LOGD(DHTTP2, "<proxy2> ping: window size global: %d/%d\n", localwinsize, remotewinsize);
    connection_lost_job = rwer->updatejob( connection_lost_job, std::bind(&Proxy2::connection_lost, this), 10000);
}

bool Proxy2::wantmore(const ReqStatus& status) {
    if((status.flags&HTTP_REQ_COMPLETED) || (status.flags&HTTP_REQ_EOF)){
        return false;
    }
    return status.remotewinsize > 0;
}


Proxy2::Proxy2(RWer* rwer) {
    this->rwer = rwer;
    if(proxy2 == nullptr){
        proxy2 = this;
    }
    rwer->SetErrorCB(std::bind(&Proxy2::Error, this, _1, _2));
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
#ifndef __ANDROID__
        this->ping_check_job = this->rwer->updatejob(
                this->ping_check_job,
                std::bind(&Proxy2::ping_check, this), 30000);
#else
        receive_time = getmtime();
#endif
        if(proxy2 != this && statusmap.empty()){
            LOG("this %p is not the main proxy2 and no clients, close it.\n", this);
            deleteLater(NOERROR);
        }
    });
    rwer->SetWriteCB([this](size_t){
        auto statusmap_copy = statusmap;
        for(auto& i: statusmap_copy){
            ReqStatus& status = i.second;
            if(wantmore(status)){
                status.req->more();
            }
        }
    });
#ifdef __ANDROID__
    receive_time = getmtime();
    ping_time = getmtime();
#endif
}


Proxy2::~Proxy2() {
}

void Proxy2::Error(int ret, int code) {
    if(ret == SOCKET_ERR && code == 0){
        return deleteLater(NOERROR);
    }
    LOGE("<proxy2> %p error: %d/%d\n", this, ret, code);
    deleteLater(ret);
}

void Proxy2::Send(uint32_t id ,const void* buff, size_t size) {
    assert(statusmap.count(id));
    ReqStatus& status = statusmap[id];
    assert((status.flags & HTTP_REQ_COMPLETED) == 0);
    assert((status.flags & HTTP_REQ_EOF) == 0);
    status.remotewinsize -= size;
    remotewinsize -= size;
    assert(status.remotewinsize >= 0);
    PushData(id, buff, size);
    if(size == 0){
        status.flags |= HTTP_REQ_COMPLETED;
        LOGD(DHTTP2, "<proxy2> send data [%d]: EOF/%d\n", id, status.remotewinsize);
    }else{
        LOGD(DHTTP2, "<proxy2> send data [%d]: %zu/%d\n", id, size, status.remotewinsize);
    }
}

void Proxy2::PushFrame(Http2_header *header){
#ifdef __ANDROID__
    uint32_t now = getmtime();
    if(http2_flag & HTTP2_FLAG_INITED
        && now - receive_time >=30000
        && now - ping_time >=5000)
    {
        ping_time = now;
        ping_check();
    }
#endif
    return Http2Base::PushFrame(header);
}

void Proxy2::ResProc(uint32_t id, HttpResHeader* header) {
    if(statusmap.count(id)){
        ReqStatus& status = statusmap[id];
        if(!header->no_body() && !header->get("Content-Length"))
        {
            header->set("Transfer-Encoding", "chunked");
        }
        status.res = new HttpRes(header, [this, &status, id]() mutable{
            auto len = status.res->cap();
            if(len < status.localwinsize){
                LOGE("(%" PRIu32 "): <proxy2> [%d] shrunken local window: %d/%d\n",
                    status.req->header->request_id,
                    id, len, status.localwinsize);
            }else{
                if((len - status.localwinsize > 2*FRAMEBODYLIMIT)) {
                    status.localwinsize += ExpandWindowSize(id, len - status.localwinsize - FRAMEBODYLIMIT);
                    return;
                }
                if(status.localwinsize < FRAMEBODYLIMIT && len > status.localwinsize){
                    status.localwinsize += ExpandWindowSize(id, len - status.localwinsize);
                }
            }
        });
        status.req->response(status.res);

    }else{
        delete header;
        LOGD(DHTTP2, "<proxy2> ResProc not found id: %d\n", id);
        Reset(id, ERR_STREAM_CLOSED);
    }
}


void Proxy2::DataProc(uint32_t id, const void* data, size_t len) {
    if(len == 0)
        return;
    localwinsize -= len;
    if(statusmap.count(id)){
        ReqStatus& status = statusmap[id];
        assert((status.flags & HTTP_RES_COMPLETED) == 0);
        assert((status.flags & HTTP_RES_EOF) == 0);
        if(len > (size_t)status.localwinsize){
            LOGE("(%" PRIu32 "): <proxy2> [%d] window size error %zu/%d\n",
                    status.req->header->request_id, id, len, status.localwinsize);
            Clean(id, status, ERR_FLOW_CONTROL_ERROR);
            return;
        }
        if(status.res == nullptr){
            //compact for legacy version.
            ResProc(id, new HttpResHeader(H200));
        }
        status.res->send(data, len);
        status.localwinsize -= len;
    }else{
        LOGD(DHTTP2, "<proxy2> DataProc not found id: %d\n", id);
        Reset(id, ERR_STREAM_CLOSED);
    }
}

void Proxy2::EndProc(uint32_t id) {
    LOGD(DHTTP2, "<proxy2> [%d]: end of stream\n", id);
    if(statusmap.count(id)) {
        ReqStatus &status = statusmap[id];
        assert((status.flags & HTTP_RES_EOF) == 0);
        assert((status.flags & HTTP_RES_COMPLETED) == 0);
        status.flags |= HTTP_RES_COMPLETED;
        status.res->send((const void*)nullptr,0);
    }
}

void Proxy2::ErrProc(int errcode) {
    LOGE("<proxy2> %p Http2 error: 0x%08x\n", this, errcode);
    deleteLater(errcode);
}

void Proxy2::Clean(uint32_t id, ReqStatus& status, uint32_t errcode){
    assert(statusmap[id].req == status.req);
    if((status.flags&HTTP_REQ_COMPLETED) == 0 || (status.flags&HTTP_RES_COMPLETED) == 0){
        Reset(id, errcode);
    }

    status.req->detach();
    if(status.flags & HTTP_CLOSED_F){
        //do nothing.
    }else if(status.res){
        status.res->trigger(errcode ? Channel::CHANNEL_ABORT : Channel::CHANNEL_CLOSED);
    }else{
        status.req->response(new HttpRes(new HttpResHeader(H500), "[[internal error]]"));
    }
    statusmap.erase(id);
}

void Proxy2::RstProc(uint32_t id, uint32_t errcode) {
    if(statusmap.count(id)){
        ReqStatus& status = statusmap[id];
        if(errcode){
            LOGE("(%" PRIu32 "): <proxy2> [%d]: stream reseted: %d\n",
                 status.req->header->request_id, id, errcode);
        }
        status.flags |= HTTP_REQ_COMPLETED | HTTP_RES_COMPLETED; //make clean not send reset back
        Clean(id, status, errcode);
    }
}

void Proxy2::WindowUpdateProc(uint32_t id, uint32_t size){
    if(id){
        if(statusmap.count(id)){
            ReqStatus& status = statusmap[id];
            LOGD(DHTTP2, "<proxy2> window size updated [%d]: %d+%d\n", id, status.remotewinsize, size);
            if((uint64_t)status.remotewinsize + size >= (uint64_t)1<<31){
                Clean(id, status, ERR_FLOW_CONTROL_ERROR);
                return;
            }
            status.remotewinsize += size;
            if(wantmore(status)){
                status.req->more();
            }
        }else{
            LOGD(DHTTP2, "<proxy2> window size updated [%d]: not found\n", id);
        }
    }else{
        LOGD(DHTTP2, "<proxy2> window size updated global: %d+%d\n", remotewinsize, size);
        if((uint64_t)remotewinsize + size >= (uint64_t)1<<31){
            ErrProc(ERR_FLOW_CONTROL_ERROR);
            return;
        }
        remotewinsize += size;
        if(remotewinsize == (int32_t)size){
            LOGD(DHTTP2, "<proxy2> active all frame\n");
            auto statusmap_copy = statusmap;
            for(auto& i: statusmap_copy){
                ReqStatus& status = i.second;
                if(wantmore(status)){
                    status.req->more();
                }
            }
        }
    }
}

void Proxy2::PingProc(const Http2_header *header){
    if(header->flags & ACK_F){
        rwer->deljob(&connection_lost_job);
        double diff = (getutime()-get64(header+1))/1000.0;
        LOG("<proxy2> Get a ping time=%.3fms\n", diff);
        if(diff >= 5000){
            LOGE("<proxy2> The ping time too long!\n");
        }
    }
    Http2Base::PingProc(header);
}

void Proxy2::ShutdownProc(uint32_t id) {
    if(statusmap.count(id) == 0){
        return;
    }
    LOGD(DHTTP2, "<proxy2> get shutdown frame from frame %d\n", id);
    ReqStatus& status = statusmap[id];
    status.flags |= HTTP_RES_EOF;
    if(status.flags & HTTP_REQ_EOF){
        Clean(id, status, ERR_STREAM_CLOSED);
    }else {
        status.res->trigger(Channel::CHANNEL_SHUTDOWN);
    }
}

void Proxy2::request(HttpReq* req, Requester*) {
    uint32_t id = GetSendId();
    assert((http2_flag & HTTP2_FLAG_GOAWAYED) == 0);
    LOGD(DHTTP2, "proxy2 request: %s [%d]\n", req->header->geturl().c_str(), id);
    statusmap[id] = ReqStatus{
       req,
       nullptr,
       (int32_t)remoteframewindowsize,
       localframewindowsize,
       0,
    };
    ReqStatus& status = statusmap[id];
    PushFrame(req->header->getframe(&request_table, id));
    req->setHandler([this, &status, id](Channel::signal s){
        assert(statusmap.count(id));
        switch(s){
        case Channel::CHANNEL_SHUTDOWN:
            assert((status.flags & HTTP_RES_EOF) == 0);
            status.flags |= HTTP_REQ_EOF;
            if(http2_flag & HTTP2_SUPPORT_SHUTDOWN) {
                LOGD(DHTTP2, "<proxy2> send shutdown frame: %d\n", id);
                Shutdown(id);
            }else{
                LOGD(DHTTP2, "<proxy2> send reset frame: %d\n", id);
                Clean(id, status, ERR_CANCEL);
            }
            break;
        case Channel::CHANNEL_CLOSED:
            status.flags |= HTTP_CLOSED_F;
            return Clean(id, status, ERR_NO_ERROR);
        case Channel::CHANNEL_ABORT:
            status.flags |= HTTP_CLOSED_F;
            return Clean(id, status, ERR_INTERNAL_ERROR);
        }
    });
    req->attach((Channel::recv_const_t)std::bind(&Proxy2::Send, this, id, _1, _2),
            [this, &status]{return Min(status.remotewinsize, this->remotewinsize);});
}

void Proxy2::init(HttpReq* req) {
    Http2Requster::init();
    request(req, nullptr);
}


void Proxy2::GoawayProc(const Http2_header* header){
    Goaway_Frame* goaway = (Goaway_Frame *)(header+1);
    uint32_t errcode = get32(goaway->errcode);
    return deleteLater(errcode);
}


void Proxy2::AdjustInitalFrameWindowSize(ssize_t diff) {
    for(auto& i: statusmap){
        i.second.remotewinsize += diff;
    }
}

std::list<write_block>::insert_iterator Proxy2::queue_head() {
    return rwer->buffer_head();
}

std::list<write_block>::insert_iterator Proxy2::queue_end() {
    return rwer->buffer_end();
}

void Proxy2::queue_insert(std::list<write_block>::insert_iterator where, const write_block& wb) {
    rwer->buffer_insert(where, wb);
}

void Proxy2::deleteLater(uint32_t errcode){
    if(proxy2 == this){
        proxy2 = nullptr;
    }
    auto statusmapCopy = statusmap;
    for(auto& i: statusmapCopy){
        Clean(i.first, i.second, errcode);
    }
    statusmap.clear();
    if((http2_flag & HTTP2_FLAG_GOAWAYED) == 0){
        Goaway(-1, errcode);
    }
    Server::deleteLater(errcode);
}

void Proxy2::dump_stat(Dumper dp, void* param) {
    dp(param, "Proxy2 %p%s id:%d (%s) (%d/%d)\n",
            this, proxy2 == this?" [M]":"", sendid,
            rwer->getPeer(),
            this->remotewinsize, this->localwinsize);
    dp(param, "  rwer: rlength:%zu, rleft:%zu, wlength:%zu, stats:%d, event:%s\n",
            rwer->rlength(), rwer->rleft(), rwer->wlength(),
            (int)rwer->getStats(), events_string[(int)rwer->getEvents()]);
    for(auto& i: statusmap){
        dp(param, "0x%x [%" PRIu32 "]: %s [%d] (%d/%d)\n",
                i.first,
                i.second.req->header->request_id,
                i.second.req->header->geturl().c_str(),
                i.second.flags,
                i.second.remotewinsize, i.second.localwinsize);
    }
}

void Proxy2::flush() {
    if(!rwer->supportReconnect()){
        proxy2 = nullptr;
    }
}


void flushproxy2(int force) {
    if(force){
        proxy2 = nullptr;
        return;
    }
    if(proxy2){
        proxy2->flush();
    }
}
