#include "guest2.h"
#include "res/responser.h"
#include "misc/util.h"
#include "misc/config.h"

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
    if(status.flags&HTTP_RES_COMPLETED){
        return false;
    }
    return status.remotewinsize > 0;
}


Guest2::Guest2(std::shared_ptr<RWer> rwer): Requester(rwer) {
    rwer->SetErrorCB(std::bind(&Guest2::Error, this, _1, _2));
    rwer->SetReadCB([this](Buffer& bb){
        LOGD(DHTTP2, "<guest2> (%s) read: len:%zu\n", getsrc(), bb.len);
        if(bb.len == 0){
            //EOF
            return deleteLater(NOERROR);
        }
        size_t ret = 0;
        while((bb.len >  0) && (ret = (this->*Http2_Proc)((const uchar*) bb.data(), bb.len))){
            bb.trunc(ret);
        }
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
            if(wantmore(status)){
                status.res->more();
            }
        }
    });
}

Guest2::~Guest2() {
    for(auto& i: statusmap){
        if((i.second.flags & HTTP_CLOSED_F) == 0) {
            i.second.req->send(ChannelMessage::CHANNEL_ABORT);
        }
        i.second.flags |= HTTP_CLOSED_F;
    }
    statusmap.clear();
}

void Guest2::Error(int ret, int code){
    LOGE("(%s): <guest2> error: %d/%d\n", getsrc(), ret, code);
    deleteLater(ret);
}

void Guest2::Recv(Buffer&& bb){
    assert(statusmap.count(bb.id));
    ReqStatus& status = statusmap[bb.id];
    assert((status.flags & HTTP_RES_COMPLETED) == 0);
    status.remotewinsize -= bb.len;
    assert(status.remotewinsize >= 0);
    remotewinsize -= bb.len;
    if(bb.len == 0){
        LOGD(DHTTP2, "<guest2> %" PRIu32 " recv data [%d]: EOF/%d\n",
             status.req->header->request_id, (int)bb.id,
             status.remotewinsize);
        PushData({nullptr, bb.id});
        status.flags |= HTTP_RES_COMPLETED;
        if(status.flags & HTTP_REQ_COMPLETED){
            rwer->addjob(std::bind(&Guest2::Clean, this, bb.id, NOERROR), 0, JOB_FLAGS_AUTORELEASE);
        }
    }else{
        if(status.req->header->ismethod("HEAD")){
            LOGD(DHTTP2, "<guest2> %" PRIu32 " recv data [%d], HEAD req discard body\n",
                 status.req->header->request_id, (int)bb.id);
            return;
        }
        LOGD(DHTTP2, "<guest2> %" PRIu32 " recv data [%d]: %zu/%d\n",
             status.req->header->request_id, (int)bb.id,
             bb.len, status.remotewinsize);
        PushData(std::move(bb));
    }
}

void Guest2::Handle(uint32_t id, ChannelMessage::Signal s){
    assert(statusmap.count(id));
    ReqStatus& status = statusmap[id];
    LOGD(DHTTP2, "<guest2> signal [%d] %" PRIu32 ": %d\n",
         (int)id, status.req->header->request_id, (int)s);
    switch(s){
    case ChannelMessage::CHANNEL_ABORT:
        status.flags |= HTTP_CLOSED_F;
        return Clean(id, HTTP2_ERR_INTERNAL_ERROR);
    }
}

void Guest2::ReqProc(uint32_t id, std::shared_ptr<HttpReqHeader> header) {
    LOGD(DHTTP2, "<guest2> %" PRIu32 " (%s) ReqProc %s\n", header->request_id, getsrc(), header->geturl().c_str());
    if(statusmap.count(id)){
        LOGD(DHTTP2, "<guest2> ReqProc dup id: %d\n", id);
        Reset(id, HTTP2_ERR_STREAM_CLOSED);
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

    status.req = std::make_shared<HttpReq>(header,
    std::bind(&Guest2::response, this, (void*)(long)id, _1),
    [this, &status, id] () mutable{
        auto len = status.req->cap();
        if(len < status.localwinsize){
            LOGE("(%s)[%" PRIu32 "]: <guest2> [%d] shrunken local window: %d/%d\n",
                getsrc(), status.req->header->request_id,
                id, len, status.localwinsize);
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
        assert((status.flags & HTTP_REQ_COMPLETED) == 0);
        if(len > (size_t)status.localwinsize){
            LOGE("(%s)[%" PRIu32 "]: <guest2> [%d] window size error %zu/%d\n", 
                getsrc(), status.req->header->request_id,
                id, len, status.localwinsize);
            Clean(id, HTTP2_ERR_FLOW_CONTROL_ERROR);
            return;
        }
        status.req->send(data, len);
        status.localwinsize -= len;
    }else{
        LOGD(DHTTP2, "<guest2> DateProc not found id: %d\n", id);
        Reset(id, HTTP2_ERR_STREAM_CLOSED);
    }
}

void Guest2::EndProc(uint32_t id) {
    LOGD(DHTTP2, "<guest2> [%d]: end of stream\n", id);
    if(statusmap.count(id)){
        ReqStatus& status = statusmap[id];
        status.req->send(nullptr);
        status.flags |= HTTP_REQ_COMPLETED;
        if(status.flags & HTTP_RES_COMPLETED) {
            Clean(id, NOERROR);
        }
    }
}


void Guest2::response(void* index, std::shared_ptr<HttpRes> res) {
    uint32_t id = (uint32_t)(long)index;
    assert(statusmap.count(id));
    ReqStatus& status = statusmap[id];
    assert(status.res == nullptr);
    status.res = res;

    res->attach([this, id](ChannelMessage& msg){
        assert(statusmap.count(id));
        ReqStatus& status = statusmap[id];
        switch(msg.type){
        case ChannelMessage::CHANNEL_MSG_HEADER:{
            auto header = std::dynamic_pointer_cast<HttpResHeader>(msg.header);
            LOGD(DHTTP2, "<guest2> get response [%d]: %s\n", id, header->status);
            HttpLog(getsrc(), status.req->header, header);
            header->del("Transfer-Encoding");
            header->del("Connection");

            auto buff = std::make_shared<Block>(BUF_LEN);
            Http2_header* const h2header = (Http2_header*) buff->data();
            memset(h2header, 0, sizeof(*h2header));
            h2header->type = HTTP2_STREAM_HEADERS;
            h2header->flags = HTTP2_END_HEADERS_F;
            set32(h2header->id, id);
            size_t len = hpack_encoder.PackHttp2Res(header, h2header + 1, BUF_LEN - sizeof(Http2_header));
            set24(h2header->length, len);
            PushFrame(Buffer{buff, len + sizeof(Http2_header)});

            if(!status.req->header->should_proxy && opt.alt_svc){
                AltSvc(id, "", opt.alt_svc);
            }
            return 1;
        }
        case ChannelMessage::CHANNEL_MSG_DATA:
            msg.data.id = id;
            Recv(std::move(msg.data));
            return 1;
        case ChannelMessage::CHANNEL_MSG_SIGNAL:
            Handle(id, msg.signal);
            return 0;
        }
        return 0;
    }, [this, &status]{return Min(status.remotewinsize, this->remotewinsize);});
}

void Guest2::Clean(uint32_t id, uint32_t errcode) {
    if(statusmap.count(id) == 0){
        return;
    }
    ReqStatus& status = statusmap[id];
    if((status.flags&HTTP_REQ_COMPLETED) == 0 || (status.flags&HTTP_RES_COMPLETED) == 0){
        Reset(id, errcode);
    }
    if((status.flags & HTTP_CLOSED_F) == 0){
        status.req->send(ChannelMessage::CHANNEL_ABORT);
    }
    if(status.res){
        status.res->detach();
    }
    statusmap.erase(id);
}

void Guest2::RstProc(uint32_t id, uint32_t errcode) {
    if(statusmap.count(id)){
        ReqStatus& status = statusmap[id];
        if(errcode){
            LOGE("(%s)[%" PRIu32 "]: <guest2> [%d]: stream  reseted: %d\n",
                getsrc(), status.req->header->request_id,
                id, errcode);
        }
        status.flags |= HTTP_REQ_COMPLETED | HTTP_RES_COMPLETED; //make clean not send reset back
        Clean(id, errcode);
    }
}


void Guest2::WindowUpdateProc(uint32_t id, uint32_t size) {
    if(id){
        if(statusmap.count(id)){
            ReqStatus& status = statusmap[id];
            LOGD(DHTTP2, "<guest2> window size updated [%d]: %d+%d\n", id, status.remotewinsize, size);
            if((uint64_t)status.remotewinsize + size >= (uint64_t)1<<31U){
                Clean(id, HTTP2_ERR_FLOW_CONTROL_ERROR);
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
        if((uint64_t)remotewinsize + size >= (uint64_t)1<<31U){
            ErrProc(HTTP2_ERR_FLOW_CONTROL_ERROR);
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

void Guest2::GoawayProc(const Http2_header* header) {
    Goaway_Frame* goaway = (Goaway_Frame *)(header+1);
    uint32_t errcode = get32(goaway->errcode);
    deleteLater(errcode);
}

void Guest2::ErrProc(int errcode) {
    LOGE("(%s): Guest2 http2 error:0x%08x\n", getsrc(), errcode);
    http2_flag |= HTTP2_FLAG_ERROR;
    deleteLater(errcode);
}

void Guest2::AdjustInitalFrameWindowSize(ssize_t diff) {
    for(auto& i: statusmap){
       i.second.remotewinsize += diff;
    }
}

std::list<Buffer>::insert_iterator Guest2::queue_head() {
    return rwer->buffer_head();
}

std::list<Buffer>::insert_iterator Guest2::queue_end() {
    return rwer->buffer_end();
}

void Guest2::queue_insert(std::list<Buffer>::insert_iterator where, Buffer&& wb) {
    rwer->buffer_insert(where, std::move(wb));
}

void Guest2::deleteLater(uint32_t errcode){
    if((http2_flag & HTTP2_FLAG_GOAWAYED) == 0){
        Goaway(-1, errcode & ERROR_MASK);
    }
    return Server::deleteLater(errcode);
}


void Guest2::dump_stat(Dumper dp, void* param) {
    dp(param, "Guest2 %p, id:%d (%s) (%d/%d)\n",
            this, sendid, getsrc(),
            this->remotewinsize, this->localwinsize);
    dp(param, "  rwer: rlength:%zu, wlength:%zu, stats:%d, event:%s\n",
            rwer->rlength(), rwer->wlength(),
            (int)rwer->getStats(), events_string[(int)rwer->getEvents()]);
    for(auto& i: statusmap){
        dp(param, "0x%x [%" PRIu32 "]: %s %s (%d/%d), flags:0x%08x\n",
                i.first, i.second.req->header->request_id,
                i.second.req->header->method,
                i.second.req->header->geturl().c_str(),
                i.second.remotewinsize, i.second.localwinsize,
                i.second.flags);
    }
}


#ifndef NDEBUG
void Guest2::PingProc(const Http2_header *header){
    LOGD(DHTTP2, "<guest2> ping: window size global: %d/%d\n", localwinsize, remotewinsize);
    return Http2Base::PingProc(header);
}
#endif
