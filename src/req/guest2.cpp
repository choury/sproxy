#include "guest2.h"
#include "res/responser.h"
#include "misc/util.h"
#include "misc/config.h"

#include <assert.h>
#include <inttypes.h>

void Guest2::connection_lost(){
    LOGE("(%s): <guest2> Nothing got too long, so close it\n", rwer->getPeer());
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
    rwer->SetErrorCB([this](int ret, int code){Error(ret, code);});
    rwer->SetReadCB([this](const Buffer& bb) -> size_t {
        LOGD(DHTTP2, "<guest2> (%s) read: len:%zu\n", this->rwer->getPeer(), bb.len);
        if(bb.len == 0){
            //EOF
            deleteLater(NOERROR);
            return 0;
        }
        size_t ret;
        size_t len = bb.len;
        const uchar* data = (const uchar*)bb.data();
        while((len > 0) && (ret = (this->*Http2_Proc)(data, len))){
            len -= ret;
            data += ret;
        }
        if((http2_flag & HTTP2_FLAG_INITED) && localwinsize < 50 *1024 *1024){
            localwinsize += ExpandWindowSize(0, 50*1024*1024);
        }
        this->connection_lost_job = UpdateJob(
                std::move(this->connection_lost_job),
                [this]{connection_lost();}, 1800000);
        return len;
    });
    rwer->SetWriteCB([this](uint64_t id){
        if(statusmap.count(id) == 0){
            return;
        }
        ReqStatus& status = statusmap[id];
        if(wantmore(status)){
            status.res->pull();
        }
    });
}

Guest2::~Guest2() {
}

void Guest2::Error(int ret, int code){
    LOGE("(%s): <guest2> error: %d/%d\n", rwer->getPeer(), ret, code);
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
            status.cleanJob = AddJob(([this, id = bb.id]{Clean(id, NOERROR);}), 0, 0);
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

void Guest2::Handle(uint32_t id, Signal s){
    assert(statusmap.count(id));
    ReqStatus& status = statusmap[id];
    LOGD(DHTTP2, "<guest2> signal [%d] %" PRIu32 ": %d\n",
         (int)id, status.req->header->request_id, (int)s);
    switch(s){
    case CHANNEL_ABORT:
        status.flags |= HTTP_CLOSED_F;
        return Clean(id, HTTP2_ERR_INTERNAL_ERROR);
    }
}

void Guest2::ReqProc(uint32_t id, std::shared_ptr<HttpReqHeader> header) {
    LOGD(DHTTP2, "<guest2> %" PRIu32 " (%s) ReqProc %s\n",
         header->request_id, rwer->getPeer(), header->geturl().c_str());
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
    };
    ReqStatus& status = statusmap[id];

    status.req = std::make_shared<HttpReq>(
            header,
            [this, id](std::shared_ptr<HttpRes> res){response((void*)(long)id, res);},
            [this, &status, id] () mutable{
                auto len = status.req->cap();
                if(len < status.localwinsize){
                    LOGE("[%" PRIu32 "]: <guest2> (%d) shrunken local window: %d/%d\n",
                         status.req->header->request_id, id, len, status.localwinsize);
                }else if(len == status.localwinsize) {
                    return;
                }else if(len - status.localwinsize > FRAMEBODYLIMIT || status.localwinsize <= FRAMEBODYLIMIT/2){
                    LOGD(DHTTP2, "<guest2> (%d) increased local window: %d -> %d\n", id, status.localwinsize, len);
                    status.localwinsize += ExpandWindowSize(id, len - status.localwinsize);
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
        if(status.flags & HTTP_REQ_COMPLETED){
            LOGD(DHTTP2, "<guest2> DateProc after closed, id: %d\n", id);
            Clean(id, HTTP2_ERR_STREAM_CLOSED);
            return;
        }
        if(len > (size_t)status.localwinsize){
            LOGE("[%" PRIu32 "]: <guest2> (%d) window size error %zu/%d\n",
                status.req->header->request_id, id, len, status.localwinsize);
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
            auto header = std::dynamic_pointer_cast<HttpResHeader>(std::get<std::shared_ptr<HttpHeader>>(msg.data));
            LOGD(DHTTP2, "<guest2> get response [%d]: %s\n", id, header->status);
            HttpLog(rwer->getPeer(), status.req->header, header);
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

            if(opt.alt_svc){
                AltSvc(id, "", opt.alt_svc);
            }
            return 1;
        }
        case ChannelMessage::CHANNEL_MSG_DATA: {
            Buffer bb = std::move(std::get<Buffer>(msg.data));
            bb.id = id;
            Recv(std::move(bb));
            return 1;
        }
        case ChannelMessage::CHANNEL_MSG_SIGNAL:
            Handle(id, std::get<Signal>(msg.data));
            return 0;
        }
        return 0;
    }, [this, &status]{return std::min(status.remotewinsize, this->remotewinsize);});
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
        status.req->send(CHANNEL_ABORT);
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
            LOGE("[%" PRIu32 "]: <guest2> (%d): stream reset:%d flags:0x%x\n",
                status.req->header->request_id, id, errcode, status.flags);
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
                status.res->pull();
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
            for(auto& i: statusmap){
                ReqStatus& status = i.second;
                if(wantmore(status)){
                    status.res->pull();
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
    LOGE("(%s): Guest2 http2 error:0x%08x\n", rwer->getPeer(), errcode);
    http2_flag |= HTTP2_FLAG_ERROR;
    deleteLater(errcode);
}

void Guest2::AdjustInitalFrameWindowSize(ssize_t diff) {
    for(auto& i: statusmap){
       i.second.remotewinsize += diff;
    }
}

void Guest2::PushFrame(Buffer&& bb) {
    if(debug[DHTTP2].enabled){
        const Http2_header *header = (const Http2_header *)bb.data();
        uint32_t length = get24(header->length);
        uint32_t id = HTTP2_ID(header->id);
        LOGD(DHTTP2, "<guest2> send a frame [%d]:%d, size:%d, flags:%d\n", id, header->type, length, header->flags);
    }
    rwer->Send(std::move(bb));
}

void Guest2::deleteLater(uint32_t errcode){
    if((http2_flag & HTTP2_FLAG_GOAWAYED) == 0){
        Goaway(recvid, errcode & ERROR_MASK);
    }
    for(auto& i: statusmap){
        if((i.second.flags & HTTP_CLOSED_F) == 0) {
            i.second.req->send(CHANNEL_ABORT);
        }
        i.second.flags |= HTTP_CLOSED_F;
        if(i.second.res){
            i.second.res->detach();
        }
    }
    statusmap.clear();
    return Server::deleteLater(errcode);
}


void Guest2::dump_stat(Dumper dp, void* param) {
    dp(param, "Guest2 %p, id: %d my_window: %d, his_window: %d\n",
            this, sendid, this->localwinsize, this->remotewinsize);
    for(auto& i: statusmap){
        dp(param, "  0x%x [%" PRIu32 "]: %s %s my_window: %d, his_window: %d, time: %dms, flags: 0x%08x [%s]\n",
                i.first, i.second.req->header->request_id,
                i.second.req->header->method,
                i.second.req->header->geturl().c_str(),
                i.second.localwinsize, i.second.remotewinsize,
                getmtime() - i.second.req->header->ctime,
                i.second.flags,
                i.second.req->header->get("User-Agent"));
    }
    rwer->dump_status(dp, param);
}

void Guest2::dump_usage(Dumper dp, void *param) {
    size_t req_usage  = 0;
    for(const auto& i: statusmap) {
        req_usage += sizeof(i.first) + sizeof(i.second);
        req_usage += i.second.req->mem_usage();
    }
    dp(param, "Guest2 %p: %zd, reqmap: %zd, rwer: %zd\n",
       this, sizeof(*this) + header_buffer->cap + hpack_decoder.get_dynamic_table_size() + hpack_encoder.get_dynamic_table_size(),
       req_usage, rwer->mem_usage());
}


#ifndef NDEBUG
void Guest2::PingProc(const Http2_header *header){
    LOGD(DHTTP2, "<guest2> ping: window size global: %d/%d\n", localwinsize, remotewinsize);
    return Http2Base::PingProc(header);
}
#endif
