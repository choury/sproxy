#include "proxy2.h"
#include "req/requester.h"
#include "misc/util.h"
#include "misc/config.h"

#include <assert.h>
#include <inttypes.h>

void Proxy2::connection_lost(){
    LOGE("(%s) <proxy2> the ping timeout, so close it\n", rwer->getPeer());
    deleteLater(PEER_LOST_ERR);
}

void Proxy2::ping_check(){
    char buff[8];
    set64(buff, getutime());
    Ping(buff);
    LOGD(DHTTP2, "<proxy2> ping: window size global: %d/%d\n", localwinsize, remotewinsize);
    connection_lost_job = rwer->updatejob(connection_lost_job, std::bind(&Proxy2::connection_lost, this), 2000);
}

bool Proxy2::wantmore(const ReqStatus& status) {
    if(!status.req){
        return false;
    }
    if((status.flags&HTTP_REQ_COMPLETED)){
        return false;
    }
    return status.remotewinsize > 0;
}


Proxy2::Proxy2(std::shared_ptr<RWer> rwer) {
    this->rwer = rwer;
    rwer->SetErrorCB(std::bind(&Proxy2::Error, this, _1, _2));
    rwer->SetReadCB([this](uint64_t, const void* data, size_t len) -> size_t {
        LOGD(DHTTP2, "<proxy2> (%s) read: len:%zu\n", this->rwer->getPeer(), len);
        if(len == 0){
            //EOF
            deleteLater(NOERROR);
            return 0;
        }
#ifndef __ANDROID__
        this->ping_check_job = this->rwer->updatejob(
                this->ping_check_job,
                std::bind(&Proxy2::ping_check, this), 10000);
#else
        receive_time = getmtime();
#endif
        size_t ret = 0;
        while((len > 0) && (ret = (this->*Http2_Proc)((const uchar*)data, len))){
            len -= ret;
            data = (const char*)data + ret;
        }
        if((http2_flag & HTTP2_FLAG_INITED) && localwinsize < 50 *1024 *1024){
            localwinsize += ExpandWindowSize(0, 50*1024*1024);
        }
        return len;
    });
    rwer->SetWriteCB([this](uint64_t id){
        if(statusmap.count(id) == 0){
            return;
        }
        ReqStatus& status = statusmap[id];
        if(wantmore(status)){
            status.req->pull();
        }
    });
#ifdef __ANDROID__
    receive_time = getmtime();
    ping_time = getmtime();
#endif
}


Proxy2::~Proxy2() {
    //we do this, because deleteLater will not be invoked when vpn_stop
    responsers.erase(this);
}

void Proxy2::Error(int ret, int code) {
    LOGE("(%s) <proxy2> error: %d/%d\n", rwer->getPeer(), ret, code);
    deleteLater(ret);
}

void Proxy2::Recv(Buffer&& bb) {
    assert(statusmap.count(bb.id));
    ReqStatus& status = statusmap[bb.id];
    if(status.flags & HTTP_REQ_COMPLETED) {
        return;
    }
    status.remotewinsize -= bb.len;
    remotewinsize -= bb.len;
    assert(status.remotewinsize >= 0);
    if(bb.len == 0){
        status.flags |= HTTP_REQ_COMPLETED;
        LOGD(DHTTP2, "<proxy2> recv data [%d]: EOF/%d\n", (int)bb.id, status.remotewinsize);
    }else{
        LOGD(DHTTP2, "<proxy2> recv data [%d]: %zu/%d\n", (int)bb.id, bb.len, status.remotewinsize);
    }
    PushData(std::move(bb));
}

void Proxy2::Handle(uint32_t id, ChannelMessage::Signal s) {
    assert(statusmap.count(id));
    ReqStatus& status = statusmap[id];
    LOGD(DHTTP2, "<proxy2> signal [%d] %" PRIu32 ": %d\n",
         (int)id, status.req->header->request_id, (int)s);
    switch(s){
    case ChannelMessage::CHANNEL_ABORT:
        status.flags |= HTTP_CLOSED_F;
        return Clean(id, status, HTTP2_ERR_INTERNAL_ERROR);
    }
}

void Proxy2::PushFrame(Buffer&& bb){
    if(debug[DHTTP2].enabled){
        const Http2_header *header = (const Http2_header *)bb.data();
        uint32_t length = get24(header->length);
        uint32_t id = HTTP2_ID(header->id);
        LOGD(DHTTP2, "<proxy2> send a frame [%d]:%d, size:%d, flags:%d\n", id, header->type, length, header->flags);
    }
#ifdef __ANDROID__
    uint32_t now = getmtime();
    if(http2_flag & HTTP2_FLAG_INITED
        && now - receive_time > 10000
        && now - ping_time > 3000)
    {
        ping_time = now;
        ping_check();
    }
#endif
    rwer->buffer_insert(std::move(bb));
}

void Proxy2::ResProc(uint32_t id, std::shared_ptr<HttpResHeader> header) {
    idle_timeout = this->rwer->updatejob(idle_timeout,std::bind(&Proxy2::deleteLater, this, CONNECT_AGED), 300000);
    if(statusmap.count(id) == 0) {
        LOGD(DHTTP2, "<proxy2> ResProc not found id: %d\n", id);
        Reset(id, HTTP2_ERR_STREAM_CLOSED);
        return;
    }
    ReqStatus& status = statusmap[id];
    if(!header->no_body() && !header->get("Content-Length"))
    {
        header->set("Transfer-Encoding", "chunked");
    }
    if(status.res){
        status.res->send(header);
        return;
    }
    status.res = std::make_shared<HttpRes>(header, [this, &status, id]() mutable{
        auto len = status.res->cap();
        if(len < status.localwinsize){
            LOGE("[%" PRIu32 "]: <proxy2> (%d) shrunken local window: %d/%d\n",
                status.req->header->request_id,
                id, len, status.localwinsize);
        }else if(len == status.localwinsize) {
            return;
        }else if(len - status.localwinsize > FRAMEBODYLIMIT || status.localwinsize <= FRAMEBODYLIMIT/2){
            LOGD(DHTTP2, "<proxy2> [%d] increased local window: %d -> %d\n", id, status.localwinsize, len);
            status.localwinsize += ExpandWindowSize(id, len - status.localwinsize);
        }
    });
    status.req->response(status.res);
}


void Proxy2::DataProc(uint32_t id, const void* data, size_t len) {
    idle_timeout = this->rwer->updatejob(idle_timeout,std::bind(&Proxy2::deleteLater, this, CONNECT_AGED), 300000);
    if(len == 0)
        return;
    localwinsize -= len;
    if(statusmap.count(id)){
        ReqStatus& status = statusmap[id];
        if(status.flags & HTTP_RES_COMPLETED){
            LOGD(DHTTP2, "<proxy2> DataProc after closed, id: %d\n", id);
            Clean(id, status, HTTP2_ERR_STREAM_CLOSED);
            return;
        }
        if(len > (size_t)status.localwinsize){
            LOGE("[%" PRIu32 "]: <proxy2> (%d) window size error %zu/%d\n",
                    status.req->header->request_id, id, len, status.localwinsize);
            Clean(id, status, HTTP2_ERR_FLOW_CONTROL_ERROR);
            return;
        }
        if(status.res == nullptr){
            //compact for legacy version server.
            //it does not send http header for udp,
            //but guest_vpn need it, so we fake one here.
            ResProc(id, UnpackHttpRes(H200));
        }
        status.res->send(data, len);
        status.localwinsize -= len;
    }else{
        LOGD(DHTTP2, "<proxy2> DataProc not found id: %d\n", id);
        Reset(id, HTTP2_ERR_STREAM_CLOSED);
    }
}

void Proxy2::EndProc(uint32_t id) {
    LOGD(DHTTP2, "<proxy2> [%d]: end of stream\n", id);
    if(statusmap.count(id)) {
        ReqStatus &status = statusmap[id];
        assert((status.flags & HTTP_RES_COMPLETED) == 0);
        status.flags |= HTTP_RES_COMPLETED;
        status.res->send(nullptr);
    }
}

void Proxy2::ErrProc(int errcode) {
    LOGE("(%s) <proxy2> Http2 error: 0x%08x\n", rwer->getPeer(), errcode);
    http2_flag |= HTTP2_FLAG_ERROR;
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
        status.res->send(ChannelMessage::CHANNEL_ABORT);
    }else{
        status.req->response(std::make_shared<HttpRes>(UnpackHttpRes(H500), "[[internal error]]"));
    }
    statusmap.erase(id);
}

void Proxy2::RstProc(uint32_t id, uint32_t errcode) {
    if(statusmap.count(id)){
        ReqStatus& status = statusmap[id];
        if(errcode){
            LOGE("[%" PRIu32 "]: <proxy2> (%d): stream reseted: %d\n",
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
                Clean(id, status, HTTP2_ERR_FLOW_CONTROL_ERROR);
                return;
            }
            status.remotewinsize += size;
            if(wantmore(status)){
                status.req->pull();
            }
        }else{
            LOGD(DHTTP2, "<proxy2> window size updated [%d]: not found\n", id);
        }
    }else{
        LOGD(DHTTP2, "<proxy2> window size updated global: %d+%d\n", remotewinsize, size);
        if((uint64_t)remotewinsize + size >= (uint64_t)1<<31){
            ErrProc(HTTP2_ERR_FLOW_CONTROL_ERROR);
            return;
        }
        remotewinsize += size;
        if(remotewinsize == (int32_t)size){
            LOGD(DHTTP2, "<proxy2> active all frame\n");
            auto statusmap_copy = statusmap;
            for(auto& i: statusmap_copy){
                ReqStatus& status = i.second;
                if(wantmore(status)){
                    status.req->pull();
                }
            }
        }
    }
}

void Proxy2::PingProc(const Http2_header *header){
    if(header->flags & HTTP2_ACK_F){
        rwer->deljob(&connection_lost_job);
        double diff = (getutime()-get64(header+1))/1000.0;
        LOG("<proxy2> Get a ping time=%.3fms\n", diff);
        if(diff >= 1000){
            LOGE("(%s) <proxy2> The ping time too long!\n", rwer->getPeer());
        }
    }
    Http2Base::PingProc(header);
}

void Proxy2::request(std::shared_ptr<HttpReq> req, Requester*) {
    uint32_t id = OpenStream();
    assert((http2_flag & HTTP2_FLAG_GOAWAYED) == 0);
    LOGD(DHTTP2, "<proxy2> request: %s [%d]\n", req->header->geturl().c_str(), id);
    statusmap[id] = ReqStatus{
       req,
       nullptr,
       (int32_t)remoteframewindowsize,
       localframewindowsize,
       0,
    };
    ReqStatus& status = statusmap[id];

    auto buff = std::make_shared<Block>(BUF_LEN);
    Http2_header* const header = (Http2_header *)buff->data();
    memset(header, 0, sizeof(*header));
    header->type = HTTP2_STREAM_HEADERS;
    header->flags = HTTP2_END_HEADERS_F;
    if(req->header->no_body()) {
        header->flags |= HTTP2_END_STREAM_F;
        status.flags |= HTTP_REQ_COMPLETED;
    }
    set32(header->id, id);
    size_t len = hpack_encoder.PackHttp2Req(req->header, header+1, BUF_LEN - sizeof(Http2_header));
    set24(header->length, len);
    PushFrame(Buffer{buff, len + sizeof(Http2_header)});

    req->attach([this, id](ChannelMessage& msg){
        idle_timeout = this->rwer->updatejob(idle_timeout,std::bind(&Proxy2::deleteLater, this, CONNECT_AGED), 300000);
        switch(msg.type){
        case ChannelMessage::CHANNEL_MSG_HEADER:
            LOGD(DHTTP2, "<proxy2> ignore header for req\n");
            return 1;
        case ChannelMessage::CHANNEL_MSG_DATA:
            msg.data.id = id;
            Recv(std::move(msg.data));
            return 1;
        case ChannelMessage::CHANNEL_MSG_SIGNAL:
            Handle(id, msg.signal);
            return 0;
        }
        return 0;
    }, [this, &status]{return std::min(status.remotewinsize, this->remotewinsize);});
}

void Proxy2::init(std::shared_ptr<HttpReq> req) {
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

void Proxy2::deleteLater(uint32_t errcode){
    responsers.erase(this);
    rwer->deljob(&idle_timeout);
    auto statusmapCopy = statusmap;
    for(auto& i: statusmapCopy){
        Clean(i.first, i.second, errcode);
    }
    assert(statusmap.empty());
    if((http2_flag & HTTP2_FLAG_GOAWAYED) == 0){
        Goaway(recvid, errcode);
    }
    Server::deleteLater(errcode);
}

void Proxy2::dump_stat(Dumper dp, void* param) {
    dp(param, "Proxy2 %p id: %d, my_window: %d, his_window: %d\n",
            this, sendid, this->localwinsize, this->remotewinsize);
    for(auto& i: statusmap){
        dp(param, "  0x%x [%" PRIu32 "]: %s, my_window: %d, his_window: %d, flags: 0x%08x\n",
                i.first,
                i.second.req->header->request_id,
                i.second.req->header->geturl().c_str(),
                i.second.localwinsize, i.second.remotewinsize,
                i.second.flags);
    }
    rwer->dump_status(dp, param);
}

void Proxy2::dump_usage(Dumper dp, void *param) {
    size_t res_usage  = 0;
    for(const auto& i: statusmap) {
        res_usage += sizeof(i.first) + sizeof(i.second);
        if(i.second.res) {
            res_usage += i.second.res->mem_usage();
        }
    }
    dp(param, "Proxy2 %p: %zd, resmap: %zd, rwer: %zd\n",
       this, sizeof(*this) + header_buffer->cap + hpack_decoder.get_dynamic_table_size() + hpack_encoder.get_dynamic_table_size(),
       res_usage, rwer->mem_usage());
}