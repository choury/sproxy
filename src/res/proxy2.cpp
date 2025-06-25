#include "proxy2.h"
#include "common/common.h"
#include "prot/memio.h"
#include "req/requester.h"
#include "misc/hook.h"

#include <assert.h>
#include <inttypes.h>

void Proxy2::connection_lost(){
    LOGE("(%s) <proxy2> the ping timeout, so close it\n", dumpDest(rwer->getDst()).c_str());
    deleteLater(PEER_LOST_ERR);
}

void Proxy2::ping_check(){
    char buff[8];
    set64(buff, getutime());
    Ping(buff);
    LOGD(DHTTP2, "<proxy2> ping: window size global: %d/%d\n", localwinsize, remotewinsize);
    connection_lost_job = UpdateJob(std::move(connection_lost_job),
                                    [this]{connection_lost();}, 2000);
}

void Proxy2::setIdle(uint32_t ms){
    idle_timeout = UpdateJob(std::move(idle_timeout), [this]{deleteLater(CONNECT_AGED);}, ms);
}

bool Proxy2::wantmore(const ReqStatus& status) {
    if(status.flags & (HTTP_REQ_COMPLETED | HTTP_CLOSED_F | HTTP_RST)){
        return false;
    }
    return status.remotewinsize > 0;
}


Proxy2::Proxy2(std::shared_ptr<RWer> rwer) {
    this->rwer = rwer;
    //readCB has moved to init()
    cb = IRWerCallback::create()->onError([this](int ret, int code){
        Error(ret, code);}
    )->onWrite([this](uint64_t id){
        if(statusmap.count(id) == 0){
            return;
        }
        ReqStatus& status = statusmap[id];
        if(wantmore(status)){
            status.rw->Unblock(id);
        }
    });
#ifdef __ANDROID__
    receive_time = getmtime();
    ping_time = getmtime();
#endif
    rwer->SetCallback(cb);
}


Proxy2::~Proxy2() {
    //we do this, because deleteLater will not be invoked when vpn_stop
    responsers.erase(this);
}

void Proxy2::Error(int ret, int code) {
    LOGE("(%s) <proxy2> error: %d/%d\n", dumpDest(rwer->getDst()).c_str(), ret, code);
    deleteLater(ret);
}

void Proxy2::SendData(Buffer&& bb){
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
    rwer->Send(std::move(bb));
}

void Proxy2::ResProc(uint32_t id, std::shared_ptr<HttpResHeader> header) {
    if(statusmap.count(id) == 0) {
        LOGD(DHTTP2, "<proxy2> ResProc not found id: %d\n", id);
        Reset(id, HTTP2_ERR_STREAM_CLOSED);
        return;
    }
    ReqStatus& status = statusmap[id];
    header->request_id = status.req->request_id;
    if(status.req->ismethod("CONNECT")) {
        header->markTunnel();
    }else if(strcmp(status.req->Dest.protocol, "websocket") == 0){
        header->markWebsocket(status.req->get("Sec-WebSocket-Key"));
    }else if(!header->no_body() && !header->get("Content-Length")) {
        header->set("Transfer-Encoding", "chunked");
    }
    status.rw->SendHeader(header);
    status.flags |= HTTP_RESPOENSED;
}


void Proxy2::DataProc(Buffer&& bb) {
    HOOK_FUNC(this, statusmap, bb);
    if(bb.len == 0)
        return;
    if ((int)bb.len > localwinsize) {
        LOG("<proxy2> global window size error %zu/%d\n", bb.len, localwinsize);
        ErrProc(HTTP2_ERR_FLOW_CONTROL_ERROR);
        return;
    }
    localwinsize -= bb.len;
    if(statusmap.count(bb.id)){
        ReqStatus& status = statusmap[bb.id];
        if(status.flags & HTTP_RES_COMPLETED){
            LOG("<proxy2> DataProc after closed, id: %" PRIu64"\n", bb.id);
            status.cleanJob = AddJob(([this, id = bb.id]{Clean(id, HTTP2_ERR_STREAM_CLOSED);}), 0, 0);
            return;
        }
        if(bb.len > (size_t)status.localwinsize){
            LOG("[%" PRIu64 "]: <proxy2> (%" PRIu64") window size error %zu/%d\n",
                    status.req->request_id, bb.id, bb.len, status.localwinsize);
            status.cleanJob = AddJob(([this, id = bb.id]{Clean(id, HTTP2_ERR_FLOW_CONTROL_ERROR);}), 0, 0);
            return;
        }
        if((status.flags & HTTP_RESPOENSED) == 0){
            //compact for legacy version server.
            //it does not send http header for udp,
            //but guest_vpn need it, so we fake one here.
            ResProc(bb.id, HttpResHeader::create(S200, sizeof(S200), status.req->request_id));
        }
        status.localwinsize -= bb.len;
        int cap = status.rw->cap(bb.id);
        if ((status.buffer && status.buffer->length() > 0) || (cap < (int)bb.len)) {
            //把多余的数据放到buffer里
            if(status.buffer == nullptr){
                status.buffer = std::make_unique<EBuffer>();
            }
            LOGD(DHTTP2, "<proxy2> DataProc put buffer [%" PRIu64"]: %zu/%d\n", bb.id, bb.len, cap);
            if(status.buffer->put((char*)bb.data(), bb.len) < 0){
                abort();
            }
            if(cap <= 0) {
                return;
            }
            auto id = bb.id;
            bb = status.buffer->get(cap);
            bb.id = id;
            status.buffer->consume(bb.len);
        }
        status.rw->Send(std::move(bb));
    }else{
        LOGD(DHTTP2, "<proxy2> DataProc not found id: %" PRIu64"\n", bb.id);
        Reset(bb.id, HTTP2_ERR_STREAM_CLOSED);
    }
}

void Proxy2::EndProc(uint32_t id) {
    LOGD(DHTTP2, "<proxy2> [%d]: end of stream\n", id);
    if(statusmap.count(id)) {
        ReqStatus &status = statusmap[id];
        assert((status.flags & HTTP_RES_COMPLETED) == 0);
        status.flags |= HTTP_RES_COMPLETED;
        if(status.buffer == nullptr || status.buffer->length() == 0){
            status.rw->Send(Buffer{nullptr, (uint64_t)id});
        }
    }
}

void Proxy2::ErrProc(int errcode) {
    LOGE("(%s) <proxy2> Http2 error: 0x%08x\n", dumpDest(rwer->getDst()).c_str(), errcode);
    http2_flag |= HTTP2_FLAG_ERROR;
    deleteLater(errcode);
}

void Proxy2::Clean(uint32_t id, uint32_t errcode){
    if(statusmap.count(id) == 0){
        return;
    }

    ReqStatus& status = statusmap[id];
    if((status.flags & HTTP_RST) == 0 && ((status.flags&HTTP_REQ_COMPLETED) == 0 || (status.flags&HTTP_RES_COMPLETED) == 0)){
        Reset(id, errcode);
    }

    status.rw->SetCallback(nullptr);
    if(status.flags & (HTTP_CLOSED_F | HTTP_RESPOENSED)){
        //do nothing.
    } else {
        response(status.rw, HttpResHeader::create(S500, sizeof(S500), status.req->request_id), "[[internal error]]");
    }
    status.rw->Close();
    statusmap.erase(id);
    if(statusmap.empty()) {
        LOG("(%s) has no request, start idle timer\n", dumpDest(rwer->getDst()).c_str());
        setIdle(300000);
    }
}

void Proxy2::RstProc(uint32_t id, uint32_t errcode) {
    Http2Requster::RstProc(id, errcode);
    if(statusmap.count(id)){
        ReqStatus& status = statusmap[id];
        if(errcode){
            LOGE("[%" PRIu64 "]: <proxy2> (%d): stream reset:%d flags:0x%x\n",
                 status.req->request_id, id, errcode, status.flags);
        }
        status.flags |= HTTP_RST;
        status.cleanJob = AddJob(([this, id, errcode]{Clean(id, errcode);}), 0, 0);
    }
}

void Proxy2::WindowUpdateProc(uint32_t id, uint32_t size){
    if(id){
        if(statusmap.count(id)){
            ReqStatus& status = statusmap[id];
            LOGD(DHTTP2, "<proxy2> window size updated [%d]: %d+%d\n", id, status.remotewinsize, size);
            if((uint64_t)status.remotewinsize + size >= (uint64_t)1<<31){
                status.cleanJob = AddJob(([this, id]{Clean(id, HTTP2_ERR_FLOW_CONTROL_ERROR);}), 0, 0);
                return;
            }
            status.remotewinsize += size;
            if(wantmore(status)){
                status.rw->Unblock(id);
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
            for(auto& i: statusmap){
                ReqStatus& status = i.second;
                if(wantmore(status)){
                    status.rw->Unblock(0);
                }
            }
        }
    }
}

void Proxy2::PingProc(const Http2_header *header){
    if(header->flags & HTTP2_ACK_F){
        connection_lost_job.reset(nullptr);
        double diff = (getutime()-get64(header+1))/1000.0;
        LOG("<proxy2> Get a ping time=%.3fms\n", diff);
        if(diff >= 1000){
            LOGE("(%s) <proxy2> The ping time too long!\n", dumpDest(rwer->getDst()).c_str());
        }
    }
    Http2Base::PingProc(header);
}

void Proxy2::request(std::shared_ptr<HttpReqHeader> req, std::shared_ptr<MemRWer> rw, Requester*) {
    uint32_t id = OpenStream();
    assert((http2_flag & HTTP2_FLAG_GOAWAYED) == 0);
    LOGD(DHTTP2, "<proxy2> request: %s [%d]\n", req->geturl().c_str(), id);
    statusmap[id] = ReqStatus{
       req,
       rw,
       nullptr,
       (int32_t)remoteframewindowsize,
       localframewindowsize,
       0,
    };
    ReqStatus& status = statusmap[id];

    Block buff(BUF_LEN);
    Http2_header* const header = (Http2_header *)buff.data();
    memset(header, 0, sizeof(*header));
    header->type = HTTP2_STREAM_HEADERS;
    header->flags = HTTP2_END_HEADERS_F;
    if(req->no_body()) {
        header->flags |= HTTP2_END_STREAM_F;
        status.flags |= HTTP_REQ_COMPLETED;
    }
    set32(header->id, id);
    size_t len = hpack_encoder.PackHttp2Req(req, header+1, BUF_LEN - sizeof(Http2_header));
    set24(header->length, len);
    SendData(Buffer{std::move(buff), len + sizeof(Http2_header), id});

    status.cb = IRWerCallback::create()->onRead([this, id](Buffer&& bb) -> size_t {
        ReqStatus& status = statusmap.at(id);
        if(status.flags & HTTP_REQ_COMPLETED) {
            return 0;
        }
        bb.id = id;
        if(bb.len == 0){
            status.flags |= HTTP_REQ_COMPLETED;
            LOGD(DHTTP2, "<proxy2> recv data [%d]: EOF/%d\n", (int)bb.id, status.remotewinsize);
            PushData({nullptr, 0, id});
            return 0;
        }
        LOGD(DHTTP2, "<proxy2> recv data [%d]: %zu/%d\n", (int)bb.id, bb.len, status.remotewinsize);
        if(status.remotewinsize <= 0 || remotewinsize <= 0) {
            return 0;
        }
        auto len = std::min({bb.len, (size_t)status.remotewinsize, (size_t)remotewinsize});
        bb.truncate(len);
        status.remotewinsize -= len;
        remotewinsize -= len;
        PushData(std::move(bb));
        return len;
    })->onWrite([this, id](uint64_t){
        ReqStatus& status = statusmap.at(id);
        auto cap = status.rw->cap(id);
        if(cap <= 0) {
            return;
        }
        if(status.buffer && status.buffer->length() > 0){
            auto bb = status.buffer->get(cap);
            bb.id = id;
            status.buffer->consume(bb.len);
            cap -= bb.len;
            status.rw->Send(std::move(bb));
            if(status.buffer->length() == 0 && (status.flags & HTTP_RES_COMPLETED)) {
                status.rw->Send(Buffer{nullptr, (uint64_t)id});
            }
        }
        int delta =  (status.buffer ?  MAX_BUF_LEN - (int)status.buffer->length(): MAX_BUF_LEN) - status.localwinsize;
        if(delta < FRAMEBODYLIMIT/2){
            return;
        }
        rwer->Unblock(id);
        if(delta > FRAMEBODYLIMIT && status.localwinsize <= MAX_BUF_LEN/2){
            LOGD(DHTTP2, "<proxy2> [%d] increased local window: %d -> %d\n",
                 (uint32_t)id, status.localwinsize, status.localwinsize + delta);
            status.localwinsize += ExpandWindowSize(id, delta);
        }
    })->onError([this, id](int ret, int code){
        ReqStatus& status = statusmap.at(id);
        LOGD(DHTTP2, "<proxy2> signal [%d] %" PRIu64 " error %d:%d\n",
             (int)id, status.req->request_id, ret, code);
        status.flags |= HTTP_CLOSED_F;
        return Clean(id, HTTP2_ERR_INTERNAL_ERROR);
    });
    status.rw->SetCallback(status.cb);
    idle_timeout.reset();
}

void Proxy2::init(bool enable_push, std::shared_ptr<HttpReqHeader> req, std::shared_ptr<MemRWer> rw) {
    Http2Requster::init(enable_push);
    if(req) {
        request(req, rw, nullptr);
    }
    cb->onRead([this](Buffer&& bb) -> size_t {
        HOOK_FUNC(this, statusmap, bb);
        uint32_t start = getmtime();
        LOGD(DHTTP2, "<proxy2> (%s) read: len:%zu, refs: %zd\n", dumpDest(this->rwer->getDst()).c_str(), bb.len, bb.refs());
        if(bb.len == 0){
            //EOF
            deleteLater(NOERROR);
            return 0;
        }
#ifndef __ANDROID__
        this->ping_check_job = UpdateJob(
                std::move(this->ping_check_job),
                [this]{ping_check();}, 10000);
#else
        receive_time = getmtime();
#endif
        size_t ret = 0;
        size_t len = 0;
        while((bb.len > 0) && (ret = (this->*Http2_Proc)(bb))){
            len += ret;
        }
        if((http2_flag & HTTP2_FLAG_INITED) && localwinsize < 10 * 1024 *1024){
            localwinsize += ExpandWindowSize(0, 10*1024*1024);
        }
        if(statusmap.count(bb.id)) {
            auto& status = statusmap[bb.id];
            if((status.flags & HTTP_RECV_1ST_BYTE) == 0){
                status.req->tracker.emplace_back("ttfb", start);
                status.flags |= HTTP_RECV_1ST_BYTE;
            }
        }
        return len;
    });
}


void Proxy2::GoawayProc(const Http2_header* header){
    Http2Requster::GoawayProc(header);
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
    std::set<uint32_t> keys;
    std::for_each(statusmap.begin(), statusmap.end(), [&keys](auto&& i){ keys.emplace(i.first);});
    for(auto& i: keys){
        Clean(i, errcode);
    }
    idle_timeout.reset();
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
        dp(param, "  0x%x [%" PRIu64 "]: %s %s, my_window: %d, his_window: %d, cap: %d, buffered: %d, flags: 0x%08x\n",
                i.first,
                i.second.req->request_id,
                i.second.req->method,
                i.second.req->geturl().c_str(),
                i.second.localwinsize, i.second.remotewinsize,
                i.second.rw ? (int)i.second.rw->cap(i.first) : 0,
                i.second.buffer ? (int)i.second.buffer->length() : 0,
                i.second.flags);
    }
    rwer->dump_status(dp, param);
}

void Proxy2::dump_usage(Dumper dp, void *param) {
    size_t res_usage  = 0;
    for(const auto& i: statusmap) {
        res_usage += sizeof(i.first) + sizeof(i.second);
        if(i.second.rw) {
            res_usage += i.second.rw->mem_usage();
        }
        if(i.second.buffer) {
            res_usage += i.second.buffer->cap();
        }
    }
    dp(param, "Proxy2 %p: %zd, resmap: %zd, rwer: %zd\n",
       this, sizeof(*this) + (header_buffer ? header_buffer->cap:0) + hpack_decoder.get_dynamic_table_size() + hpack_encoder.get_dynamic_table_size(),
       res_usage, rwer->mem_usage());
}
