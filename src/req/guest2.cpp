#include "guest2.h"
#include "res/responser.h"
#include "misc/config.h"
#include "misc/hook.h"
#include "prot/netio.h"

#include <assert.h>
#include <inttypes.h>

void Guest2::connection_lost(){
    LOGE("(%s): <guest2> Nothing got too long, so close it\n", dumpDest(rwer->getSrc()).c_str());
    deleteLater(PEER_LOST_ERR);
}

bool Guest2::wantmore(const ReqStatus& status) {
    if(status.flags&(HTTP_RES_COMPLETED | HTTP_CLOSED_F | HTTP_RST)){
        return false;
    }
    return status.remotewinsize > 0;
}


Guest2::Guest2(std::shared_ptr<RWer> rwer): Requester(rwer) {
    cb = ISocketCallback::create()->onRead([this](Buffer&& bb) -> size_t {
        HOOK_FUNC(this, statusmap, bb);
        LOGD(DHTTP2, "<guest2> (%s) read: len:%zu\n", dumpDest(this->rwer->getSrc()).c_str(), bb.len);
        if(bb.len == 0){
            //EOF
            deleteLater(NOERROR);
            return 0;
        }
        size_t ret = 0;
        size_t len = 0;
        while((bb.len > 0) && (ret = (this->*Http2_Proc)(bb))){
            len += ret;
        }
        if((http2_flag & HTTP2_FLAG_INITED) && localwinsize < 10 * 1024 *1024){
            localwinsize += ExpandWindowSize(0, 10*1024*1024);
        }
        this->connection_lost_job = UpdateJob(
                std::move(this->connection_lost_job),
                [this]{connection_lost();}, 1800000);
        return len;
    })->onWrite([this](uint64_t id){
        if(statusmap.count(id) == 0){
            return;
        }
        ReqStatus& status = statusmap[id];
        if(wantmore(status)){
            status.rw->pull(id);
        }
    })->onError([this](int ret, int code){
        Error(ret, code);
    });
    rwer->SetCallback(cb);
}

Guest2::~Guest2() {
}

void Guest2::Error(int ret, int code){
    LOGE("(%s): <guest2> error: %d/%d\n", dumpDest(rwer->getSrc()).c_str(), ret, code);
    deleteLater(ret);
}

size_t Guest2::Recv(Buffer&& bb){
    ReqStatus& status = statusmap.at(bb.id);
    assert((status.flags & HTTP_RES_COMPLETED) == 0);
    if(bb.len == 0){
        LOGD(DHTTP2, "<guest2> %" PRIu64 " recv data [%d]: EOF/%d\n",
             status.req->request_id, (int)bb.id, status.remotewinsize);
        PushData({nullptr, bb.id});
        status.flags |= HTTP_RES_COMPLETED;
        if(status.flags & HTTP_REQ_COMPLETED){
            status.cleanJob = AddJob(([this, id = bb.id]{Clean(id, NOERROR);}), 0, 0);
        }
        return 0;
    }
    LOGD(DHTTP2, "<guest2> %" PRIu64 " recv data [%d]: %zu/%d\n",
            status.req->request_id, (int)bb.id, bb.len, status.remotewinsize);
    if(status.remotewinsize <= 0 || remotewinsize <= 0) {
        return 0;
    }
    auto len = std::min({bb.len, (size_t)status.remotewinsize, (size_t)remotewinsize});
    bb.truncate(len);
    status.remotewinsize -= bb.len;
    remotewinsize -= bb.len;
    if(status.req->ismethod("HEAD")){
        LOGD(DHTTP2, "<guest2> %" PRIu64 " recv data [%d], HEAD req discard body\n",
                status.req->request_id, (int)bb.id);
        return len;
    }
    PushData(std::move(bb));
    return len;
}

void Guest2::ReqProc(uint32_t id, std::shared_ptr<HttpReqHeader> header) {
    LOGD(DHTTP2, "<guest2> %" PRIu64 " (%s) ReqProc %s\n",
         header->request_id, dumpDest(rwer->getSrc()).c_str(), header->geturl().c_str());
    if(statusmap.count(id)){
        LOGD(DHTTP2, "<guest2> ReqProc dup id: %d\n", id);
        Reset(id, HTTP2_ERR_STREAM_CLOSED);
        return;
    }

    auto _cb = response(id);
    statusmap[id] = ReqStatus{
        header,
        std::make_shared<MemRWer>(rwer->getSrc(), _cb),
        _cb,
        (int32_t)remoteframewindowsize,
        localframewindowsize,
    };
    ReqStatus& status = statusmap[id];
    distribute(status.req, status.rw, this);
}

void Guest2::DataProc(Buffer&& bb) {
    HOOK_FUNC(this, statusmap, bb);
    if(bb.len == 0)
        return;
    if ((int)bb.len > localwinsize) {
        LOG("<guest2> global window size error %zu/%d\n", bb.len, localwinsize);
        ErrProc(HTTP2_ERR_FLOW_CONTROL_ERROR);
        return;
    }
    localwinsize -= bb.len;
    if(statusmap.count(bb.id)){
        ReqStatus& status = statusmap[bb.id];
        if(status.flags & HTTP_REQ_COMPLETED){
            LOG("<guest2> DateProc after closed, id: %" PRIu64"\n", bb.id);
            status.cleanJob = AddJob(([this, id = bb.id]{Clean(id, HTTP2_ERR_STREAM_CLOSED);}), 0, 0);
            return;
        }
        if(bb.len > (size_t)status.localwinsize){
            LOG("[%" PRIu64 "]: <guest2> (%" PRIu64") window size error %zu/%d\n",
                status.req->request_id, bb.id, bb.len, status.localwinsize);
            status.cleanJob = AddJob(([this, id = bb.id]{Clean(id, HTTP2_ERR_FLOW_CONTROL_ERROR);}), 0, 0);
            return;
        }
        status.localwinsize -= bb.len;
        auto cap = status.rw->bufsize();
        if ((status.buffer && status.buffer->length() > 0) || (cap < bb.len)) {
            //把多余的数据放到buffer里
            if(status.buffer == nullptr){
                status.buffer = std::make_unique<EBuffer>();
            }
            LOGD(DHTTP2, "<guest2> DataProc put buffer [%" PRIu64"]: %zu/%zd\n", bb.id, bb.len, cap);
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
        status.rw->push_data(std::move(bb));
    }else{
        LOGD(DHTTP2, "<guest2> DateProc not found id: %" PRIu64"\n", bb.id);
        Reset(bb.id, HTTP2_ERR_STREAM_CLOSED);
    }
}

void Guest2::EndProc(uint32_t id) {
    LOGD(DHTTP2, "<guest2> [%d]: end of stream\n", id);
    if(statusmap.count(id) == 0){
        return;
    }
    ReqStatus& status = statusmap[id];
    status.flags |= HTTP_REQ_COMPLETED;
    if(status.buffer == nullptr || status.buffer->length() == 0){
        status.rw->push_data(Buffer{nullptr, (uint64_t)id});
        if(status.flags & HTTP_RES_COMPLETED){
            status.cleanJob = AddJob(([this, id]{Clean(id, NOERROR);}), 0, 0);
        }
    }
}

std::shared_ptr<IMemRWerCallback> Guest2::response(uint64_t id) {
    return IMemRWerCallback::create()->onHeader([this, id](std::shared_ptr<HttpResHeader> res){
        ReqStatus& status = statusmap.at(id);
        status.req->tracker.emplace_back("header", getmtime());
        LOGD(DHTTP2, "<guest2> get response [%" PRIu64"]: %s\n", id, res->status);
        HttpLog(dumpDest(rwer->getSrc()), status.req, res);

        Block buff(BUF_LEN);
        Http2_header* const h2header = (Http2_header*) buff.data();
        memset(h2header, 0, sizeof(*h2header));
        h2header->type = HTTP2_STREAM_HEADERS;
        h2header->flags = HTTP2_END_HEADERS_F;
        set32(h2header->id, id);
        size_t len = hpack_encoder.PackHttp2Res(res, h2header + 1, BUF_LEN - sizeof(Http2_header));
        set24(h2header->length, len);
        SendData(Buffer{std::move(buff), len + sizeof(Http2_header), id});

        if(opt.alt_svc){
            AltSvc(id, "", opt.alt_svc);
        }
    })->onData([this, id](Buffer bb) -> size_t {
        bb.id = id;
        return Recv(std::move(bb));
    })->onSignal([this, id](Signal s) {
        ReqStatus& status = statusmap.at(id);
        LOGD(DHTTP2, "<guest2> signal [%d] %" PRIu64 ": %d\n",
            (int)id, status.req->request_id, (int)s);
        switch(s){
        case CHANNEL_ABORT:
            status.flags |= HTTP_CLOSED_F;
            status.cleanJob = AddJob(([this, id]{Clean(id, HTTP2_ERR_INTERNAL_ERROR);}), 0, 0);
            return;
        }
    })->onWrite([this, id](uint64_t){
        ReqStatus& status = statusmap.at(id);
        auto cap = status.rw->bufsize();
        if(cap <= 0) {
            return;
        }
        if(status.buffer && status.buffer->length() > 0){
            auto bb = status.buffer->get(cap);
            bb.id = id;
            status.buffer->consume(bb.len);
            cap -= bb.len;
            status.rw->push_data(std::move(bb));
            if(status.buffer->length() == 0 && (status.flags & HTTP_REQ_COMPLETED)) {
                status.rw->push_data(Buffer{nullptr, (uint64_t)id});
                if(status.flags & HTTP_RES_COMPLETED){
                    status.cleanJob = AddJob(([this, id]{Clean(id, NOERROR);}), 0, 0);
                }
            }
        }
        int delta = (status.buffer ? MAX_BUF_LEN - (int)status.buffer->length(): MAX_BUF_LEN) - status.localwinsize;
        if(delta < FRAMEBODYLIMIT/2){
            return;
        }
        rwer->Unblock(id);
        if(delta > FRAMEBODYLIMIT && status.localwinsize <= MAX_BUF_LEN/2){
            LOGD(DHTTP2, "<guest2> [%" PRIu64"] increased local window: %d -> %d\n", id, status.localwinsize, status.localwinsize + delta);
            status.localwinsize += ExpandWindowSize(id, delta);
        }
    })->onCap([this, id]() -> ssize_t{
        ReqStatus& status = statusmap.at(id);
        return std::min(status.remotewinsize, this->remotewinsize);
    });
}

void Guest2::Clean(uint32_t id, uint32_t errcode) {
    if(statusmap.count(id) == 0){
        return;
    }
    ReqStatus& status = statusmap[id];
    if((status.flags & HTTP_RST) == 0 && ((status.flags&HTTP_REQ_COMPLETED) == 0 || (status.flags&HTTP_RES_COMPLETED) == 0)){
        Reset(id, errcode);
    }
    if((status.flags & HTTP_CLOSED_F) == 0){
        status.rw->push_signal(CHANNEL_ABORT);
    }
    statusmap.erase(id);
}

void Guest2::RstProc(uint32_t id, uint32_t errcode) {
    Http2Responser::RstProc(id, errcode);
    if(statusmap.count(id)){
        ReqStatus& status = statusmap[id];
        if(errcode){
            LOGE("[%" PRIu64 "]: <guest2> (%d): stream reset:%d flags:0x%x\n",
                status.req->request_id, id, errcode, status.flags);
        }
        status.flags |= HTTP_RST;
        Clean(id, errcode);
    }
}


void Guest2::WindowUpdateProc(uint32_t id, uint32_t size) {
    if(id){
        if(statusmap.count(id)){
            ReqStatus& status = statusmap[id];
            LOGD(DHTTP2, "<guest2> window size updated [%d]: %d+%d\n", id, status.remotewinsize, size);
            if((uint64_t)status.remotewinsize + size >= (uint64_t)1<<31U){
                status.cleanJob = AddJob(([this, id]{Clean(id, HTTP2_ERR_FLOW_CONTROL_ERROR);}), 0, 0);
                return;
            }
            status.remotewinsize += size;
            if(wantmore(status)){
                status.rw->pull(id);
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
                    status.rw->pull(i.first);
                }
            }
        }
    }
}

void Guest2::GoawayProc(const Http2_header* header) {
    Http2Responser::GoawayProc(header);
    Goaway_Frame* goaway = (Goaway_Frame *)(header+1);
    uint32_t errcode = get32(goaway->errcode);
    deleteLater(errcode);
}

void Guest2::ErrProc(int errcode) {
    LOGE("(%s): Guest2 http2 error:0x%08x\n", dumpDest(rwer->getSrc()).c_str(), errcode);
    http2_flag |= HTTP2_FLAG_ERROR;
    deleteLater(errcode);
}

void Guest2::AdjustInitalFrameWindowSize(ssize_t diff) {
    for(auto& i: statusmap){
       i.second.remotewinsize += diff;
    }
}

void Guest2::SendData(Buffer&& bb) {
    rwer->Send(std::move(bb));
}

void Guest2::deleteLater(uint32_t errcode){
    if((http2_flag & HTTP2_FLAG_GOAWAYED) == 0){
        Goaway(recvid, errcode & ERROR_MASK);
    }
    for(auto& i: statusmap){
        if((i.second.flags & HTTP_CLOSED_F) == 0) {
            i.second.rw->push_signal(CHANNEL_ABORT);
        }
        i.second.flags |= HTTP_CLOSED_F;
    }
    return Server::deleteLater(errcode);
}


void Guest2::dump_stat(Dumper dp, void* param) {
    dp(param, "Guest2 %p, id: %d my_window: %d, his_window: %d\n",
            this, sendid, this->localwinsize, this->remotewinsize);
    for(auto& i: statusmap){
        dp(param, "  0x%x [%" PRIu64 "]: %s %s my_window: %d, his_window: %d, cap: %d, buffered: %d, time: %dms, flags: 0x%08x [%s]\n",
                i.first, i.second.req->request_id,
                i.second.req->method,
                i.second.req->geturl().c_str(),
                i.second.localwinsize, i.second.remotewinsize,
                (int)i.second.rw->bufsize(),
                i.second.buffer ? (int)i.second.buffer->length() : 0,
                getmtime() - std::get<1>(i.second.req->tracker[0]),
                i.second.flags,
                i.second.req->get("User-Agent"));
    }
    rwer->dump_status(dp, param);
}

void Guest2::dump_usage(Dumper dp, void *param) {
    size_t req_usage  = 0;
    for(const auto& i: statusmap) {
        req_usage += sizeof(i.first) + sizeof(i.second);
        req_usage += i.second.req->mem_usage();
        if(i.second.buffer) {
            req_usage += i.second.buffer->cap();
        }
    }
    dp(param, "Guest2 %p: %zd, reqmap: %zd, rwer: %zd\n",
       this, sizeof(*this) + (header_buffer ? header_buffer->cap : 0) + hpack_decoder.get_dynamic_table_size() + hpack_encoder.get_dynamic_table_size(),
       req_usage, rwer->mem_usage());
}


#ifndef NDEBUG
void Guest2::PingProc(const Http2_header *header){
    LOGD(DHTTP2, "<guest2> ping: window size global: %d/%d\n", localwinsize, remotewinsize);
    return Http2Base::PingProc(header);
}
#endif
