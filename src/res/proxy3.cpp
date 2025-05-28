#include "proxy3.h"
#include "misc/hook.h"

#include <assert.h>
#include <inttypes.h>


Proxy3::Proxy3(std::shared_ptr<QuicRWer> rwer){
    this->rwer = rwer;
    cb = IRWerCallback::create()->onRead([this](Buffer&& bb) -> size_t {
        HOOK_FUNC(this, statusmap, bb);
        LOGD(DHTTP3, "<proxy3> (%s) read [%" PRIu64"]: len:%zu\n", dumpDest(this->rwer->getSrc()).c_str(), bb.id, bb.len);
        if(bb.len == 0){
            //fin
            if(ctrlid_remote && bb.id == ctrlid_remote){
                Error(PROTOCOL_ERR, HTTP3_ERR_CLOSED_CRITICAL_STREAM);
                return 0;
            }
            if(!statusmap.count(bb.id)){
                return 0;
            }
            ReqStatus& status = statusmap[bb.id];
            LOGD(DHTTP3, "<proxy3> [%" PRIu64 "]: end of stream\n", bb.id);
            assert((status.flags & HTTP_RES_COMPLETED) == 0);
            status.flags |= HTTP_RES_COMPLETED;
            status.res->send(Buffer{nullptr, bb.id});
            return 0;
        }

        size_t ret = 0;
        size_t len = 0;
        while((bb.len > 0) && (ret = Http3_Proc(bb))){
            len += ret;
        }
        return len;
    })->onWrite([this](uint64_t id){
        if(statusmap.count(id) == 0){
            return;
        }
        ReqStatus& status = statusmap[id];
        if(!status.req){
            return;
        }
        if(status.flags & (HTTP_RES_COMPLETED | HTTP_CLOSED_F | HTTP_RST)){
            return;
        }
        if(this->rwer->cap(id) > 64){
            // reserve 64 bytes for http stream header
            status.req->pull();
        }
    })->onError([this](int ret, int code){
        return Error(ret, code);
    });
    rwer->SetCallback(cb);
    rwer->setResetHandler([this](uint64_t id, uint32_t errcode){RstProc(id, errcode);});
}

Proxy3::~Proxy3() {
    //we do this, because deleteLater will not be invoked when vpn_stop
    responsers.erase(this);
}

void Proxy3::Error(int ret, int code) {
    LOGE("(%s) <proxy3> error: %d/%d\n", dumpDest(rwer->getSrc()).c_str(), ret, code);
    http3_flag |= HTTP3_FLAG_ERROR;
    deleteLater(ret);
}

void Proxy3::Reset(uint64_t id, uint32_t code) {
    return std::dynamic_pointer_cast<QuicRWer>(rwer)->reset(id, code);
}

bool Proxy3::DataProc(Buffer& bb){
    HOOK_FUNC(this, statusmap, bb);
    idle_timeout = UpdateJob(std::move(idle_timeout),
                             [this]{deleteLater(CONNECT_AGED);}, 300000);
    if(bb.len == 0){
        return true;
    }
    if(statusmap.count(bb.id)){
        ReqStatus& status = statusmap[bb.id];
        if(status.flags & HTTP_RES_COMPLETED) {
            LOGD(DHTTP3, "<proxy3> DataProc after closed, id:%d\n", (int)bb.id);
            status.cleanJob = AddJob(([this, id = bb.id]{Clean(id, HTTP3_ERR_STREAM_CREATION_ERROR);}), 0, 0);
            return true;
        }
        if(status.res->cap() < (int)bb.len){
            LOGE("[%" PRIu64 "]: <proxy3> (%" PRIu64") the guest's write buff is full (%s) %d vs %zd\n",
                 status.req->header->request_id, bb.id, status.req->header->geturl().c_str(), status.res->cap(), bb.len);
            return false;
        }
        status.res->send(std::move(bb));
    }else{
        LOGD(DHTTP3, "<proxy3> DataProc not found id: %" PRIu64 "\n", bb.id);
        Reset(bb.id, HTTP3_ERR_STREAM_CREATION_ERROR);
    }
    return true;
}

void Proxy3::GoawayProc(uint64_t id){
    LOGD(DHTTP3, "<proxy3> [%" PRIu64 "]: goaway\n", id);
    return deleteLater(NOERROR);
}

void Proxy3::SendData(Buffer&& bb) {
    rwer->Send(std::move(bb));
}

uint64_t Proxy3::CreateUbiStream() {
    return std::dynamic_pointer_cast<QuicRWer>(rwer)->createUbiStream();
}

void Proxy3::request(std::shared_ptr<HttpReq> req, Requester*) {
    uint64_t id = maxDataId = std::dynamic_pointer_cast<QuicRWer>(rwer)->createBiStream();
    assert((http3_flag & HTTP3_FLAG_GOAWAYED) == 0);
    LOGD(DHTTP3, "<proxy3> request: %s [%" PRIu64"]\n", req->header->geturl().c_str(), id);
    statusmap[id] = ReqStatus{
        req,
        nullptr,
        0,
        };

    Block buff(BUF_LEN);
    memset(buff.data(), 0, BUF_LEN);
    size_t len = qpack_encoder.PackHttp3Req(req->header, buff.data(), BUF_LEN);
    size_t pre = variable_encode_len(HTTP3_STREAM_HEADERS) + variable_encode_len(len);
    char* p = (char*) buff.reserve(-(char) pre);
    p += variable_encode(p, HTTP3_STREAM_HEADERS);
    p += variable_encode(p, len);
    SendData({std::move(buff), pre + len, id});
    req->attach([this, id](ChannelMessage&& msg){
        HOOK_FUNC(this, statusmap, id, msg);
        idle_timeout = UpdateJob(std::move(idle_timeout),
                                 [this]{deleteLater(CONNECT_AGED);}, 300000);
        switch(msg.type){
        case ChannelMessage::CHANNEL_MSG_HEADER:
            LOGD(DHTTP3, "<proxy3> ignore header for req\n");
            return 1;
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
        //详情见guest3.cpp
    }, [this, id]{return rwer->cap(id) - 9;});
}


void Proxy3::init(std::shared_ptr<HttpReq> req) {
    Init();
    request(req, nullptr);
}

void Proxy3::ResProc(uint64_t id, std::shared_ptr<HttpResHeader> header) {
    idle_timeout = UpdateJob(std::move(idle_timeout),
                             [this]{deleteLater(CONNECT_AGED);}, 300000);
    if(statusmap.count(id)){
        ReqStatus& status = statusmap[id];
        header->request_id = status.req->header->request_id;
        if(status.req->header->ismethod("CONNECT")) {
            header->markTunnel();
        }else if(strcmp(status.req->header->Dest.protocol, "websocket") == 0){
            header->markWebsocket(status.req->header->get("Sec-WebSocket-Key"));
        }else if(!header->no_body() && !header->get("Content-Length"))
        {
            header->set("Transfer-Encoding", "chunked");
        }
        if(status.res){
            status.res->send(header);
        }else{
            status.res = std::make_shared<HttpRes>(header, [this, id]{rwer->Unblock(id);});
            status.req->response(status.res);
        }
    }else{
        LOGD(DHTTP3, "<proxy3> ResProc not found id: %" PRIu64"\n", id);
        Reset(id, HTTP3_ERR_STREAM_CREATION_ERROR);
    }
}

void Proxy3::Recv(Buffer&& bb) {
    assert(statusmap.count(bb.id));
    ReqStatus& status = statusmap[bb.id];
    assert((status.flags & HTTP_REQ_COMPLETED) == 0);
    if(bb.len == 0){
        status.flags |= HTTP_REQ_COMPLETED;
        LOGD(DHTTP3, "<proxy3> recv data [%" PRIu64 "]: EOF\n", bb.id);
        SendData({nullptr, bb.id});
    }else{
        LOGD(DHTTP3, "<proxy3> recv data [%" PRIu64 "]: %zu\n", bb.id, bb.len);
        PushData(std::move(bb));
    }
}

void Proxy3::Handle(uint64_t id, Signal s) {
    assert(statusmap.count(id));
    ReqStatus& status = statusmap[id];
    LOGD(DHTTP3, "<proxy3> signal [%d] %" PRIu64 ": %d\n",
         (int)id, status.req->header->request_id, (int)s);
    switch(s){
    case CHANNEL_ABORT:
        status.flags |= HTTP_CLOSED_F;
        return Clean(id, HTTP3_ERR_CONNECT_ERROR);
    }
}

void Proxy3::ErrProc(int errcode) {
    LOGE("(%s) <proxy3> Http3 error: 0x%08x\n", dumpDest(rwer->getSrc()).c_str(), errcode);
    deleteLater(errcode);
}

void Proxy3::RstProc(uint64_t id, uint32_t errcode) {
    if(statusmap.count(id)){
        ReqStatus& status = statusmap[id];
        if(errcode){
            LOGE("[%" PRIu64 "]: <proxy3> (%" PRIu64 "): stream reset:%d flags:0x%x\n",
                 status.req->header->request_id, id, errcode, status.flags);
        }
        status.flags |= HTTP_RST;
        status.cleanJob = AddJob(([this, id, errcode]{Clean(id, errcode);}), 0, 0);
    }
}

void Proxy3::Clean(uint64_t id, uint32_t errcode) {
    if(statusmap.count(id) == 0){
        return;
    }

    ReqStatus& status = statusmap[id];
    if((status.flags & HTTP_RST) == 0 && ((status.flags&HTTP_REQ_COMPLETED) == 0 || (status.flags&HTTP_RES_COMPLETED) == 0)){
        Reset(id, errcode);
    }

    if(status.flags & HTTP_CLOSED_F){
        //do nothing.
    }else if(status.res){
        status.res->send(CHANNEL_ABORT);
    }else{
        status.req->response(
                std::make_shared<HttpRes>(
                        HttpResHeader::create(S500, sizeof(S500), status.req->header->request_id),
                        "[[internal error]]"));
    }
    status.req->detach();
    statusmap.erase(id);
}


void Proxy3::deleteLater(uint32_t errcode) {
    http3_flag |= HTTP3_FLAG_CLEANNING;
    idle_timeout.reset(nullptr);
    responsers.erase(this);
    std::set<uint64_t> keys;
    std::for_each(statusmap.begin(), statusmap.end(), [&keys](auto&& i){ keys.emplace(i.first);});
    for(auto& i: keys){
        Clean(i, errcode);
    }
    assert(statusmap.empty());
    if((http3_flag & HTTP3_FLAG_GOAWAYED) == 0){
        Goaway(maxDataId);
    }
    Server::deleteLater(errcode);
}

void Proxy3::dump_stat(Dumper dp, void* param) {
    dp(param, "Proxy3 %p data id:%" PRIx64"\n"
            "local ctr:%" PRIx64", remote ctr:%" PRIx64", "
            "local eqpack:%" PRIx64", remote eqpack:%" PRIx64", local dqpack:%" PRIx64", remote dqpack:%" PRIx64"\n",
            this, maxDataId, ctrlid_local, ctrlid_remote,
            qpackeid_local, qpackeid_remote, qpackdid_local, qpackdid_remote);
    for(auto& i: statusmap){
        dp(param, "  0x%lx [%" PRIu64 "]: %s %s, flags: 0x%08x\n",
           i.first,
           i.second.req->header->request_id,
           i.second.req->header->method,
           i.second.req->header->geturl().c_str(),
           i.second.flags);
    }
    rwer->dump_status(dp, param);
}

void Proxy3::dump_usage(Dumper dp, void *param) {
    size_t res_usage  = 0;
    for(const auto& i: statusmap) {
        res_usage += sizeof(i.first) + sizeof(i.second);
        if(i.second.res) {
            res_usage += i.second.res->mem_usage();
        }
    }
    dp(param, "Proxy3 %p: %zd, resmap: %zd, rwer: %zd\n",
       this, sizeof(*this) + qpack_encoder.get_dynamic_table_size() + qpack_decoder.get_dynamic_table_size(),
       res_usage, rwer->mem_usage());
}
