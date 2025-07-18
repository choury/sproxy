#include "proxy3.h"
#include "misc/hook.h"
#include "prot/quic/quicio.h"

#include <assert.h>
#include <inttypes.h>


Proxy3::Proxy3(std::shared_ptr<RWer> rwer){
    this->rwer = rwer;
    cb = IQuicCallback::create()->onRead([this](Buffer&& bb) -> size_t {
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
            status.rw->Send(Buffer{nullptr, bb.id});
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
            status.rw->Unblock(id);
        }
    })->onError([this](int ret, int code){
        return Error(ret, code);
    });
    std::dynamic_pointer_cast<IQuicCallback>(cb)->onDatagram([this](Buffer&& bb){
        Datagram_Proc(std::move(bb));
    })->onReset([this](uint64_t id, uint32_t error) {
        RstProc(id, error);
    });
    rwer->SetCallback(cb);
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
    return std::dynamic_pointer_cast<QuicBase>(rwer)->reset(id, code);
}

bool Proxy3::DataProc(Buffer&& bb){
    HOOK_FUNC(this, statusmap, bb);
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
        if(status.rw->cap(bb.id) < (int)bb.len){
            LOGE("[%" PRIu64 "]: <proxy3> (%" PRIu64") the guest's write buff is full (%s) %zd vs %zd\n",
                 status.req->request_id, bb.id, status.req->geturl().c_str(), status.rw->cap(bb.id), bb.len);
            return false;
        }
        status.rw->Send(std::move(bb));
    }else{
        LOGD(DHTTP3, "<proxy3> DataProc not found id: %" PRIu64 "\n", bb.id);
        Reset(bb.id, HTTP3_ERR_STREAM_CREATION_ERROR);
    }
    return true;
}

void Proxy3::DatagramProc(Buffer&& bb) {
    // Check if stream exists
    if(statusmap.count(bb.id) == 0) {
        LOGD(DHTTP3, "<proxy3> Datagram for non-existent stream %" PRIu64", dropping\n", bb.id);
        return;
    }

    ReqStatus& status = statusmap[bb.id];
    if(status.flags & (HTTP_RST | HTTP_CLOSED_F)) {
        LOGD(DHTTP3, "<proxy3> DatagramProc after closed, id:%d\n", (int)bb.id);
        return;
    }

    // Forward datagram to the request handler
    status.rw->Send(std::move(bb));
}

void Proxy3::GoawayProc(uint64_t id){
    LOGD(DHTTP3, "<proxy3> [%" PRIu64 "]: goaway\n", id);
    return deleteLater(NOERROR);
}

void Proxy3::SendData(Buffer&& bb) {
    rwer->Send(std::move(bb));
}

void Proxy3::SendDatagram(Buffer&& bb) {
    std::dynamic_pointer_cast<QuicBase>(rwer)->sendDatagram(std::move(bb));
}

uint64_t Proxy3::CreateUbiStream() {
    return std::dynamic_pointer_cast<QuicBase>(rwer)->createUbiStream();
}

void Proxy3::request(std::shared_ptr<HttpReqHeader> req, std::shared_ptr<MemRWer> rw, Requester*) {
    uint64_t id = maxDataId = std::dynamic_pointer_cast<QuicBase>(rwer)->createBiStream();
    assert((http3_flag & HTTP3_FLAG_GOAWAYED) == 0);
    LOGD(DHTTP3, "<proxy3> request: %s [%" PRIu64"]\n", req->geturl().c_str(), id);
    statusmap[id] = ReqStatus{
        req,
        rw,
        nullptr,
        0,
    };
    ReqStatus& status = statusmap[id];

    Block buff(BUF_LEN);
    memset(buff.data(), 0, BUF_LEN);
    size_t len = qpack_encoder.PackHttp3Req(req, buff.data(), BUF_LEN);
    size_t pre = variable_encode_len(HTTP3_STREAM_HEADERS) + variable_encode_len(len);
    char* p = (char*) buff.reserve(-(char) pre);
    p += variable_encode(p, HTTP3_STREAM_HEADERS);
    p += variable_encode(p, len);
    SendData({std::move(buff), pre + len, id});
    status.cb = IRWerCallback::create()->onRead([this, id](Buffer&& bb) -> size_t {
        HOOK_FUNC(this, statusmap, id, bb);
        ReqStatus& status = statusmap.at(id);
        bb.id = id;
        auto len = bb.len;
        assert((status.flags & HTTP_REQ_COMPLETED) == 0);
        if((http3_flag & HTTP3_FLAG_H3_DATAGRAM) && std::dynamic_pointer_cast<PMemRWer>(status.rw)) {
            LOGD(DHTTP3, "<proxy3> recv datagram [%" PRIu64 "]: %zu\n", bb.id, len);
            PushDatagram(std::move(bb));
            return len;
        }
        if(bb.len == 0){
            status.flags |= HTTP_REQ_COMPLETED;
            LOGD(DHTTP3, "<proxy3> recv data [%" PRIu64 "]: EOF\n", bb.id);
            SendData({nullptr, bb.id});
        }else{
            LOGD(DHTTP3, "<proxy3> recv data [%" PRIu64 "]: %zu\n", bb.id, len);
            PushData(std::move(bb));
        }
        return len;
    })->onWrite([this, id](uint64_t){
        rwer->Unblock(id);
    })->onError([this, id](int ret, int code){
        ReqStatus& status = statusmap.at(id);
        LOGD(DHTTP3, "<proxy3> signal [%d] %" PRIu64 " error %d:%d\n",
             (int)id, status.req->request_id, ret, code);
        status.flags |= HTTP_CLOSED_F;
        status.cleanJob = AddJob(([this, id]{Clean(id, HTTP3_ERR_CONNECT_ERROR);}), 0, 0);
        return;
    });
    status.rw->SetCallback(status.cb);
    idle_timeout.reset();
}

bool Proxy3::reconnect() {
    LOGD(DHTTP3, "<proxy3> connection (%s) attempting migration\n", dumpDest(rwer->getSrc()).c_str());
    // For QUIC connections, we can attempt migration
    // Trigger migration on the underlying QuicRWer
    if (auto quic_rwer = std::dynamic_pointer_cast<QuicRWer>(rwer)) {
        if (quic_rwer->triggerMigration()){
            LOGD(DHTTP3, "<proxy3> QUIC migration successful, preserving connection\n");
            setIdle(300000);
            return true; // Keep connection for successful migration
        } else {
            LOGE("(%s) <proxy3> QUIC migration failed, need to create new connection\n", dumpDest(rwer->getSrc()).c_str());
            return false; // Migration failed, upper layer should create new connection
        }
    }
    LOGD(DHTTP3, "<proxy3> Not a QUIC connection, cleaning up\n");
    return false; // Not a QUIC connection, clean up
}

void Proxy3::init(std::shared_ptr<HttpReqHeader> req, std::shared_ptr<MemRWer> rw) {
    Init();
    request(req, rw, nullptr);
}

void Proxy3::ResProc(uint64_t id, std::shared_ptr<HttpResHeader> header) {
    if(statusmap.count(id)){
        ReqStatus& status = statusmap[id];
        header->request_id = status.req->request_id;
        if(status.req->ismethod("CONNECT")) {
            header->markTunnel();
        }else if(strcmp(status.req->Dest.protocol, "websocket") == 0){
            header->markWebsocket(status.req->get("Sec-WebSocket-Key"));
        }else if(!header->no_body() && !header->get("Content-Length"))
        {
            header->set("Transfer-Encoding", "chunked");
        }
        status.rw->SendHeader(header);
        status.flags |= HTTP_RESPOENSED;
    }else{
        LOGD(DHTTP3, "<proxy3> ResProc not found id: %" PRIu64"\n", id);
        Reset(id, HTTP3_ERR_STREAM_CREATION_ERROR);
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
                 status.req->request_id, id, errcode, status.flags);
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

    status.rw->SetCallback(nullptr);
    if(status.flags & (HTTP_CLOSED_F | HTTP_RESPOENSED)){
        //do nothing.
    }else{
        response(status.rw, HttpResHeader::create(S500, sizeof(S500), status.req->request_id), "[[internal error]]");
    }
    status.rw->Close();
    statusmap.erase(id);
    setIdle(300000);
}

void Proxy3::setIdle(uint32_t ms) {
    if(statusmap.empty()) {
        LOG("(%s) has no request, start idle timer\n", dumpDest(rwer->getDst()).c_str());
        idle_timeout = UpdateJob(std::move(idle_timeout), [this]{deleteLater(CONNECT_AGED);}, ms);
    }
}


void Proxy3::deleteLater(uint32_t errcode) {
    http3_flag |= HTTP3_FLAG_CLEANNING;
    responsers.erase(this);
    std::set<uint64_t> keys;
    std::for_each(statusmap.begin(), statusmap.end(), [&keys](auto&& i){ keys.emplace(i.first);});
    for(auto& i: keys){
        Clean(i, errcode);
    }
    idle_timeout.reset();
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
           i.second.req->request_id,
           i.second.req->method,
           i.second.req->geturl().c_str(),
           i.second.flags);
    }
    rwer->dump_status(dp, param);
}

void Proxy3::dump_usage(Dumper dp, void *param) {
    size_t res_usage  = 0;
    for(const auto& i: statusmap) {
        res_usage += sizeof(i.first) + sizeof(i.second);
        if(i.second.rw) {
            res_usage += i.second.rw->mem_usage();
        }
    }
    dp(param, "Proxy3 %p: %zd, resmap: %zd, rwer: %zd\n",
       this, sizeof(*this) + qpack_encoder.get_dynamic_table_size() + qpack_decoder.get_dynamic_table_size(),
       res_usage, rwer->mem_usage());
}

