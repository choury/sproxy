#include "proxy3.h"

#include <assert.h>
#include <inttypes.h>


Proxy3::Proxy3(std::shared_ptr<QuicRWer> rwer){
    this->rwer = rwer;
    rwer->SetErrorCB(std::bind(&Proxy3::Error, this, _1, _2));
    rwer->SetReadCB([this](const Buffer& bb) -> size_t {
        LOGD(DHTTP3, "<proxy3> (%s) read [%" PRIu64"]: len:%zu\n", this->rwer->getPeer(), bb.id, bb.len);
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
            status.res->send(nullptr);
            return 0;
        }

        size_t ret = 0;
        size_t len = bb.len;
        const char* data = (const char*)bb.data();
        while((len > 0) && (ret = Http3_Proc(data, len, bb.id))){
            len -= ret;
            data += ret;
        }
        return len;
    });
    rwer->SetWriteCB([this](uint64_t id){
        if(statusmap.count(id) == 0){
            return;
        }
        ReqStatus& status = statusmap[id];
        if(!status.req){
            return;
        }
        if (status.flags&HTTP_REQ_COMPLETED){
            return;
        }
        if(this->rwer->cap(id) > 64){
            // reserve 64 bytes for http stream header
            status.req->pull();
        }
    });
    rwer->setResetHandler(std::bind(&Proxy3::RstProc, this, _1, _2));
}

Proxy3::~Proxy3() {
    //we do this, because deleteLater will not be invoked when vpn_stop
    responsers.erase(this);
}

void Proxy3::Error(int ret, int code) {
    LOGE("(%s) <proxy3> error: %d/%d\n", rwer->getPeer(), ret, code);
    http3_flag |= HTTP3_FLAG_ERROR;
    deleteLater(ret);
}

void Proxy3::Reset(uint64_t id, uint32_t code) {
    return std::dynamic_pointer_cast<QuicRWer>(rwer)->reset(id, code);
}

bool Proxy3::DataProc(uint64_t id, const void* data, size_t len){
    idle_timeout = UpdateJob(std::move(idle_timeout),
                             std::bind(&Proxy3::deleteLater, this, CONNECT_AGED), 300000);
    if(len == 0){
        return true;
    }
    if(statusmap.count(id)){
        ReqStatus& status = statusmap[id];
        if(status.flags & HTTP_RES_COMPLETED) {
            LOGD(DHTTP3, "<proxy3> DataProc after closed, id:%d\n", (int)id);
            Clean(id, status, HTTP3_ERR_STREAM_CREATION_ERROR);
            return true;
        }
        if(status.res->cap() < (int)len){
            LOGE("[%" PRIu32 "]: <proxy3> (%" PRIu64") the guest's write buff is full (%s)\n",
                 status.req->header->request_id, id, status.req->header->geturl().c_str());
            return false;
        }
        status.res->send(data, len);
    }else{
        LOGD(DHTTP3, "<proxy3> DataProc not found id: %" PRIu64 "\n", id);
        Reset(id, HTTP3_ERR_STREAM_CREATION_ERROR);
    }
    return true;
}

void Proxy3::GoawayProc(uint64_t id){
    LOGD(DHTTP3, "<proxy3> [%" PRIu64 "]: goaway\n", id);
    return deleteLater(NOERROR);
}

void Proxy3::PushFrame(Buffer&& bb) {
    rwer->buffer_insert(std::move(bb));
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

    auto buff = std::make_shared<Block>(BUF_LEN);
    memset(buff->data(), 0, BUF_LEN);
    size_t len = qpack_encoder.PackHttp3Req(req->header, buff->data(), BUF_LEN);
    size_t pre = variable_encode_len(HTTP3_STREAM_HEADERS) + variable_encode_len(len);
    char* p = (char*) buff->reserve(-(char) pre);
    p += variable_encode(p, HTTP3_STREAM_HEADERS);
    p += variable_encode(p, len);
    PushFrame({buff, pre + len, id});
    req->attach([this, id](ChannelMessage& msg){
        idle_timeout = UpdateJob(std::move(idle_timeout),
                                 std::bind(&Proxy3::deleteLater, this, CONNECT_AGED), 300000);
        switch(msg.type){
        case ChannelMessage::CHANNEL_MSG_HEADER:
            LOGD(DHTTP3, "<proxy3> ignore header for req\n");
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
        //详情见guest3.cpp
    }, [this, id]{return rwer->cap(id) - 9;});
}


void Proxy3::init(std::shared_ptr<HttpReq> req) {
    Init();
    request(req, nullptr);
}

void Proxy3::ResProc(uint64_t id, std::shared_ptr<HttpResHeader> header) {
    idle_timeout = UpdateJob(std::move(idle_timeout),
                             std::bind(&Proxy3::deleteLater, this, CONNECT_AGED), 300000);
    if(statusmap.count(id)){
        ReqStatus& status = statusmap[id];
        if(!header->no_body() && !header->get("Content-Length"))
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
        PushFrame({nullptr, bb.id});
    }else{
        LOGD(DHTTP3, "<proxy3> recv data [%" PRIu64 "]: %zu\n", bb.id, bb.len);
        PushData(std::move(bb));
    }
}

void Proxy3::Handle(uint64_t id, ChannelMessage::Signal s) {
    assert(statusmap.count(id));
    ReqStatus& status = statusmap[id];
    LOGD(DHTTP3, "<proxy3> signal [%d] %" PRIu32 ": %d\n",
         (int)id, status.req->header->request_id, (int)s);
    switch(s){
    case ChannelMessage::CHANNEL_ABORT:
        status.flags |= HTTP_CLOSED_F;
        return Clean(id, status, HTTP3_ERR_CONNECT_ERROR);
    }
}

void Proxy3::ErrProc(int errcode) {
    LOGE("(%s) <proxy3> Http3 error: 0x%08x\n", rwer->getPeer(), errcode);
    deleteLater(errcode);
}

void Proxy3::RstProc(uint64_t id, uint32_t errcode) {
    if(statusmap.count(id)){
        ReqStatus& status = statusmap[id];
        if(errcode){
            LOGE("[%" PRIu32 "]: <proxy3> (%" PRIu64 "): stream reset: %d\n",
                 status.req->header->request_id, id, errcode);
        }
        status.flags |= HTTP_REQ_COMPLETED | HTTP_RES_COMPLETED; //make clean not send reset back
        Clean(id, status, errcode);
    }
}

void Proxy3::Clean(uint64_t id, Proxy3::ReqStatus& status, uint32_t errcode) {
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


void Proxy3::deleteLater(uint32_t errcode) {
    http3_flag |= HTTP3_FLAG_CLEANNING;
    idle_timeout.reset(nullptr);
    responsers.erase(this);
    auto statusmapCopy = statusmap;
    for(auto& i: statusmapCopy){
        Clean(i.first, i.second, errcode);
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
        dp(param, "  0x%lx [%" PRIu32 "]: %s %s, flags: 0x%08x\n",
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
