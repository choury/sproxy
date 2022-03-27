#include "proxy3.h"

#include <assert.h>
#include <inttypes.h>


Proxy3* proxy3 = nullptr;

Proxy3::Proxy3(std::shared_ptr<QuicRWer> rwer){
    this->rwer = rwer;
    if( proxy3 == nullptr){
        proxy3 = this;
    }
    rwer->SetErrorCB(std::bind(&Proxy3::Error, this, _1, _2));
    rwer->SetReadCB([this](buff_block& bb){
        if(bb.len == 0){
            //fin
            uint64_t id = bb.id;
            if(ctrlid_remote && id == ctrlid_remote){
                return Error(PROTOCOL_ERR, HTTP3_ERR_CLOSED_CRITICAL_STREAM);
            }
            if(!statusmap.count(id)){
                return;
            }
            ReqStatus& status = statusmap[id];
            LOGD(DHTTP3, "<proxy3> [%" PRIu64 "]: end of stream\n", id);
            assert((status.flags & HTTP_RES_EOF) == 0);
            assert((status.flags & HTTP_RES_COMPLETED) == 0);
            status.flags |= HTTP_RES_COMPLETED;
            status.res->send((const void*)nullptr,0);
            return;
        }

        const char* data = (const char*)bb.buff;
        size_t ret = 0;
        while((bb.offset < bb.len) && (ret = Http3_Proc((uchar*)data + bb.offset, bb.len-bb.offset, bb.id))){
            bb.offset += ret;
        }
        assert(bb.offset <= bb.len);
        if(proxy3 != this && statusmap.empty()){
            LOG("this %p is not the main proxy3 and no clients, close it.\n", this);
            deleteLater(NOERROR);
        }
    });
    rwer->SetWriteCB([this](size_t){
        auto statusmap_copy = statusmap;
        for(auto& i: statusmap_copy){
            ReqStatus& status = i.second;
            if(!status.req){
                continue;
            }
            if (status.flags&HTTP_REQ_COMPLETED || status.flags&HTTP_REQ_EOF){
                continue;
            }
            if(this->rwer->cap(i.first) > 9){
                // reserve 9 bytes for http stream header
                status.req->more();
            }
        }
    });
    rwer->setResetHandler(std::bind(&Proxy3::RstProc, this, _1, _2));
}

Proxy3::~Proxy3() {
    //we do this, because deleteLater will not invoked when vpn_stop
    if(proxy3 == this){
        proxy3 = nullptr;
    }
}

void Proxy3::Error(int ret, int code) {
    LOGE("<proxy3> %p error: %d/%d\n", this, ret, code);
    http3_flag |= HTTP3_FLAG_ERROR;
    deleteLater(ret);
}

void Proxy3::Reset(uint64_t id, uint32_t code) {
    return std::dynamic_pointer_cast<QuicRWer>(rwer)->Reset(id, code);
}

void Proxy3::DataProc(uint64_t id, const void* data, size_t len){
    if(len == 0){
        return;
    }
    if(statusmap.count(id)){
        ReqStatus& status = statusmap[id];
        assert((status.flags & HTTP_RES_COMPLETED) == 0);
        assert((status.flags & HTTP_RES_EOF) == 0);
        status.res->send(data, len);
    }else{
        LOGD(DHTTP3, "<proxy3> DataProc not found id: %" PRIu64 "\n", id);
        Reset(id, HTTP3_ERR_STREAM_CREATION_ERROR);
    }
}

void Proxy3::GoawayProc(uint64_t id){
    LOGD(DHTTP3, "<proxy3> [%" PRIu64 "]: goaway\n", id);
    return deleteLater(NOERROR);
}

void Proxy3::PushFrame(uint64_t id, void* buff, size_t len) {
    assert(len <= rwer->cap(id));
    rwer->buffer_insert(rwer->buffer_end(), buff_block{buff, len, 0, id});
}

uint64_t Proxy3::CreateUbiStream() {
    return std::dynamic_pointer_cast<QuicRWer>(rwer)->CreateUbiStream();
}

void Proxy3::request(std::shared_ptr<HttpReq> req, Requester*) {
    uint64_t id = maxDataId = std::dynamic_pointer_cast<QuicRWer>(rwer)->CreateBiStream();
    assert((http3_flag & HTTP3_FLAG_GOAWAYED) == 0);
    LOGD(DHTTP3, "proxy3 request: %s [%" PRIu64"]\n", req->header->geturl().c_str(), id);
    statusmap[id] = ReqStatus{
        req,
        nullptr,
        0,
        };

    void* buff = p_malloc(BUF_LEN);
    memset(buff, 0, BUF_LEN);
    size_t len = qpack_encoder.PackHttp3Req(req->header, buff, BUF_LEN);
    size_t pre = variable_encode_len(HTTP3_STREAM_HEADERS) + variable_encode_len(len);
    buff =  p_move(buff, -(char)pre);
    char* p = (char*)buff;
    p += variable_encode(p, HTTP3_STREAM_HEADERS);
    p += variable_encode(p, len);
    PushFrame(id, buff, p - (char*)buff + len);
    ReqStatus& status = statusmap[id];
    req->setHandler([this, &status, id](Channel::signal s){
        assert(statusmap.count(id));
        switch(s){
        case Channel::CHANNEL_SHUTDOWN:
            assert((status.flags & HTTP_RES_EOF) == 0);
            status.flags |= HTTP_REQ_EOF;
            if(http3_flag & HTTP3_SUPPORT_SHUTDOWN) {
                LOGD(DHTTP3, "<proxy3> send shutdown frame: %" PRIu64"\n", id);
                Shutdown(id);
            }else{
                LOGD(DHTTP3, "<proxy3> send reset frame: %" PRIu64"\n", id);
                Clean(id, status, HTTP3_ERR_REQUEST_CANCELLED);
            }
            break;
        case Channel::CHANNEL_CLOSED:
            status.flags |= HTTP_CLOSED_F;
            return Clean(id, status, HTTP3_ERR_NO_ERROR);
        case Channel::CHANNEL_ABORT:
            status.flags |= HTTP_CLOSED_F;
            return Clean(id, status, HTTP3_ERR_CONNECT_ERROR);
        }
    });
    req->attach((Channel::recv_const_t)std::bind(&Proxy3::Send, this, id, _1, _2),
                [this, id]{return rwer->cap(id) - 9;});
}


void Proxy3::init(std::shared_ptr<HttpReq> req) {
    Init();
    request(req, nullptr);
}

void Proxy3::ResProc(uint64_t id, HttpResHeader* header) {
    if(statusmap.count(id)){
        ReqStatus& status = statusmap[id];
        if(!header->no_body() && !header->get("Content-Length"))
        {
            header->set("Transfer-Encoding", "chunked");
        }
        status.res = std::make_shared<HttpRes>(header, []{});
        status.req->response(status.res);
    }else{
        delete header;
        LOGD(DHTTP3, "<proxy3> ResProc not found id: %" PRIu64"\n", id);
        Reset(id, HTTP3_ERR_STREAM_CREATION_ERROR);
    }
}

void Proxy3::Send(uint64_t id, const void* buff, size_t size) {
    assert(statusmap.count(id));
    ReqStatus& status = statusmap[id];
    assert((status.flags & HTTP_REQ_COMPLETED) == 0);
    assert((status.flags & HTTP_REQ_EOF) == 0);
    if(size == 0){
        status.flags |= HTTP_REQ_COMPLETED;
        PushFrame(id, nullptr, 0);
        LOGD(DHTTP3, "<proxy3> send data [%" PRIu64 "]: EOF\n", id);
    }else{
        PushData(id, buff, size);
        LOGD(DHTTP3, "<proxy3> send data [%" PRIu64 "]: %zu\n", id, size);
    }
}

void Proxy3::ErrProc(int errcode) {
    LOGE("<proxy3> %p Http3 error: 0x%08x\n", this, errcode);
    deleteLater(errcode);
}

void Proxy3::RstProc(uint64_t id, uint32_t errcode) {
    if(statusmap.count(id)){
        ReqStatus& status = statusmap[id];
        if(errcode){
            LOGE("(%" PRIu32 "): <proxy3> [%" PRIu64 "]: stream reset: %d\n",
                 status.req->header->request_id, id, errcode);
        }
        status.flags |= HTTP_REQ_COMPLETED | HTTP_RES_COMPLETED; //make clean not send reset back
        Clean(id, status, errcode);
    }
}


void Proxy3::ShutdownProc(uint64_t id){
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
        status.res->trigger(errcode ? Channel::CHANNEL_ABORT : Channel::CHANNEL_CLOSED);
    }else{
        status.req->response(std::make_shared<HttpRes>(UnpackHttpRes(H500), "[[internal error]]"));
    }
    statusmap.erase(id);
}


void Proxy3::deleteLater(uint32_t errcode) {
    if(proxy3 == this){
        proxy3 = nullptr;
    }
    auto statusmapCopy = statusmap;
    for(auto& i: statusmapCopy){
        Clean(i.first, i.second, errcode);
    }
    statusmap.clear();
    if((http3_flag & HTTP3_FLAG_GOAWAYED) == 0){
        Goaway(maxDataId);
    }
    Server::deleteLater(errcode);
}

void Proxy3::dump_stat(Dumper dp, void* param) {
    dp(param, "Proxy3 %p%s id:%" PRIu64" (%s)\n",
       this, proxy3 == this?" [M]":"", maxDataId,
       rwer->getPeer());
    dp(param, "  rwer: rlength:%zu, wlength:%zu, stats:%d, event:%s\n",
       rwer->rlength(), rwer->wlength(),
       (int)rwer->getStats(), events_string[(int)rwer->getEvents()]);
    for(auto& i: statusmap){
        dp(param, "0x%lx [%" PRIu32 "]: %s [%d]\n",
           i.first,
           i.second.req->header->request_id,
           i.second.req->header->geturl().c_str(),
           i.second.flags);
    }
}
