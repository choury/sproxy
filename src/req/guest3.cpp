//
// Created by 周威 on 2022/3/19.
//

#include "guest3.h"
#include "res/responser.h"
#include <assert.h>
#include <inttypes.h>

Guest3::Guest3(int fd, const sockaddr_storage *addr, SSL_CTX *ctx, QuicMgr* quic_mgr):
    Requester(nullptr)
{
    auto qrwer = std::make_shared<QuicRWer>(fd, addr, ctx, quic_mgr, std::bind(&Guest3::Error, this, _1, _2));
    init(qrwer);
    qrwer->SetConnectCB([this, qrwer](const sockaddr_storage&){
        const unsigned char *data;
        unsigned int len;
        qrwer->get_alpn(&data, &len);
        if ((data && strncasecmp((const char*)data, "h3", len) != 0)) {
            LOGE("(%s) unknown protocol: %.*s\n", rwer->getPeer(), len, data);
            return Server::deleteLater(PROTOCOL_ERR);
        }
        qrwer->setResetHandler(std::bind(&Guest3::RstProc, this, _1, _2));
        Init();
    });
    rwer->SetReadCB([this](uint64_t id, const void* data, size_t len) -> size_t {
        LOGD(DHTTP3, "<guest3> (%s) read [%" PRIu64"]: len:%zu\n", this->rwer->getPeer(), id, len);
        if(len == 0){
            //fin
            if(ctrlid_remote && id == ctrlid_remote){
                Error(PROTOCOL_ERR, HTTP3_ERR_CLOSED_CRITICAL_STREAM);
                return 0;
            }
            if(!statusmap.count(id)){
                return 0;
            }
            LOGD(DHTTP3, "<guest3> [%" PRIu64 "]: end of stream\n", id);
            ReqStatus& status = statusmap[id];
            status.req->send(nullptr);
            status.flags |= HTTP_REQ_COMPLETED;
            if(status.flags & HTTP_RES_COMPLETED) {
                Clean(id, NOERROR);
            }
            return 0;
        }
        size_t ret = 0;
        while((len > 0) && (ret = Http3_Proc((const uchar*)data, len, id))){
            len -= ret;
            data = (const char*)data + ret;
        }
        return len;
    });
    rwer->SetWriteCB([this](uint64_t id){
        if(statusmap.count(id) == 0){
            return;
        }
        ReqStatus& status = statusmap[id];
        if(status.res == nullptr){
            return;
        }
        if((status.flags & HTTP_RES_COMPLETED)){
            return;
        }
        if(this->rwer->cap(id) >= 64){
            // reserve 64 bytes for http stream header
            status.res->pull();
        }
    });
}

Guest3::~Guest3() {
    for(auto& i: statusmap){
        if((i.second.flags & HTTP_CLOSED_F) == 0) {
            i.second.req->send(ChannelMessage::CHANNEL_ABORT);
        }
        i.second.flags |= HTTP_CLOSED_F;
    }
    statusmap.clear();
}

void Guest3::AddInitData(const void *buff, size_t len) {
    auto qrwer = std::dynamic_pointer_cast<QuicRWer>(rwer);
    qrwer->walkPackets(buff, len);
    qrwer->reorderData();
}

void Guest3::Error(int ret, int code){
    LOGE("(%s): <guest3> error: %d/%d\n", rwer->getPeer(), ret, code);
    deleteLater(ret);
}

void Guest3::Recv(Buffer&& bb){
    assert(statusmap.count(bb.id));
    ReqStatus& status = statusmap[bb.id];
    assert((status.flags & HTTP_RES_COMPLETED) == 0);
    if(bb.len == 0){
        LOGD(DHTTP3, "<guest3> %" PRIu32" recv data [%" PRIu64"]: EOF\n",
             status.req->header->request_id, bb.id);
        PushFrame({nullptr, bb.id});
        status.flags |= HTTP_RES_COMPLETED;
        if(status.flags & HTTP_REQ_COMPLETED) {
            rwer->addjob(std::bind(&Guest3::Clean, this, bb.id, NOERROR), 0, JOB_FLAGS_AUTORELEASE);
        }
    }else{
        if(status.req->header->ismethod("HEAD")){
            LOGD(DHTTP3, "<guest3> %" PRIu32" recv data [%" PRIu64"]: HEAD req discard body\n",
                 status.req->header->request_id, bb.id);
            return;
        }
        LOGD(DHTTP3, "<guest3> %" PRIu32 " recv data [%" PRIu64"]: %zu, cap: %d\n",
             status.req->header->request_id, bb.id, bb.len, (int)rwer->cap(bb.id));
        PushData(std::move(bb));
    }
}

void Guest3::Handle(uint64_t id, ChannelMessage::Signal s) {
    assert(statusmap.count(id));
    ReqStatus& status = statusmap[id];
    LOGD(DHTTP3, "<guest3> signal [%d] %" PRIu32 ": %d\n",
         (int)id, status.req->header->request_id, (int)s);
    switch(s){
    case ChannelMessage::CHANNEL_ABORT:
        status.flags |= HTTP_CLOSED_F;
        return Clean(id, HTTP3_ERR_INTERNAL_ERROR);
    }
}

void Guest3::ReqProc(uint64_t id, std::shared_ptr<HttpReqHeader> header) {
    LOGD(DHTTP3, "<guest3> %" PRIu32 " (%s) ReqProc %s\n",
         header->request_id, rwer->getPeer(), header->geturl().c_str());
    if(statusmap.count(id)){
        LOGD(DHTTP3, "<guest3> ReqProc dup id: %" PRIu64"\n", id);
        Reset(id, HTTP3_ERR_STREAM_CREATION_ERROR);
        return;
    }

    statusmap[id] = ReqStatus{
            nullptr,
            nullptr,
            0,
    };
    ReqStatus& status = statusmap[id];

    status.req = std::make_shared<HttpReq>(header,
              std::bind(&Guest3::response, this, (void*)id, _1),
                 [this, id]{ rwer->Unblock(id);});
    distribute(status.req, this);
}

bool Guest3::DataProc(uint64_t id, const void* data, size_t len) {
    if(len == 0)
        return true;
    if(statusmap.count(id)){
        ReqStatus& status = statusmap[id];
        if(status.flags & HTTP_REQ_COMPLETED){
            LOGD(DHTTP3, "<guest3> DateProc after closed, id: %" PRIu64"\n", id);
            Clean(id, HTTP3_ERR_STREAM_CREATION_ERROR);
            return true;
        }
        if(status.req->cap() < (int)len){
            LOGE("[%" PRIu32 "]: <guest3> (%" PRIu64")the host's buff is full (%s)\n",
                 status.req->header->request_id, id, status.req->header->geturl().c_str());
            return false;
        }
        status.req->send(data, len);
    }else{
        LOGD(DHTTP3, "<guest3> DateProc not found id: %" PRIu64"\n", id);
        Reset(id, HTTP3_ERR_STREAM_CREATION_ERROR);
    }
    return true;
}

void Guest3::response(void* index, std::shared_ptr<HttpRes> res) {
    uint64_t id = (uint64_t)index;
    assert(statusmap.count(id));
    ReqStatus& status = statusmap[id];
    assert(status.res == nullptr);
    status.res = res;
    res->attach([this, id](ChannelMessage& msg){
        switch(msg.type){
        case ChannelMessage::CHANNEL_MSG_HEADER: {
            assert(statusmap.count(id));
            ReqStatus &status = statusmap[id];
            auto header = std::dynamic_pointer_cast<HttpResHeader>(msg.header);
            LOGD(DHTTP3, "<guest3> get response [%" PRIu64"]: %s\n", id, header->status);
            HttpLog(rwer->getPeer(), status.req->header, header);
            header->del("Transfer-Encoding");
            header->del("Connection");

            auto buff = std::make_shared<Block>(BUF_LEN);
            size_t len = qpack_encoder.PackHttp3Res(header, buff->data(), BUF_LEN);
            size_t pre = variable_encode_len(HTTP3_STREAM_HEADERS) + variable_encode_len(len);
            char *p = (char *) buff->reserve(-pre);
            p += variable_encode(p, HTTP3_STREAM_HEADERS);
            p += variable_encode(p, len);
            PushFrame({buff, len + pre, id});
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
        //这里是没办法准确计算cap的，因为rwer返回的可用量http3这里写的时候会再加头部数据
        //所以如果对端缓存了这个值(比如proxy2的localwindow),那么它每写一次数据
        //这个值就会小一点，最终就localwindow就会比实际cap大挺多,我们预留一点buffer,
        //如果还是不够，多出来的数据会放入quic的fullq队列中
    }, [this, id]{return rwer->cap(id)*97/100 - 9;});
}

void Guest3::Clean(uint64_t id, uint32_t errcode) {
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

void Guest3::RstProc(uint64_t id, uint32_t errcode) {
    if(statusmap.count(id)){
        ReqStatus& status = statusmap[id];
        if(errcode){
            LOGE("[%" PRIu32 "]: <guest3> (%" PRIu64"): stream  reseted: %d\n",
                 status.req->header->request_id, id, errcode);
        }
        status.flags |= HTTP_REQ_COMPLETED | HTTP_RES_COMPLETED; //make clean not send reset back
        Clean(id, errcode);
    }
}

void Guest3::GoawayProc(uint64_t id) {
    LOGD(DHTTP3, "<guest3> [%" PRIu64 "]: goaway\n", id);
    return deleteLater(NOERROR);
}

void Guest3::PushFrame(Buffer&& bb) {
    rwer->buffer_insert(std::move(bb));
}

uint64_t Guest3::CreateUbiStream() {
    return std::dynamic_pointer_cast<QuicRWer>(rwer)->CreateUbiStream();
}

void Guest3::Reset(uint64_t id, uint32_t code) {
    return std::dynamic_pointer_cast<QuicRWer>(rwer)->Reset(id, code);
}

void Guest3::ErrProc(int errcode) {
    LOGE("(%s): Guest3 http3 error:0x%08x\n", rwer->getPeer(), errcode);
    http3_flag |= HTTP3_FLAG_ERROR;
    deleteLater(errcode);
}

void Guest3::deleteLater(uint32_t errcode){
    http3_flag |= HTTP3_FLAG_CLEANNING;
    if((http3_flag & HTTP3_FLAG_GOAWAYED) == 0){
        Goaway(maxDataId);
    }
    return Server::deleteLater(errcode);
}


void Guest3::dump_stat(Dumper dp, void* param) {
    dp(param, "Guest3 %p, data id: %" PRIx64"\n"
            "local ctr:%" PRIx64", remote ctr:%" PRIx64", "
            "local eqpack:%" PRIx64", remote eqpack:%" PRIx64", local dqpack:%" PRIx64", remote dqpack:%" PRIx64"\n",
            this, maxDataId, ctrlid_local, ctrlid_remote,
            qpackeid_local, qpackeid_remote, qpackdid_local, qpackdid_remote);
    for(auto& i: statusmap){
        dp(param, "  0x%lx [%" PRIu32 "]: %s %s, time: %dms, flags: 0x%08x\n",
           i.first, i.second.req->header->request_id,
           i.second.req->header->method,
           i.second.req->header->geturl().c_str(),
           getmtime() - i.second.req->header->ctime,
           i.second.flags);
    }
    rwer->dump_status(dp, param);
}

void Guest3::dump_usage(Dumper dp, void *param) {
    size_t req_usage  = 0;
    for(const auto& i: statusmap) {
        req_usage += sizeof(i.first) + sizeof(i.second);
        req_usage += i.second.req->mem_usage();
    }
    dp(param, "Guest3 %p: %zd, reqmap: %zd, rwer: %zd\n",
       this, sizeof(*this) + qpack_encoder.get_dynamic_table_size() + qpack_decoder.get_dynamic_table_size(),
       req_usage, rwer->mem_usage());
}
