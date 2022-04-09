//
// Created by 周威 on 2022/3/19.
//

#include "guest3.h"
#include "res/responser.h"
#include <assert.h>
#include <inttypes.h>

Guest3::Guest3(int fd, sockaddr_storage *addr, SSL_CTX *ctx):
    Requester(std::make_shared<QuicRWer>(fd, addr, ctx, std::bind(&Guest3::Error, this, _1, _2),
    [this](const sockaddr_storage&){
        std::shared_ptr<QuicRWer> qrwer = std::dynamic_pointer_cast<QuicRWer>(rwer);
        const unsigned char *data;
        unsigned int len;
        qrwer->get_alpn(&data, &len);
        if ((data && strncasecmp((const char*)data, "h3", len) != 0)) {
            LOGE("unknown protocol: %.*s\n", len, data);
            return Server::deleteLater(PROTOCOL_ERR);
        }
        qrwer->setResetHandler(std::bind(&Guest3::RstProc, this, _1, _2));
        Init();
    }))
{
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
            LOGD(DHTTP3, "<guest3> [%" PRIu64 "]: end of stream\n", id);
            ReqStatus& status = statusmap[id];
            assert((status.flags & HTTP_REQ_EOF) == 0);
            status.req->send((const void*)nullptr, 0);
            status.flags |= HTTP_REQ_COMPLETED;
            if(status.flags & HTTP_RES_COMPLETED) {
                Clean(id, status, NOERROR);
            }
            return;
        }
        const char* data = (const char*)bb.buff;
        size_t ret = 0;
        while((bb.offset < bb.len) && (ret = Http3_Proc((uchar*)data + bb.offset, bb.len-bb.offset, bb.id))){
            bb.offset += ret;
        }
        assert(bb.offset <= bb.len);
    });
    rwer->SetWriteCB([this](size_t){
        auto statusmap_copy = statusmap;
        for(auto& i: statusmap_copy){
            ReqStatus& status = i.second;
            if(status.res == nullptr){
                continue;
            }
            if((status.flags&HTTP_REQ_COMPLETED) && (status.flags&HTTP_RES_COMPLETED)){
                Clean(i.first, i.second, NOERROR);
                continue;
            }
            if((status.flags & HTTP_RES_COMPLETED) || (status.flags & HTTP_RES_EOF)){
                continue;
            }
            if(this->rwer->cap(i.first) >= 9){
                // reserve 9 bytes for http stream header
                status.res->more();
            }
        }
    });
}

Guest3::~Guest3() {
    statusmap.clear();
}


void Guest3::Error(int ret, int code){
    LOGE("(%s): <guest3> error: %d/%d\n", getsrc(), ret, code);
    deleteLater(ret);
}

void Guest3::Send(uint64_t id, const void* buff, size_t size){
    assert(statusmap.count(id));
    ReqStatus& status = statusmap[id];
    assert((status.flags & HTTP_RES_COMPLETED) == 0);
    assert((status.flags & HTTP_RES_EOF) == 0);
    if(size == 0){
        status.flags |= HTTP_RES_COMPLETED;
        PushFrame(id, nullptr, 0);
        LOGD(DHTTP3, "<guest3> %" PRIu32" send data [%" PRIu64"]: EOF\n",
             status.req->header->request_id, id);
    }else{
        PushData(id, buff, size);
        LOGD(DHTTP3, "<guest3> %" PRIu32 " send data [%" PRIu64"]: %zu\n",
             status.req->header->request_id, id, size);
    }
}

void Guest3::ReqProc(uint64_t id, HttpReqHeader* header) {
    LOGD(DHTTP3, "<guest3> %" PRIu32 " (%s) ReqProc %s\n", header->request_id, getsrc(), header->geturl().c_str());
    if(statusmap.count(id)){
        delete header;
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
                 std::bind(&RWer::EatReadData, rwer));
    distribute(status.req, this);
}

void Guest3::DataProc(uint64_t id, const void* data, size_t len) {
    if(len == 0)
        return;
    if(statusmap.count(id)){
        ReqStatus& status = statusmap[id];
        assert((status.flags & HTTP_REQ_EOF) == 0);
        assert((status.flags & HTTP_REQ_COMPLETED) == 0);
        status.req->send(data, len);
    }else{
        LOGD(DHTTP3, "<guest3> DateProc not found id: %" PRIu64"\n", id);
        Reset(id, HTTP3_ERR_STREAM_CREATION_ERROR);
    }
}

void Guest3::response(void* index, std::shared_ptr<HttpRes> res) {
    uint64_t id = (uint64_t)index;
    assert(statusmap.count(id));
    ReqStatus& status = statusmap[id];
    LOGD(DHTTP3, "<guest3> get response [%" PRIu64"]: %s\n", id, res->header->status);
    HttpLog(getsrc(), status.req, res);
    res->header->del("Transfer-Encoding");
    res->header->del("Connection");
    status.res = res;

    void* buff = p_malloc(BUF_LEN);
    memset(buff, 0, BUF_LEN);
    size_t len = qpack_encoder.PackHttp3Res(res->header, buff, BUF_LEN);
    size_t pre = variable_encode_len(HTTP3_STREAM_HEADERS) + variable_encode_len(len);
    buff =  p_move(buff, -(char)pre);
    char* p = (char*)buff;
    p += variable_encode(p, HTTP3_STREAM_HEADERS);
    p += variable_encode(p, len);
    PushFrame(id, buff, p - (char*)buff + len);

    res->setHandler([this, &status, id](Channel::signal s){
        assert(statusmap.count(id));
        switch(s){
        case Channel::CHANNEL_SHUTDOWN:
            assert((status.flags & HTTP_REQ_EOF) == 0);
            status.flags |= HTTP_RES_EOF;
            if(http3_flag & HTTP3_SUPPORT_SHUTDOWN) {
                LOGD(DHTTP3, "<guest3> send shutdown frame: %" PRIu64"\n", id);
                Shutdown(id);
            }else{
                LOGD(DHTTP3, "<guest3> send reset frame: %" PRIu64"\n", id);
                Clean(id, status, HTTP3_ERR_REQUEST_CANCELLED);
            }
            break;
        case Channel::CHANNEL_CLOSED:
            status.flags |= HTTP_CLOSED_F;
            return Clean(id, status, NOERROR);
        case Channel::CHANNEL_ABORT:
            status.flags |= HTTP_CLOSED_F;
            return Clean(id, status, HTTP3_ERR_INTERNAL_ERROR);
        }
    });
    res->attach((Channel::recv_const_t)std::bind(&Guest3::Send, this, id, _1, _2),
                [this, id]{return rwer->cap(id) - 9;});
}

void Guest3::Clean(uint64_t id, ReqStatus &status, uint32_t errcode) {
    assert(statusmap[id].req == status.req);

    if((status.flags&HTTP_REQ_COMPLETED) == 0 || (status.flags&HTTP_RES_COMPLETED) == 0){
        Reset(id, errcode);
    }
    if((status.flags & HTTP_CLOSED_F) == 0){
        status.req->trigger(errcode ? Channel::CHANNEL_ABORT : Channel::CHANNEL_CLOSED);
    }
    statusmap.erase(id);
}

void Guest3::RstProc(uint64_t id, uint32_t errcode) {
    if(statusmap.count(id)){
        ReqStatus& status = statusmap[id];
        if(errcode){
            LOGE("(%s)[%" PRIu32 "]: <guest3> [%" PRIu64"]: stream  reseted: %d\n",
                 getsrc(), status.req->header->request_id,
                 id, errcode);
        }
        status.flags |= HTTP_REQ_COMPLETED | HTTP_RES_COMPLETED; //make clean not send reset back
        Clean(id, status, errcode);
    }
}

void Guest3::ShutdownProc(uint64_t id) {
}

void Guest3::GoawayProc(uint64_t id) {
    LOGD(DHTTP3, "<guest3> [%" PRIu64 "]: goaway\n", id);
    return deleteLater(NOERROR);
}

void Guest3::PushFrame(uint64_t id, void* buff, size_t len) {
    assert((int)len <= rwer->cap(id));
    rwer->buffer_insert(rwer->buffer_end(), buff_block{buff, len, 0, id});
}

uint64_t Guest3::CreateUbiStream() {
    return std::dynamic_pointer_cast<QuicRWer>(rwer)->CreateUbiStream();
}

void Guest3::Reset(uint64_t id, uint32_t code) {
    return std::dynamic_pointer_cast<QuicRWer>(rwer)->Reset(id, code);
}

void Guest3::ErrProc(int errcode) {
    LOGE("(%s): Guest3 http3 error:0x%08x\n", getsrc(), errcode);
    http3_flag |= HTTP3_FLAG_ERROR;
    deleteLater(errcode);
}

void Guest3::deleteLater(uint32_t errcode){
    for(auto& i: statusmap){
        if((i.second.flags & HTTP_CLOSED_F) == 0) {
            i.second.req->trigger(errcode ? Channel::CHANNEL_ABORT : Channel::CHANNEL_CLOSED);
        }
        i.second.flags |= HTTP_CLOSED_F;
    }
    statusmap.clear();
    if((http3_flag & HTTP3_FLAG_GOAWAYED) == 0){
        Goaway(maxDataId);
    }
    return Server::deleteLater(errcode);
}

std::shared_ptr<QuicRWer> Guest3::getQuicRWer() {
    return std::dynamic_pointer_cast<QuicRWer>(rwer);
}

void Guest3::dump_stat(Dumper dp, void* param) {
    dp(param, "Guest3 %p, id:%" PRIu64" (%s)\n", this, maxDataId, getsrc());
    dp(param, "  rwer: rlength:%zu, wlength:%zu, stats:%d, event:%s\n",
       rwer->rlength(), rwer->wlength(),
       (int)rwer->getStats(), events_string[(int)rwer->getEvents()]);
    for(auto& i: statusmap){
        dp(param, "0x%lx [%" PRIu32 "]: %s %s\n",
           i.first, i.second.req->header->request_id,
           i.second.req->header->method,
           i.second.req->header->geturl().c_str());
    }
}


