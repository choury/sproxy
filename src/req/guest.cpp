#include "guest.h"
#include "guest2.h"
#include "res/responser.h"
#include "misc/util.h"
#include "misc/config.h"
#include "prot/sslio.h"

#include <string.h>
#include <assert.h>
#include <inttypes.h>

void Guest::ReadHE(Buffer& bb){
    LOGD(DHTTP, "<guest> (%s) read: len:%zu\n", getsrc(), bb.len);
    if(bb.len == 0){
        //EOF
        if(statuslist.empty()){
            return deleteLater(NOERROR);
        }
        ReqStatus& status = statuslist.back();
        if(status.flags & HTTP_CLOSED_F){
            return deleteLater(NOERROR);
        }
        status.flags |= HTTP_REQ_EOF;
        if((status.flags & HTTP_RES_EOF)
        || status.req->header->ismethod("PING")
        || status.req->header->ismethod("SEND"))
        {
            deleteLater(NOERROR);
        }else{
            status.req->send(ChannelMessage::CHANNEL_SHUTDOWN);
        }
        return;
    }
    const char* data = (const char*) bb.data();
    size_t ret = 0;
    while(bb.len > 0 && (ret = (this->*Http_Proc)(data, bb.len))){
        bb.trunc(ret);
    }
}

void Guest::WriteHE(size_t len){
    if(statuslist.empty()){
        return;
    }
    ReqStatus& status = statuslist.front();
    LOGD(DHTTP, "<guest> (%s) written: wlength:%zu, flags:0x%08x\n", getsrc(), len, status.flags);
    if(status.flags & HTTP_RES_EOF){
        if(rwer->wlength() == 0){
            std::dynamic_pointer_cast<SocketRWer>(rwer)->Shutdown();
        }
        return;
    }
    if((status.flags & HTTP_REQ_COMPLETED) && (status.flags & HTTP_RES_COMPLETED)){
        return deqReq();
    }
    if(status.flags & HTTP_RES_COMPLETED){
        return;
    }
    if(status.res){
        status.res->more();
    }
}

Guest::Guest(int fd, const sockaddr_storage* addr, SSL_CTX* ctx): Requester(nullptr){
    if(ctx){
        init(std::make_shared<SslRWer>(fd, addr, ctx, std::bind(&Guest::Error, this, _1, _2),
            [this](const sockaddr_storage&){
                std::shared_ptr<SslRWer> srwer = std::dynamic_pointer_cast<SslRWer>(rwer);
                const unsigned char *data;
                unsigned int len;
                srwer->get_alpn(&data, &len);
                if ((data && strncasecmp((const char*)data, "h2", len) == 0)) {
                    new Guest2(srwer);
                    rwer = nullptr;
                    assert(statuslist.empty());
                    return Server::deleteLater(NOERROR);
                }
            }
        ));
    }else{
        init(std::make_shared<StreamRWer>(fd, addr, std::bind(&Guest::Error, this, _1, _2)));
    }
    rwer->SetReadCB(std::bind(&Guest::ReadHE, this, _1));
    rwer->SetWriteCB(std::bind(&Guest::WriteHE, this, _1));
}

void Guest::ReqProc(std::shared_ptr<HttpReqHeader> header) {
    LOGD(DHTTP, "<guest> ReqProc %" PRIu32 " %s\n", header->request_id, header->geturl().c_str());
    auto req = std::make_shared<HttpReq>(header,
            std::bind(&Guest::response, this, nullptr, _1),
            std::bind(&RWer::EatReadData, rwer));

    statuslist.emplace_back(ReqStatus{req, nullptr, 0});
    if(statuslist.size() == 1){
        distribute(req, this);
    }
}

void Guest::deqReq() {
    ReqStatus& status = statuslist.front();
    if((status.flags & HTTP_CLOSED_F) == 0) {
        status.req->send(ChannelMessage::CHANNEL_CLOSED);
    }
    statuslist.pop_front();

    if(!statuslist.empty()){
        distribute(statuslist.front().req, this);
    }
}

ssize_t Guest::DataProc(const void *buff, size_t size) {
    ReqStatus& status = statuslist.back();
    assert((status.flags & HTTP_REQ_EOF) == 0);
    assert((status.flags & HTTP_REQ_COMPLETED) == 0);
    int len = status.req->cap();
    len = Min(len, size);
    if (len <= 0) {
        LOGE("(%s)[%" PRIu32 "]: <guest> the host's buff is full (%s)\n", 
            getsrc(), status.req->header->request_id,
            status.req->header->geturl().c_str());
        rwer->delEvents(RW_EVENT::READ);
        return -1;
    }
    status.req->send(buff, (size_t)len);
    rx_bytes += len;
    LOGD(DHTTP, "<guest> DataProc %" PRIu32 ": size:%zu, send:%d/%zu\n", status.req->header->request_id, size, len, rx_bytes);
    return len;
}

void Guest::EndProc() {
    ReqStatus& status = statuslist.back();
    LOGD(DHTTP, "<guest> EndProc %" PRIu32 "\n", status.req->header->request_id);
    rwer->addEvents(RW_EVENT::READ);
    status.req->send(nullptr);
    if(status.flags & HTTP_RES_COMPLETED){
        deqReq();
    }else{
        status.flags |= HTTP_REQ_COMPLETED;
    }
}

void Guest::ErrProc() {
    Error(PROTOCOL_ERR, 0);
}

void Guest::Error(int ret, int code) {
    if(ret == SSL_SHAKEHAND_ERR){
        LOGE("(%s): <guest> ssl_accept error %d/%d\n", getsrc(), ret, code);
    }
    if(statuslist.empty()){
        return deleteLater(PEER_LOST_ERR);
    }
    ReqStatus& status = statuslist.back();
    LOGE("(%s)[%" PRIu32 "]: <guest> error (%s) %d/%d http_flag:0x%x\n",
            getsrc(), status.req->header->request_id,
            status.req->header->geturl().c_str(), ret, code, http_flag);
    deleteLater(ret);
}

void Guest::response(void*, std::shared_ptr<HttpRes> res) {
    ReqStatus& status = statuslist.front();
    assert(status.res == nullptr);
    status.res = res;
    res->attach([this, &status](ChannelMessage& msg){
        switch(msg.type){
        case ChannelMessage::CHANNEL_MSG_HEADER: {
            auto header = std::dynamic_pointer_cast<HttpResHeader>(msg.header);
            HttpLog(getsrc(), status.req->header, header);
            if (status.req->header->ismethod("CONNECT") ||
                status.req->header->ismethod("SEND")) {
                if (memcmp(header->status, "200", 3) == 0) {
                    strcpy(header->status, "200 Connection established");
                    header->del("Transfer-Encoding");
                }
            } else if (header->get("Transfer-Encoding")) {
                status.flags |= HTTP_CHUNK_F;
            } else if (header->get("Content-Length") == nullptr) {
                status.flags |= HTTP_NOLENGTH_F;
            }
            if (!status.req->header->should_proxy && opt.alt_svc) {
                header->set("Alt-Svc", opt.alt_svc);
            }
            auto buff = std::make_shared<Block>(BUF_LEN);
            size_t len = PackHttpRes(header, buff->data(), BUF_LEN);
            rwer->buffer_insert(rwer->buffer_end(), Buffer{buff, len});
            return 1;
        }
        case ChannelMessage::CHANNEL_MSG_DATA:
            Recv(std::move(msg.data));
            return 1;
        case ChannelMessage::CHANNEL_MSG_SIGNAL:
            Handle(msg.signal);
            return 0;
        }
        return 0;
    }, [this]{ return  rwer->cap(0); });
}

void Guest::Recv(Buffer&& bb) {
    ReqStatus& status = statuslist.front();
    assert((status.flags & HTTP_RES_EOF) == 0);
    assert((status.flags & HTTP_RES_COMPLETED) == 0);
    size_t len = bb.len;
    if(status.flags & HTTP_CHUNK_F){
        char chunkbuf[100];
        int chunklen = snprintf(chunkbuf, sizeof(chunkbuf), "%x" CRLF, (uint32_t)bb.len);
        bb.trunc(-chunklen);
        memcpy(bb.data(), chunkbuf, chunklen);
        rwer->buffer_insert(rwer->buffer_end(), std::move(bb));
        rwer->buffer_insert(rwer->buffer_end(), Buffer{CRLF, strlen(CRLF)});
    }else{
        rwer->buffer_insert(rwer->buffer_end(), std::move(bb));
    }
    tx_bytes += len;
    if(len == 0){
        status.flags |= HTTP_RES_COMPLETED;
        LOGD(DHTTP, "<guest> Recv %" PRIu32 ": EOF/%zu\n", status.req->header->request_id, tx_bytes);
    }else{
        LOGD(DHTTP, "<guest> Recv %" PRIu32 ": size:%zu/%zu\n", status.req->header->request_id, len, tx_bytes);
    }
}

void Guest::Handle(ChannelMessage::Signal s) {
    ReqStatus& status = statuslist.front();
    LOGD(DHTTP, "<guest> signal %" PRIu32 ": %d\n", status.req->header->request_id, (int)s);
    switch(s) {
    case ChannelMessage::CHANNEL_SHUTDOWN:
        assert((status.flags & HTTP_REQ_EOF) == 0);
        status.flags |= HTTP_RES_EOF;
        rwer->addEvents(RW_EVENT::READ);
        if (rwer->wlength() == 0) {
            std::dynamic_pointer_cast<SocketRWer>(rwer)->Shutdown();
        }
        break;
    case ChannelMessage::CHANNEL_CLOSED:
    case ChannelMessage::CHANNEL_ABORT:
        status.flags |= HTTP_CLOSED_F;
        if ((status.flags & HTTP_REQ_COMPLETED) && (status.flags & HTTP_RES_COMPLETED)) {
            return deqReq();
        }
        return deleteLater(PEER_LOST_ERR);
    }
}

void Guest::deleteLater(uint32_t errcode){
    for(auto& status: statuslist){
        if((status.flags & HTTP_CLOSED_F) == 0){
            status.req->send(errcode ? ChannelMessage::CHANNEL_ABORT : ChannelMessage::CHANNEL_CLOSED);
        }
        status.res = nullptr;
        status.flags |= HTTP_CLOSED_F;
    }
    Server::deleteLater(errcode);
}

Guest::~Guest() {
    // we can't do this in deleteLater, because EndProc may be called after it.
    statuslist.clear();
}

void Guest::dump_stat(Dumper dp, void* param){
    dp(param, "Guest %p, (%s)\n", this, getsrc());
    dp(param, "  rwer: rlength:%zu, wlength:%zu, stats:%d, event:%s\n",
            rwer->rlength(), rwer->wlength(),
            (int)rwer->getStats(), events_string[(int)rwer->getEvents()]);
    for(const auto& status : statuslist){
        dp(param, "req [%" PRIu32 "]: %s %s [%d] [%s]\n",
                status.req->header->request_id,
                status.req->header->method,
                status.req->header->geturl().c_str(),
                status.flags,
                status.req->header->get("User-Agent"));
    }
}
