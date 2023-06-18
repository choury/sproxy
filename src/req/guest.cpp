#include "guest.h"
#include "guest2.h"
#include "res/responser.h"
#include "misc/util.h"
#include "misc/config.h"
#include "misc/strategy.h"
#include "prot/sslio.h"

#include <string.h>
#include <assert.h>
#include <inttypes.h>

size_t Guest::ReadHE(const Buffer& bb){
    LOGD(DHTTP, "<guest> (%s) read: len:%zu\n", rwer->getPeer(), bb.len);
    if(bb.len == 0){
        //EOF
        if(statuslist.empty()){
            //clearly close
            deleteLater(NOERROR);
            return 0;
        }
        ReqStatus& status = statuslist.back();
        if(Http_Proc == &Guest::AlwaysProc){
            assert(statuslist.size() == 1);
            //对于AlwaysProc，收到EOF视为请求结束
            if(status.req) {
                status.req->send(nullptr);
            }
            if(status.rwer) {
                status.rwer->push(nullptr);
            }
            status.flags |= HTTP_REQ_COMPLETED;
            if(status.flags & HTTP_RES_COMPLETED){
                deleteLater(NOERROR);
            }
            return 0;
        }
        for(const auto& st : statuslist) {
            if ((st.flags & HTTP_REQ_COMPLETED) == 0) {
                deleteLater(PEER_LOST_ERR);
                break;
            }
        }
        return 0;
    }
    size_t ret = 0;
    size_t len = bb.len;
    const char* data = (const char*)bb.data();
    while(len > 0 && (ret = (this->*Http_Proc)(data, len))){
        len -= ret;
        data += ret;
    }
    return len;
}

int Guest::mread(std::shared_ptr<HttpReqHeader>, Buffer&& bb) {
    LOGD(DHTTP, "<guest> (%s) read: len:%zu\n", rwer->getPeer(), bb.len);
    assert(statuslist.size() == 1);
    auto& status = statuslist.front();
    assert((status.flags & HTTP_RES_COMPLETED) == 0);
    if (bb.len == 0) {
        rwer->buffer_insert(nullptr);
        status.flags |= HTTP_RES_COMPLETED;
        if(status.flags & HTTP_REQ_COMPLETED) {
            deleteLater(NOERROR);
        }
        return 0;
    }
    int cap = rwer->cap(0);
    if(cap <= 0) {
        errno = EAGAIN;
        return -1;
    }
    int len = std::min(bb.len, (size_t)cap);
    bb.truncate(len);
    rwer->buffer_insert(std::move(bb));
    return len;
}

void Guest::WriteHE(uint64_t){
    if(statuslist.empty()){
        return;
    }
    ReqStatus& status = statuslist.front();
    LOGD(DHTTP, "<guest> (%s) written, flags:0x%08x\n", rwer->getPeer(), status.flags);
    if(status.flags & HTTP_RES_COMPLETED){
        return;
    }
    if(status.res){
        status.res->pull();
    }
}

Guest::Guest(int fd, const sockaddr_storage* addr, SSL_CTX* ctx): Requester(nullptr){
    if(ctx){
        auto srwer = std::make_shared<SslRWer<StreamRWer>>(ctx, fd, addr, std::bind(&Guest::Error, this, _1, _2));
        init(srwer);

        srwer->SetConnectCB([this](const sockaddr_storage&){
            //不要捕获rwer,否则不能正常释放shared_ptr
            auto srwer = std::dynamic_pointer_cast<SslRWer<StreamRWer>>(this->rwer);
            const unsigned char *data;
            unsigned int len;
            srwer->get_alpn(&data, &len);
            if ((data && strncasecmp((const char*)data, "h2", len) == 0)) {
                new Guest2(srwer);
                rwer = nullptr;
                assert(statuslist.empty());
                return deleteLater(NOERROR);
            }
        });
    }else{
        init(std::make_shared<StreamRWer>(fd, addr, std::bind(&Guest::Error, this, _1, _2)));
    }
    rwer->SetReadCB(std::bind(&Guest::ReadHE, this, _1));
    rwer->SetWriteCB(std::bind(&Guest::WriteHE, this, _1));
}

Guest::Guest(std::shared_ptr<RWer> rwer): Requester(rwer){
    auto srwer = std::dynamic_pointer_cast<SslRWer<MemRWer>>(rwer);
    if(srwer) {
        srwer->SetConnectCB([this](const sockaddr_storage&){
            auto srwer = std::dynamic_pointer_cast<SslRWer<MemRWer>>(this->rwer);
            const unsigned char *data;
            unsigned int len;
            srwer->get_alpn(&data, &len);
            if ((data && strncasecmp((const char*)data, "h2", len) == 0)) {
                new Guest2(srwer);
                this->rwer = nullptr;
                assert(statuslist.empty());
                return deleteLater(NOERROR);
            }
        });
        forceTls = true;
    }
    rwer->SetErrorCB(std::bind(&Guest::Error, this, _1, _2));
    rwer->SetReadCB(std::bind(&Guest::ReadHE, this, _1));
    rwer->SetWriteCB(std::bind(&Guest::WriteHE, this, _1));
}

void Guest::ReqProc(std::shared_ptr<HttpReqHeader> header) {
    if(header->ismethod("CONNECT") && header->Dest.port == HTTPPORT) {
        auto mrwer = std::make_shared<MemRWer>(header->Dest.hostname, std::bind(&Guest::mread, this, header,  _1));
        statuslist.emplace_back(ReqStatus{nullptr, nullptr, mrwer, HTTP_NOEND_F});
        rwer->buffer_insert({HCONNECT, strlen(HCONNECT)});
        new Guest(mrwer);
        return;
    }
    if(header->ismethod("CONNECT") && header->Dest.port == HTTPSPORT) {
        auto Stra = getstrategy(header->Dest.hostname);
        if (Stra.s == Strategy::local || (opt.ca.key &&  mayBeBlocked(header->Dest.hostname))) {
            auto ctx = initssl(0, header->Dest.hostname);
            auto srwer = std::make_shared<SslRWer<MemRWer>>(ctx, header->Dest.hostname,
                                                            std::bind(&Guest::mread, this, header, _1));
            statuslist.emplace_back(ReqStatus{nullptr, nullptr, srwer, HTTP_NOEND_F});
            rwer->buffer_insert({HCONNECT, strlen(HCONNECT)});
            new Guest(srwer);
            return;
        }
    }
    if(forceTls) {
        strcpy(header->Dest.scheme, "https");
    }
    LOGD(DHTTP, "<guest> ReqProc %" PRIu32 " %s\n", header->request_id, header->geturl().c_str());
    auto req = std::make_shared<HttpReq>(header,
            std::bind(&Guest::response, this, nullptr, _1),
            [this]{ rwer->Unblock(0);});

    statuslist.emplace_back(ReqStatus{req, nullptr, nullptr, 0});
    if(statuslist.size() == 1){
        distribute(req, this);
    }
}

void Guest::deqReq() {
    if(rwer->idle(0)){
        return deleteLater(NOERROR);
    }
    if(statuslist.empty()){
        return;
    }
    ReqStatus& status = statuslist.front();
    //转送的请求不会走到这里，因为他们直接调用deletaLater销毁
    assert(status.rwer == nullptr && status.req);
    if((status.flags & HTTP_CLOSED_F) == 0) {
        status.req->send(ChannelMessage::CHANNEL_ABORT);
    }
    if(status.res){
        status.res->detach();
    }
    statuslist.pop_front();
    if(!statuslist.empty()){
        distribute(statuslist.front().req, this);
    }
}

ssize_t Guest::DataProc(const void *buff, size_t size) {
    ReqStatus& status = statuslist.back();
    assert((status.flags & HTTP_REQ_COMPLETED) == 0);
    int len = size;
    if(status.req) {
        len = std::min(len, (int)status.req->cap());
    }
    if(status.rwer) {
        len = std::min(len, (int)status.rwer->cap(0));
    }
    if (len <= 0) {
        LOGE("[%" PRIu32 "]: <guest> the host's buff is full (%s)\n",
            status.req->header->request_id, status.req->header->geturl().c_str());
        rwer->delEvents(RW_EVENT::READ);
        return -1;
    }
    if(status.req) {
        status.req->send(buff, (size_t)len);
    }
    if(status.rwer) {
        status.rwer->push({buff, (size_t)len});
    }
    rx_bytes += len;
    if(status.req){
        LOGD(DHTTP, "<guest> DataProc %" PRIu32 ": size:%zu, send:%d/%zu\n", status.req->header->request_id, size, len, rx_bytes);
    }
    if(status.rwer) {
        LOGD(DHTTP, "<guest> DataProc %s: size:%zu, send:%d/%zu\n", status.rwer->getPeer(), size, len, rx_bytes);
    }
    return len;
}

void Guest::EndProc() {
    ReqStatus& status = statuslist.back();
    assert(status.req);
    LOGD(DHTTP, "<guest> EndProc %" PRIu32 "\n", status.req->header->request_id);
    rwer->addEvents(RW_EVENT::READ);
    status.req->send(nullptr);
    status.flags |= HTTP_REQ_COMPLETED;
    if(status.flags & HTTP_RES_COMPLETED){
        deqReq();
    }
}

void Guest::ErrProc() {
    Error(PROTOCOL_ERR, 0);
}

void Guest::Error(int ret, int code) {
    if(ret == SSL_SHAKEHAND_ERR){
        LOGE("(%s): <guest> ssl_accept error %d/%d\n", rwer->getPeer(), ret, code);
    }
    if(statuslist.empty()){
        return deleteLater(PEER_LOST_ERR);
    }
    ReqStatus& status = statuslist.back();
    if(status.req) {
        LOGE("[%" PRIu32 "]: <guest> error (%s) %d/%d http_flag:0x%x\n",
            status.req->header->request_id, status.req->header->geturl().c_str(), ret, code, http_flag);
    }
    deleteLater(ret);
}

void Guest::response(void*, std::shared_ptr<HttpRes> res) {
    ReqStatus& status = statuslist.front();
    assert(status.res == nullptr && status.req);
    status.res = res;
    res->attach([this, &status](ChannelMessage& msg){
        assert(!statuslist.empty());
        switch(msg.type){
        case ChannelMessage::CHANNEL_MSG_HEADER: {
            auto header = std::dynamic_pointer_cast<HttpResHeader>(msg.header);
            HttpLog(rwer->getPeer(), status.req->header, header);
            if (status.req->header->ismethod("CONNECT") ||
                status.req->header->ismethod("SEND")) {
                if (memcmp(header->status, "200", 3) == 0) {
                    strcpy(header->status, "200 Connection established");
                    header->del("Transfer-Encoding");
                }
            } else if (header->get("Transfer-Encoding")) {
                status.flags |= HTTP_CHUNK_F;
            }
            if(header->no_end()) {
                status.flags |= HTTP_NOEND_F;
            }
            if (!status.req->header->should_proxy && opt.alt_svc) {
                header->set("Alt-Svc", opt.alt_svc);
            }
            if(forceTls) {
                header->del("Strict-Transport-Security");
            }
            Buffer buff{BUF_LEN};
            buff.truncate(PackHttpRes(header, buff.mutable_data(), BUF_LEN));
            rwer->buffer_insert(std::move(buff));
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
    assert((status.flags & HTTP_RES_COMPLETED) == 0);
    if(bb.len == 0){
        status.flags |= HTTP_RES_COMPLETED;
        LOGD(DHTTP, "<guest> recv %" PRIu32 ": EOF/%zu\n", status.req->header->request_id, tx_bytes);
        if(status.flags & HTTP_NOEND_F){
            assert(statuslist.size() == 1);
            //对于没有长度字段的响应，直接关闭连接来结束
            rwer->buffer_insert(nullptr);
        }else if(status.flags & HTTP_CHUNK_F){
            rwer->buffer_insert({"0" CRLF CRLF, 5});
        }
        //如果既不是没有长度的请求，也非chunked，则无需发送额外数据来标记结束
        if(status.flags & HTTP_REQ_COMPLETED) {
            rwer->addjob(std::bind(&Guest::deqReq, this), 0, JOB_FLAGS_AUTORELEASE);
        }
        return;
    }
    if(status.req->header->ismethod("HEAD")){
        LOGD(DHTTP, "<guest> recv %" PRIu32 ": HEAD req discard body\n", status.req->header->request_id);
        return;
    }
    tx_bytes += bb.len;
    LOGD(DHTTP, "<guest> recv %" PRIu32 ": size:%zu/%zu\n", status.req->header->request_id, bb.len, tx_bytes);
    if(status.flags & HTTP_CHUNK_F){
        char chunkbuf[100];
        int chunklen = snprintf(chunkbuf, sizeof(chunkbuf), "%x" CRLF, (uint32_t)bb.len);
        bb.reserve(-chunklen);
        memcpy(bb.mutable_data(), chunkbuf, chunklen);
        rwer->buffer_insert(std::move(bb));
        rwer->buffer_insert(Buffer{CRLF, 2});
    }else{
        rwer->buffer_insert(std::move(bb));
    }
}

void Guest::Handle(ChannelMessage::Signal s) {
    ReqStatus& status = statuslist.front();
    LOGD(DHTTP, "<guest> signal %" PRIu32 ": %d\n", status.req->header->request_id, (int)s);
    switch(s) {
    case ChannelMessage::CHANNEL_ABORT:
        status.flags |= HTTP_CLOSED_F;
        if ((status.flags & HTTP_REQ_COMPLETED) && (status.flags & HTTP_RES_COMPLETED)) {
            return deqReq();
        }
        return deleteLater(PROTOCOL_ERR);
    }
}

void Guest::deleteLater(uint32_t errcode) {
    for(auto& status: statuslist){
        if(status.flags & HTTP_CLOSED_F){
            continue;
        }
        status.flags |= HTTP_CLOSED_F;
        if(status.req) {
            status.req->send(ChannelMessage::CHANNEL_ABORT);
        }
        if(status.res) {
            status.res->detach();
        }
        if(status.rwer) {
            status.rwer->push(nullptr);
            status.rwer->detach();
        }
    }
    statuslist.clear();
    Server::deleteLater(errcode);
}

Guest::~Guest() {
    if(rwer) {
        LOGD(DHTTP, "<guest> (%s) destoryed: rx:%zu, tx:%zu\n", rwer->getPeer(), rx_bytes, tx_bytes);
    }
}

void Guest::dump_stat(Dumper dp, void* param){
    dp(param, "Guest %p, tx:%zd, rx:%zd\n", this, tx_bytes, rx_bytes);
    for(const auto& status : statuslist){
        if(status.req) {
            dp(param, "  [%" PRIu32 "]: %s %s, time: %dms, flags: 0x%08x [%s]\n",
                    status.req->header->request_id,
                    status.req->header->method,
                    status.req->header->geturl().c_str(),
                    getmtime() - status.req->header->ctime,
                    status.flags,
                    status.req->header->get("User-Agent"));
        }
        if(status.rwer) {
            dp(param, "  [MemRWer]: %s, flags: 0x%08x\n", status.rwer->getPeer(), status.flags);
        }
    }
    rwer->dump_status(dp, param);
}

void Guest::dump_usage(Dumper dp, void *param) {
    size_t req_usage  = statuslist.size() * sizeof(ReqStatus);
    for(const auto& status: statuslist) {
        if(status.req == nullptr) {
            continue;
        }
        req_usage += status.req->mem_usage();
    }
    dp(param, "Guest %p: %zd, reqlist: %zd, rwer: %zd\n",
       this, sizeof(*this), req_usage, rwer->mem_usage());
}
