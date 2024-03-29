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

int Guest::mread(std::shared_ptr<HttpReqHeader>, std::variant<Buffer, Signal> data) {
    return std::visit([this](auto&& arg) -> int {
        using T = std::decay_t<decltype(arg)>;
        if constexpr (std::is_same_v<T, int>) {
            Handle(arg);
        } else if constexpr (std::is_same_v<T, Buffer>) {
            LOGD(DHTTP, "<guest> (%s) read: len:%zu\n", rwer->getPeer(), arg.len);
            assert(statuslist.size() == 1);
            auto& status = statuslist.front();
            assert((status.flags & HTTP_RES_COMPLETED) == 0);
            if (arg.len == 0) {
                rwer->Send(nullptr);
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
            int len = std::min(arg.len, (size_t)cap);
            arg.truncate(len);
            rwer->Send(std::move(arg));
            return len;
        }
        return 0;
    }, data);
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
        auto srwer = std::make_shared<SslRWer>(ctx, fd, addr, [this](int ret, int code){
            Error(ret, code);
        });
        init(srwer);

        srwer->SetConnectCB([this](const sockaddr_storage&){
            //不要捕获rwer,否则不能正常释放shared_ptr
            LOGD(DHTTP, "<guest> %s connected\n", rwer->getPeer());
            auto srwer = std::dynamic_pointer_cast<SslRWer>(this->rwer);
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
        init(std::make_shared<StreamRWer>(fd, addr, [this](int ret, int code) {
            Error(ret, code);
        }));
    }
    rwer->SetReadCB([this](const Buffer& bb) {
        return ReadHE(bb);
    });
    rwer->SetWriteCB([this](uint64_t id){
        return WriteHE(id);
    });
}

Guest::Guest(std::shared_ptr<RWer> rwer_): Requester(rwer_){
    auto srwer = std::dynamic_pointer_cast<SslMer>(rwer);
    if(srwer) {
        srwer->SetConnectCB([this](const sockaddr_storage&){
            LOGD(DHTTP, "<guest> %s connected\n", rwer->getPeer());
            auto srwer = std::dynamic_pointer_cast<SslMer>(this->rwer);
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
        mitmProxy = true;
    }
    rwer->SetErrorCB([this](int ret, int code){
        Error(ret, code);
    });
    rwer->SetReadCB([this](const Buffer& bb){
        return ReadHE(bb);
    });
    rwer->SetWriteCB([this](uint64_t id){
        return WriteHE(id);
    });
}

void Guest::ReqProc(std::shared_ptr<HttpReqHeader> header) {
    if(header->ismethod("CONNECT") && header->Dest.port == HTTPPORT) {
        auto mrwer = std::make_shared<MemRWer>(rwer->getPeer(),
                                               [this, header](auto&& data) {
                                                   return mread(header, std::forward<decltype(data)>(data));
                                               },
                                               [this]{ return  rwer->cap(0);});
        statuslist.emplace_back(ReqStatus{nullptr, nullptr, mrwer, HTTP_NOEND_F});
        rwer->Send({HCONNECT, strlen(HCONNECT)});
        new Guest(mrwer);
        return;
    }
    if(header->ismethod("CONNECT") && header->Dest.port == HTTPSPORT) {
        bool shouldMitm = (opt.mitm_mode == Enable) ||
                (opt.mitm_mode == Auto && opt.ca.key && mayBeBlocked(header->Dest.hostname));
        if (shouldMitm || getstrategy(header->Dest.hostname).s == Strategy::local) {
            auto ctx = initssl(0, header->Dest.hostname);
            auto srwer = std::make_shared<SslMer>(ctx, rwer->getPeer(),
                                                  [this, header](auto&& data) {
                                                      return mread(header, std::forward<decltype(data)>(data));
                                                  },
                                                  [this]{ return  rwer->cap(0);});
            statuslist.emplace_back(ReqStatus{nullptr, nullptr, srwer, HTTP_NOEND_F});
            rwer->Send({HCONNECT, strlen(HCONNECT)});
            new Guest(srwer);
            return;
        }
    }
    if(mitmProxy && header->http_method()) {
        strcpy(header->Dest.scheme, "https");
        strcpy(header->Dest.protocol, "ssl");
    }
    LOGD(DHTTP, "<guest> ReqProc %" PRIu32 " %s\n", header->request_id, header->geturl().c_str());
    auto req = std::make_shared<HttpReq>(header,
            [this](std::shared_ptr<HttpRes> res) { response(nullptr, res); },
            [this]{ rwer->Unblock(0);});

    statuslist.emplace_back(ReqStatus{req, nullptr, nullptr});
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
        status.req->send(CHANNEL_ABORT);
    }
    if(status.res){
        status.res->detach();
    }
    statuslist.pop_front();
    if(!statuslist.empty()){
        distribute(statuslist.front().req, this);
    }else if(rwer->isEof()){
        //不会再有新的请求了，可以直接关闭
        deleteLater(NOERROR);
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
        len = std::min(len, (int)status.rwer->bufsize());
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
        status.rwer->push(Buffer{buff, (size_t)len});
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
    if (status.req == nullptr) {
        return deleteLater(ret);
    }
    if(ret == PROTOCOL_ERR && code == PEER_LOST_ERR && strcmp(status.req->header->Dest.protocol, "udp") == 0){
        return deleteLater(PEER_LOST_ERR);
    }
    LOGE("[%" PRIu32 "]: <guest> error (%s) %d/%d flags:0x%x http_flag:0x%x\n",
        status.req->header->request_id, status.req->header->geturl().c_str(),
        ret, code, status.flags, http_flag);
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
            auto header = std::dynamic_pointer_cast<HttpResHeader>(std::get<std::shared_ptr<HttpHeader>>(msg.data));
            HttpLog(rwer->getPeer(), status.req->header, header);
            if (status.req->header->ismethod("CONNECT")) {
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
            if (opt.alt_svc) {
                header->set("Alt-Svc", opt.alt_svc);
            }
            Buffer buff{BUF_LEN};
            buff.truncate(PackHttpRes(header, buff.mutable_data(), BUF_LEN));
            rwer->Send(std::move(buff));
            return 1;
        }
        case ChannelMessage::CHANNEL_MSG_DATA:
            Recv(std::move(std::get<Buffer>(msg.data)));
            return 1;
        case ChannelMessage::CHANNEL_MSG_SIGNAL:
            Handle(std::get<Signal>(msg.data));
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
            rwer->Send(nullptr);
        }else if(status.flags & HTTP_CHUNK_F){
            rwer->Send({"0" CRLF CRLF, 5});
        }
        //如果既不是没有长度的请求，也非chunked，则无需发送额外数据来标记结束
        if(status.flags & HTTP_REQ_COMPLETED) {
            status.cleanJob = AddJob([this]{ deqReq(); }, 0, 0);
        }
        if(status.rwer && status.req && (status.flags & HTTP_CLOSED_F) == 0) {
            status.flags |= HTTP_CLOSED_F;
            status.req->send(CHANNEL_ABORT);
            return deleteLater(PEER_LOST_ERR);
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
        rwer->Send(std::move(bb));
        rwer->Send({CRLF, 2});
    }else{
        rwer->Send(std::move(bb));
    }
}

void Guest::Handle(Signal s) {
    ReqStatus& status = statuslist.front();
    LOGD(DHTTP, "<guest> signal %" PRIu32 ": %d\n", status.req->header->request_id, (int)s);
    switch(s) {
    case CHANNEL_ABORT:
        status.flags |= HTTP_CLOSED_F;
        if ((status.flags & HTTP_REQ_COMPLETED) && (status.flags & HTTP_RES_COMPLETED)) {
            //如果是已经干净结束的请求，那么直接清理掉就可以了，链接可以继续使用
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
            status.req->send(CHANNEL_ABORT);
        }
        if(status.res) {
            status.res->detach();
        }
        if(status.rwer) {
            status.rwer->push(CHANNEL_ABORT);
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
