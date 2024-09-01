#include "guest.h"
#include "guest2.h"
#include "guest_sni.h"
#include "res/responser.h"
#include "res/rproxy2.h"
#include "misc/util.h"
#include "misc/config.h"
#include "misc/strategy.h"
#include "prot/sslio.h"

#include <string.h>
#include <assert.h>
#include <inttypes.h>

size_t Guest::ReadHE(Buffer&& bb){
    LOGD(DHTTP, "<guest> (%s) read: len:%zu, refs: %zd\n", dumpDest(rwer->getSrc()).c_str(), bb.len, bb.refs());
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
                status.req->send(Buffer{nullptr, bb.id});
            }
            if(status.rwer) {
                status.rwer->push(Buffer{nullptr, bb.id});
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
    size_t len = bb.len;
    while(bb.len > 0 && (this->*Http_Proc)(bb));
    return len - bb.len;
}

int Guest::mread(std::shared_ptr<HttpReqHeader>,
        std::variant<std::reference_wrapper<Buffer>, Buffer, Signal> data) {
    auto BufferHandle = [this](Buffer& bb) {
        LOGD(DHTTP, "<guest> (%s) read: len:%zu\n", dumpDest(rwer->getSrc()).c_str(), bb.len);
        assert(statuslist.size() == 1);
        auto& status = statuslist.front();
        assert((status.flags & HTTP_RES_COMPLETED) == 0);
        if (bb.len == 0) {
            rwer->Send({nullptr, bb.id});
            status.flags |= HTTP_RES_COMPLETED;
            if(status.flags & HTTP_REQ_COMPLETED) {
                deleteLater(NOERROR);
            }
            return 0;
        }
        int cap = rwer->cap(bb.id);
        if(cap <= 0) {
            errno = EAGAIN;
            return -1;
        }
        if(cap >= (int)bb.len) {
            cap = bb.len;
            rwer->Send(std::move(bb));
        } else {
            auto cbb = bb;
            cbb.truncate(cap);
            rwer->Send(std::move(cbb));
        }
        return cap;
    };
    return std::visit([&](auto&& arg) -> int {
        using T = std::decay_t<decltype(arg)>;
        if constexpr (std::is_same_v<T, int>) {
            Handle(arg);
        } else if constexpr (std::is_same_v<T, Buffer>) {
            return BufferHandle(arg);
        } else if constexpr (std::is_same_v<T, std::reference_wrapper<Buffer>>) {
            return BufferHandle(arg.get());
        }
        return 0;
    }, data);
}

void Guest::WriteHE(uint64_t){
    if(statuslist.empty()){
        return;
    }
    ReqStatus& status = statuslist.front();
    LOGD(DHTTP, "<guest> (%s) written, flags:0x%08x\n", dumpDest(rwer->getSrc()).c_str(), status.flags);
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
        this->rwer = srwer;
        srwer->SetConnectCB([this](const sockaddr_storage&){
            //不要捕获rwer,否则不能正常释放shared_ptr
            auto srwer = std::dynamic_pointer_cast<SslRWer>(this->rwer);
            const unsigned char *data;
            unsigned int len;
            srwer->get_alpn(&data, &len);
            LOGD(DHTTP, "<guest> %s connected: %.*s\n", dumpDest(rwer->getSrc()).c_str(), len, (const char*)data);
            if (data == nullptr || data[0] == 0) {
                return;
            }
            assert(statuslist.empty());
            if (strncasecmp((const char*)data, "h2", len) == 0) {
                new Guest2(srwer);
                rwer = nullptr;
                return Server::deleteLater(NOERROR);
            }
            if (strncasecmp((const char*)data, "r2", len) == 0) {
                (new Rproxy2(srwer))->init();
                rwer = nullptr;
                return Server::deleteLater(NOERROR);
            }
        });
    }else{
        rwer = std::make_shared<StreamRWer>(fd, addr, [this](int ret, int code) {
            Error(ret, code);
        });
    }
    rwer->SetReadCB([this](Buffer&& bb) {
        return ReadHE(std::move(bb));
    });
    rwer->SetWriteCB([this](uint64_t id){
        return WriteHE(id);
    });
}

Guest::Guest(std::shared_ptr<RWer> rwer_): Requester(rwer_){
    auto srwer = std::dynamic_pointer_cast<SslMer>(rwer);
    if(srwer) {
        srwer->SetConnectCB([this](const sockaddr_storage&){
            LOGD(DHTTP, "<guest> %s connected\n", dumpDest(rwer->getSrc()).c_str());
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
    }
    rwer->SetErrorCB([this](int ret, int code){
        Error(ret, code);
    });
    rwer->SetReadCB([this](Buffer&& bb){
        return ReadHE(std::move(bb));
    });
    rwer->SetWriteCB([this](uint64_t id){
        return WriteHE(id);
    });
}

void Guest::ReqProc(uint64_t id, std::shared_ptr<HttpReqHeader> header) {
    static const char*  HCONNECT = "HTTP/1.1 200 Connection establishe" CRLF CRLF;
    if(header->ismethod("CONNECT")) {
        if(header->Dest.port == HTTPPORT) {
            if(!headless) rwer->Send({HCONNECT, strlen(HCONNECT), id});
            Http_Proc = (bool (HttpBase::*)(Buffer&))&Guest::HeaderProc;
            return;
        }
        if(header->Dest.port == HTTPSPORT) {
            if(!headless) rwer->Send({HCONNECT, strlen(HCONNECT), id});
            bool shouldMitm = (opt.mitm_mode == Enable) ||
            (opt.mitm_mode == Auto && opt.ca.key && mayBeBlocked(header->Dest.hostname));
            if (shouldMitm || getstrategy(header->Dest.hostname).s == Strategy::local) {
                auto ctx = initssl(0, header->Dest.hostname);
                auto srwer = std::make_shared<SslMer>(ctx, rwer->getSrc(),
                                                      [this, header](auto&& data) {
                                                          return mread(header, std::forward<decltype(data)>(data));
                                                      },
                                                      [this, id]{ return  rwer->cap(id);});
                statuslist.emplace_back(ReqStatus{nullptr, nullptr, srwer, HTTP_NOEND_F});
                new Guest(srwer);
            } else {
                auto mrwer = std::make_shared<MemRWer>(rwer->getSrc(),
                                               [this, header](auto&& data) {
                                                   return mread(header, std::forward<decltype(data)>(data));
                                               },
                                               [this, id]{ return  rwer->cap(id);});
                statuslist.emplace_back(ReqStatus{nullptr, nullptr, mrwer, HTTP_NOEND_F});
                new Guest_sni(mrwer, header->Dest.hostname, header->get("User-Agent"));
            }
            return;
        }
    }
    if(header->Dest.scheme[0] == 0 && header->http_method()) {
        if(rwer->isTls()) {
            strcpy(header->Dest.scheme, "https");
            strcpy(header->Dest.protocol, "ssl");
        } else {
            strcpy(header->Dest.scheme, "http");
            strcpy(header->Dest.protocol, "tcp");
        }
    }
    LOGD(DHTTP, "<guest> ReqProc %" PRIu64 " %s\n", header->request_id, header->geturl().c_str());
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

ssize_t Guest::DataProc(Buffer& bb) {
    ReqStatus& status = statuslist.back();
    assert((status.flags & HTTP_REQ_COMPLETED) == 0);
    int cap = 0;
    if(status.req) {
        cap = status.req->cap();
    }
    if(status.rwer) {
        cap = status.rwer->bufsize();
    }
    if (cap <= 0) {
        LOGE("[%" PRIu64 "]: <guest> the host's buff is full (%s)\n",
            status.req->header->request_id, status.req->header->geturl().c_str());
        rwer->delEvents(RW_EVENT::READ);
        return -1;
    }
    auto tx = [&](Buffer&& bb) {
        if (status.req) {
            LOGD(DHTTP, "<guest> DataProc %" PRIu64 ": cap:%zu, send:%d/%zu\n",
                 status.req->header->request_id, bb.len, cap, rx_bytes);
            status.req->send(std::move(bb));
        }
        if (status.rwer) {
            LOGD(DHTTP, "<guest> DataProc %s: cap:%zu, send:%d/%zu\n",
                 dumpDest(status.rwer->getSrc()).c_str(), bb.len, cap, rx_bytes);
            status.rwer->push(std::move(bb));
        }
    };
    if((size_t)cap < bb.len) {
        auto cbb = bb;
        cbb.truncate(cap);
        tx(std::move(cbb));
        bb.reserve(cap);
    } else {
        cap = bb.len;
        tx(std::move(bb));
    }
    rx_bytes += cap;
    return cap;
}

void Guest::EndProc(uint64_t) {
    ReqStatus& status = statuslist.back();
    assert(status.req);
    LOGD(DHTTP, "<guest> EndProc %" PRIu64 "\n", status.req->header->request_id);
    rwer->addEvents(RW_EVENT::READ);
    status.req->send(nullptr);
    status.flags |= HTTP_REQ_COMPLETED;
    if(status.flags & HTTP_RES_COMPLETED){
        deqReq();
    }
}

void Guest::ErrProc(uint64_t) {
    Error(PROTOCOL_ERR, 0);
}

void Guest::Error(int ret, int code) {
    if(ret == SSL_SHAKEHAND_ERR){
        LOGE("(%s): <guest> ssl_accept error %d/%d\n", dumpDest(rwer->getSrc()).c_str(), ret, code);
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
    LOGE("[%" PRIu64 "]: <guest> error (%s) %d/%d flags:0x%x http_flag:0x%x\n",
        status.req->header->request_id, status.req->header->geturl().c_str(),
        ret, code, status.flags, http_flag);
    deleteLater(ret);
}

void Guest::response(void*, std::shared_ptr<HttpRes> res) {
    ReqStatus& status = statuslist.front();
    assert(status.res == nullptr && status.req);
    status.res = res;
    res->attach([this, &status](ChannelMessage&& msg){
        assert(!statuslist.empty());
        switch(msg.type){
        case ChannelMessage::CHANNEL_MSG_HEADER: {
            auto header = std::dynamic_pointer_cast<HttpResHeader>(std::get<std::shared_ptr<HttpHeader>>(msg.data));
            HttpLog(dumpDest(rwer->getSrc()), status.req->header, header);
            if (status.req->header->ismethod("CONNECT")) {
                if (headless) {
                    status.flags |= HTTP_NOEND_F;
                    if(memcmp(header->status, "200", 3) == 0){
                        rwer->Unblock(0);
                        return 1;
                    }else {
                        deleteLater(PEER_LOST_ERR);
                        return 0;
                    }
                }
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
            Buffer buff{BUF_LEN, header->request_id};
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
    static Buffer crlf{CRLF, 2};
    ReqStatus& status = statuslist.front();
    assert((status.flags & HTTP_RES_COMPLETED) == 0);
    if(bb.len == 0){
        status.flags |= HTTP_RES_COMPLETED;
        LOGD(DHTTP, "<guest> recv %" PRIu64 ": EOF/%zu\n", status.req->header->request_id, tx_bytes);
        if(status.flags & HTTP_NOEND_F){
            assert(statuslist.size() == 1);
            //对于没有长度字段的响应，直接关闭连接来结束
            rwer->Send({nullptr, bb.id});
        }else if(status.flags & HTTP_CHUNK_F){
            rwer->Send({"0" CRLF CRLF, 5, bb.id});
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
        LOGD(DHTTP, "<guest> recv %" PRIu64 ": HEAD req discard body\n", status.req->header->request_id);
        return;
    }
    tx_bytes += bb.len;
    LOGD(DHTTP, "<guest> recv %" PRIu64 ": size:%zu/%zu, refs: %zd\n",
         status.req->header->request_id, bb.len, tx_bytes, bb.refs());
    if(status.flags & HTTP_CHUNK_F){
        char chunkbuf[100];
        int chunklen = snprintf(chunkbuf, sizeof(chunkbuf), "%x" CRLF, (uint32_t)bb.len);
        if(bb.refs() == 1) {
            bb.reserve(-chunklen);
            memcpy(bb.mutable_data(), chunkbuf, chunklen);
        } else {
            rwer->Send(Buffer{chunkbuf, (size_t)chunklen, bb.id});
        }
        rwer->Send(std::move(bb));
        auto cbb = crlf;
        cbb.id = bb.id;
        rwer->Send(std::move(cbb));
    }else{
        rwer->Send(std::move(bb));
    }
}

void Guest::Handle(Signal s) {
    ReqStatus& status = statuslist.front();
    LOGD(DHTTP, "<guest> signal %" PRIu64 ": %d\n", status.req->header->request_id, (int)s);
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
        if((status.flags & HTTP_CLOSED_F) == 0 && status.req){
            status.req->send(CHANNEL_ABORT);
            status.flags |= HTTP_CLOSED_F;
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
        LOGD(DHTTP, "<guest> (%s) destoryed: rx:%zu, tx:%zu\n", dumpDest(rwer->getSrc()).c_str(), rx_bytes, tx_bytes);
    }
}

void Guest::dump_stat(Dumper dp, void* param){
    dp(param, "Guest %p, tx:%zd, rx:%zd\n", this, tx_bytes, rx_bytes);
    for(const auto& status : statuslist){
        if(status.req) {
            dp(param, "  [%" PRIu64 "]: %s %s, time: %dms, flags: 0x%08x [%s]\n",
                    status.req->header->request_id,
                    status.req->header->method,
                    status.req->header->geturl().c_str(),
                    getmtime() - status.req->header->ctime,
                    status.flags,
                    status.req->header->get("User-Agent"));
        }
        if(status.rwer) {
            dp(param, "  [MemRWer]: %s, flags: 0x%08x\n", dumpDest(status.rwer->getSrc()).c_str(), status.flags);
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
