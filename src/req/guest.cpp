#include "guest.h"
#include "guest2.h"
#include "res/responser.h"
#include "res/rproxy2.h"
#include "misc/config.h"
#include "misc/hook.h"
#include "misc/job.h"
#include "prot/sslio.h"
#include "prot/tls.h"
#include "prot/memio.h"

#include <string.h>
#include <assert.h>
#include <inttypes.h>

size_t Guest::ReadHE(Buffer&& bb){
    HOOK_FUNC(this, statuslist, bb);
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
            status.rw->push_data(Buffer{nullptr, bb.id});
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

void Guest::WriteHE(uint64_t id){
    if(statuslist.empty()){
        return;
    }
    ReqStatus& status = statuslist.front();
    LOGD(DHTTP, "<guest> (%s) written, flags:0x%08x\n", dumpDest(rwer->getSrc()).c_str(), status.flags);
    if(status.flags & (HTTP_RES_COMPLETED | HTTP_CLOSED_F | HTTP_RST)){
        return;
    }
    status.rw->pull(id);
}

Guest::Guest(int fd, const sockaddr_storage* addr, SSL_CTX* ctx): Requester(nullptr){
    cb = ISocketCallback::create()->onRead([this](Buffer&& bb) {
        return ReadHE(std::move(bb));
    })->onWrite([this](uint64_t id){
        return WriteHE(id);
    })->onError([this](int ret, int code){
        Error(ret, code);
    });
    if(ctx){
        std::dynamic_pointer_cast<ISocketCallback>(cb)->onConnect([this](const sockaddr_storage&, uint32_t){
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
        rwer = std::make_shared<SslRWer>(ctx, fd, addr, cb);
    }else{
        int type;
        socklen_t len = sizeof(type);
        if(getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &len) < 0){
            LOGF("Faild to get socket type: %s\n", strerror(errno));
        }
        if(type == SOCK_STREAM) {
            rwer = std::make_shared<StreamRWer>(fd, addr, cb);
        }else if(type == SOCK_DGRAM) {
            rwer = std::make_shared<PacketRWer>(fd, addr, cb);
        }else {
            LOGF("unknown socket type: %d\n", type);
        }
    }
}

Guest::Guest(std::shared_ptr<RWer> rwer): Requester(rwer){
    cb = ISocketCallback::create()->onRead([this](Buffer&& bb){
        return ReadHE(std::move(bb));
    })->onWrite([this](uint64_t id){
        return WriteHE(id);
    })->onError([this](int ret, int code){
        Error(ret, code);
    });
    if(std::dynamic_pointer_cast<SslMer>(rwer)) {
        std::dynamic_pointer_cast<ISocketCallback>(cb)->onConnect([this](const sockaddr_storage&, uint32_t){
            LOGD(DHTTP, "<guest> %s connected\n", dumpDest(this->rwer->getSrc()).c_str());
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
    rwer->SetCallback(cb);
}

void Guest::ReqProc(uint64_t id, std::shared_ptr<HttpReqHeader> header) {
    static const char*  HCONNECT = "HTTP/1.1 200 Connection establishe" CRLF CRLF;
    auto _cb = response(id);
    if(header->ismethod("CONNECT")) {
        if(header->Dest.port == HTTPPORT) {
            if(!headless) rwer->Send({HCONNECT, strlen(HCONNECT), id});
            Http_Proc = (bool (HttpBase::*)(Buffer&))&Guest::HeaderProc;
            return;
        }
        if(header->Dest.port == HTTPSPORT && shouldNegotiate(header, this)) {
            if(!headless) rwer->Send({HCONNECT, strlen(HCONNECT), id});
            auto ctx = initssl(0, header->Dest.hostname);
            auto srwer = std::make_shared<SslMer>(ctx, rwer->getSrc(), _cb);
            statuslist.emplace_back(ReqStatus{header, srwer, _cb, HTTP_NOEND_F});
            new Guest(srwer);
            return;
        }
    }
    header->set("User-Agent", generateUA(header->get("User-Agent"), "", header->request_id));
    if(header->Dest.scheme[0] == 0 && header->http_method()) {
        if(rwer->isTls()) {
            strcpy(header->Dest.scheme, "https");
            if(header->Dest.protocol[0] == 0) {
                strcpy(header->Dest.protocol, "ssl");
            }
        } else {
            strcpy(header->Dest.scheme, "http");
            if(header->Dest.protocol[0] == 0) {
                strcpy(header->Dest.protocol, "tcp");
            }
        }
    }

    LOGD(DHTTP, "<guest> ReqProc %" PRIu64 " %s\n", header->request_id, header->geturl().c_str());
    std::shared_ptr<MemRWer> rw = std::make_shared<MemRWer>(getSrc(), _cb);
    statuslist.emplace_back(ReqStatus{header, rw, _cb});
    if(statuslist.size() == 1){
        distribute(header, rw, this);
    } else {
        LOGD(DHTTP, "<guest> ReqProc %" PRIu64 " %s, waiting for the previous request to finish\n",
             header->request_id, header->geturl().c_str());
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
    if((status.flags & HTTP_CLOSED_F) == 0) {
        status.rw->push_signal(CHANNEL_ABORT);
    }
    statuslist.pop_front();
    if(!statuslist.empty()){
        auto& status = statuslist.front();
        LOGD(DHTTP, "<guest> deqReq %" PRIu64 " %s\n",
             status.req->request_id, status.req->geturl().c_str());
        distribute(status.req, status.rw, this);
    }else if(rwer->isEof()){
        //不会再有新的请求了，可以直接关闭
        deleteLater(NOERROR);
    }
}

ssize_t Guest::DataProc(Buffer& bb) {
    HOOK_FUNC(this, statuslist, bb);
    ReqStatus& status = statuslist.back();
    assert((status.flags & HTTP_REQ_COMPLETED) == 0);
    int cap = status.rw->bufsize();
    if (cap <= 0) {
        LOGE("[%" PRIu64 "]: <guest> the host's buff is full (%s)\n",
            status.req->request_id, status.req->geturl().c_str());
        rwer->delEvents(RW_EVENT::READ);
        return -1;
    }
    auto tx = [&](Buffer&& bb) {
        LOGD(DHTTP, "<guest> DataProc %" PRIu64 ": cap:%zu, send:%d/%zu\n",
                status.req->request_id, bb.len, cap, rx_bytes);
        status.rw->push_data(std::move(bb));
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
    LOGD(DHTTP, "<guest> EndProc %" PRIu64 "\n", status.req->request_id);
    rwer->addEvents(RW_EVENT::READ);
    status.rw->push_data(nullptr);
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
    if(ret == PROTOCOL_ERR && code == PEER_LOST_ERR && strcmp(status.req->Dest.protocol, "udp") == 0){
        return deleteLater(PEER_LOST_ERR);
    }
    LOGE("[%" PRIu64 "]: <guest> error (%s) %d/%d flags:0x%x http_flag:0x%x\n",
        status.req->request_id, status.req->geturl().c_str(),
        ret, code, status.flags, http_flag);
    deleteLater(ret);
}

std::shared_ptr<IMemRWerCallback> Guest::response(uint64_t id) {
    return IMemRWerCallback::create()->onHeader([this](std::shared_ptr<HttpResHeader> res){
        ReqStatus& status = statuslist.front();
        status.req->tracker.emplace_back("header", getmtime());
        HttpLog(dumpDest(rwer->getSrc()), status.req, res);
        if (status.req->ismethod("CONNECT")) {
            status.flags |= HTTP_NOEND_F;
            if (headless) {
                if(memcmp(res->status, "200", 3) == 0){
                    rwer->Unblock(0);
                    return;
                }else {
                    deleteLater(PEER_LOST_ERR);
                    return;
                }
            }
        } else if (res->get("Transfer-Encoding")) {
            status.flags |= HTTP_CHUNK_F;
        }
        if(res->no_end()) {
            status.flags |= HTTP_NOEND_F;
        }
        if (opt.alt_svc) {
            res->set("Alt-Svc", opt.alt_svc);
        }
        Buffer buff{BUF_LEN, res->request_id};
        buff.truncate(PackHttpRes(res, buff.mutable_data(), BUF_LEN));
        rwer->Send(std::move(buff));
    })->onData([this](Buffer bb) {
        return Recv(std::move(bb));
    })->onSignal([this](Signal s) {
        ReqStatus& status = statuslist.front();
        LOGD(DHTTP, "<guest> signal %" PRIu64 ": %d\n", status.req->request_id, (int)s);
        switch(s) {
        case CHANNEL_ABORT:
            status.flags |= HTTP_CLOSED_F;
            if ((status.flags & HTTP_REQ_COMPLETED) && (status.flags & HTTP_RES_COMPLETED)) {
                //如果是已经干净结束的请求，那么直接清理掉就可以了，链接可以继续使用
                status.cleanJob = AddJob([this]{ deqReq(); }, 0, 0);
                return;
            }
            return deleteLater(PROTOCOL_ERR);
        }
    })->onWrite([this, id](uint64_t) {
        rwer->Unblock(id);
    })->onCap([this, id] ()-> ssize_t {
        return rwer->cap(id);
    });
}

size_t Guest::Recv(Buffer&& bb) {
    static Buffer crlf{CRLF, 2};
    ReqStatus& status = statuslist.front();
    assert((status.flags & HTTP_RES_COMPLETED) == 0);
    if(bb.len == 0){
        status.req->tracker.emplace_back("eof", getmtime());
        status.flags |= HTTP_RES_COMPLETED;
        LOGD(DHTTP, "<guest> recv %" PRIu64 ": EOF/%zu\n", status.req->request_id, tx_bytes);
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
        return 0;
    }
    if(tx_bytes == 0) {
        status.req->tracker.emplace_back("body", getmtime());
    }
    tx_bytes += bb.len;
    LOGD(DHTTP, "<guest> recv %" PRIu64 ": size:%zu/%zu, refs: %zd\n",
         status.req->request_id, bb.len, tx_bytes, bb.refs());
    if(status.req->ismethod("HEAD")){
        LOGD(DHTTP, "<guest> recv %" PRIu64 ": HEAD req discard body\n", status.req->request_id);
        return bb.len;
    }
    auto len = bb.len;
    if(status.flags & HTTP_CHUNK_F){
        char chunkbuf[100];
        int chunklen = snprintf(chunkbuf, sizeof(chunkbuf), "%x" CRLF, (uint32_t)bb.len);
        if(bb.refs() == 1) {
            bb.reserve(-chunklen);
            memcpy(bb.mutable_data(), chunkbuf, chunklen);
        } else {
            rwer->Send(Buffer{chunkbuf, (size_t)chunklen, bb.id});
        }
        auto cbb = crlf;
        cbb.id = bb.id;
        rwer->Send(std::move(bb));
        rwer->Send(std::move(cbb));
    }else{
        rwer->Send(std::move(bb));
    }
    return len;
}

void Guest::deleteLater(uint32_t errcode) {
    for(auto& status: statuslist){
        if((status.flags & HTTP_CLOSED_F) == 0){
            status.cb = nullptr;
            status.rw->push_signal(CHANNEL_ABORT);
            status.flags |= HTTP_CLOSED_F;
        }
    }
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
        dp(param, "  [%" PRIu64 "]: %s %s, time: %dms, flags: 0x%08x [%s]\n",
                status.req->request_id,
                status.req->method,
                status.req->geturl().c_str(),
                getmtime() - std::get<1>(status.req->tracker[0]),
                status.flags,
                status.req->get("User-Agent"));
    }
    rwer->dump_status(dp, param);
}

void Guest::dump_usage(Dumper dp, void *param) {
    size_t req_usage  = statuslist.size() * sizeof(ReqStatus);
    for(const auto& status: statuslist) {
        req_usage += status.req->mem_usage();
    }
    dp(param, "Guest %p: %zd, reqlist: %zd, rwer: %zd\n",
       this, sizeof(*this), req_usage, rwer->mem_usage());
}
