#include "host.h"
#include "proxy2.h"
#include "req/requester.h"
#include "prot/sslio.h"
#ifdef HAVE_QUIC
#include "proxy3.h"
#include "prot/quic/quicio.h"
#endif
#include "misc/config.h"
#include "misc/hook.h"

#include <string.h>
#include <assert.h>
#include <inttypes.h>

static const unsigned char alpn_protos_http12[] =
    "\x08http/1.1" \
    "\x02h2";

__attribute__((unused)) static const unsigned char alpn_protos_http3[] =
    "\x02h3";

Host::Host(const Destination& dest){
    assert(dest.port);
    assert(dest.protocol[0]);
    memcpy(&Server, &dest, sizeof(Destination));
    bool isWebsocket = strcmp(dest.protocol, "websocket") == 0;
    cb = ISocketCallback::create()->onConnect([this](const sockaddr_storage&, uint32_t resolved_time){
        connected(resolved_time);
    })->onError([this](int ret, int code){
        Error(ret, code);
    });
    if(strcmp(dest.protocol, "tcp") == 0 || (isWebsocket && strcmp(dest.scheme, "http") == 0)){
        rwer = std::make_shared<StreamRWer>(dest, cb);
    }else if(strcmp(dest.protocol, "ssl") == 0 || (isWebsocket && strcmp(dest.scheme, "https") == 0)){
        auto srwer = std::make_shared<SslRWer>(dest, cb);
        if(!opt.disable_http2 && !isWebsocket){
            //FIXME: 基于http2的websocket协议暂时禁用，因为在连接之前无法判断服务端是否能支持
            //根据rfc8441，只有连接建立之后收到setting帧才能判断
            srwer->set_alpn(alpn_protos_http12, sizeof(alpn_protos_http12)-1);
        }
        rwer = srwer;
#ifdef HAVE_QUIC
    }else if(strcmp(dest.protocol, "quic") == 0){
        auto qrwer = std::make_shared<QuicRWer>(dest, cb);
        qrwer->setAlpn(alpn_protos_http3, sizeof(alpn_protos_http3) - 1);
        rwer = qrwer;
#endif
    }else{
        LOGE("Unknown protocol: %s\n", dest.protocol);
    }
}

Host::~Host(){
    if(rwer){
        LOGD(DHTTP, "<host> (%s) destoryed: rx:%zu, tx:%zu\n", dumpDest(rwer->getDst()).c_str(), rx_bytes, tx_bytes);
    }else{
        LOGD(DHTTP, "<host> null destoryed: rx:%zu, tx:%zu\n", rx_bytes, tx_bytes);
    }
}

void Host::reply(){
    if(!rwer->IsConnected()){
        return;
    }
    if(!status.req->chain_proxy && status.req->ismethod("CONNECT")) {
        status.rw->SetCallback(status.cb);
        Http_Proc = &Host::AlwaysProc;
        assert(strcmp(status.req->Dest.protocol, "tcp") == 0);
        uint64_t id = status.req->request_id;
        status.rw->SendHeader(HttpResHeader::create(S200, sizeof(S200), id));
        status.flags |= HTTP_RESPOENSED;
        return;
    }
    Buffer buff{BUF_LEN, status.req->request_id};
    buff.truncate(PackHttpReq(status.req, buff.mutable_data(), BUF_LEN));
    rwer->Send(std::move(buff));
    status.rw->SetCallback(status.cb);
}

void Host::connected(uint32_t resolved_time) {
    status.req->tracker.emplace_back("dns", resolved_time);
    status.req->tracker.emplace_back("connected", getmtime());
    std::string key = dumpDest(Server) + '@' + Server.protocol;
    LOGD(DHTTP, "<host> %s (%s) connected\n", dumpDest(rwer->getDst()).c_str(), key.c_str());
    if(responsers.has(key)) {
        responsers.at(key)->request(status.req, status.rw);
        return Server::deleteLater(NOERROR);
    }
    auto srwer = std::dynamic_pointer_cast<SslRWer>(rwer);
    if(srwer){
        const unsigned char *data;
        unsigned int len;
        srwer->get_alpn(&data, &len);
        if (data && strncasecmp((const char*)data, "h2", len) == 0) {
            LOG("<host> delegate %" PRIu64 " %s to proxy2\n",
                status.req->request_id, status.req->geturl().c_str());
            Proxy2 *proxy = new Proxy2(srwer);
            rwer = nullptr;

            proxy->init(false, status.req, status.rw);
            responsers.add(key, proxy);
            return Server::deleteLater(NOERROR);
        }
    }
#ifdef HAVE_QUIC
    auto qrwer = std::dynamic_pointer_cast<QuicRWer>(rwer);
    if(qrwer){
        const unsigned char *data;
        unsigned int len;
        qrwer->getAlpn(&data, &len);
        if(data && strncasecmp((const char*)data, "h3", len) == 0) {
            LOG("<host> delegate %" PRIu64 " %s to proxy3\n",
                status.req->request_id, status.req->geturl().c_str());
            Proxy3 *proxy = new Proxy3(qrwer);
            rwer = nullptr;

            proxy->init(status.req, status.rw);
            responsers.add(key, proxy);
            return Server::deleteLater(NOERROR);
        }
        LOGE("(%s) <host> quic only support http3\n", dumpDest(rwer->getDst()).c_str());
        return deleteLater(PROTOCOL_ERR);
    }
#endif
    cb->onRead([this](Buffer&& bb) -> size_t {
        HOOK_FUNC(this, status, bb);
        LOGD(DHTTP, "<host> (%s) read: len:%zu\n", dumpDest(rwer->getDst()).c_str(), bb.len);
        if((status.flags & HTTP_RECV_1ST_BYTE) == 0){
            status.req->tracker.emplace_back("ttfb", getmtime());
            status.flags |= HTTP_RECV_1ST_BYTE;
        }
        if(bb.len == 0){
            //EOF
            if(Http_Proc == &Host::AlwaysProc){
                //对于AlwayProc的响应，读到EOF视为响应结束
                status.flags |= HTTP_RES_COMPLETED;
                status.rw->Send(Buffer{nullptr, bb.id});
                return 0;
            }
            if((status.flags & HTTP_RES_COMPLETED) == 0){
                deleteLater(PEER_LOST_ERR);
            }
            return 0;
        }
        size_t len = bb.len;
        while((bb.len >  0) &&  (this->*Http_Proc)(bb));
        return len - bb.len;
    })->onWrite([this](uint64_t){
        LOGD(DHTTP, "<host> (%s) written, flags:0x%08x\n", dumpDest(rwer->getDst()).c_str(), status.flags);
        if(status.flags & (HTTP_RES_COMPLETED | HTTP_CLOSED_F | HTTP_RST)){
            return;
        }
        status.rw->Unblock(0);
    });
    reply();
}

void Host::request(std::shared_ptr<HttpReqHeader> req, std::shared_ptr<MemRWer> rw) {
    if(rwer == nullptr) {
        uint64_t id = req->request_id;
        response(rw, HttpResHeader::create(S400, sizeof(S400), id), "[[Unknown protocol]]\n");
        return Server::deleteLater(PROTOCOL_ERR);
    }
    LOGD(DHTTP, "<host> request %" PRIu64 ": %s\n", req->request_id, req->geturl().c_str());
    assert(status.flags == 0);
    assert(status.req == nullptr);
    assert(status.rw == nullptr);
    status.req = req;
    status.rw = rw;
    if(req->no_end()){
        status.flags |= HTTP_NOEND_F;
    }
    status.cb = IRWerCallback::create()->onRead([this](Buffer&& bb) -> size_t{
        assert((status.flags & HTTP_REQ_COMPLETED) == 0);
        if(bb.len == 0){
            status.flags |= HTTP_REQ_COMPLETED;
            LOGD(DHTTP, "<host> recv %" PRIu64 ": EOF/%zu, http_flag:0x%x\n",
                status.req->request_id, tx_bytes, http_flag);
            if(status.flags & HTTP_NOEND_F){
                //如果是这种，只能通过关闭连接的方式来结束请求
                rwer->Send({nullptr, bb.id});
            }else{
                //TODO: chunked
                //其他情况，可以不发送结束符
            }
            return 0;
        }
        auto cap = rwer->cap(bb.id);
        LOGD(DHTTP, "<host> recv %" PRIu64 ": size:%zu/%zd/%zu, http_flag:0x%x\n",
            status.req->request_id, bb.len, cap, tx_bytes, http_flag);

        if (cap <= 0) {
            LOGE("[%" PRIu64 "]: <host> the RWer write buff is full (%s)\n",
                status.req->request_id, status.req->geturl().c_str());
            return 0;
        }
        auto len = std::min(bb.len, (size_t)cap);
        tx_bytes += len;
        bb.truncate(len);
        rwer->Send(std::move(bb));
        return len;
    })->onWrite([this](uint64_t id){
        rwer->Unblock(id);
    })->onError([this](int ret, int code){
        LOGD(DHTTP, "<host> signal %" PRIu64 " err %d:%d\n", status.req->request_id, ret, code);
        status.flags |= HTTP_CLOSED_F;
        return deleteLater(PEER_LOST_ERR);
    });
    reply();
}

void Host::ResProc(uint64_t, std::shared_ptr<HttpResHeader> header) {
    LOGD(DHTTP, "<host> ResProc %" PRIu64": %s, http_flag:0x%x\n",
         status.req->request_id ,header->status, http_flag);
    header->request_id = status.req->request_id;
    if(status.req->ismethod("HEAD")){
        http_flag |= HTTP_IGNORE_BODY_F;
    }
    if(status.req->ismethod("CONNECT")) {
        header->markTunnel();
    }else if(strcmp(status.req->Dest.protocol, "websocket") == 0){
        header->markWebsocket(status.req->get("Sec-WebSocket-Key"));
    }
    status.rw->SendHeader(header);
    status.flags |= HTTP_RESPOENSED;
}

ssize_t Host::DataProc(Buffer& bb) {
    HOOK_FUNC(this, status, status);
    assert((status.flags & HTTP_RES_COMPLETED) == 0);
    int cap = status.rw->cap(bb.id);
    if (cap <= 0) {
        LOGE("[%" PRIu64 "]: <host> the guest's write buff is full (%s)\n",
            status.req->request_id,
            status.req->geturl().c_str());
        rwer->delEvents(RW_EVENT::READ);
        return -1;
    }
    LOGD(DHTTP, "<host> DataProc %" PRIu64 ": cap:%d, send:%zd/%zu\n",
         status.req->request_id, cap, bb.len, rx_bytes);
    cap = std::min(cap, BUF_LEN);
    if((size_t)cap < bb.len) {
        auto cbb = bb;
        cbb.truncate(cap);
        status.rw->Send(std::move(cbb));
        bb.reserve(cap);
    } else {
        cap = bb.len;
        status.rw->Send(std::move(bb));
        bb.len = 0;
    }
    rx_bytes += cap;
    return cap;
}

void Host::EndProc(uint64_t) {
    LOGD(DHTTP, "<host> EndProc %" PRIu64 "\n", status.req->request_id);
    status.flags |= HTTP_RES_COMPLETED;
    status.rw->Send(Buffer{nullptr, status.req->request_id});
}

void Host::ErrProc(uint64_t){
    Error(PROTOCOL_ERR, 0);
}

void Host::Error(int ret, int code) {
    if(status.req) {
        LOGE("[%" PRIu64 "]: <host> error (%s) %d/%d flags:0x%x http_flag:0x%x\n",
            status.req->request_id, status.req->geturl().c_str(),
            ret, code, status.flags, http_flag);
    }else{
        LOGE("(%s) <host> error %d/%d http_flag:0x%x\n",
             dumpDest(rwer->getDst()).c_str(), ret, code, http_flag);
    }
    deleteLater(ret);
}

void Host::deleteLater(uint32_t errcode){
    status.rw->SetCallback(nullptr);
    if(status.flags & (HTTP_CLOSED_F | HTTP_RESPOENSED)){
        //do nothing.
    }else{
        uint64_t id = status.req->request_id;
        switch(errcode) {
        case DNS_FAILED:
            response(status.rw, HttpResHeader::create(S503, sizeof(S503), id), "[[dns failed]]\n");
            break;
        case CONNECT_FAILED:
            response(status.rw, HttpResHeader::create(S503, sizeof(S503), id), "[[connect failed]]\n");
            break;
        case SOCKET_ERR:
            response(status.rw, HttpResHeader::create(S502, sizeof(S502), id), "[[socket error]]\n");
            break;
        default:
            response(status.rw, HttpResHeader::create(S500, sizeof(S500), id), "[[internal error]]\n");
        }
    }
    status.rw->Close();
    status.flags |= HTTP_CLOSED_F;
    Server::deleteLater(errcode);
}

void Host::distribute(std::shared_ptr<HttpReqHeader> req, const Destination& dest, std::shared_ptr<MemRWer> rw) {
    std::string key = dumpDest(dest) + '@' + dest.protocol;
    if(responsers.has(key)) {
        return responsers.at(key)->request(req, rw);
    }
    return (new Host(dest))->request(req, rw);
}

void Host::dump_stat(Dumper dp, void* param) {
    dp(param, "Host %p, rx: %zd, tx: %zd\n", this, rx_bytes, tx_bytes);
    if(status.req){
        dp(param, "  [%" PRIu64 "]: %s %s, flags: 0x%08x\n",
                status.req->request_id,
                status.req->method,
                status.req->geturl().c_str(),
                status.flags);
    }
    rwer->dump_status(dp, param);
}

void Host::dump_usage(Dumper dp, void *param) {
    dp(param, "Host %p: %zd, res: %zd, rwer: %zd\n", this, sizeof(*this), status.rw->mem_usage(), rwer->mem_usage());
}

void flushconnect() {
    LOGD(DNET, "Network change detected - checking connections for migration capability\n");
    // Check each responser to see if it can reconnect/migrate
    std::vector<std::string> to_remove;
    for (auto it = responsers.begin(); it != responsers.end(); ++it) {
        const std::string& key = it->first;
        Responser* responser = it->second;

        if (!responser->reconnect()) {
            // Responser cannot reconnect, mark for removal
            to_remove.push_back(key);
            LOGD(DNET, "Marking connection for cleanup: %s\n", key.c_str());
        } else {
            LOGD(DNET, "Preserving connection for migration: %s\n", key.c_str());
        }
    }

    // Remove connections that cannot migrate
    for (const std::string& key : to_remove) {
        responsers.erase(key);
    }
    LOGD(DNET, "Network change processed: preserved %zu connections, removed %zu connections\n",
         responsers.size(), to_remove.size());
}
