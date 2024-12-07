#include "host.h"
#include "proxy2.h"
#include "req/requester.h"
#include "prot/sslio.h"
#include "misc/util.h"
#ifdef HAVE_QUIC
#include "proxy3.h"
#include "prot/quic/quicio.h"
#endif

#include <string.h>
#include <assert.h>
#include <inttypes.h>

static const unsigned char alpn_protos_http12[] =
    "\x08http/1.1" \
    "\x02h2";

__attribute__((unused)) static const unsigned char alpn_protos_http3[] =
    "\x02h3";

Host::Host(const Destination* dest){
    assert(dest->port);
    assert(dest->protocol[0]);
    memcpy(&Server, dest, sizeof(Destination));
    bool isWebsocket = strcmp(dest->protocol, "websocket") == 0;
    if(strcmp(dest->protocol, "tcp") == 0 || (isWebsocket && strcmp(dest->scheme, "http") == 0)){
        auto srwer = std::make_shared<StreamRWer>(
                dest->hostname, dest->port, Protocol::TCP,
                [this](int ret, int code){Error(ret, code);});
        rwer = srwer;
        srwer->SetConnectCB([this](const sockaddr_storage&){connected();});
    }else if(strcmp(dest->protocol, "ssl") == 0 || (isWebsocket && strcmp(dest->scheme, "https") == 0)){
        auto srwer = std::make_shared<SslRWer>(
                dest->hostname, dest->port, Protocol::TCP,
                [this](int ret, int code){Error(ret, code);});
        if(!opt.disable_http2 && !isWebsocket){
            //FIXME: 基于http2的websocket协议暂时禁用，因为在连接之前无法判断服务端是否能支持
            //根据rfc8441，只有连接建立之后收到setting帧才能判断
            srwer->set_alpn(alpn_protos_http12, sizeof(alpn_protos_http12)-1);
        }
        rwer = srwer;
        srwer->SetConnectCB([this](const sockaddr_storage&){connected();});
#ifdef HAVE_QUIC
    }else if(strcmp(dest->protocol, "quic") == 0){
        auto qrwer = std::make_shared<QuicRWer>(
                dest->hostname, dest->port, Protocol::QUIC,
                [this](int ret, int code){Error(ret, code);});
        qrwer->setAlpn(alpn_protos_http3, sizeof(alpn_protos_http3) - 1);
        rwer = qrwer;
        qrwer->SetConnectCB([this](const sockaddr_storage&){connected();});
#endif
    }else{
        LOGE("Unknown protocol: %s\n", dest->protocol);
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
    if(rwer->getStats() != RWerStats::Connected){
        return;
    }
    // 对于request来说，必须先调用response再调用attach，或者就直接在attach的回调中response
    // 因为attach的时候有可能触发了错误，此时response就会有问题，比如连接已经被shutdown了
    auto header = status.req->header;
    if(!header->chain_proxy){
        if(header->ismethod("CONNECT")) {
            Http_Proc = &Host::AlwaysProc;
            assert(strcmp(header->Dest.protocol, "tcp") == 0);
            uint64_t id = status.req->header->request_id;
            status.res = std::make_shared<HttpRes>(HttpResHeader::create(S200, sizeof(S200), id),
                                                   [this] { rwer->Unblock(0); });
            status.req->response(status.res);
            goto attach;
        }
    }
    {
        Buffer buff{BUF_LEN, header->request_id};
        buff.truncate(PackHttpReq(header, buff.mutable_data(), BUF_LEN));
        rwer->Send(std::move(buff));
    }
attach:
    status.req->attach([this](ChannelMessage&& msg){
        switch(msg.type){
            case ChannelMessage::CHANNEL_MSG_HEADER:
                LOGD(DHTTP, "<host> ignore header for req\n");
                return 1;
            case ChannelMessage::CHANNEL_MSG_DATA:
                Recv(std::move(std::get<Buffer>(msg.data)));
                return 1;
            case ChannelMessage::CHANNEL_MSG_SIGNAL:
                Handle(std::get<Signal>(msg.data));
                return 0;
        }
        return 0;
    }, [this]{ return rwer->cap(0); });
}

void Host::connected() {
    assert(status.res == nullptr);
    std::string key = dumpDest(Server) + '@' + Server.protocol;
    LOGD(DHTTP, "<host> %s (%s) connected\n", dumpDest(rwer->getDst()).c_str(), key.c_str());
    if(responsers.has(key)) {
        responsers.at(key)->request(status.req, nullptr);
        return Server::deleteLater(NOERROR);
    }
    auto srwer = std::dynamic_pointer_cast<SslRWer>(rwer);
    if(srwer){
        const unsigned char *data;
        unsigned int len;
        srwer->get_alpn(&data, &len);
        if (data && strncasecmp((const char*)data, "h2", len) == 0) {
            LOG("<host> delegate %" PRIu64 " %s to proxy2\n",
                status.req->header->request_id, status.req->header->geturl().c_str());
            Proxy2 *proxy = new Proxy2(srwer);
            rwer = nullptr;

            proxy->init(status.req);
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
                status.req->header->request_id, status.req->header->geturl().c_str());
            Proxy3 *proxy = new Proxy3(qrwer);
            rwer = nullptr;

            proxy->init(status.req);
            responsers.add(key, proxy);
            return Server::deleteLater(NOERROR);
        }
        LOGE("(%s) <host> quic only support http3\n", dumpDest(rwer->getDst()).c_str());
        return deleteLater(PROTOCOL_ERR);
    }
#endif
    rwer->SetReadCB([this](Buffer&& bb) -> size_t {
        LOGD(DHTTP, "<host> (%s) read: len:%zu\n", dumpDest(rwer->getDst()).c_str(), bb.len);
        if(bb.len == 0){
            //EOF
            if(Http_Proc == &Host::AlwaysProc){
                //对于AlwayProc的响应，读到EOF视为响应结束
                status.flags |= HTTP_RES_COMPLETED;
                status.res->send(Buffer{nullptr, bb.id});
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
    });
    rwer->SetWriteCB([this](uint64_t){
        LOGD(DHTTP, "<host> (%s) written, flags:0x%08x\n", dumpDest(rwer->getDst()).c_str(), status.flags);
        if(status.flags & HTTP_REQ_COMPLETED){
            return;
        }
        status.req->pull();
    });
    reply();
}

void Host::Handle(Signal s){
    LOGD(DHTTP, "<host> signal %" PRIu64 ": %d\n", status.req->header->request_id, (int)s);
    switch(s){
    case CHANNEL_ABORT:
        status.flags |= HTTP_CLOSED_F;
        return deleteLater(PEER_LOST_ERR);
    }
}

void Host::request(std::shared_ptr<HttpReq> req, Requester*) {
    if(rwer == nullptr) {
        uint64_t id = req->header->request_id;
        req->response(std::make_shared<HttpRes>(HttpResHeader::create(S400, sizeof(S400), id),
                                                "[[Unknown protocol]]\n"));
        return Server::deleteLater(PROTOCOL_ERR);
    }
    LOGD(DHTTP, "<host> request %" PRIu64 ": %s\n",
         req->header->request_id,
         req->header->geturl().c_str());
    assert(status.flags == 0);
    assert(status.req == nullptr);
    assert(status.res == nullptr);
    status.req = req;
    if(req->header->no_end()){
        status.flags |= HTTP_NOEND_F;
    }
    reply();
}

void Host::Recv(Buffer&& bb){
    assert((status.flags & HTTP_REQ_COMPLETED) == 0);
    if(bb.len == 0){
        status.flags |= HTTP_REQ_COMPLETED;
        LOGD(DHTTP, "<host> recv %" PRIu64 ": EOF/%zu, http_flag:0x%x\n",
             status.req->header->request_id, tx_bytes, http_flag);
        if(status.flags & HTTP_NOEND_F){
            //如果是这种，只能通过关闭连接的方式来结束请求
            rwer->Send({nullptr, bb.id});
        }else{
            //TODO: chunked
            //其他情况，可以不发送结束符
        }
        return;
    }

    tx_bytes += bb.len;
    LOGD(DHTTP, "<host> recv %" PRIu64 ": size:%zu/%zu, http_flag:0x%x\n",
         status.req->header->request_id, bb.len, tx_bytes, http_flag);
    rwer->Send(std::move(bb));
}

void Host::ResProc(uint64_t id, std::shared_ptr<HttpResHeader> header) {
    LOGD(DHTTP, "<host> ResProc %" PRIu64": %s, http_flag:0x%x\n",
         status.req->header->request_id ,header->status, http_flag);
    header->request_id = status.req->header->request_id;
    if(status.req->header->ismethod("HEAD")){
        http_flag |= HTTP_IGNORE_BODY_F;
    }
    if(status.req->header->ismethod("CONNECT")) {
        header->markTunnel();
    }else if(strcmp(status.req->header->Dest.protocol, "websocket") == 0){
        header->markWebsocket(status.req->header->get("Sec-WebSocket-Key"));
    }
    if(status.res){
        status.res->send(header);
    }else{
        status.res = std::make_shared<HttpRes>(header, [this, id]{ rwer->Unblock(id);});
        status.req->response(status.res);
    }
}

ssize_t Host::DataProc(Buffer& bb) {
    assert((status.flags & HTTP_RES_COMPLETED) == 0);
    if(status.res == nullptr){
        status.res = std::make_shared<HttpRes>(HttpResHeader::create(S200, sizeof(S200), bb.id),
                                               [this, id= bb.id]{ rwer->Unblock(id);});
        status.req->response(status.res);
    }
    int cap = status.res->cap();
    if (cap <= 0) {
        LOGE("[%" PRIu64 "]: <host> the guest's write buff is full (%s)\n",
            status.req->header->request_id,
            status.req->header->geturl().c_str());
        rwer->delEvents(RW_EVENT::READ);
        return -1;
    }
    LOGD(DHTTP, "<host> DataProc %" PRIu64 ": cap:%zu, send:%d/%zu\n",
         status.req->header->request_id, bb.len, cap, rx_bytes);
    if((size_t)cap < bb.len) {
        auto cbb = bb;
        cbb.truncate(cap);
        status.res->send(std::move(cbb));
        bb.reserve(cap);
    } else {
        cap = bb.len;
        status.res->send(std::move(bb));
    }
    rx_bytes += cap;
    return cap;
}

void Host::EndProc(uint64_t) {
    LOGD(DHTTP, "<host> EndProc %" PRIu64 "\n", status.req->header->request_id);
    status.flags |= HTTP_RES_COMPLETED;
    status.res->send(Buffer{nullptr, status.req->header->request_id});
}

void Host::ErrProc(uint64_t){
    Error(PROTOCOL_ERR, 0);
}

void Host::Error(int ret, int code) {
    if(status.req) {
        LOGE("[%" PRIu64 "]: <host> error (%s) %d/%d flags:0x%x http_flag:0x%x\n",
            status.req->header->request_id, status.req->header->geturl().c_str(),
            ret, code, status.flags, http_flag);
    }else{
        LOGE("(%s) <host> error %d/%d http_flag:0x%x\n",
             dumpDest(rwer->getDst()).c_str(), ret, code, http_flag);
    }
    deleteLater(ret);
}

void Host::deleteLater(uint32_t errcode){
    if(status.flags & HTTP_CLOSED_F){
        //do nothing.
    }else if(status.res){
        status.res->send(CHANNEL_ABORT);
    }else {
        uint64_t id = status.req->header->request_id;
        switch(errcode) {
        case DNS_FAILED:
            status.req->response(std::make_shared<HttpRes>(HttpResHeader::create(S503, sizeof(S503), id),
                                                           "[[dns failed]]\n"));
            break;
        case CONNECT_FAILED:
            status.req->response(std::make_shared<HttpRes>(HttpResHeader::create(S503, sizeof(S503), id),
                                                           "[[connect failed]]\n"));
            break;
        case SOCKET_ERR:
            status.req->response(std::make_shared<HttpRes>(HttpResHeader::create(S502, sizeof(S502), id),
                                                           "[[socket error]]\n"));
            break;
        default:
            status.req->response(std::make_shared<HttpRes>(HttpResHeader::create(S500, sizeof(S500), id),
                                                           "[[internal error]]\n"));
        }
    }
    if(status.req){
        status.req->detach();
    }
    status.flags |= HTTP_CLOSED_F;
    Server::deleteLater(errcode);
}

void Host::distribute(std::shared_ptr<HttpReq> req, const Destination& dest, Requester* src) {
    std::string key = dumpDest(dest) + '@' + dest.protocol;
    if(responsers.has(key)) {
        return responsers.at(key)->request(req, src);
    }
    return (new Host(&dest))->request(req, src);
}

void Host::dump_stat(Dumper dp, void* param) {
    dp(param, "Host %p, rx: %zd, tx: %zd\n", this, rx_bytes, tx_bytes);
    if(status.req){
        dp(param, "  [%" PRIu64 "]: %s %s, flags: 0x%08x\n",
                status.req->header->request_id,
                status.req->header->method,
                status.req->header->geturl().c_str(),
                status.flags);
    }
    rwer->dump_status(dp, param);
}

void Host::dump_usage(Dumper dp, void *param) {
    if(status.res) {
        dp(param, "Host %p: %zd, res: %zd, rwer: %zd\n", this, sizeof(*this), status.res->mem_usage(),
           rwer->mem_usage());
    }else {
        dp(param, "Host %p: %zd, rwer: %zd\n", this, sizeof(*this), rwer->mem_usage());
    }
}

void flushconnect() {
    responsers.clear();
}
