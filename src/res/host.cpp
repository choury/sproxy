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

    if(strcmp(dest->protocol, "tcp") == 0){
        auto srwer = std::make_shared<StreamRWer>(dest->hostname, dest->port, Protocol::TCP,
                              std::bind(&Host::Error, this, _1, _2));
        rwer = srwer;
        srwer->SetConnectCB(std::bind(&Host::connected, this));
    }else if(strcmp(dest->protocol, "ssl") == 0 ) {
        auto srwer = std::make_shared<SslRWer<StreamRWer>>(dest->hostname, dest->port, Protocol::TCP,
                                     std::bind(&Host::Error, this, _1, _2));
        if(!opt.disable_http2){
            srwer->set_alpn(alpn_protos_http12, sizeof(alpn_protos_http12)-1);
        }
        rwer = srwer;
        srwer->SetConnectCB(std::bind(&Host::connected, this));
#ifdef HAVE_QUIC
    }else if(strcmp(dest->protocol, "quic") == 0){
        auto qrwer = std::make_shared<QuicRWer>(dest->hostname, dest->port, Protocol::QUIC,
                                     std::bind(&Host::Error, this, _1, _2));
        qrwer->setAlpn(alpn_protos_http3, sizeof(alpn_protos_http3) - 1);
        rwer = qrwer;
        qrwer->SetConnectCB(std::bind(&Host::connected, this));
#endif
    }else{
        LOGE("Unknown protocol: %s\n", dest->protocol);
    }
}

Host::~Host(){
    if(rwer){
        LOGD(DHTTP, "<host> (%s) destoryed: rx:%zu, tx:%zu\n", rwer->getPeer(), rx_bytes, tx_bytes);
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
            status.res = std::make_shared<HttpRes>(UnpackHttpRes(H200), [this] { rwer->Unblock(0); });
            status.req->response(status.res);
            goto attach;
        }
    }
    {
        Buffer buff{BUF_LEN};
        buff.truncate(PackHttpReq(header, buff.mutable_data(), BUF_LEN));
        rwer->buffer_insert(std::move(buff));
    }
attach:
    status.req->attach([this](ChannelMessage& msg){
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
    std::string key = dumpDest(&Server);
    LOGD(DHTTP, "<host> %s (%s) connected\n", rwer->getPeer(), key.c_str());
    if(responsers.has(key)) {
        responsers.at(key)->request(status.req, nullptr);
        return Server::deleteLater(NOERROR);
    }
    auto srwer = std::dynamic_pointer_cast<SslRWer<StreamRWer>>(rwer);
    if(srwer){
        const unsigned char *data;
        unsigned int len;
        srwer->get_alpn(&data, &len);
        if ((data && strncasecmp((const char*)data, "h2", len) == 0)) {
            LOG("<host> delegate %" PRIu32 " %s to proxy2\n",
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
        if((data && strncasecmp((const char*)data, "h3", len) == 0)) {
            LOG("<host> delegate %" PRIu32 " %s to proxy3\n",
                status.req->header->request_id, status.req->header->geturl().c_str());
            Proxy3 *proxy = new Proxy3(qrwer);
            rwer = nullptr;

            proxy->init(status.req);
            responsers.add(key, proxy);
            return Server::deleteLater(NOERROR);
        }
        LOGE("(%s) <host> quic only support http3\n", rwer->getPeer());
        return deleteLater(PROTOCOL_ERR);
    }
#endif
    rwer->SetReadCB([this](const Buffer& bb) -> size_t {
        LOGD(DHTTP, "<host> (%s) read: len:%zu\n", rwer->getPeer(), bb.len);
        if(bb.len == 0){
            //EOF
            if(Http_Proc == &Host::AlwaysProc){
                //对于AlwayProc的响应，读到EOF视为响应结束
                status.flags |= HTTP_RES_COMPLETED;
                status.res->send(nullptr);
                return 0;
            }
            if((status.flags & HTTP_RES_COMPLETED) == 0){
                deleteLater(PEER_LOST_ERR);
            }
            return 0;
        }
        size_t ret = 0;
        size_t len = bb.len;
        const char *data = (const char*)bb.data();
        while((len >  0) && (ret = (this->*Http_Proc)(data, len))){
            len -= ret;
            data += ret;
        }
        return len;
    });
    rwer->SetWriteCB([this](uint64_t){
        LOGD(DHTTP, "<host> (%s) written, flags:0x%08x\n", rwer->getPeer(), status.flags);
        if(status.flags & HTTP_REQ_COMPLETED){
            return;
        }
        status.req->pull();
    });
    reply();
}

void Host::Handle(Signal s){
    LOGD(DHTTP, "<host> signal %" PRIu32 ": %d\n", status.req->header->request_id, (int)s);
    switch(s){
    case CHANNEL_ABORT:
        status.flags |= HTTP_CLOSED_F;
        return deleteLater(PEER_LOST_ERR);
    }
}

void Host::request(std::shared_ptr<HttpReq> req, Requester*) {
    if(rwer == nullptr) {
        req->response(std::make_shared<HttpRes>(UnpackHttpRes(H400), "[[Unknown protocol]]\n"));
        return Server::deleteLater(PROTOCOL_ERR);
    }
    LOGD(DHTTP, "<host> request %" PRIu32 ": %s\n",
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
        LOGD(DHTTP, "<host> recv %" PRIu32 ": EOF/%zu, http_flag:0x%x\n",
             status.req->header->request_id, tx_bytes, http_flag);
        if(status.flags & HTTP_NOEND_F){
            //如果是这种，只能通过关闭连接的方式来结束请求
            rwer->buffer_insert(nullptr);
        }else{
            //TODO: chunked
            //其他情况，可以不发送结束符
        }
        return;
    }

    tx_bytes += bb.len;
    LOGD(DHTTP, "<host> recv %" PRIu32 ": size:%zu/%zu, http_flag:0x%x\n",
         status.req->header->request_id, bb.len, tx_bytes, http_flag);
    rwer->buffer_insert(std::move(bb));
}

void Host::ResProc(std::shared_ptr<HttpResHeader> header) {
    LOGD(DHTTP, "<host> ResProc %" PRIu32": %s, http_flag:0x%x\n",
         status.req->header->request_id ,header->status, http_flag);
    if(status.req->header->ismethod("HEAD")){
        http_flag |= HTTP_IGNORE_BODY_F;
    }
    if(status.res){
        status.res->send(header);
    }else{
        status.res = std::make_shared<HttpRes>(header, [this]{ rwer->Unblock(0);});
        status.req->response(status.res);
    }
}

ssize_t Host::DataProc(const void* buff, size_t size) {
    assert((status.flags & HTTP_RES_COMPLETED) == 0);
    if(status.res == nullptr){
        status.res = std::make_shared<HttpRes>(UnpackHttpRes(H200), [this]{ rwer->Unblock(0);});
        status.req->response(status.res);
    }
    int len = status.res->cap();
    len = std::min(len, (int)size);

    if (len <= 0) {
        LOGE("[%" PRIu32 "]: <host> the guest's write buff is full (%s)\n",
            status.req->header->request_id,
            status.req->header->geturl().c_str());
        rwer->delEvents(RW_EVENT::READ);
        return -1;
    }
    status.res->send(buff, (size_t)len);
    rx_bytes += len;
    LOGD(DHTTP, "<host> DataProc %" PRIu32 ": size:%zu, send:%d/%zu\n",
         status.req->header->request_id, size, len, rx_bytes);
    return len;
}

void Host::EndProc() {
    LOGD(DHTTP, "<host> EndProc %" PRIu32 "\n", status.req->header->request_id);
    status.flags |= HTTP_RES_COMPLETED;
    status.res->send(nullptr);
}

void Host::ErrProc(){
    Error(PROTOCOL_ERR, 0);
}

void Host::Error(int ret, int code) {
    if(status.req) {
        LOGE("[%" PRIu32 "]: <host> error (%s) %d/%d http_flag:0x%x\n",
            status.req->header->request_id,
            status.req->header->geturl().c_str(), ret, code, http_flag);
    }else{
        LOGE("(%s) <host> error %d/%d http_flag:0x%x\n",
             rwer->getPeer(), ret, code, http_flag);
    }
    deleteLater(ret);
}

void Host::deleteLater(uint32_t errcode){
    if(status.req){
        status.req->detach();
    }
    if(status.flags & HTTP_CLOSED_F){
        //do nothing.
    }else if(status.res){
        status.res->send(CHANNEL_ABORT);
    }else {
        switch(errcode) {
        case DNS_FAILED:
            status.req->response(std::make_shared<HttpRes>(UnpackHttpRes(H503), "[[dns failed]]\n"));
            break;
        case CONNECT_FAILED:
            status.req->response(std::make_shared<HttpRes>(UnpackHttpRes(H503), "[[connect failed]]\n"));
            break;
        case SOCKET_ERR:
            status.req->response(std::make_shared<HttpRes>(UnpackHttpRes(H502), "[[socket error]]\n"));
            break;
        default:
            status.req->response(std::make_shared<HttpRes>(UnpackHttpRes(H500), "[[internal error]]\n"));
        }
    }
    status.flags |= HTTP_CLOSED_F;
    Server::deleteLater(errcode);
}

void Host::distribute(std::shared_ptr<HttpReq> req, const Destination* dest, Requester* src) {
    std::string key = dumpDest(dest);
    if(responsers.has(key)) {
        return responsers.at(key)->request(req, src);
    }
    return (new Host(dest))->request(req, src);
}

void Host::dump_stat(Dumper dp, void* param) {
    dp(param, "Host %p, rx: %zd, tx: %zd\n", this, rx_bytes, tx_bytes);
    if(status.req){
        dp(param, "  [%" PRIu32 "]: %s %s, flags: 0x%08x\n",
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
