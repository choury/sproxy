#include "host.h"
#include "proxy2.h"
#include "proxy3.h"
#include "req/requester.h"
#include "prot/sslio.h"
#include "prot/quic/quicio.h"

#include <string.h>
#include <assert.h>
#include <inttypes.h>
                    
static const unsigned char alpn_protos_http12[] =
    "\x08http/1.1" \
    "\x02h2";

static const unsigned char alpn_protos_http3[] =
    "\x02h3";

Host::Host(const Destination* dest){
    assert(dest->port);
    memcpy(&Server, dest, sizeof(Destination));

    if(dest->scheme[0] == 0 || strcasecmp(dest->scheme, "http") == 0){
        rwer = std::make_shared<StreamRWer>(dest->hostname, dest->port, Protocol::TCP,
                              std::bind(&Host::Error, this, _1, _2),
                              std::bind(&Host::connected, this));
    }else if(strcasecmp(dest->scheme, "https") == 0 ) {
        auto srwer = std::make_shared<SslRWer>(dest->hostname, dest->port, Protocol::TCP,
                                     std::bind(&Host::Error, this, _1, _2),
                                     std::bind(&Host::connected, this));
        if(!opt.disable_http2){
            srwer->set_alpn(alpn_protos_http12, sizeof(alpn_protos_http12)-1);
        }
        rwer = srwer;
    }else if(strcasecmp(dest->scheme, "udp") == 0) {
        rwer = std::make_shared<PacketRWer>(dest->hostname, dest->port, Protocol::UDP,
                              std::bind(&Host::Error, this, _1, _2),
                              std::bind(&Host::connected, this));
    }else if(strcasecmp(dest->scheme, "quic") == 0){
        auto qrwer = std::make_shared<QuicRWer>(dest->hostname, dest->port, Protocol::QUIC,
                                     std::bind(&Host::Error, this, _1, _2),
                                     std::bind(&Host::connected, this));
        qrwer->set_alpn(alpn_protos_http3, sizeof(alpn_protos_http3)-1);
        rwer = qrwer;
    }else{
        LOGF("Unkonw scheme: %s\n", dest->scheme);
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
    auto req = status.req;
    if(!req->header->should_proxy){
        if(req->header->ismethod("CONNECT")) {
            Http_Proc = &Host::AlwaysProc;
            status.res = std::make_shared<HttpRes>(UnpackHttpRes(H200), std::bind(&RWer::EatReadData, rwer));
            req->response(status.res);
        }else if(req->header->ismethod("SEND")){
            Http_Proc = &Host::AlwaysProc;
        }
    }
    void* buff = p_malloc(BUF_LEN);
    size_t len = PackHttpReq(req->header, buff, BUF_LEN);
    auto head = rwer->buffer_head();
    assert(rwer->wlength() == 0 || head->offset == 0);
    rwer->buffer_insert(head, buff_block{buff, len});
    req->attach(std::bind(&Host::Send, this, _1, _2), [this]{ return rwer->cap(0); });
}

void Host::connected() {
    LOGD(DHTTP, "<host> (%s) connected\n", rwer->getPeer());
    auto srwer = std::dynamic_pointer_cast<SslRWer>(rwer);
    if(srwer){
        const unsigned char *data;
        unsigned int len;
        srwer->get_alpn(&data, &len);
        if ((data && strncasecmp((const char*)data, "h2", len) == 0)) {
            LOG("<host> delegate %" PRIu32 " %s to proxy2\n",
                status.req->header->request_id,
                status.req->header->geturl().c_str());
            Proxy2 *proxy = new Proxy2(srwer);
            rwer = nullptr;

            proxy->init(status.req);
            assert(status.res == nullptr);
            return Server::deleteLater(NOERROR);
        }
    }
    auto qrwer = std::dynamic_pointer_cast<QuicRWer>(rwer);
    if(qrwer){
        const unsigned char *data;
        unsigned int len;
        qrwer->get_alpn(&data, &len);
        if((data && strncasecmp((const char*)data, "h3", len) == 0)) {
            LOG("<host> delegate %" PRIu32 " %s to proxy3\n",
                status.req->header->request_id,
                status.req->header->geturl().c_str());
            Proxy3 *proxy = new Proxy3(qrwer);
            rwer = nullptr;

            proxy->init(status.req);
            assert(status.res == nullptr);
            return Server::deleteLater(NOERROR);
        }
        LOGE("(%s) <host> quic only support http3\n", rwer->getPeer());
        return deleteLater(PROTOCOL_ERR);
    }
    rwer->SetReadCB([this](buff_block& bb){
        if(bb.len == 0){
            //EOF
            status.flags |= HTTP_RES_EOF;
            if((status.flags & HTTP_REQ_EOF) || status.res == nullptr){
                deleteLater(NOERROR);
            }else {
                status.res->trigger(Channel::CHANNEL_SHUTDOWN);
            }
            return;
        }
        const char* data = (const char*)bb.buff;
        size_t ret = 0;
        while((bb.offset < bb.len) && (ret = (this->*Http_Proc)(data+bb.offset, bb.len-bb.offset))){
            bb.offset += ret;
        }
        assert(bb.offset <= bb.len);
        LOGD(DHTTP, "<host> (%s) read: len:%zu, consumed:%zu\n", rwer->getPeer(), bb.len, bb.offset);
    });
    rwer->SetWriteCB([this](size_t len){
        LOGD(DHTTP, "<host> (%s) written: wlength:%zu\n", rwer->getPeer(), len);
        if(status.flags & HTTP_REQ_EOF) {
            if (rwer->wlength() == 0){
                rwer->Shutdown();
            }
            return;
        }
        if((status.flags & HTTP_REQ_COMPLETED) || (status.flags & HTTP_REQ_EOF)){
            return;
        }
        status.req->more();
    });
    reply();
}

void Host::request(std::shared_ptr<HttpReq> req, Requester*) {
    LOGD(DHTTP, "<host> request %" PRIu32 ": %s\n",
         req->header->request_id,
         req->header->geturl().c_str());
    assert(status.flags == 0);
    assert(status.req == nullptr);
    assert(status.res == nullptr);
    status.req = req;
    req->setHandler([this, req](Channel::signal s){
        LOGD(DHTTP, "<host> signal %" PRIu32 ": %d\n", req->header->request_id, (int)s);
        switch(s){
        case Channel::CHANNEL_SHUTDOWN:
            assert(strcasecmp(Server.scheme, "udp"));
            assert((status.flags & HTTP_RES_EOF) == 0);
            status.flags |= HTTP_REQ_EOF;
            if(rwer->getStats() != RWerStats::Connected){
                return;
            }
            rwer->addEvents(RW_EVENT::READ);
            if (rwer->wlength() == 0) {
                rwer->Shutdown();
            }
            break;
        case Channel::CHANNEL_CLOSED:
        case Channel::CHANNEL_ABORT:
            status.flags |= HTTP_CLOSED_F;
            return deleteLater(PEER_LOST_ERR);
        }
    });
    reply();
}

void Host::Send(void* buff, size_t size){
    assert((status.flags & HTTP_REQ_COMPLETED) == 0);
    rwer->buffer_insert(rwer->buffer_end(), buff_block{buff, size});
    tx_bytes += size;
    if(size == 0){
        status.flags |= HTTP_REQ_COMPLETED;
        LOGD(DHTTP, "<host> Send %" PRIu32 ": EOF/%zu, http_flag:0x%x\n",
             status.req->header->request_id, tx_bytes, http_flag);
    }else{
        LOGD(DHTTP, "<host> Send %" PRIu32 ": size:%zu/%zu, http_flag:0x%x\n",
             status.req->header->request_id, size, tx_bytes, http_flag);
    }
}

void Host::ResProc(HttpResHeader* header) {
    LOGD(DHTTP, "<host> ResProc %" PRIu32": %s, http_flag:0x%x\n",
         status.req->header->request_id ,header->status, http_flag);
    if(status.req->header->ismethod("HEAD")){
        http_flag |= HTTP_IGNORE_BODY_F;
    }
    assert(status.res == nullptr);
    status.res = std::make_shared<HttpRes>(header, std::bind(&RWer::EatReadData, rwer));
    status.req->response(status.res);
}

ssize_t Host::DataProc(const void* buff, size_t size) {
    assert((status.flags & HTTP_RES_EOF) == 0);
    assert((status.flags & HTTP_RES_COMPLETED) == 0);
    if(status.res == nullptr){
        status.res = std::make_shared<HttpRes>(UnpackHttpRes(H200), std::bind(&RWer::EatReadData, rwer));
        status.req->response(status.res);
    }
    int len = status.res->cap();
    len = Min(len, size);

    if (len <= 0) {
        LOGE("(%s)[%" PRIu32 "]: <host> the guest's write buff is full (%s)\n", 
            rwer->getPeer(), status.req->header->request_id, 
            status.req->header->geturl().c_str());
        if(strcasecmp(Server.scheme, "udp") == 0){
            return size;
        }
        rwer->delEvents(RW_EVENT::READ);
        return -1;
    }
    status.res->send(buff, len);
    rx_bytes += len;
    LOGD(DHTTP, "<host> DataProc %" PRIu32 ": size:%zu, send:%d/%zu\n",
         status.req->header->request_id, size, len, rx_bytes);
    return len;
}

void Host::EndProc() {
    LOGD(DHTTP, "<host> EndProc %" PRIu32 "\n", status.req->header->request_id);
    status.flags |= HTTP_RES_COMPLETED;
    status.res->send((const void*)nullptr, 0);
}

void Host::ErrProc(){
    Error(PROTOCOL_ERR, 0);
}

void Host::Error(int ret, int code) {
    if(status.req) {
        LOGE("(%s)[%" PRIu32 "]: <host> error (%s) %d/%d http_flag:0x%x\n",
            rwer->getPeer(), status.req->header->request_id, 
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
        status.res->trigger(errcode ? Channel::CHANNEL_ABORT : Channel::CHANNEL_CLOSED);
        status.req = nullptr;
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

void Host::gethost(std::shared_ptr<HttpReq> req, const Destination* dest, Requester* src) {
    if(req->header->should_proxy && memcmp(dest, &opt.Server, sizeof(Destination)) == 0) {
        if(proxy3){
            return proxy3->request(req, src);
        }
        if(proxy2){
            return proxy2->request(req, src);
        }
    }
    if(req->header->ismethod("CONNECT") ||  req->header->ismethod("SEND")){
    }
    (new Host(dest))->request(req, src);
}

void Host::dump_stat(Dumper dp, void* param) {
    dp(param, "Host %p, (%s)\n", this, rwer->getPeer());
    dp(param, "  rwer: rlength:%zu, wlength:%zu, stats:%d, event:%s\n",
            rwer->rlength(), rwer->wlength(),
            (int)rwer->getStats(), events_string[(int)rwer->getEvents()]);
    if(status.req){
        dp(param, "req [%" PRIu32 "]: %s [%d]\n",
                status.req->header->request_id,
                status.req->header->geturl().c_str(),
                status.flags);
    }
}
