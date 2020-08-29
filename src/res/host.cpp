#include "host.h"
#include "proxy2.h"
#include "req/requester.h"
#include "misc/util.h"
#include "misc/sslio.h"
#include "misc/net.h"

#include <string.h>
#include <assert.h>
#include <inttypes.h>
                    
static const unsigned char alpn_protos_string[] =
    "\x8http/1.1" \
    "\x2h2";

Host::Host(const Destination* dest){
    assert(dest->port);
    memcpy(&Server, dest, sizeof(Destination));

    if(dest->schema[0] == 0 || strcasecmp(dest->schema, "http") == 0){
        rwer = new StreamRWer(dest->hostname, dest->port, Protocol::TCP,
                              std::bind(&Host::Error, this, _1, _2),
                              std::bind(&Host::connected, this));
    }else if(strcasecmp(dest->schema, "https") == 0 ) {
        SslRWer *srwer = new SslRWer(dest->hostname, dest->port, Protocol::TCP,
                                     std::bind(&Host::Error, this, _1, _2),
                                     std::bind(&Host::connected, this));
        if(!opt.disable_http2){
            srwer->set_alpn(alpn_protos_string, sizeof(alpn_protos_string)-1);
        }
        rwer = srwer;
    }else if(strcasecmp(dest->schema, "udp") == 0){
        rwer = new PacketRWer(dest->hostname, dest->port, Protocol::UDP,
                              std::bind(&Host::Error, this, _1, _2),
                              std::bind(&Host::connected, this));
    }else{
        LOGE("Unkonw schema: %s\n", dest->schema);
    }
}

Host::~Host(){
    LOGD(DHTTP, "host %s destoryed: rx:%zu, tx:%zu\n", rwer->getDest(), rx_bytes, tx_bytes);
}

void Host::reply(){
    if(rwer->getStats() != RWerStats::Connected){
        return;
    }
    HttpReq* req = status.req;
    if(!req->header->should_proxy){
        if(req->header->ismethod("CONNECT")) {
            Http_Proc = &Host::AlwaysProc;
            status.res = new HttpRes(new HttpResHeader(H200), std::bind(&RWer::EatReadData, rwer));
            req->response(status.res);
        }else if(req->header->ismethod("SEND")){
            Http_Proc = &Host::AlwaysProc;
        }
    }
    size_t len;
    char* buff = req->header->getstring(len);
    auto head = rwer->buffer_head();
    assert(rwer->wlength() == 0 || head->offset == 0);
    rwer->buffer_insert(head, write_block{buff, len, 0});
    req->attach(std::bind(&Host::Send, this, _1, _2), [this]{ return 1024*1024 - rwer->wlength(); });
}

void Host::connected() {
    SslRWer* swrer = dynamic_cast<SslRWer*>(rwer);
    LOGD(DHTTP, "host %s connected\n", rwer->getDest());
    if(swrer){
        const unsigned char *data;
        unsigned int len;
        swrer->get_alpn(&data, &len);
        if ((data && strncasecmp((const char*)data, "h2", len) == 0)) {
            LOG("host delegate %" PRIu64 " %s to proxy2\n",
                status.req->header->request_id,
                status.req->header->geturl().c_str());
            Proxy2 *proxy = new Proxy2(rwer);
            rwer = nullptr;

            proxy->init(status.req);
            assert(status.res == nullptr);
            return Server::deleteLater(NOERROR);
        }
    }
    rwer->SetReadCB([this](size_t len){
        const char* data = this->rwer->rdata();
        size_t consumed = 0;
        size_t ret = 0;
        while((ret = (this->*Http_Proc)(data+consumed, len-consumed))){
            consumed += ret;
        }
        assert(consumed <= len);
        LOGD(DHTTP, "host %s read: len:%zu, consumed:%zu\n", rwer->getDest(), len, consumed);
        this->rwer->consume(data, consumed);
    });
    rwer->SetWriteCB([this](size_t len){
        LOGD(DHTTP, "host %s written: wlength:%zu\n", rwer->getDest(), len);
        if(status.flags & HTTP_REQ_EOF) {
            if (rwer->wlength() == 0){
                rwer->Shutdown();
            }
            return;
        }
        if((status.flags & HTTP_REQ_COMPLETED) || (status.flags & HTTP_REQ_EOF)){
            return;
        }
        if(len){
            status.req->more();
        }
    });
    reply();
}

void Host::request(HttpReq* req, Requester*) {
    LOGD(DHTTP, "host request %" PRIu64 ": %s\n",
         req->header->request_id,
         req->header->geturl().c_str());
    assert(status.flags == 0);
    assert(status.req == nullptr);
    assert(status.res == nullptr);
    status.req = req;
    req->setHandler([this, req](Channel::signal s){
        LOGD(DHTTP, "host signal %" PRIu64 ": %d\n", req->header->request_id, (int)s);
        switch(s){
        case Channel::CHANNEL_SHUTDOWN:
            assert(strcasecmp(Server.schema, "udp"));
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
    rwer->buffer_insert(rwer->buffer_end(), write_block{buff, size, 0});
    tx_bytes += size;
    if(size == 0){
        status.flags |= HTTP_REQ_COMPLETED;
        LOGD(DHTTP, "host Send %" PRIu64 ": EOF/%zu, http_flag:%d\n",
             status.req->header->request_id, tx_bytes, http_flag);
    }else{
        LOGD(DHTTP, "host Send %" PRIu64 ": size:%zu/%zu, http_flag:%d\n",
             status.req->header->request_id, size, tx_bytes, http_flag);
    }
}

void Host::ResProc(HttpResHeader* header) {
    LOGD(DHTTP, "host ResProc %" PRIu64": %s, http_flag:%d\n",
         status.req->header->request_id ,header->status, http_flag);
    if(status.req->header->ismethod("HEAD")){
        http_flag |= HTTP_IGNORE_BODY_F;
    }
    status.res = new HttpRes(header, std::bind(&RWer::EatReadData, rwer));
    status.req->response(status.res);
}

ssize_t Host::DataProc(const void* buff, size_t size) {
    assert((status.flags & HTTP_RES_EOF) == 0);
    assert((status.flags & HTTP_RES_COMPLETED) == 0);
    if(status.res == nullptr){
        assert(strcasecmp(Server.schema, "udp") == 0);
        status.res = new HttpRes(new HttpResHeader(H200), std::bind(&RWer::EatReadData, rwer));
        status.req->response(status.res);
    }
    int len = status.res->cap();
    len = Min(len, size);

    if (len <= 0) {
        LOGE("The guest's write buff is full (%" PRIu64 ")\n", status.req->header->request_id);
        if(strcasecmp(Server.schema, "udp") == 0){
            return size;
        }
        rwer->delEvents(RW_EVENT::READ);
        return -1;
    }
    status.res->send(buff, len);
    rx_bytes += len;
    LOGD(DHTTP, "host DataProc %" PRIu64 ": size:%zu, send:%d/%zu\n",
         status.req->header->request_id, size, len, rx_bytes);
    return len;
}

void Host::EndProc() {
    LOGD(DHTTP, "host EndProc %" PRIu64 "\n", status.req->header->request_id);
    status.flags |= HTTP_RES_COMPLETED;
    status.res->send((const void*)nullptr, 0);
}

void Host::ErrProc(){
    Error(HTTP_PROTOCOL_ERR, 0);
}

void Host::Error(int ret, int code) {
    LOGD(DHTTP, "host Error %" PRIu64 ": ret:%d, code:%d, http_flag:0x%08x\n",
            status.req->header->request_id, ret, code, http_flag);
    if((ret == READ_ERR || ret == SOCKET_ERR) && code == 0 && status.res){
        //EOF
        status.flags |= HTTP_RES_EOF;
        if(status.flags & HTTP_REQ_EOF){
            deleteLater(NOERROR);
        }else {
            status.res->trigger(Channel::CHANNEL_SHUTDOWN);
        }
        return;
    }
    LOGE("Host error <%s> %" PRIu64 " %d/%d\n",
         rwer->getDest(), status.req->header->request_id, ret, code);
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
    }else {
        switch(errcode) {
        case DNS_FAILED:
            status.req->response(new HttpRes(new HttpResHeader(H503), "[[dns failed]]\n"));
            break;
        case CONNECT_FAILED:
            status.req->response(new HttpRes(new HttpResHeader(H503), "[[connect failed]]\n"));
            break;
        case CONNECT_TIMEOUT:
            status.req->response(new HttpRes(new HttpResHeader(H504), "[[connect timeout]]\n"));
            break;
        case SOCKET_ERR:
        case READ_ERR:
        case WRITE_ERR:
            status.req->response(new HttpRes(new HttpResHeader(H502), "[[socket error]]\n"));
            break;
        default:
            status.req->response(new HttpRes(new HttpResHeader(H500), "[[internal error]]\n"));
        }
    }
    Server::deleteLater(errcode);
}

void Host::gethost(HttpReq *req, const Destination* dest, Requester* src) {
    if(req->header->should_proxy && memcmp(dest, &opt.Server, sizeof(Destination)) == 0 && proxy2){
        return proxy2->request(req, src);
    }
    if(req->header->ismethod("CONNECT") ||  req->header->ismethod("SEND")){
    }
    (new Host(dest))->request(req, src);
}

void Host::dump_stat(Dumper dp, void* param) {
    dp(param, "Host %p, <%s> (%s)\n", this, rwer->getDest(), rwer->getPeer());
    dp(param, "  rwer: rlength:%zu, rleft:%zu, wlength:%zu, stats:%d, event:%s\n",
            rwer->rlength(), rwer->rleft(), rwer->wlength(),
            (int)rwer->getStats(), events_string[(int)rwer->getEvents()]);
    if(status.req){
        dp(param, "req [%" PRIu64 "]: %s [%d]\n",
                status.req->header->request_id,
                status.req->header->geturl().c_str(),
                status.flags);
    }
}
