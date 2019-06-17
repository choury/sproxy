#include "host.h"
#include "proxy2.h"
#include "req/requester.h"
#include "misc/job.h"
#include "misc/util.h"
#include "misc/sslio.h"
#include "misc/net.h"

#include <string.h>
#include <errno.h>
#include <assert.h>
                    
static const unsigned char alpn_protos_string[] =
    "\x8http/1.1" \
    "\x2h2";

Host::Host(const Destination* dest){
    assert(dest->port);
    assert(dest->protocol[0]);
    memcpy(&Server, dest, sizeof(Destination));

    if(strcasecmp(dest->protocol, "http") == 0){
        rwer = new StreamRWer(dest->hostname, dest->port, Protocol::TCP,
                              std::bind(&Host::Error, this, _1, _2),
                              std::bind(&Host::connected, this));
    }else if(strcasecmp(dest->protocol, "https") == 0 ) {
        SslRWer *srwer = new SslRWer(dest->hostname, dest->port, Protocol::TCP,
                                     std::bind(&Host::Error, this, _1, _2),
                                     std::bind(&Host::connected, this));
        if(!opt.disable_http2){
            srwer->set_alpn(alpn_protos_string, sizeof(alpn_protos_string)-1);
        }
        rwer = srwer;
    }else if(strcasecmp(dest->protocol, "udp") == 0){
        rwer = new PacketRWer(dest->hostname, dest->port, Protocol::UDP,
                              std::bind(&Host::Error, this, _1, _2),
                              std::bind(&Host::connected, this));
    }else{
        LOGE("Unkonw protocol: %s\n", dest->protocol);
    }
}

Host::~Host(){
    LOGD(DHTTP, "host destoryed: rx:%zu, tx:%zu", rx_bytes, tx_bytes);
    delete req;
}

void Host::connected() {
    SslRWer* swrer = dynamic_cast<SslRWer*>(rwer);
    LOGD(DHTTP, "host %s:%d connected\n", Server.hostname, Server.port);
    if(swrer){
        const unsigned char *data;
        unsigned int len;
        swrer->get_alpn(&data, &len);
        if ((data && strncasecmp((const char*)data, "h2", len) == 0)) {
            LOG("delegate %s to proxy2\n", req?req->geturl().c_str():"NONE");
            Proxy2 *proxy = new Proxy2(rwer);
            rwer = nullptr;

            proxy->init(req);
            req = nullptr;
            return deleteLater(PEER_LOST_ERR);
        }
    }
    if(req == nullptr){ //requester has called finished yet.
        return;
    }
    if(req->ismethod("CONNECT")){
        if(!req->should_proxy){
            Http_Proc = &Host::AlwaysProc;
            HttpResHeader* res = new HttpResHeader(H200, sizeof(H200));
            res->index = req->index;
            assert(!req->src.expired());
            req->src.lock()->response(res);
        }
    }else if(req->ismethod("SEND") || req->ismethod("PING")){
        Http_Proc = &Host::AlwaysProc;
    }
    size_t len;
    char* buff = req->getstring(len);
    auto head = rwer->buffer_head();
    assert(rwer->wlength() == 0 || head->offset == 0);
    rwer->buffer_insert(head, write_block{buff, len, 0});
    rwer->SetReadCB([this](size_t len){
        const char* data = this->rwer->rdata();
        size_t consumed = 0;
        size_t ret = 0;
        while((ret = (this->*Http_Proc)(data+consumed, len-consumed))){
            consumed += ret;
        }
        LOGD(DHTTP, "host %s read: len:%zu, consumed:%zu\n", dumpDest(&Server), len, consumed);
        this->rwer->consume(data, consumed);
    });
    rwer->SetWriteCB([this](size_t len){
        LOGD(DHTTP, "host %s writed: wlength:%zu\n", dumpDest(&Server), len);
        if(req && len){
            req->src.lock()->writedcb(req->index);
        }
        if(rwer->wlength() == 0 && (http_flag & HTTP_CLIENT_CLOSE_F)){
            rwer->Shutdown();
        }
    });
}

void* Host::request(HttpReqHeader* req) {
    LOGD(DHTTP, "host request: %s\n", req->geturl().c_str());
    if(this->req){
        assert(req->src.lock() == this->req->src.lock());
        delete this->req;
    }
    if(rwer->getStats() == RWerStats::Connected){
        size_t len;
        char* buff = req->getstring(len);
        rwer->buffer_insert(rwer->buffer_end(), write_block{buff, len, 0});
        if(req->ismethod("CONNECT")){
            if(!req->should_proxy){
                Http_Proc = &Host::AlwaysProc;
                HttpResHeader* res = new HttpResHeader(H200, sizeof(H200));
                res->index = req->index;
                req->src.lock()->response(res);
            }
        }else if(req->ismethod("SEND") || req->ismethod("PING")){
            Http_Proc = &Host::AlwaysProc;
        }
    }
    this->req = req;
    return reinterpret_cast<void*>(1);
}

int32_t Host::bufleft(void*) {
    return 1024*1024 - rwer->wlength();
}

void Host::Send(void* buff, size_t size,  __attribute__ ((unused)) void* index) {
    assert((long)index == 1);
    assert((http_flag & HTTP_CLIENT_CLOSE_F) == 0);
    rwer->buffer_insert(rwer->buffer_end(), write_block{buff, size, 0});
    tx_bytes += size;
    LOGD(DHTTP, "host %s Send: size:%zu/%zu, http_flag:%d\n", dumpDest(&Server), size, tx_bytes, http_flag);
}

void Host::ResProc(HttpResHeader* res) {
    LOGD(DHTTP, "host %s ResProc: %s, http_flag:%d\n", dumpDest(&Server), res->status, http_flag);
    assert(!req->src.expired());
    if(req->ismethod("HEAD")){
        http_flag |= HTTP_IGNORE_BODY_F;
    }
    res->index = req->index;
    req->src.lock()->response(res);
}

ssize_t Host::DataProc(const void* buff, size_t size) {
    assert(!req->src.expired());
    int len = req->src.lock()->bufleft(req->index);
    len = Min(len, size);

    if (len <= 0) {
        LOGE("(%s): The guest's write buff is full (%s)\n",
             req->src.lock()->getsrc(req->index), Server.hostname);
        if(strcasecmp(Server.protocol, "udp") == 0){
            return size;
        }
        rwer->delEvents(RW_EVENT::READ);
        return -1;
    }
    req->src.lock()->Send(buff,  len, req->index);
    rx_bytes += len;
    LOGD(DHTTP, "host %s DataProc: size:%zu, send:%d/%zu\n", dumpDest(&Server), size, len, rx_bytes);
    return len;
}

void Host::EndProc() {
    LOGD(DHTTP, "host %s EndProc\n", dumpDest(&Server));
    assert(!req->src.expired());
    req->src.lock()->finish(NOERROR, req->index);
}

void Host::ErrProc(){
    Error(HTTP_PROTOCOL_ERR, 0);
}

void Host::Error(int ret, int code) {
    if((ret == READ_ERR || ret == SOCKET_ERR) && code == 0){
        http_flag |= HTTP_SERVER_CLOSE_F;
        return deleteLater(NOERROR | DISCONNECT_FLAG);
    }
    LOGE("Host error <%s> %d/%d\n", dumpDest(&Server), ret, code);
    deleteLater(ret);
}

void Host::finish(uint32_t flags, void* index) {
    assert((long)index == 1);
    LOGD(DHTTP, "host %s finish: flags:%u, http_flag: %u\n", dumpDest(&Server), flags, http_flag);
    uint8_t errcode = flags & ERROR_MASK;
    if(errcode || (flags & DISCONNECT_FLAG)){
        delete req;
        req = nullptr;
        deleteLater(flags);
        return;
    }
    if(Http_Proc == &Host::AlwaysProc){
        http_flag |= HTTP_CLIENT_CLOSE_F;
        if(rwer->wlength() == 0){
            rwer->Shutdown();
        }
    }
}

void Host::deleteLater(uint32_t errcode){
    assert(errcode);
    if(req){
        assert(!req->src.expired());
        if(errcode == CONNECT_TIMEOUT || errcode == DNS_FAILED){
            HttpResHeader* res = new HttpResHeader(H504, sizeof(H504));
            res->index = req->index;
            req->src.lock()->response(res);
        }else if(errcode == CONNECT_FAILED){
            HttpResHeader* res = new HttpResHeader(H503, sizeof(H503));
            res->index = req->index;
            req->src.lock()->response(res);
        }
        req->src.lock()->finish(errcode, req->index);
        delete req;
        req = nullptr;
    }
    Peer::deleteLater(errcode);
}

void Host::writedcb(const void* index) {
    LOGD(DHTTP, "host %s writedcb: http_flag:%d, rlength:%zu, wlength:%zu, bufleft:%d\n", 
        dumpDest(&Server), http_flag, rwer->rlength(), rwer->wlength(), req->src.lock()->bufleft(req->index));
    if((http_flag & HTTP_SERVER_CLOSE_F) == 0){
        Peer::writedcb(index);
    }
}


std::weak_ptr<Responser>
Host::gethost(
    const Destination* dest,
    HttpReqHeader* req,
    std::weak_ptr<Responser> responser_ptr)
{
    if(req->should_proxy && memcmp(dest, &opt.Server, sizeof(Destination)) == 0 && !proxy2.expired()){
        return proxy2;
    }
    if(!req->ismethod("CONNECT") &&  !req->ismethod("SEND") && !responser_ptr.expired()){
        auto host = std::dynamic_pointer_cast<Host>(responser_ptr.lock());
        if(host != nullptr && memcmp(dest, &host->Server, sizeof(Destination)) == 0)
            return host;
    }
    return std::dynamic_pointer_cast<Responser>((new Host(dest))->shared_from_this());
}


void Host::dump_stat(Dumper dp, void* param) {
    dp(param, "Host %p, <%s>\n", this, dumpDest(&Server));
    dp(param, "  rwer: rlength:%zu, rleft:%zu, wlength:%zu, stats:%d, event:%s\n",
            rwer->rlength(), rwer->rleft(), rwer->wlength(),
            (int)rwer->getStats(), events_string[(int)rwer->getEvents()]);
    if(req){
        dp(param, "request %s %s: %p, %p\n",
                req->method, req->geturl().c_str(),
                req->src.lock().get(), req->index);
    }
}
