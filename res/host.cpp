#include "host.h"
#include "req/requester.h"
#include "misc/job.h"
#include "misc/util.h"
#include "misc/vssl.h"

#include <string.h>
#include <errno.h>
#include <assert.h>
                    
static const unsigned char alpn_protos_string[] =
    "\x8http/1.1" \
    "\x2h2";

Host::Host(Protocol protocol, const char* hostname, uint16_t port, bool use_ssl): protocol(protocol), port(port){
    assert(port);
    assert(protocol == Protocol::TCP || protocol == Protocol::UDP);
    snprintf(this->hostname, sizeof(this->hostname), "%s", hostname);

    if(use_ssl){
        SRWer *srwer = new SRWer(hostname, port, protocol, std::bind(&Host::Error, this, _1, _2));
        if(use_http2){
            srwer->set_alpn(alpn_protos_string, sizeof(alpn_protos_string)-1);
        }
        rwer = srwer;
    }else{
        rwer = new RWer(hostname, port, protocol, std::bind(&Host::Error, this, _1, _2));
    }
    rwer->SetConnectCB(std::bind(&Host::connected, this));
}

Host::~Host(){
    if(req){
        delete req;
    }
}

#if 0
void Host::discard() {
    req = nullptr;
}
#endif

void Host::connected() {
    isconnected = true;
    if(req->ismethod("CONNECT")){
        if(!req->should_proxy){
            Http_Proc = &Host::AlwaysProc;
            HttpResHeader* res = new HttpResHeader(H200, sizeof(H200));
            res->index = req->index;
            req->src->response(res);
        }
    }else if(req->ismethod("SEND") || req->ismethod("PING")){
        Http_Proc = &Host::AlwaysProc;
    }
    size_t len;
    char* buff = req->getstring(len);
    auto head = rwer->buffer_head();
    assert(head->wlen == 0);
    rwer->buffer_insert(head, buff, len);
    rwer->SetReadCB([this](size_t len){
        len = (this->*Http_Proc)(rwer->data(), len);
        rwer->consume(len);
    });
    rwer->SetWriteCB([this](size_t len){
        if(req && len){
            req->src->writedcb(req->index);
        }
        if(rwer->wlength() == 0 && (http_flag & HTTP_CLIENT_CLOSE_F)){
            rwer->Shutdown();
        }
    });
}

void* Host::request(HttpReqHeader* req) {
    if(this->req){
        assert(req->src == this->req->src);
        delete this->req;
    }
    if(isconnected){
        size_t len;
        char* buff = req->getstring(len);
        rwer->buffer_insert(rwer->buffer_end(), buff, len);
        if(req->ismethod("CONNECT")){
            if(!req->should_proxy){
                Http_Proc = &Host::AlwaysProc;
                HttpResHeader* res = new HttpResHeader(H200, sizeof(H200));
                res->index = req->index;
                req->src->response(res);
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

ssize_t Host::Send(void* buff, size_t size, void* index) {
    assert((long)index == 1);
    assert((http_flag & HTTP_CLIENT_CLOSE_F) == 0);
    rwer->buffer_insert(rwer->buffer_end(), buff, size);
    return size;
}

void Host::ResProc(HttpResHeader* res) {
    assert(req);
    if(req->ismethod("HEAD")){
        http_flag |= HTTP_IGNORE_BODY_F;
    }
    res->index = req->index;
    req->src->response(res);
}

ssize_t Host::DataProc(const void* buff, size_t size) {
    assert(req);
    int len = req->src->bufleft(req->index);

    if (len <= 0) {
        LOGE("(%s): The guest's write buff is full (%s)\n",
             req->src->getsrc(req->index), req->hostname);
        rwer->setEpoll(0);
        return -1;
    }
    return req->src->Send(buff, Min(size, len), req->index);
}

void Host::EndProc() {
    assert(req);
    if(!req->src->finish(NOERROR, req->index)){
        delete req;
        req = nullptr;
        Peer::deleteLater(PEER_LOST_ERR);
    }
}

void Host::ErrProc(){
    Error(HTTP_PROTOCOL_ERR, 0);
}

void Host::Error(int ret, int code) {
    if(ret == READ_ERR && code == 0 && req){
        http_flag |= HTTP_SERVER_CLOSE_F;
        if(Http_Proc == &Host::AlwaysProc){
            EndProc();
        }else{
            deleteLater(PEER_LOST_ERR);
        }
        return;
    }
    if(ret == SOCKET_ERR && code == 0 && ret){
        deleteLater(NOERROR | DISCONNECT_FLAG);
    }else{
        LOGE("Host-http error %d/%d\n", ret, code);
        deleteLater(ret);
    }
}

bool Host::finish(uint32_t flags, void* index) {
    assert((long)index == 1);
    uint8_t errcode = flags & ERROR_MASK;
    if(errcode == VPN_AGED_ERR){
        deleteLater(errcode);
        return false;
    }
    if(errcode || (flags & DISCONNECT_FLAG)){
        delete req;
        req = nullptr;
        deleteLater(flags);
        return false;
    }
    if(Http_Proc == &Host::AlwaysProc){
        http_flag |= HTTP_CLIENT_CLOSE_F;
        if(rwer->wlength() == 0){
            rwer->Shutdown();
        }
    }
    return true;
}

void Host::deleteLater(uint32_t errcode){
    assert(errcode);
    if(req){
        if(!req->ismethod("SEND")){
            if(errcode == CONNECT_TIMEOUT || errcode == DNS_FAILED){
                HttpResHeader* res = new HttpResHeader(H504, sizeof(H504));
                res->index = req->index;
                req->src->response(res);
            }else if(errcode == CONNECT_FAILED){
                HttpResHeader* res = new HttpResHeader(H503, sizeof(H503));
                res->index = req->index;
                req->src->response(res);
            }
        }
        req->src->finish(errcode, req->index);
        delete req;
        req = nullptr;
    }
    Peer::deleteLater(errcode);
}

void Host::writedcb(void* index) {
    if((http_flag & HTTP_SERVER_CLOSE_F) == 0){
        Peer::writedcb(index);
    }
}


Host* Host::gethost(const char* hostname, uint16_t port, Protocol protocol, HttpReqHeader* req, Responser* responser_ptr){
    Host* host = dynamic_cast<Host *>(responser_ptr);
    if(req->ismethod("CONNECT") || req->ismethod("SEND")){
        return new Host(protocol, hostname, port, req->should_proxy);
    }
    if (host){
        if(strcasecmp(host->hostname, hostname) == 0
            && host->port == port
            && host->protocol == protocol)
        {
            return host;
        }
    }
    return new Host(protocol, hostname, port, req->should_proxy);
}


void Host::dump_stat() {
    LOG("Host %p, <%s> (%s:%d):\n", this, protstr(protocol), hostname, port);
    if(req){
        LOG("    %s %s: %p, %p\n",
            req->method, req->geturl().c_str(),
            req->src, req->index);
    }
}
