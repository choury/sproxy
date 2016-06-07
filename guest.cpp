#include "guest.h"
#include "net.h"
#include "responser.h"

#include <set>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>


Guest::Guest(Guest&& copy): Peer(copy.fd), sourceport(copy.sourceport){
    strcpy(this->sourceip, copy.sourceip);
    copy.fd = 0;
}

Guest::Guest(int fd,  struct sockaddr_in6 *myaddr): Peer(fd) {
    inet_ntop(AF_INET6, &myaddr->sin6_addr, sourceip, sizeof(sourceip));
    sourceport = ntohs(myaddr->sin6_port);

    updateEpoll(EPOLLIN | EPOLLOUT);
    handleEvent = (void (Con::*)(uint32_t))&Guest::defaultHE;
}


int Guest::showerrinfo(int ret, const char *s) {
    if (ret < 0) {
        if (errno != EAGAIN) {
            LOGE("([%s]:%d): %s:%m\n", sourceip, sourceport, s);
        } else {
            return 0;
        }
    }else if(ret){
        LOGE("([%s]:%d): %s:%d\n",sourceip, sourceport, s, ret);
    }
    return 1;
}

void Guest::defaultHE(uint32_t events) {
    if (events & EPOLLERR || events & EPOLLHUP) {
        int       error = 0;
        socklen_t errlen = sizeof(error);

        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, (void*)&error, &errlen) == 0) {
            LOGE("([%s]:%d): guest error:%m\n", sourceip, sourceport);
        }
        clean(INTERNAL_ERR, this);
        return;
    }
    
    if (events & EPOLLIN || http_getlen) {
        (this->*Http_Proc)();
    }

    if (events & EPOLLOUT) {
        int ret = Peer::Write();
        if (ret <= 0) {
            if (showerrinfo(ret, "guest write error")) {
                clean(WRITE_ERR, this);
            }
            return;
        }
        if (ret != WRITE_NOTHING && !responser_ptr.expired()){
            Responser * responser = dynamic_cast<Responser *>(responser_ptr.get());
            responser->writedcb(this);
        }

    }
}

void Guest::closeHE(uint32_t events) {
    int ret = Peer::Write();
    if (ret == WRITE_NOTHING ||
        (ret <= 0 && showerrinfo(ret, "write error while closing"))) {
        delete this;
        return;
    }
}


Ptr Guest::shared_from_this() {
    return Peer::shared_from_this();
}


ssize_t Guest::Read(void* buff, size_t len){
    return Peer::Read(buff, len);
}

void Guest::ErrProc(int errcode) {
    if (showerrinfo(errcode, "Guest-Http error")) {
        clean(errcode, this);
    }
}

void Guest::ReqProc(HttpReqHeader& req) {
    this->flag = 0;
    responser_ptr = distribute(req, responser_ptr);
}

void Guest::response(HttpResHeader& res) {
    size_t len;
    char *buff=res.getstring(len);
    Peer::Write(buff, len, this);
    if(res.get("Transfer-Encoding")){
        flag |= ISCHUNKED_F;
    }
}

ssize_t Guest::Write(void *buff, size_t size, Peer* who, uint32_t) {
    size_t len = Min(bufleft(who), size);
    ssize_t ret = 0;
    if(flag & ISCHUNKED_F){
        char chunkbuf[100];
        int chunklen = snprintf(chunkbuf, sizeof(chunkbuf), "%x" CRLF, (uint32_t)size);
        if(Peer::Write((const void *)chunkbuf, chunklen, this) != chunklen)
            assert(0);
        ret = Peer::Write(buff, len, this);
        if(Peer::Write(CRLF, strlen(CRLF), this) != strlen(CRLF))
            assert(0);
    }else{
        ret = Peer::Write(buff, size, this);
    }
    return ret;
}

ssize_t Guest::Write(const void *buff, size_t size, Peer* who, uint32_t) {
    size_t len = Min(bufleft(who), size);
    ssize_t ret = 0;
    if(flag & ISCHUNKED_F){
        char chunkbuf[100];
        int chunklen = snprintf(chunkbuf, sizeof(chunkbuf), "%x" CRLF, (uint32_t)size);
        if(Peer::Write((const void *)chunkbuf, chunklen, this) != chunklen)
            assert(0);
        ret = Peer::Write(buff, len, this);
        if(Peer::Write(CRLF, strlen(CRLF), this) != strlen(CRLF))
            assert(0);
    }else{
        ret = Peer::Write(buff, size, this);
    }
    return ret;
}


ssize_t Guest::DataProc(const void *buff, size_t size) {
    Responser *responser = dynamic_cast<Responser *>(responser_ptr.get());
    if (responser == NULL) {
        LOGE("([%s]:%d): connecting to host lost\n", sourceip, sourceport);
        clean(PEER_LOST_ERR, this);
        return -1;
    }
    int len = responser->bufleft(this);
    if (len <= 0) {
        LOGE("([%s]:%d): The host's buff is full\n", sourceip, sourceport);
        responser->wait(this);
        return -1;
    }
    return responser->Write(buff, Min(size, len), this);
}

void Guest::clean(uint32_t errcode, Peer* who, uint32_t)
{
    if(!responser_ptr.expired()){
        Responser *responser = dynamic_cast<Responser *>(responser_ptr.get());
        responser->clean(errcode, this);
    }
    Peer::clean(errcode, who);
}


const char* Guest::getip(){
    return sourceip;
}

const char* Guest::getsrc(){
    static char src[DOMAINLIMIT];
    sprintf(src, "[%s]:%d", sourceip, sourceport);
    return src;
}



Guest::~Guest(){
}
