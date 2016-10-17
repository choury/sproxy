#include "guest.h"
#include "net.h"
#include "responser.h"

#include <set>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>


Guest::Guest(int fd,  struct sockaddr_in6 *myaddr): Requester(fd, myaddr) {
}


void Guest::ResetResponser(Responser *r){
    responser_ptr = r;
}


void Guest::defaultHE(uint32_t events) {
    if (events & EPOLLERR || events & EPOLLHUP) {
        int       error = 0;
        socklen_t errlen = sizeof(error);

        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, (void*)&error, &errlen) == 0) {
            LOGE("([%s]:%d): guest error:%s\n",
                 sourceip, sourceport, strerror(error));
        }
        clean(INTERNAL_ERR, this);
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
        if (ret != WRITE_NOTHING && responser_ptr){
            responser_ptr->writedcb(this);
        }

    }
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
    }else{
        flag &= ~ISCHUNKED_F;
    }
}

ssize_t Guest::Write(void *buff, size_t size, Peer* who, uint32_t) {
    size_t len = Min(bufleft(who), size);
    if(flag & ISCHUNKED_F){
        char chunkbuf[100];
        int chunklen = snprintf(chunkbuf, sizeof(chunkbuf), "%x" CRLF, (uint32_t)size);
        buff = p_move(buff, -chunklen);
        memcpy(buff, chunkbuf, chunklen);
        ssize_t ret = Peer::Write(buff, chunklen + len, this);
        if(ret <= 0){
            return ret;
        }else{
            if(Peer::Write(memcpy(p_malloc(strlen(CRLF)), CRLF, strlen(CRLF)),
                           strlen(CRLF), this) != strlen(CRLF))
                assert(0);
            assert(ret >= chunklen);
            return ret - chunklen;
        }
    }else{
        return Peer::Write(buff, size, this);
    }
}

ssize_t Guest::DataProc(const void *buff, size_t size) {
    if (responser_ptr == NULL) {
        LOGE("([%s]:%d): connecting to host lost\n", sourceip, sourceport);
        clean(PEER_LOST_ERR, this);
        return -1;
    }
    int len = responser_ptr->bufleft(this);
    if (len <= 0) {
        LOGE("([%s]:%d): The host's buff is full\n", sourceip, sourceport);
        responser_ptr->wait(this);
        return -1;
    }
    return responser_ptr->Write(buff, Min(size, len), this);
}

void Guest::clean(uint32_t errcode, Peer* who, uint32_t) {
    assert(who);
    assert(dynamic_cast<Responser *>(who) == responser_ptr || who == this);
    if(responser_ptr){
        if(who == this){
            responser_ptr->clean(errcode, this);
        }
        responser_ptr = nullptr;
    }
    Peer::clean(errcode, who);
}

void Guest::discard() {
    responser_ptr = nullptr;
    Requester::discard();
}


