#include "guest.h"
#include "net.h"
#include "responser.h"

#include <set>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>


void guesttick(Guest* guest){
    guest->request_next();
}

Guest::Guest(int fd,  struct sockaddr_in6 *myaddr): Requester(fd, myaddr) {
    add_tick_func((void (*)(void *))guesttick, this);
}


void Guest::ResetResponser(Responser *r){
    responser_ptr = r;
}

void Guest::request_next() {
    while(status == none && reqs.size()){
        HttpReq req = std::move(reqs.front());
        reqs.pop();
        Responser* responser = distribute(req.header, responser_ptr);
        if(responser && responser != responser_ptr){
           responser_ptr = responser;
        }
        if(responser){
            if(req.header.ismethod("CONNECT")){
                status = presistent;
            }else{
                status = requesting;
            }
            while(1){
                auto block = req.body.pop();
                if(block.second == 0)
                    break;
                responser_ptr->Write(block.first, block.second, this);
            }
        }
    }
}


void Guest::defaultHE(uint32_t events) {
    if (events & EPOLLERR || events & EPOLLHUP) {
        int       error = 0;
        socklen_t errlen = sizeof(error);

        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, (void*)&error, &errlen) == 0) {
            LOGE("(%s): guest error:%s\n", getsrc(), strerror(error));
        }
        clean(INTERNAL_ERR, this);
    }

    if (events & EPOLLIN ) {
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
    if(status == none && reqs.empty()){
        Responser* responser = distribute(req, responser_ptr);
        if(responser && responser != responser_ptr){
           responser_ptr = responser;
        }
        if(responser){
            if(req.ismethod("CONNECT")){
                status = presistent;
            }else{
                status = requesting;
            }
        }
    }else{
        reqs.push(HttpReq(req));
    }
}

void Guest::response(HttpResHeader& res) {
    if(status == presistent){
        if(memcmp(res.status, "200", 4) == 0){
            strcpy(res.status, "200 Connection established");
            res.del("Transfer-Encoding");
        }
    }else if(res.get("Transfer-Encoding")){
        status = chunked;
    }else if(res.no_left()){
        status = none;
    }
    size_t len;
    char *buff=res.getstring(len);
    Peer::Write(buff, len, this);
}

ssize_t Guest::Write(void *buff, size_t size, Peer* who, uint32_t) {
    size_t ret;
    size_t len = Min(bufleft(who), size);
    assert(who == this || who == responser_ptr);
    if(status == chunked){
        char chunkbuf[100];
        int chunklen = snprintf(chunkbuf, sizeof(chunkbuf), "%x" CRLF, (uint32_t)size);
        buff = p_move(buff, -chunklen);
        memcpy(buff, chunkbuf, chunklen);
        ret = Peer::Write(buff, chunklen + len, this);
        if(ret > 0){
            if(Peer::Write(memcpy(p_malloc(strlen(CRLF)), CRLF, strlen(CRLF)),
                           strlen(CRLF), this) != strlen(CRLF))
                assert(0);
            assert(ret >= (size_t)chunklen);
            ret -= chunklen;
        }
    }else{
        ret =  Peer::Write(buff, size, this);
    }
    if(size == 0){
        status = none;
    }
    return ret;
}

ssize_t Guest::DataProc(const void *buff, size_t size) {
    if (responser_ptr == NULL) {
        LOGE("(%s): connecting to host lost\n", getsrc());
        clean(PEER_LOST_ERR, this);
        return -1;
    }
    int len = responser_ptr->bufleft(this);
    if (len <= 0) {
        LOGE("(%s): The host's buff is full\n", getsrc());
        responser_ptr->wait(this);
        return -1;
    }
    if(reqs.size()){
        return reqs.back().body.push(buff, size);
    }else{
        return responser_ptr->Write(buff, Min(size, len), this);
    }
}

void Guest::clean(uint32_t errcode, Peer* who, uint32_t) {
    assert(who);
    assert(dynamic_cast<Responser *>(who) == responser_ptr || who == this);
    if(who == this && responser_ptr){
        responser_ptr->clean(errcode, this);
    }
    responser_ptr = nullptr;
    del_tick_func((void (*)(void *))guesttick, this);
    Peer::clean(errcode, who);
}

void Guest::discard() {
    responser_ptr = nullptr;
    Requester::discard();
}


