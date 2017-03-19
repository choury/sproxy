#include "guest.h"
#include "misc/net.h"
#include "res/responser.h"
#include "misc/job.h"

#include <set>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>


void request_next(Guest* guest){
    guest->request_next();
}

Guest::Guest(int fd,  struct sockaddr_in6 *myaddr): Requester(fd, myaddr) {
}


void Guest::request_next() {
    while(status == Status::idle && reqs.size()){
        HttpReq req = std::move(reqs.front());
        reqs.pop();
        Responser* res_ptr = distribute(req.header, responser_ptr);
        if(res_ptr){
            if(req.header.ismethod("CONNECT")){
                status = Status::presistent;
            }else{
                status = Status::requesting;
            }
            void* res_index = res_ptr->request(std::move(req.header));
            if(responser_ptr && (res_ptr != responser_ptr || res_index != responser_index)){
                responser_ptr->clean(NOERROR, responser_index);
            }
            responser_ptr = res_ptr;
            responser_index = res_index;
            while(1){
                auto block = req.body.pop();
                if(block.second == 0)
                    break;
                responser_ptr->Write(block.first, block.second, responser_index);
            }
        }
    }
    del_job((job_func)::request_next, this);
}


void Guest::defaultHE(uint32_t events) {
    if (events & EPOLLERR || events & EPOLLHUP) {
        int       error = 0;
        socklen_t errlen = sizeof(error);

        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, (void*)&error, &errlen) == 0) {
            LOGE("(%s): guest error:%s\n", getsrc(), strerror(error));
        }
        clean(INTERNAL_ERR, 0);
    }

    if (events & EPOLLIN ) {
        (this->*Http_Proc)();
    }

    if (events & EPOLLOUT) {
        int ret = Peer::Write_buff();
        if (ret <= 0) {
            if (showerrinfo(ret, "guest write error")) {
                clean(WRITE_ERR, 0);
            }
            return;
        }
        if (ret != WRITE_NOTHING && responser_ptr){
            responser_ptr->writedcb(responser_index);
        }

    }
}

ssize_t Guest::Read(void* buff, size_t len){
    return Peer::Read(buff, len);
}

void Guest::ErrProc(int errcode) {
    if (showerrinfo(errcode, "Guest-Http error")) {
        clean(errcode, 0);
    }
}

void Guest::ReqProc(HttpReqHeader&& req) {
    req.index = (void *)1;
    if(status == Status::idle && reqs.empty()){
        Responser* res_ptr = distribute(req, responser_ptr);
        if(res_ptr){
            if(req.ismethod("CONNECT")){
                status = Status::presistent;
            }else{
                status = Status::requesting;
            }
            void* res_index = res_ptr->request(std::move(req));
            if(responser_ptr && (res_ptr != responser_ptr || res_index != responser_index)){
                responser_ptr->clean(NOERROR, responser_index);
            }
            responser_ptr = res_ptr;
            responser_index = res_index;
        }
    }else{
        reqs.push(HttpReq(req));
    }
}

void Guest::response(HttpResHeader&& res) {
    assert((uint32_t)(long)res.index == 1);
    if(status == Status::presistent){
        if(memcmp(res.status, "200", 3) == 0){
            strcpy(res.status, "200 Connection established");
            res.del("Transfer-Encoding");
        }
    }else if(res.get("Transfer-Encoding")){
        status = Status::chunked;
    }else if(res.no_body()){
        status = Status::idle;
        if(!reqs.empty())
            add_job((job_func)::request_next, this, 0);
    }
    size_t len;
    char *buff=res.getstring(len);
    Requester::Write(buff, len, 0);
}

ssize_t Guest::Write(void *buff, size_t size, void* index) {
    assert((uint32_t)(long)index == 1);
    size_t ret;
    size_t len = Min(bufleft(responser_index), size);
    if(status == Status::chunked){
        char chunkbuf[100];
        int chunklen = snprintf(chunkbuf, sizeof(chunkbuf), "%x" CRLF, (uint32_t)size);
        buff = p_move(buff, -chunklen);
        memcpy(buff, chunkbuf, chunklen);
        ret = Requester::Write(buff, chunklen + len, 0);
        if(ret > 0){
            assert(ret >= (size_t)chunklen);
            if(Requester::Write(p_memdup(CRLF, strlen(CRLF)), strlen(CRLF), index) != strlen(CRLF))
                assert(0);
            ret -= chunklen;
        }
    }else{
        ret =  Requester::Write(buff, size, 0);
    }
    if(size == 0){
        status = Status::idle;
        if(!reqs.empty())
            add_job((job_func)::request_next, this, 0);
    }
    return ret;
}

ssize_t Guest::DataProc(const void *buff, size_t size) {
    if (responser_ptr == nullptr) {
        LOGE("(%s): connecting to host lost\n", getsrc());
        clean(PEER_LOST_ERR, 0);
        return -1;
    }
    int len = responser_ptr->bufleft(responser_index);
    if (len <= 0) {
        LOGE("(%s): The host's buff is full\n", getsrc());
        responser_ptr->wait(responser_index);
        updateEpoll(0);
        return -1;
    }
    if(reqs.size()){
        return reqs.back().body.push(buff, size);
    }else{
        return responser_ptr->Write(buff, Min(size, len), responser_index);
    }
}

void Guest::clean(uint32_t errcode, void* index) {
    assert((long)index == 0 || (long)index == 1);
    if(index == nullptr && responser_ptr){
        responser_ptr->clean(errcode, responser_index);
    }
    responser_ptr = nullptr;
    del_job((job_func)::request_next, this);
    Peer::clean(errcode, 0);
}
