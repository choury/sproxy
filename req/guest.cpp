#include "guest.h"
#include "misc/net.h"
#include "res/responser.h"
#include "misc/job.h"

//#include <set>
//#include <string.h>
//#include <errno.h>
#include <assert.h>
//#include <arpa/inet.h>


/*
void request_next(Guest* guest){
    guest->request_next();
}
*/

Guest::Guest(int fd,  struct sockaddr_in6 *myaddr): Requester(fd, myaddr) {
}


        /*
void Guest::request_next() {
    while(status == Status::idle && reqs.size()){
        HttpReq req = std::move(reqs.front());
        reqs.pop_front();
        Responser* res_ptr = distribute(req.header, responser_ptr);
        if(res_ptr){
            if(req.header.ismethod("CONNECT")){
                status = Status::presistent;
            }else if(req.header.ismethod("HEAD")){
                status = Status::headonly;
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
        */


void Guest::defaultHE(uint32_t events) {
    if (events & EPOLLERR || events & EPOLLHUP) {
        int       error = 0;
        socklen_t errlen = sizeof(error);

        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, (void*)&error, &errlen) == 0) {
            LOGE("(%s): guest error:%s\n", getsrc(nullptr), strerror(error));
        }
        deleteLater(INTERNAL_ERR);
        return;
    }

    if (events & EPOLLIN ) {
        (this->*Http_Proc)();
    }

    if (events & EPOLLOUT) {
        int ret = buffer.Write([this](const void* buff, size_t size){
            return Write(buff, size);
        });
        if (ret < 0 && showerrinfo(ret, "guest write error")) {
            deleteLater(WRITE_ERR);
            return;
        }
        if(buffer.length == 0){
            updateEpoll(EPOLLIN);
        }
        if (responser_ptr){
            responser_ptr->writedcb(responser_index);
        }
    }
}

void Guest::closeHE(uint32_t events) {
    int ret = buffer.Write([this](const void* buff, size_t size){
        return Write(buff, size);
    });
    if (ret <= 0 && showerrinfo(ret, "write error while closing")) {
        delete this;
        return;
    }
}


ssize_t Guest::Read(void* buff, size_t len){
    return Peer::Read(buff, len);
}


void Guest::ReqProc(HttpReqHeader* req) {
    req->index = (void *)1;
    assert(status != Status::connect_method && status != Status::send_method);
    Responser* res_ptr = distribute(req, responser_ptr);
    if(res_ptr){
        if(req->ismethod("CONNECT")){
            status = Status::connect_method;
        }else if(req->ismethod("SEND")){
            status = Status::send_method;
        }
        void* res_index = res_ptr->request(req);
        if(responser_ptr && (res_ptr != responser_ptr || res_index != responser_index)){
            responser_ptr->finish(PEER_LOST_ERR, responser_index);
        }
        responser_ptr = res_ptr;
        responser_index = res_index;
    }else{
        delete req;
    }
}

ssize_t Guest::DataProc(const void *buff, size_t size) {
    if (responser_ptr == nullptr) {
        LOGE("(%s): connecting to host lost\n", getsrc(nullptr));
        deleteLater(PEER_LOST_ERR);
        return -1;
    }
    int len = responser_ptr->bufleft(responser_index);
    if (len <= 0) {
        LOGE("(%s): The host's buff is full\n", getsrc(nullptr));
        updateEpoll(0);
        return -1;
    }
    return responser_ptr->Send(buff, Min(size, len), responser_index);
}

void Guest::EndProc() {
    status = Status::idle;
}


void Guest::ErrProc(int errcode) {
    if (showerrinfo(errcode, "Guest-Http error")) {
        deleteLater(HTTP_PROTOCOL_ERR);
    }
}

void Guest::response(HttpResHeader* res) {
    assert((uint32_t)(long)res->index == 1);
    if(status == Status::connect_method){
        if(memcmp(res->status, "200", 3) == 0){
            strcpy(res->status, "200 Connection established");
            res->del("Transfer-Encoding");
        }
    }else if(res->get("Transfer-Encoding")){
        status = Status::chunked;
    }
    size_t len;
    char *buff=res->getstring(len);
    buffer.push(buff, len);
    updateEpoll(events | EPOLLOUT);
    delete res;
}

int32_t Guest::bufleft(void*){
    return 1024*1024 - buffer.length;
}


ssize_t Guest::Send(void *buff, size_t size, void* index) {
    assert((uint32_t)(long)index == 1);
    size_t len = Min(bufleft(nullptr), size);
    if(status == Status::chunked){
        char chunkbuf[100];
        int chunklen = snprintf(chunkbuf, sizeof(chunkbuf), "%x" CRLF, (uint32_t)len);
        buff = p_move(buff, -chunklen);
        memcpy(buff, chunkbuf, chunklen);
        buffer.push(buff, chunklen+len);
        buffer.push(p_memdup(CRLF, strlen(CRLF)), strlen(CRLF));
    }else{
        buffer.push(buff, size);
    }
    updateEpoll(events | EPOLLOUT);
    return len;
}

void Guest::transfer(void* index, Responser* res_ptr, void* res_index) {
    assert(index == responser_index);
    responser_ptr = res_ptr;
    responser_index = res_index;
}

void Guest::discard() {
    responser_ptr = nullptr;
    responser_index = nullptr;
    Requester::discard();
}


void Guest::deleteLater(uint32_t errcode){
    if(responser_ptr){
        assert(responser_index);
        responser_ptr->finish(errcode, responser_index);
        responser_ptr = nullptr;
        responser_index = nullptr;
    }
    Peer::deleteLater(errcode);
}

void Guest::finish(uint32_t errcode, void* index) {
    assert((uint32_t)(long)index == 1);
    responser_ptr = nullptr;
    responser_index = nullptr;
    if(errcode){
        return Peer::deleteLater(errcode ? errcode : PEER_LOST_ERR);
    }else{
        Peer::Send((const void*)nullptr,0, index);
    }
}

const char* Guest::getsrc(void *){
    static char src[DOMAINLIMIT];
    sprintf(src, "[%s]:%d", sourceip, sourceport);
    return src;
}

void Guest::dump_stat(){
    LOG("Guest %p, %s: %p, %p\n", this, getsrc(nullptr), responser_ptr, responser_index);
}
