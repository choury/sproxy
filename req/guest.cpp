#include "guest.h"
#include "misc/net.h"
#include "res/responser.h"
#include "misc/job.h"

//#include <set>
#include <string.h>
//#include <errno.h>
#include <assert.h>

Guest::Guest(int fd,  struct sockaddr_in6 *myaddr): Requester(fd, myaddr) {
}


void Guest::defaultHE(uint32_t events) {
    if (events & EPOLLERR || events & EPOLLHUP) {
        int       error = 0;
        socklen_t errlen = sizeof(error);

        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, (void*)&error, &errlen) == 0) {
            if(error){
                LOGE("(%s): guest error:%s\n", getsrc(nullptr), strerror(error));
            }
        }
        deleteLater(INTERNAL_ERR);
        return;
    }

    if (events & EPOLLOUT) {
        int ret = buffer.Write([this](const void* buff, size_t size){
            return Write(buff, size);
        });
        if (ret < 0 && showerrinfo(ret, "guest write error")) {
            deleteLater(WRITE_ERR);
            return;
        }
        if (ret && responser_ptr){
            responser_ptr->writedcb(responser_index);
        }
        if(buffer.length == 0){
            updateEpoll(this->events & ~EPOLLOUT);
            if(http_flag & HTTP_SERVER_CLOSE_F){
                shutdown(fd, SHUT_WR);
            }
        }
    }
    
    if ((events & EPOLLIN || http_getlen) &&
        (Status_flags & GUEST_REQ_COMPLETED) == 0 )
    {
        (this->*Http_Proc)();
    }
}

void Guest::closeHE(uint32_t) {
    int ret = buffer.Write([this](const void* buff, size_t size){
        return Write(buff, size);
    });
    if ((buffer.length == 0) ||
        (ret <= 0 && showerrinfo(ret, "write error while closing"))) {
        delete this;
        return;
    }
}


ssize_t Guest::Read(void* buff, size_t len){
    return Peer::Read(buff, len);
}


void Guest::ReqProc(HttpReqHeader* req) {
    req->index = (void *)1;
    assert(Status_flags == GUEST_IDELE_F);
    Responser* res_ptr = distribute(req, responser_ptr);
    if(res_ptr){
        if(req->ismethod("CONNECT")){
            Status_flags |= GUEST_CONNECT_F;
        }else if(req->ismethod("SEND")){
            Status_flags |= GUEST_SEND_F;
        }
        Status_flags |= GUEST_PROCESSING_F;
        void* res_index = res_ptr->request(req);
        if(responser_ptr && (res_ptr != responser_ptr || res_index != responser_index)){
            responser_ptr->finish(PEER_LOST_ERR, responser_index);
        }
        responser_ptr = res_ptr;
        responser_index = res_index;
    }else{
        if(responser_ptr){
            responser_ptr->finish(PEER_LOST_ERR, responser_index);
        }
        responser_ptr = nullptr;
        responser_index = nullptr;
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

bool Guest::EndProc() {
    if(responser_ptr){
        if(Status_flags & GUEST_RES_COMPLETED){
            Status_flags = GUEST_IDELE_F;
        }else{
            Status_flags |= GUEST_REQ_COMPLETED;
        }
        if(!responser_ptr->finish(NOERROR, responser_index)){
            responser_ptr = nullptr;
            Peer::deleteLater(PEER_LOST_ERR);
        }else{
            updateEpoll(events & ~EPOLLIN);
        }
        return false;
    }else{
        Status_flags = GUEST_IDELE_F;
        return true;
    }
}


void Guest::ErrProc(int errcode) {
    if(errcode == 0){
        http_flag |= HTTP_CLIENT_CLOSE_F;
        if(Status_flags == GUEST_IDELE_F){
            deleteLater(NOERROR | DISCONNECT_FLAG);
        }else{
            updateEpoll(events & ~EPOLLIN);
        }
        return;
    }
    if(showerrinfo(errcode, "Guest-Http error")) {
        deleteLater(HTTP_PROTOCOL_ERR);
    }
}

void Guest::response(HttpResHeader* res) {
    assert((uint32_t)(long)res->index == 1);
    if(Status_flags & GUEST_CONNECT_F){
        if(memcmp(res->status, "200", 3) == 0){
            strcpy(res->status, "200 Connection established");
            res->del("Transfer-Encoding");
        }
    }else if(res->get("Transfer-Encoding")){
        Status_flags |= GUEST_CHUNK_F;
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
    if(Status_flags & GUEST_CHUNK_F){
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
    assert(errcode);
    if(responser_ptr){
        assert(responser_index);
        responser_ptr->finish(errcode, responser_index);
        responser_ptr = nullptr;
        responser_index = nullptr;
    }
    Peer::deleteLater(errcode);
}

bool Guest::finish(uint32_t flags, void* index) {
    assert((uint32_t)(long)index == 1);
    uint8_t errcode = flags & ERROR_MASK;
    if(errcode){
        responser_ptr = nullptr;
        responser_index = nullptr;
        Peer::deleteLater(PEER_LOST_ERR);
        return false;
    }
    updateEpoll(events | EPOLLIN);
    Peer::Send((const void*)nullptr,0, index);
    if(Status_flags & GUEST_CONNECT_F){
        http_flag |= HTTP_SERVER_CLOSE_F;
    }
    if(Status_flags & GUEST_REQ_COMPLETED){
        Status_flags = GUEST_IDELE_F;
    }else{
        Status_flags |= GUEST_RES_COMPLETED;
    }
    if(flags & DISCONNECT_FLAG){
        responser_ptr = nullptr;
        responser_index = nullptr;
        return false;
    }
    return true;
}

void Guest::writedcb(void* index) {
    if((http_flag & HTTP_CLIENT_CLOSE_F) == 0){
        Peer::writedcb(index);
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
