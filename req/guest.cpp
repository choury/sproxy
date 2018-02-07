#include "guest.h"
#include "guest2.h"
#include "misc/net.h"
#include "res/responser.h"
#include "misc/job.h"
#include "misc/util.h"
#include "misc/sslio.h"

#include <string.h>
#include <assert.h>

Guest::Guest(int fd,  const sockaddr_un *myaddr): Requester(myaddr) {
    rwer = new StreamRWer(fd, std::bind(&Guest::Error, this, _1, _2));
    rwer->SetReadCB([this](size_t len){
        const char* data = this->rwer->data();
        size_t consumed = 0;
        size_t ret = 0;
        while((ret = (this->*Http_Proc)(data+consumed, len-consumed))){
            consumed += ret;
        }
        this->rwer->consume(data, consumed);
    });
    rwer->SetWriteCB([this](size_t len){
        if(responser_ptr && len){
            responser_ptr->writedcb(responser_index);
        }
        if(rwer->wlength() == 0 && (http_flag & HTTP_SERVER_CLOSE_F)){
            rwer->Shutdown();
        }
    });
}

Guest::Guest(int fd,  const sockaddr_un *myaddr, SSL_CTX* ctx): Requester(myaddr) {
    rwer = new SslRWer(fd, ctx, std::bind(&Guest::Error, this, _1, _2));
    rwer->SetReadCB([this](size_t len){
        const char* data = rwer->data();
        len = (this->*Http_Proc)(data, len);
        rwer->consume(data, len);
    });
    rwer->SetWriteCB([this](size_t len){
        if(responser_ptr && len){
            responser_ptr->writedcb(responser_index);
        }
        if(rwer->wlength() == 0 && (http_flag & HTTP_SERVER_CLOSE_F)){
            rwer->Shutdown();
        }
    });
    rwer->SetConnectCB([this](){
        SslRWer* srwer = dynamic_cast<SslRWer*>(rwer);
        const unsigned char *data;
        unsigned int len;
        srwer->get_alpn(&data, &len);
        if ((data && strncasecmp((const char*)data, "h2", len) == 0)) {
            new Guest2(sourceip, sourceport, srwer);
            rwer = nullptr;
            delete this;
            return;
        }
    });
}

void Guest::ReqProc(HttpReqHeader* req) {
    if(Status_flags != GUEST_IDELE_F){
        Status_flags |= GUEST_ERROR_F;
        LOGE("pipeline are not supported!\n");
        delete req;
        return;
    }
    req->index = (void *)1;
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
    if (responser_ptr == nullptr || (Status_flags & GUEST_ERROR_F)) {
        LOGE("(%s): connecting to host lost or error ocured\n", getsrc(nullptr));
        deleteLater(PEER_LOST_ERR);
        return -1;
    }
    int len = responser_ptr->bufleft(responser_index);
    if (len <= 0) {
        LOGE("(%s): The host's buff is full\n", getsrc(nullptr));
        rwer->setEpoll(0);
        return -1;
    }
    return responser_ptr->Send(buff, Min(size, len), responser_index);
}

void Guest::EndProc() {
    if(responser_ptr){
        if(Status_flags & GUEST_RES_COMPLETED){
            Status_flags = GUEST_IDELE_F;
        }else{
            Status_flags |= GUEST_REQ_COMPLETED;
        }
        responser_ptr->finish(NOERROR, responser_index);
        rwer->delEpoll(EPOLLIN);
        return;
    }else if((Status_flags & GUEST_ERROR_F) == 0){
        Status_flags = GUEST_IDELE_F;
    }
}

void Guest::ErrProc() {
    Error(HTTP_PROTOCOL_ERR, 0);
}


void Guest::Error(int ret, int code) {
    if((ret == READ_ERR || ret == SOCKET_ERR) && code == 0){
        http_flag |= HTTP_CLIENT_CLOSE_F;
        deleteLater(NOERROR | DISCONNECT_FLAG);
        return;
    }
    LOGE("Guest error %s: %d/%d\n", getsrc(nullptr), ret, code);
    deleteLater(ret);
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
    rwer->buffer_insert(rwer->buffer_end(), buff, len);
    delete res;
}

int32_t Guest::bufleft(void*){
    return 1024*1024 - rwer->wlength();
}


ssize_t Guest::Send(void *buff, size_t size, void* index) {
    assert((uint32_t)(long)index == 1);
    assert((http_flag & HTTP_SERVER_CLOSE_F) == 0);
    size_t len = Min(bufleft(nullptr), size);
    if(Status_flags & GUEST_CHUNK_F){
        char chunkbuf[100];
        int chunklen = snprintf(chunkbuf, sizeof(chunkbuf), "%x" CRLF, (uint32_t)len);
        buff = p_move(buff, -chunklen);
        memcpy(buff, chunkbuf, chunklen);
        rwer->buffer_insert(rwer->buffer_end(), buff, chunklen+len);
        rwer->buffer_insert(rwer->buffer_end(), CRLF, strlen(CRLF));
    }else{
        rwer->buffer_insert(rwer->buffer_end(), buff, size);
    }
    return len;
}

void Guest::transfer(void* index, Responser* res_ptr, void* res_index) {
    assert(index == responser_index);
    responser_ptr = res_ptr;
    responser_index = res_index;
}

void Guest::deleteLater(uint32_t errcode){
    assert(errcode);
    Status_flags |= GUEST_ERROR_F;
    if(responser_ptr){
        assert(responser_index);
        responser_ptr->finish(errcode, responser_index);
        responser_ptr = nullptr;
        responser_index = nullptr;
    }
    Peer::deleteLater(errcode);
}

void Guest::finish(uint32_t flags, void* index) {
    assert((uint32_t)(long)index == 1);
    uint8_t errcode = flags & ERROR_MASK;
    if(errcode){
        responser_ptr = nullptr;
        responser_index = nullptr;
        Peer::deleteLater(errcode);
        return;
    }
    rwer->addEpoll(EPOLLIN);
    Peer::Send((const void*)nullptr,0, index);
    if((Status_flags & GUEST_CONNECT_F) || (Status_flags & GUEST_SEND_F)){
        assert((flags & DISCONNECT_FLAG) == 0);
        http_flag |= HTTP_SERVER_CLOSE_F;
        if(rwer->wlength() == 0){
            rwer->Shutdown();
        }
        return;
    } 

    if(Status_flags & GUEST_REQ_COMPLETED){
        Status_flags = GUEST_IDELE_F;
    }else{
        Status_flags |= GUEST_RES_COMPLETED;
    }
    if(flags & DISCONNECT_FLAG){
        responser_ptr = nullptr;
        responser_index = nullptr;
    }
}

void Guest::writedcb(void* index) {
    if((http_flag & HTTP_CLIENT_CLOSE_F) == 0){
        Peer::writedcb(index);
    }
}


const char* Guest::getsrc(const void *){
    static char src[DOMAINLIMIT];
    sprintf(src, "[%s]:%d", sourceip, sourceport);
    return src;
}

void Guest::dump_stat(){
    LOG("Guest %p, %s: %p, %p\n", this, getsrc(nullptr), responser_ptr, responser_index);
}
