#include "guest.h"
#include "guest2.h"
#include "misc/net.h"
#include "res/responser.h"
#include "misc/util.h"
#include "misc/sslio.h"

#include <string.h>
#include <assert.h>

void Guest::ReadHE(size_t len){
    const char* data = rwer->rdata();
    size_t consumed = 0;
    size_t ret = 0;
    while((ret = (this->*Http_Proc)(data+consumed, len-consumed))){
        consumed += ret;
    }
    LOGD(DHTTP, "guest ReadHE %s: len:%zu, consumed:%zu\n", getsrc(nullptr), len, consumed);
    rwer->consume(data, consumed);
}

Guest::Guest(int fd,  const sockaddr_un *myaddr): Requester(myaddr) {
    rwer = new StreamRWer(fd, std::bind(&Guest::Error, this, _1, _2));
    rwer->SetReadCB(std::bind(&Guest::ReadHE, this, _1));
    rwer->SetWriteCB([this](size_t len){
        LOGD(DHTTP, "guest writed %s: wlength:%zu, http_flag:0x%08x\n", getsrc(nullptr), rwer->wlength(), http_flag);
        if(!responser_ptr.expired() && len){
            responser_ptr.lock()->writedcb(responser_index);
        }
        if(rwer->wlength() == 0 && (http_flag & HTTP_WRITE_CLOSE_F)){
            rwer->Shutdown();
        }
    });
}

Guest::Guest(int fd,  const sockaddr_un *myaddr, SSL_CTX* ctx): Requester(myaddr) {
    rwer = new SslRWer(fd, ctx, std::bind(&Guest::Error, this, _1, _2),
    [this](const sockaddr_un&){
        SslRWer* srwer = dynamic_cast<SslRWer*>(rwer);
        const unsigned char *data;
        unsigned int len;
        srwer->get_alpn(&data, &len);
        if ((data && strncasecmp((const char*)data, "h2", len) == 0)) {
            new Guest2(sourceip, sourceport, srwer);
            rwer = nullptr;
            Peer::deleteLater(PEER_LOST_ERR);
        }
    });
    rwer->SetReadCB(std::bind(&Guest::ReadHE, this, _1));
    rwer->SetWriteCB([this](size_t len){
        LOGD(DHTTP, "guest WriteCB %s: wlength:%zu, http_flag:0x%08x\n", getsrc(nullptr), rwer->wlength(), http_flag);
        if(!responser_ptr.expired() && len){
            responser_ptr.lock()->writedcb(responser_index);
        }
        if(rwer->wlength() == 0 && (http_flag & HTTP_WRITE_CLOSE_F)){
            rwer->Shutdown();
        }
    });
}

void Guest::ReqProc(HttpReqHeader* req) {
    LOGD(DHTTP, "guest ReqProc %s: Status:0x%08x\n", getsrc(nullptr), Status_flags);
    assert((Status_flags & GUEST_CONNECT_F) == 0 && (Status_flags & GUEST_SEND_F) == 0);
    assert((Status_flags == GUEST_NONE_F) || (Status_flags & GUEST_REQ_COMPLETED));
    req->index = (void *)1;
    auto res_ptr = distribute(req, responser_ptr);
    if(!res_ptr.expired()){
        if(req->ismethod("CONNECT")){
            Status_flags = GUEST_CONNECT_F;
        }else if(req->ismethod("SEND")){
            Status_flags = GUEST_SEND_F;
        }else{
            Status_flags = GUEST_NONE_F;
        }
        void* res_index = res_ptr.lock()->request(req);
        if(!responser_ptr.expired() && (res_ptr.lock() != responser_ptr.lock() || res_index != responser_index)){
            responser_ptr.lock()->finish(PEER_LOST_ERR, responser_index);
        }
        responser_ptr = res_ptr;
        responser_index = res_index;
    }else{
        delete req;
    }
}

ssize_t Guest::DataProc(const void *buff, size_t size) {
    if (responser_ptr.expired() || (Status_flags & GUEST_ERROR_F)) {
        LOGE("(%s): connecting to host lost or error ocured\n", getsrc(nullptr));
        deleteLater(PEER_LOST_ERR);
        return -1;
    }
    assert((http_flag & HTTP_READ_CLOSE_F) == 0);
    int len = responser_ptr.lock()->bufleft(responser_index);
    len = Min(len, size);
    if (len <= 0) {
        LOGE("(%s): The host's buff is full\n", getsrc(nullptr));
        rwer->delEvents(RW_EVENT::READ);
        return -1;
    }
    responser_ptr.lock()->Send(buff, len, responser_index);
    rx_bytes += len;
    LOGD(DHTTP, "guest DataProc %s: size:%zu, send:%d/%zu\n", getsrc(nullptr), size, len, rx_bytes);
    return len;
}

void Guest::EndProc() {
    LOGD(DHTTP, "guest EndProc %s: status:0x%08x\n", getsrc(nullptr), Status_flags);
    rwer->addEvents(RW_EVENT::READ);
    if(!responser_ptr.expired()){
        responser_ptr.lock()->Send((const void*)nullptr, 0, responser_index);
    }
    Status_flags |= GUEST_REQ_COMPLETED;
}

void Guest::ErrProc() {
    Error(HTTP_PROTOCOL_ERR, 0);
}


void Guest::Error(int ret, int code) {
    LOGD(DHTTP, "guest Error %s: ret:%d, code:%d, http_flag:0x%08x\n", getsrc(nullptr), ret, code, http_flag);
    if(responser_ptr.expired()){
        return deleteLater(ret | DISCONNECT_FLAG);
    }
    if((ret == READ_ERR || ret == SOCKET_ERR) && code == 0){
        if(http_flag & HTTP_READ_CLOSE_F){
            return;
        }
        http_flag |= HTTP_READ_CLOSE_F;
        uint32_t flags = NOERROR;
        if(http_flag & HTTP_WRITE_CLOSE_F){
            flags |= DISCONNECT_FLAG;
        }
        if(responser_ptr.lock()->finish(flags, responser_index) & FINISH_RET_BREAK){
            responser_ptr = std::weak_ptr<Responser>();
            deleteLater(DISCONNECT_FLAG);
        }
        return;
    }
    if(Status_flags != GUEST_NONE_F){
        LOGE("Guest error %s: %d/%d/0x%08x\n", getsrc(nullptr), ret, code, Status_flags);
    }
    deleteLater(ret);
}

void Guest::response(HttpResHeader* res) {
    assert((uint32_t)(long)res->index == 1);
    LOGD(DHTTP, "guest response %s: %s\n", getsrc(nullptr), res->status);
    if(Status_flags & GUEST_CONNECT_F){
        if(memcmp(res->status, "200", 3) == 0){
            strcpy(res->status, "200 Connection established");
            res->del("Transfer-Encoding");
        }
    }else if(Status_flags & GUEST_SEND_F){
        //ignore response
        delete res;
        return;
    }else if(res->get("Transfer-Encoding")){
        Status_flags |= GUEST_CHUNK_F;
    }else if(res->get("Content-Length") == nullptr) {
        Status_flags |= GUEST_NOLENGTH_F;
    }
    size_t len;
    char *buff=res->getstring(len);
    rwer->buffer_insert(rwer->buffer_end(), write_block{buff, len, 0});
    delete res;
}

int32_t Guest::bufleft(void*){
    return 1024*1024 - rwer->wlength();
}


void Guest::Send(void *buff, size_t size, __attribute__ ((unused)) void* index) {
    assert((uint32_t)(long)index == 1);
    assert((http_flag & HTTP_WRITE_CLOSE_F) == 0);
    if(Status_flags & GUEST_CHUNK_F){
        char chunkbuf[100];
        int chunklen = snprintf(chunkbuf, sizeof(chunkbuf), "%x" CRLF, (uint32_t)size);
        buff = p_move(buff, -chunklen);
        memcpy(buff, chunkbuf, chunklen);
        rwer->buffer_insert(rwer->buffer_end(), write_block{buff, (size_t)chunklen+size, 0});
        rwer->buffer_insert(rwer->buffer_end(), write_block{p_strdup(CRLF), strlen(CRLF), 0});
    }else{
        rwer->buffer_insert(rwer->buffer_end(), write_block{buff, size, 0});
    }
    tx_bytes += size;
    if(size == 0){
        LOGD(DHTTP, "guest Send %s: EOF/%zu\n", getsrc(nullptr), tx_bytes);
    }else{
        LOGD(DHTTP, "guest Send %s: size:%zu/%zu\n", getsrc(nullptr), size, tx_bytes);
    }
}

void Guest::transfer(__attribute__ ((unused)) void* index, std::weak_ptr<Responser> res_ptr, void* res_index) {
    LOGD(DHTTP, "guest transfer %s\n", getsrc(nullptr));
    assert(index == responser_index);
    responser_ptr = res_ptr;
    responser_index = res_index;
}

void Guest::deleteLater(uint32_t errcode){
    assert(errcode);
    Status_flags |= GUEST_ERROR_F;
    if(!responser_ptr.expired()){
        assert(responser_index);
        responser_ptr.lock()->finish(errcode, responser_index);
        responser_ptr = std::weak_ptr<Responser>();
        responser_index = nullptr;
    }
    Peer::deleteLater(errcode);
}

int Guest::finish(uint32_t flags, void* index) {
    LOGD(DHTTP, "guest finish %s: flags:0x%08x, status:0x%08x\n", getsrc(nullptr), flags, Status_flags);
    assert((uint32_t)(long)index == 1);
    uint8_t errcode = flags & ERROR_MASK;
    if(errcode || (flags & DISCONNECT_FLAG)){
        responser_ptr = std::weak_ptr<Responser>();
        responser_index = nullptr;
        deleteLater(flags);
        return FINISH_RET_BREAK;
    }
    if(http_flag & HTTP_READ_CLOSE_F){
        deleteLater(DISCONNECT_FLAG);
        return FINISH_RET_BREAK;
    }
    rwer->addEvents(RW_EVENT::READ);
    http_flag |= HTTP_WRITE_CLOSE_F;
    if(rwer->wlength() == 0){
        rwer->Shutdown();
    }
    return FINISH_RET_NOERROR;
}

void Guest::writedcb(const void* index) {
    LOGD(DHTTP, "guest writedcb %s: http_flag:%u, status:0x%08x\n", getsrc(nullptr), http_flag, Status_flags);
    if((http_flag & HTTP_READ_CLOSE_F) == 0){
        Peer::writedcb(index);
    }
}

const char* Guest::getsrc(const void *){
    static char src[DOMAINLIMIT];
    sprintf(src, "[%s]:%d", sourceip, sourceport);
    return src;
}

void Guest::dump_stat(Dumper dp, void* param){
    dp(param, "Guest %p, %s: responser:%p, index:%p\n", this, getsrc(nullptr), responser_ptr.lock().get(), responser_index);
    dp(param, "  rwer: rlength:%zu, rleft:%zu, wlength:%zu, stats:%d, event:%s\n",
            rwer->rlength(), rwer->rleft(), rwer->wlength(),
            (int)rwer->getStats(), events_string[(int)rwer->getEvents()]);
}
