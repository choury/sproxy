#include "guest.h"
#include "guest2.h"
#include "misc/net.h"
#include "res/responser.h"
#include "misc/util.h"
#include "misc/sslio.h"

#include <string.h>
#include <assert.h>
#include <inttypes.h>

void Guest::ReadHE(size_t len){
    const char* data = rwer->rdata();
    size_t consumed = 0;
    size_t ret = 0;
    while((ret = (this->*Http_Proc)(data+consumed, len-consumed))){
        consumed += ret;
    }
    LOGD(DHTTP, "guest %s read: len:%zu, consumed:%zu\n", getsrc(), len, consumed);
    rwer->consume(data, consumed);
}

void Guest::WriteHE(size_t len){
    if(statuslist.empty()){
        return;
    }
    GStatus& status = statuslist.front();
    LOGD(DHTTP, "guest %s written: wlength:%zu, flags:0x%08x\n", getsrc(), rwer->wlength(), status.flags);
    if(status.flags & HTTP_RES_EOF){
        if(rwer->wlength() == 0){
            rwer->Shutdown();
        }
        return;
    }
    if((status.flags&HTTP_REQ_COMPLETED) && (status.flags&HTTP_RES_COMPLETED)){
        return deqReq();
    }
    if((status.flags & HTTP_RES_COMPLETED) || (status.flags & HTTP_RES_EOF)){
        return;
    }
    if(len && status.res){
        status.res->more();
    }
}

Guest::Guest(int fd):
    Requester(new StreamRWer(fd, std::bind(&Guest::Error, this, _1, _2)))
{
    rwer->SetReadCB(std::bind(&Guest::ReadHE, this, _1));
    rwer->SetWriteCB(std::bind(&Guest::WriteHE, this, _1));
}

Guest::Guest(int fd, SSL_CTX* ctx):
    Requester(new SslRWer(fd, ctx, std::bind(&Guest::Error, this, _1, _2),
    [this](const sockaddr_un&){
        SslRWer* srwer = dynamic_cast<SslRWer*>(rwer);
        const unsigned char *data;
        unsigned int len;
        srwer->get_alpn(&data, &len);
        if ((data && strncasecmp((const char*)data, "h2", len) == 0)) {
            new Guest2(srwer);
            rwer = nullptr;
            assert(statuslist.empty());
            return Server::deleteLater(NOERROR);
        }
    }))
{
    rwer->SetReadCB(std::bind(&Guest::ReadHE, this, _1));
    rwer->SetWriteCB(std::bind(&Guest::WriteHE, this, _1));
}

void Guest::ReqProc(HttpReqHeader* header) {
    LOGD(DHTTP, "guest ReqProc %" PRIu64 " %s\n", header->request_id, header->geturl().c_str());
    HttpReq *req = new HttpReq(header,
            std::bind(&Guest::response, this, nullptr, _1),
            std::bind(&RWer::EatReadData, rwer));

    statuslist.emplace_back(GStatus{req, nullptr, 0});
    if(statuslist.size() == 1){
        distribute(req, this);
    }
}

void Guest::deqReq() {
    GStatus& status = statuslist.front();
    if((status.flags & HTTP_CLOSED_F) == 0) {
        status.req->trigger(Channel::CHANNEL_CLOSED);
    }
    delete status.req;
    delete status.res;
    statuslist.pop_front();

    if(!statuslist.empty()){
        distribute(statuslist.front().req, this);
    }
}

ssize_t Guest::DataProc(const void *buff, size_t size) {
    GStatus& status = statuslist.back();
    assert((status.flags & HTTP_REQ_EOF) == 0);
    assert((status.flags & HTTP_REQ_COMPLETED) == 0);
    int len = status.req->cap();
    len = Min(len, size);
    if (len <= 0) {
        LOGE("The host's buff is full (%" PRIu64 ")\n", status.req->header->request_id);
        rwer->delEvents(RW_EVENT::READ);
        return -1;
    }
    status.req->send(buff, len);
    rx_bytes += len;
    LOGD(DHTTP, "guest DataProc %" PRIu64 ": size:%zu, send:%d/%zu\n", status.req->header->request_id, size, len, rx_bytes);
    return len;
}

void Guest::EndProc() {
    GStatus& status = statuslist.back();
    LOGD(DHTTP, "guest EndProc %" PRIu64 "\n", status.req->header->request_id);
    rwer->addEvents(RW_EVENT::READ);
    status.req->send((const void*)nullptr, 0);
    if(status.flags & HTTP_RES_COMPLETED){
        deqReq();
    }else{
        status.flags |= HTTP_REQ_COMPLETED;
    }
}

void Guest::ErrProc() {
    Error(HTTP_PROTOCOL_ERR, 0);
}

void Guest::Error(int ret, int code) {
    if(statuslist.empty()){
        return deleteLater(PEER_LOST_ERR);
    }
    GStatus& status = statuslist.back();
    LOGD(DHTTP, "guest Error %" PRIu64 ": ret:%d, code:%d, http_flag:0x%08x\n",
            status.req->header->request_id, ret, code, http_flag);
    if((ret == READ_ERR || ret == SOCKET_ERR) && code == 0 && (status.flags & HTTP_CLOSED_F) == 0){
        //EOF
        status.flags |= HTTP_REQ_EOF;
        if((status.flags & HTTP_RES_EOF)
            || status.req->header->ismethod("PING")
            || status.req->header->ismethod("SEND"))
        {
            deleteLater(NOERROR);
        }else{
            status.req->trigger(Channel::CHANNEL_SHUTDOWN);
        }
        return;
    }
    LOGE("Guest error <%s> %" PRIu64 " %d/%d\n",
            getsrc(), status.req->header->request_id, ret, code);
    deleteLater(ret);
}

void Guest::response(void*, HttpRes* res) {
    GStatus& status = statuslist.front();
    HttpLog(getsrc(), status.req, res);
    status.res = res;
    if(status.req->header->ismethod("CONNECT")){
        if(memcmp(res->header->status, "200", 3) == 0){
            strcpy(res->header->status, "200 Connection established");
            res->header->del("Transfer-Encoding");
        }
    }else if(res->header->get("Transfer-Encoding")){
        status.flags |= HTTP_CHUNK_F;
    }else if(res->header->get("Content-Length") == nullptr) {
        status.flags |= HTTP_NOLENGTH_F;
    }
    size_t len;
    char *buff = res->header->getstring(len);
    rwer->buffer_insert(rwer->buffer_end(), write_block{buff, len, 0});
    res->setHandler([this, &status](Channel::signal s){
        LOGD(DHTTP, "guest signal %" PRIu64 ": %d\n", status.req->header->request_id, (int)s);
        switch(s) {
        case Channel::CHANNEL_SHUTDOWN:
            assert((status.flags & HTTP_REQ_EOF) == 0);
            status.flags |= HTTP_RES_EOF;
            rwer->addEvents(RW_EVENT::READ);
            if (rwer->wlength() == 0) {
                rwer->Shutdown();
            }
            break;
        case Channel::CHANNEL_CLOSED:
        case Channel::CHANNEL_ABORT:
            status.flags |= HTTP_CLOSED_F;
            if ((status.flags & HTTP_REQ_COMPLETED) && (status.flags & HTTP_RES_COMPLETED)) {
                //deque in write callback
                return;
            }
            return deleteLater(PEER_LOST_ERR);
        }
    });
    res->attach(std::bind(&Guest::Send, this, _1, _2), [this]{ return 1024*1024 - rwer->wlength(); });
}

void Guest::Send(void *buff, size_t size) {
    GStatus& status = statuslist.front();
    assert((status.flags & HTTP_RES_EOF) == 0);
    assert((status.flags & HTTP_RES_COMPLETED) == 0);
    if(status.flags & HTTP_CHUNK_F){
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
        status.flags |= HTTP_RES_COMPLETED;
        LOGD(DHTTP, "guest Send %" PRIu64 ": EOF/%zu\n", status.req->header->request_id, tx_bytes);
    }else{
        LOGD(DHTTP, "guest Send %" PRIu64 ": size:%zu/%zu\n", status.req->header->request_id, size, tx_bytes);
    }
}

void Guest::deleteLater(uint32_t errcode){
    for(auto& status: statuslist){
        if((status.flags & HTTP_CLOSED_F) == 0){
            status.req->trigger(errcode ? Channel::CHANNEL_ABORT : Channel::CHANNEL_CLOSED);
        }
        status.flags |= HTTP_CLOSED_F;
    }
    Server::deleteLater(errcode);
}

Guest::~Guest() {
    for(auto& status: statuslist){
        delete status.req;
        delete status.res;
    }
    statuslist.clear();
}

void Guest::dump_stat(Dumper dp, void* param){
    dp(param, "Guest %p, %s\n", this, getsrc());
    dp(param, "  rwer: rlength:%zu, rleft:%zu, wlength:%zu, stats:%d, event:%s\n",
            rwer->rlength(), rwer->rleft(), rwer->wlength(),
            (int)rwer->getStats(), events_string[(int)rwer->getEvents()]);
    for(auto status : statuslist){
        dp(param, "req [%" PRIu64 "]: %s %s [%d] [%s]\n",
                status.req->header->request_id,
                status.req->header->method,
                status.req->header->geturl().c_str(),
                status.flags,
                status.req->header->get("User-Agent"));
    }
}
