#include "proxy2.h"
#include "req/requester.h"
#include "misc/job.h"
#include "misc/util.h"

#include <assert.h>

Proxy2* proxy2 = nullptr;


int Proxy2::connection_lost(){
    LOGE("<proxy2> %p the ping timeout, so close it\n", this);
    deleteLater(PEER_LOST_ERR);
    return 0;
}

int Proxy2::ping_check(){
    char buff[8];
    set64(buff, getutime());
    Ping(buff);
    LOGD(DHTTP2, "<proxy2> ping: window size global: %d/%d\n", localwinsize, remotewinsize);
    add_delayjob(std::bind(&Proxy2::connection_lost, this), this, 10000);
    return 0;
}

Proxy2::Proxy2(RWer* rwer) {
    this->rwer = rwer;
    if(proxy2 == nullptr){
        proxy2 = this;
    }
    rwer->SetErrorCB(std::bind(&Proxy2::Error, this, _1, _2));
    rwer->SetReadCB([this](size_t len){
        const char* data = this->rwer->data();
        size_t consumed = 0;
        size_t ret = 0;
        while((ret = (this->*Http2_Proc)((uchar*)data+consumed, len-consumed))){
            consumed += ret;
        }
        if((http2_flag & HTTP2_FLAG_INITED) && localwinsize < 50 *1024 *1024){
            localwinsize += ExpandWindowSize(0, 50*1024*1024);
        }
        this->rwer->consume(data, consumed);
#ifndef __ANDROID__
        add_delayjob(std::bind(&Proxy2::ping_check, this), this, 30000);
#else
        receive_time = getmtime();
#endif
        if(proxy2 != this && statusmap.empty()){
            LOG("this is not the proxy2 and no clients, close it.\n");
            deleteLater(PEER_LOST_ERR);
        }
    });
    rwer->SetWriteCB([this](size_t){
        for(auto i: statusmap){
            ReqStatus& status = i.second;
            if(status.remotewinsize > 0){
                status.req_ptr->writedcb(status.req_index);
            }
        }
    });
#ifdef __ANDROID__
    receive_time = getmtime();
    ping_time = getmtime();
#endif
}


Proxy2::~Proxy2() {
    del_delayjob(std::bind(&Proxy2::ping_check, this), this);
    del_delayjob(std::bind(&Proxy2::connection_lost, this), this);
    proxy2 = (proxy2 == this) ? nullptr: proxy2;
}

void Proxy2::Error(int ret, int code) {
    if((ret == READ_ERR || ret == SOCKET_ERR) && code == 0){
        deleteLater(PEER_LOST_ERR);
        return;
    }
    LOGE("proxy2 error: %d/%d\n", ret, code);
    deleteLater(ret);
}


int32_t Proxy2::bufleft(void* index) {
    int32_t globalwindow = Min(1024*1024 - rwer->wlength(), this->remotewinsize);
    if(index)
        return Min(statusmap.at((uint32_t)(long)index).remotewinsize, globalwindow);
    else
        return globalwindow;
}

ssize_t Proxy2::Send(void* buff, size_t size, void* index) {
    uint32_t id = (uint32_t)(long)index;
    assert(statusmap.count(id));
    assert((statusmap[id].req_flags & STREAM_WRITE_CLOSED) == 0);
    size = Min(size, FRAMEBODYLIMIT);
    Http2_header *header=(Http2_header *)p_move(buff, -(char)sizeof(Http2_header));
    memset(header, 0, sizeof(Http2_header));
    set32(header->id, id);
    set24(header->length, size);
    if(size == 0) {
        LOGD(DHTTP2, "<proxy2> [%d]: set stream end\n", id);
        header->flags = END_STREAM_F;
    }
    PushFrame(header);
    this->remotewinsize -= size;
    statusmap[id].remotewinsize -= size;
    return size;
}

void Proxy2::PushFrame(Http2_header *header){
#ifdef __ANDROID__
    uint32_t now = getmtime();
    if(http2_flag & HTTP2_FLAG_INITED
        && now - receive_time >=30000
        && now - ping_time >=5000)
    {
        ping_time = now;
        ping_check();
    }
#endif
    return Http2Base::PushFrame(header);
}

void Proxy2::ResProc(HttpResHeader* res) {
    uint32_t id = (uint32_t)(long)res->index;
    if(statusmap.count(id)){
        ReqStatus& status = statusmap[id];
        if(!res->no_body() && res->status[0] != '1' &&  //1xx should not have body
           !res->get("Content-Length"))
        {
            res->add("Transfer-Encoding", "chunked");
        }
        res->index = status.req_index;  //change back to req's id
        status.req_ptr->response(res);
    }else{
        delete res;
        LOGD(DHTTP2, "<proxy2> ResProc not found id: %d\n", id);
        Reset(id, ERR_STREAM_CLOSED);
    }
}


void Proxy2::DataProc(uint32_t id, const void* data, size_t len) {
    if( len == 0)
        return;
    localwinsize -= len;
    if(statusmap.count(id)){
        ReqStatus& status = statusmap[id];
        assert((status.req_flags & STREAM_READ_CLOSED) == 0);
        Requester* requester = status.req_ptr;
        if(len > (size_t)status.localwinsize){
            Reset(id, ERR_FLOW_CONTROL_ERROR);
            LOGE("(%s) :<proxy2> [%d] window size error\n", requester->getsrc(status.req_index), id);
            requester->finish(ERR_FLOW_CONTROL_ERROR, status.req_index);
            statusmap.erase(id);
            return;
        }
        size_t sended = 0;
        while(sended != len){
            sended += requester->Send((const char*)data + sended, len - sended, status.req_index);
        }
        status.localwinsize -= len;
    }else{
        LOGD(DHTTP2, "<proxy2> DataProc not found id: %d\n", id);
        Reset(id, ERR_STREAM_CLOSED);
    }
}

void Proxy2::EndProc(uint32_t id){
    LOGD(DHTTP2, "<proxy2> [%d]: end of stream\n", id);
    if(statusmap.count(id)) {
        ReqStatus &status = statusmap[id];
        if(status.req_flags & STREAM_WRITE_CLOSED){
            status.req_ptr->finish(NOERROR | DISCONNECT_FLAG, status.req_index);
            statusmap.erase(id);
        }else{
            status.req_ptr->finish(NOERROR, status.req_index);
            status.req_flags |= STREAM_READ_CLOSED;
        }
    }
}


void Proxy2::ErrProc(int errcode) {
    LOGE("Proxy2 Http2 error: %d\n", errcode);
    deleteLater(ERR_INTERNAL_ERROR);
}

void Proxy2::RstProc(uint32_t id, uint32_t errcode) {
    if(statusmap.count(id)){
        ReqStatus& status = statusmap[id];
        if(errcode){
            LOGE("(%s) <proxy2> [%d]: stream reseted: %d\n",
                 status.req_ptr->getsrc(status.req_index), id, errcode);
        }
        status.req_ptr->finish(errcode?errcode:PEER_LOST_ERR, status.req_index);
        statusmap.erase(id);
    }
}

void Proxy2::WindowUpdateProc(uint32_t id, uint32_t size){
    if(id){
        if(statusmap.count(id)){
            ReqStatus& status = statusmap[id];
            LOGD(DHTTP2, "<proxy2> window size updated [%d]: %d+%d\n", id, status.remotewinsize, size);
            if((uint64_t)status.remotewinsize + size >= (uint64_t)1<<31){
                Reset(id, ERR_FLOW_CONTROL_ERROR);
                return;
            }
            status.remotewinsize += size;
            status.req_ptr->writedcb(status.req_index);
        }else{
            LOGD(DHTTP2, "<proxy2> window size updated [%d]: not found\n", id);
        }
    }else{
        LOGD(DHTTP2, "<proxy2> window size updated global: %d+%d\n", remotewinsize, size);
        if((uint64_t)remotewinsize + size >= (uint64_t)1<<31){
            ErrProc(ERR_FLOW_CONTROL_ERROR);
            return;
        }
        remotewinsize += size;
        if(remotewinsize == (int32_t)size){
            LOGD(DHTTP2, "<proxy2> active all frame\n");
            for(auto i: statusmap){
                ReqStatus& status = i.second;
                if(status.remotewinsize > 0){
                    status.req_ptr->writedcb(status.req_index);
                }
            }
        }
    }
}

void Proxy2::PingProc(const Http2_header *header){
    if(header->flags & ACK_F){
        del_delayjob(std::bind(&Proxy2::connection_lost, this), this);
        double diff = (getutime()-get64(header+1))/1000.0;
        LOG("<Proxy2> Get a ping time=%.3fms\n", diff);
        if(diff >= 5000){
            LOGE("<Proxy2> The ping time too long!\n");
        }
    }
    Http2Base::PingProc(header);
}

void* Proxy2::request(HttpReqHeader* req) {
    assert(req->src && req->index);
    uint32_t id = GetSendId();
    statusmap[id] = ReqStatus{
       req->src,
       req->index,
       (int32_t)remoteframewindowsize,
       localframewindowsize,
       0,
    };
    void *index =reinterpret_cast<void*>(id);  //change to proxy server's id
    req->index = index;
    PushFrame(req->getframe(&request_table, id));
    delete req;
    return index;
}

void Proxy2::init(HttpReqHeader* req) {
    if(req){
        assert(req->src && req->index);
        std::queue<write_block> cached;
        for(auto i = rwer->buffer_head() ; i!= rwer->buffer_end(); i++){
            assert(i->wlen == 0);
            assert(i->buff);
            cached.push(*i);
        }
        rwer->Clear(false);
        Http2Requster::init();
        Requester* req_ptr = req->src;
        void*      req_index = req->index;
        void* index = request(req);
        req_ptr->transfer(req_index, this, index);
        while(!cached.empty()){
            auto i = cached.front();
            Send(i.buff, i.len, index);
            cached.pop();
        }
    }else{
        rwer->Clear(true);
        Http2Requster::init();
    }
}


void Proxy2::GoawayProc(const Http2_header* header){
    Goaway_Frame* goaway = (Goaway_Frame *)(header+1);
    uint32_t errcode = get32(goaway->errcode);
    http2_flag |= HTTP2_FLAG_GOAWAYED;
    return deleteLater(errcode | DISCONNECT_FLAG);
}


void Proxy2::AdjustInitalFrameWindowSize(ssize_t diff) {
    for(auto i: statusmap){
       i.second.remotewinsize += diff;
    }
}

std::list<write_block>::insert_iterator Proxy2::queue_head() {
    return rwer->buffer_head();
}

std::list<write_block>::insert_iterator Proxy2::queue_end() {
    return rwer->buffer_end();
}

void Proxy2::queue_insert(std::list<write_block>::insert_iterator where, void* buff, size_t len) {
    rwer->buffer_insert(where, buff, len);
}


void Proxy2::finish(uint32_t flags, void* index) {
    uint32_t id = (uint32_t)(long)index;
    assert(statusmap.count(id));
    ReqStatus& status = statusmap[id];
    uint8_t errcode = flags & ERROR_MASK;
    if(errcode == 0 ){
        if((status.req_flags & STREAM_WRITE_CLOSED) == 0){
            Peer::Send((const void*)nullptr, 0, index);
            status.req_flags |= STREAM_WRITE_CLOSED;
        }
        if((flags & DISCONNECT_FLAG) && (status.req_flags & STREAM_READ_CLOSED)){
            statusmap.erase(id);
            return;
        }
    }
    if(errcode || (flags & DISCONNECT_FLAG)){
        Reset(id, errcode>30?ERR_INTERNAL_ERROR:errcode);
        statusmap.erase(id);
    }
}

void Proxy2::deleteLater(uint32_t errcode){
    proxy2 = (proxy2 == this) ? nullptr: proxy2;
    for(auto i: statusmap){
        i.second.req_ptr->finish(errcode, i.second.req_index);
    }
    statusmap.clear();
    if((http2_flag & HTTP2_FLAG_GOAWAYED) == 0){
        http2_flag |= HTTP2_FLAG_GOAWAYED;
        Goaway(-1, errcode);
    }
    Peer::deleteLater(errcode);
}

void Proxy2::writedcb(void* index){
    uint32_t id = (uint32_t)(long)index;
    if(statusmap.count(id)){
        ReqStatus& status = statusmap[id];
        auto len = status.req_ptr->bufleft(status.req_index);
        if(len <= status.localwinsize ||
           (len - status.localwinsize < FRAMEBODYLIMIT &&
            status.localwinsize >= FRAMEBODYLIMIT))
            return;
        status.localwinsize += ExpandWindowSize(id, len - status.localwinsize);
    }
}

void Proxy2::dump_stat(Dumper dp, void* param) {
    dp(param, "Proxy2 %p, id:%d: %s\n", this, sendid, this==proxy2?"[M]":"");
    for(auto i: statusmap){
        dp(param, "0x%x: %p, %p (%d/%d)\n",
            i.first, i.second.req_ptr, i.second.req_index,
            i.second.remotewinsize, i.second.localwinsize);
    }
}

void Proxy2::flush() {
    if(!rwer->supportReconnect()){
        proxy2 = (proxy2 == this) ? nullptr: proxy2;
    }
}


void flushproxy2(bool force) {
    if(force){
        proxy2 = nullptr;
        return;
    }
    if(proxy2){
        proxy2->flush();
    }
}
