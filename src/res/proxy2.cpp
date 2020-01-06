#include "proxy2.h"
#include "req/requester.h"
#include "misc/util.h"
#include "misc/config.h"

#include <assert.h>

std::weak_ptr<Proxy2> proxy2;


void Proxy2::connection_lost(){
    LOGE("<proxy2> %p the ping timeout, so close it\n", this);
    deleteLater(PEER_LOST_ERR);
}

void Proxy2::ping_check(){
    char buff[8];
    set64(buff, getutime());
    Ping(buff);
    LOGD(DHTTP2, "<proxy2> ping: window size global: %d/%d\n", localwinsize, remotewinsize);
    connection_lost_job = rwer->updatejob( connection_lost_job, std::bind(&Proxy2::connection_lost, this), 10000);
}

Proxy2::Proxy2(RWer* rwer) {
    this->rwer = rwer;
    if(proxy2.expired()){
        proxy2 = std::dynamic_pointer_cast<Proxy2>(shared_from_this());
    }
    rwer->SetErrorCB(std::bind(&Proxy2::Error, this, _1, _2));
    rwer->SetReadCB([this](size_t len){
        const char* data = this->rwer->rdata();
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
        this->ping_check_job = this->rwer->updatejob(
                this->ping_check_job,
                std::bind(&Proxy2::ping_check, this), 30000);
#else
        receive_time = getmtime();
#endif
        if(!proxy2.expired() && proxy2.lock() != shared_from_this() && statusmap.empty()){
            LOG("this is not the proxy2 and no clients, close it.\n");
            deleteLater(PEER_LOST_ERR);
        }
    });
    rwer->SetWriteCB([this](size_t){
        auto statusmap_copy = statusmap;
        for(auto& i: statusmap_copy){
            ReqStatus& status = i.second;
            assert(!status.req_ptr.expired());
            if(status.remotewinsize > 0){
                status.req_ptr.lock()->writedcb(status.req_index);
            }
        }
    });
#ifdef __ANDROID__
    receive_time = getmtime();
    ping_time = getmtime();
#endif
}


Proxy2::~Proxy2() {
}

void Proxy2::Error(int ret, int code) {
    if((ret == READ_ERR || ret == SOCKET_ERR) && code == 0){
        return deleteLater(PEER_LOST_ERR);
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

void Proxy2::Send(const void* buff, size_t size, void* index) {
    uint32_t id = (uint32_t)(long)index;
    assert(statusmap.count(id));
    ReqStatus& status = statusmap[id];
    assert(!status.req_ptr.expired());
    assert((status.req_flags & STREAM_WRITE_ENDED) == 0);
    assert((status.req_flags & STREAM_WRITE_CLOSED) == 0);
    status.remotewinsize -= size;
    remotewinsize -= size;
    assert(status.remotewinsize >= 0);
    PushData(id, buff, size);
    if(size == 0){
        status.req_flags |= STREAM_WRITE_ENDED;
        LOGD(DHTTP2, "<Proxy2> send data [%d]: EOF/%d\n", id, status.remotewinsize);
        if(status.req_flags & STREAM_READ_ENDED){
            rwer->addjob(std::bind([](std::weak_ptr<Requester> req_ptr, void* index) {
                if(!req_ptr.expired()){
                    req_ptr.lock()->finish(NOERROR | DISCONNECT_FLAG, index);
                }
            }, status.req_ptr, status.req_index), 0, JOB_FLAGS_AUTORELEASE);
            statusmap.erase(id);
        }
    }else{
        LOGD(DHTTP2, "<proxy2> send data [%d]: %zu/%d\n", id, size, status.remotewinsize);
    }
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
        if(!res->no_body() && !res->get("Content-Length"))
        {
            res->set("Transfer-Encoding", "chunked");
        }
        res->index = status.req_index;  //change back to req's id
        assert(!status.req_ptr.expired());
        status.req_ptr.lock()->response(res);
    }else{
        delete res;
        LOGD(DHTTP2, "<proxy2> ResProc not found id: %d\n", id);
        Reset(id, ERR_STREAM_CLOSED);
    }
}


void Proxy2::DataProc(uint32_t id, const void* data, size_t len) {
    if(len == 0)
        return;
    localwinsize -= len;
    if(statusmap.count(id)){
        ReqStatus& status = statusmap[id];
        assert((status.req_flags & STREAM_READ_ENDED) == 0);
        assert((status.req_flags & STREAM_READ_CLOSED) == 0);
        assert(!status.req_ptr.expired());
        auto requester = status.req_ptr.lock();
        if(len > (size_t)status.localwinsize){
            Reset(id, ERR_FLOW_CONTROL_ERROR);
            LOGE("(%s) :<proxy2> [%d] window size error %zu/%d\n",
                requester->getsrc(status.req_index), id, len, status.localwinsize);
            requester->finish(ERR_FLOW_CONTROL_ERROR, status.req_index);
            statusmap.erase(id);
            return;
        }
        requester->Send(data, len, status.req_index);
        status.localwinsize -= len;
    }else{
        LOGD(DHTTP2, "<proxy2> DataProc not found id: %d\n", id);
        Reset(id, ERR_STREAM_CLOSED);
    }
}

void Proxy2::EndProc(uint32_t id) {
    LOGD(DHTTP2, "<proxy2> [%d]: end of stream\n", id);
    if(statusmap.count(id)) {
        ReqStatus &status = statusmap[id];
        assert(!status.req_ptr.expired());
        assert((status.req_flags & STREAM_READ_CLOSED) == 0);
        if((status.req_flags & STREAM_READ_ENDED) == 0) {
            status.req_flags |= STREAM_READ_ENDED;
            status.req_ptr.lock()->Send((const void *) nullptr, 0, status.req_index);
        }
        if(status.req_flags & STREAM_WRITE_ENDED){
            status.req_ptr.lock()->finish(NOERROR | DISCONNECT_FLAG, status.req_index);
            statusmap.erase(id);
        }
    }
}


void Proxy2::ErrProc(int errcode) {
    LOGE("Proxy2 Http2 error: 0x%08x\n", errcode);
    deleteLater(errcode);
}

void Proxy2::RstProc(uint32_t id, uint32_t errcode) {
    if(statusmap.count(id)){
        ReqStatus& status = statusmap[id];
        assert(!status.req_ptr.expired());
        if(errcode){
            LOGE("(%s) <proxy2> [%d]: stream reseted: %d\n",
                 status.req_ptr.lock()->getsrc(status.req_index), id, errcode);
        }
        status.req_ptr.lock()->finish(errcode | DISCONNECT_FLAG, status.req_index);
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
            assert(!status.req_ptr.expired());
            status.req_ptr.lock()->writedcb(status.req_index);
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
            auto statusmap_copy = statusmap;
            for(auto& i: statusmap_copy){
                ReqStatus& status = i.second;
                assert(!status.req_ptr.expired());
                if(status.remotewinsize > 0){
                    status.req_ptr.lock()->writedcb(status.req_index);
                }
            }
        }
    }
}

void Proxy2::PingProc(const Http2_header *header){
    if(header->flags & ACK_F){
        rwer->deljob(&connection_lost_job);
        double diff = (getutime()-get64(header+1))/1000.0;
        LOG("<Proxy2> Get a ping time=%.3fms\n", diff);
        if(diff >= 5000){
            LOGE("<Proxy2> The ping time too long!\n");
        }
    }
    Http2Base::PingProc(header);
}

void Proxy2::ShutdownProc(uint32_t id) {
    if(statusmap.count(id) == 0){
        return;
    }
    LOGD(DHTTP2, "<proxy2> get shutdown frame from frame %d\n", id);
    ReqStatus& status = statusmap[id];
    status.req_flags |= STREAM_READ_CLOSED;
    if(status.req_ptr.lock()->finish(NOERROR, status.req_index) & FINISH_RET_BREAK){
        Reset(id, PEER_LOST_ERR);
        statusmap.erase(id);
    }
}

void* Proxy2::request(HttpReqHeader* req) {
    assert(!req->src.expired() && req->index);
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

std::weak_ptr<Proxy2> Proxy2::init(HttpReqHeader* req) {
    if(req){
        assert(!req->src.expired() && req->index);
        //we should clear all pending buffer in rwer later, so save it first
        std::queue<write_block> cached;
        for(auto i = rwer->buffer_head() ; i!= rwer->buffer_end(); i++){
            assert(i->offset == 0);
            assert(i->buff);
            cached.push(*i);
        }
        LOGD(DHTTP2, "<proxy2> resend %zd blocks from host\n", cached.size());
        rwer->Clear(false);
        Http2Requster::init();
        auto  req_ptr = req->src.lock();
        void*  req_index = req->index;
        void* index = request(req);
        req_ptr->transfer(req_index, std::dynamic_pointer_cast<Responser>(shared_from_this()), index);
        while(!cached.empty()){
            auto i = cached.front();
            Send(i.buff, i.len, index);
            cached.pop();
        }
    }else{
        rwer->Clear(true);
        Http2Requster::init();
    }
    return std::dynamic_pointer_cast<Proxy2>(shared_from_this());
}


void Proxy2::GoawayProc(const Http2_header* header){
    Goaway_Frame* goaway = (Goaway_Frame *)(header+1);
    uint32_t errcode = get32(goaway->errcode);
    http2_flag |= HTTP2_FLAG_GOAWAYED;
    return deleteLater(errcode | DISCONNECT_FLAG);
}


void Proxy2::AdjustInitalFrameWindowSize(ssize_t diff) {
    for(auto& i: statusmap){
        i.second.remotewinsize += diff;
    }
}

std::list<write_block>::insert_iterator Proxy2::queue_head() {
    return rwer->buffer_head();
}

std::list<write_block>::insert_iterator Proxy2::queue_end() {
    return rwer->buffer_end();
}

void Proxy2::queue_insert(std::list<write_block>::insert_iterator where, const write_block& wb) {
    rwer->buffer_insert(where, wb);
}


int Proxy2::finish(uint32_t flags, void* index) {
    uint32_t id = (uint32_t)(long)index;
    LOGD(DHTTP2, "<proxy2> finish flags:0x%08x, id:%u\n", flags, id);
    ReqStatus& status = statusmap[id];
    uint8_t errcode = flags & ERROR_MASK;
    if(errcode || (flags & DISCONNECT_FLAG) || (status.req_flags & STREAM_READ_CLOSED)){
        Reset(id, errcode>30?ERR_INTERNAL_ERROR:errcode);
        statusmap.erase(id);
        return FINISH_RET_BREAK;
    }
    assert((status.req_flags & STREAM_WRITE_CLOSED) == 0);
    status.req_flags |= STREAM_WRITE_CLOSED;
    if(http2_flag & HTTP2_SUPPORT_SHUTDOWN) {
        LOGD(DHTTP2, "<proxy2> send shutdown frame: %d\n", id);
        Shutdown(id);
        return FINISH_RET_NOERROR;
    }else{
        LOGD(DHTTP2, "<proxy2> send reset frame: %d\n", id);
        Reset(id, ERR_CANCEL);
        statusmap.erase(id);
        return FINISH_RET_BREAK;
    }
}

void Proxy2::deleteLater(uint32_t errcode){
    if(!proxy2.expired() && proxy2.lock() == shared_from_this()){
        proxy2 = std::weak_ptr<Proxy2>();
    }
    for(auto& i: statusmap){
        assert(!i.second.req_ptr.expired());
        i.second.req_ptr.lock()->finish(errcode, i.second.req_index);
    }
    statusmap.clear();
    if((http2_flag & HTTP2_FLAG_GOAWAYED) == 0){
        http2_flag |= HTTP2_FLAG_GOAWAYED;
        Goaway(-1, errcode);
    }
    Peer::deleteLater(errcode);
}

void Proxy2::writedcb(const void* index){
    uint32_t id = (uint32_t)(long)index;
    if(statusmap.count(id)){
        ReqStatus& status = statusmap[id];
        assert(!status.req_ptr.expired());
        auto len = status.req_ptr.lock()->bufleft(status.req_index);
        if(len > status.localwinsize && (len - status.localwinsize > FRAMEBODYLIMIT)) {
            status.localwinsize += ExpandWindowSize(id, len - status.localwinsize);
        }
    }
}

void Proxy2::dump_stat(Dumper dp, void* param) {
    if(proxy2.expired()){
        dp(param, "Proxy2 %p, id:%d\n", this, sendid);
    }else{
        dp(param, "Proxy2 %p, id:%d: %s\n", this, sendid, proxy2.lock() == shared_from_this()?"[M]":"");
    }
    dp(param, "  rwer: rlength:%zu, rleft:%zu, wlength:%zu, stats:%d, event:%s\n",
            rwer->rlength(), rwer->rleft(), rwer->wlength(),
            (int)rwer->getStats(), events_string[(int)rwer->getEvents()]);
    for(auto& i: statusmap){
        assert(!i.second.req_ptr.expired());
        dp(param, "0x%x: %p, %p (%d/%d)\n",
            i.first, i.second.req_ptr.lock().get(), i.second.req_index,
            i.second.remotewinsize, i.second.localwinsize);
    }
}

void Proxy2::flush() {
    if(!rwer->supportReconnect()){
        proxy2 = std::weak_ptr<Proxy2>();
    }
}


void flushproxy2(int force) {
    if(force){
        proxy2 = std::weak_ptr<Proxy2>();
        return;
    }
    if(!proxy2.expired()){
        proxy2.lock()->flush();
    }
}
