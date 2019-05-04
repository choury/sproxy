#include "guest2.h"
#include "res/responser.h"
#include "misc/job.h"
#include "misc/util.h"

#include <assert.h>

int Guest2::connection_lost(){
    LOGE("(%s): <guest2> Nothing got too long, so close it\n", getsrc(nullptr));
    deleteLater(PEER_LOST_ERR);
    return 0;
}

void Guest2::init(RWer* rwer) {
    this->rwer = rwer;
    rwer->SetErrorCB(std::bind(&Guest2::Error, this, _1, _2));
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
        add_delayjob(std::bind(&Guest2::connection_lost, this), this, 1800000);
    });
    rwer->SetWriteCB([this](size_t){
        for(auto& i: statusmap){
            ResStatus& status = i.second;
            assert(!status.res_ptr.expired());
            if(status.remotewinsize > 0){
                status.res_ptr.lock()->writedcb(status.res_index);
            }
        }
    });
}


Guest2::Guest2(const char* ip, uint16_t port, RWer* rwer): Requester(ip, port) {
    init(rwer);
}

Guest2::Guest2::Guest2(const sockaddr_un* addr, RWer* rwer):Requester(addr) {
    init(rwer);
}


Guest2::~Guest2() {
    del_delayjob(std::bind(&Guest2::connection_lost, this), this);
}

void Guest2::Error(int ret, int code){
    if((ret == READ_ERR || ret == SOCKET_ERR) && code == 0){
        deleteLater(NOERROR | DISCONNECT_FLAG);
        return;
    }
    LOGE("guest2 error: %d/%d\n", ret, code);
    deleteLater(ret);
}

int32_t Guest2::bufleft(void* index) {
    int32_t globalwindow = Min(1024*1024 - rwer->wlength(), this->remotewinsize);
    if(index){
        assert(statusmap.count((uint32_t)(long)index));
        return Min(statusmap[(uint32_t)(long)index].remotewinsize, globalwindow);
    }else
        return globalwindow;
}

void Guest2::Send(const void* buff, size_t size, void* index){
    uint32_t id = (uint32_t)(long)index;
    if(statusmap.count(id)){
        ResStatus& status = statusmap[id];
        assert((status.res_flags & STREAM_WRITE_CLOSED) == 0);
        status.remotewinsize -= size;
        assert(status.remotewinsize >= 0);
        LOGD(DHTTP2, "<guest2> send data [%d]: %zu/%d\n", id, size, status.remotewinsize);
    }
    remotewinsize -= size;
    PushData(id, buff, size);
}

void Guest2::ReqProc(HttpReqHeader* req) {
    uint32_t id = (uint32_t)(long)req->index;
    if(statusmap.count(id)){
        delete req;
        LOGD(DHTTP2, "<guest2> ReqProc dup id: %d\n", id);
        Reset(id, ERR_STREAM_CLOSED);
        return;
    }

    auto responser = distribute(req, std::weak_ptr<Responser>());
    if(!responser.expired()){
        statusmap[id]=ResStatus{
            responser,
            nullptr,
            (int32_t)remoteframewindowsize,
            localframewindowsize,
            0,
        };
        statusmap[id].res_index = responser.lock()->request(req);
    }else{
        finish(0, req->index);
        delete req;
    }
}

void Guest2::DataProc(uint32_t id, const void* data, size_t len) {
    if(len == 0)
        return;
    localwinsize -= len;
    if(statusmap.count(id)){
        ResStatus& status = statusmap[id];
        assert((status.res_flags & STREAM_READ_CLOSED) == 0);
        assert(!status.res_ptr.expired());
        auto responser = status.res_ptr.lock();
        if(len > (size_t)status.localwinsize){
            Reset(id, ERR_FLOW_CONTROL_ERROR);
            responser->finish(ERR_FLOW_CONTROL_ERROR, status.res_index);
            LOGE("(%s): <guest2> [%d] window size error %zu/%d\n", getsrc(nullptr), id, len, status.localwinsize);
            statusmap.erase(id);
            return;
        }
        responser->Send(data, len, status.res_index);
        status.localwinsize -= len;
    }else{
        LOGD(DHTTP2, "<guest2> DateProc not found id: %d\n", id);
        Reset(id, ERR_STREAM_CLOSED);
    }
}

void Guest2::EndProc(uint32_t id) {
    LOGD(DHTTP2, "<guest2> [%d]: end of stream\n", id);
    if(statusmap.count(id)){
        ResStatus& status = statusmap[id];
        assert(!status.res_ptr.expired());
        if(status.res_flags & STREAM_WRITE_CLOSED){
            status.res_ptr.lock()->finish(NOERROR | DISCONNECT_FLAG, status.res_index);
            statusmap.erase(id);
        }else{
            status.res_ptr.lock()->finish(NOERROR, status.res_index);
            status.res_flags |= STREAM_READ_CLOSED;
        }
    }
}


void Guest2::response(HttpResHeader* res) {
    assert(res->index);
    uint32_t id  = (uint32_t)(long)res->index;
    LOGD(DHTTP2, "<guest2> get response [%d]: %s\n", id, res->status);
    res->del("Transfer-Encoding");
    res->del("Connection");
    PushFrame(res->getframe(&request_table, id));
    delete res;
}

void Guest2::transfer(void* index, std::weak_ptr<Responser> res_ptr, void* res_index) {
    uint32_t id = (uint32_t)(long)index;
    assert(statusmap.count(id));
    ResStatus& status = statusmap[id];
    status.res_ptr = res_ptr;
    status.res_index = res_index;
}


void Guest2::RstProc(uint32_t id, uint32_t errcode) {
    if(statusmap.count(id)){
        if(errcode)
            LOGE("(%s) <guest2> [%d]: stream  reseted: %d\n", getsrc(nullptr), id, errcode);
        ResStatus& status = statusmap[id];
        assert(!status.res_ptr.expired());
        status.res_ptr.lock()->finish(errcode | DISCONNECT_FLAG,  status.res_index);
        statusmap.erase(id);
    }
}


void Guest2::WindowUpdateProc(uint32_t id, uint32_t size) {
    if(id){
        if(statusmap.count(id)){
            ResStatus& status = statusmap[id];
            LOGD(DHTTP2, "<guest2> window size updated [%d]: %d+%d\n", id, status.remotewinsize, size);
            if((uint64_t)status.remotewinsize + size >= (uint64_t)1<<31u){
                Reset(id, ERR_FLOW_CONTROL_ERROR);
                return;
            }
            status.remotewinsize += size;
            assert(!status.res_ptr.expired());
            status.res_ptr.lock()->writedcb(status.res_index);
        }else{
            LOGD(DHTTP2, "<guest2> window size updated [%d]: not found\n", id);
        }
    }else{
        LOGD(DHTTP2, "<guest2> window size updated global: %d+%d\n", remotewinsize, size);
        if((uint64_t)remotewinsize + size >= (uint64_t)1<<31u){
            ErrProc(ERR_FLOW_CONTROL_ERROR);
            return;
        }
        remotewinsize += size;
        if(remotewinsize == (int32_t)size){
            LOGD(DHTTP2, "<guest2> get global window active all frame\n");
            for(auto& i: statusmap){
                ResStatus& status = i.second;
                assert(!status.res_ptr.expired());
                if(status.remotewinsize > 0){
                    status.res_ptr.lock()->writedcb(status.res_index);
                }
            }
        }
    }
}


void Guest2::GoawayProc(const Http2_header* header) {
    Goaway_Frame* goaway = (Goaway_Frame *)(header+1);
    uint32_t errcode = get32(goaway->errcode);
    http2_flag |= HTTP2_FLAG_GOAWAYED;
    deleteLater(errcode | DISCONNECT_FLAG);
}

void Guest2::ErrProc(int errcode) {
    LOGE("Guest2 http2 error:%d\n", errcode);
    deleteLater(errcode);
}

void Guest2::AdjustInitalFrameWindowSize(ssize_t diff) {
    for(auto& i: statusmap){
       i.second.remotewinsize += diff;
    }
}

std::list<write_block>::insert_iterator Guest2::queue_head() {
    return rwer->buffer_head();
}

std::list<write_block>::insert_iterator Guest2::queue_end() {
    return rwer->buffer_end();
}

void Guest2::queue_insert(std::list<write_block>::insert_iterator where, const write_block& wb) {
    rwer->buffer_insert(where, wb);
}

void Guest2::finish(uint32_t flags, void* index) {
    uint32_t id = (uint32_t)(long)index;
    if(statusmap.count(id) == 0){
        LOGD(DHTTP2, "<guest2> finish not found id: %d\n", id);
        Peer::Send((const void*)nullptr, 0, index);
        return;
    }
    ResStatus& status = statusmap[id];
    uint8_t errcode = flags & ERROR_MASK;
    if(errcode == 0 ){
        if((status.res_flags & STREAM_WRITE_CLOSED) == 0){
            Peer::Send((const void*)nullptr, 0, index);
            status.res_flags |= STREAM_WRITE_CLOSED;
        }
        if((flags & DISCONNECT_FLAG) && (status.res_flags & STREAM_READ_CLOSED)){
            statusmap.erase(id);
            return;
        }
    }
    if(errcode || (flags & DISCONNECT_FLAG)){
        Reset(id, errcode>30?ERR_INTERNAL_ERROR:errcode);
        statusmap.erase(id);
    }
}

void Guest2::deleteLater(uint32_t errcode){
    for(auto& i: statusmap){
        assert(!i.second.res_ptr.expired());
        i.second.res_ptr.lock()->finish(errcode, i.second.res_index);
    }
    statusmap.clear();
    if((http2_flag & HTTP2_FLAG_GOAWAYED) == 0){
        http2_flag |= HTTP2_FLAG_GOAWAYED;
        Goaway(-1, errcode & ERROR_MASK);
    }
    return Peer::deleteLater(errcode);
}

void Guest2::writedcb(const void* index){
    uint32_t id = (uint32_t)(long)index;
    if(statusmap.count(id)){
        ResStatus& status = statusmap[id];
        assert(!status.res_ptr.expired());
        auto len = status.res_ptr.lock()->bufleft(status.res_index);
        if(len > status.localwinsize && (len - status.localwinsize > FRAMEBODYLIMIT)){
            status.localwinsize += ExpandWindowSize(id, len - status.localwinsize);
        }
    }
}

const char * Guest2::getsrc(const void* index){
    static char src[DOMAINLIMIT];
    if(index == nullptr){
        sprintf(src, "%s:%d", sourceip, sourceport);
    }else{
        sprintf(src, "%s:%d [%u]", sourceip, sourceport, (uint32_t)(long)index);
    }
    return src;
}


void Guest2::dump_stat(Dumper dp, void* param) {
    dp(param, "Guest2 %p %s:\n", this, getsrc(nullptr));
    dp(param, "  rwer: rlength:%zu, rleft:%zu, wlength:%zu, stats:%d, event:%s\n",
            rwer->rlength(), rwer->rleft(), rwer->wlength(),
            (int)rwer->getStats(), events_string[(int)rwer->getEvents()]);
    for(auto& i: statusmap){
        dp(param, "0x%x: %p, %p (%d/%d)\n",
                i.first, i.second.res_ptr.lock().get(), i.second.res_index,
                i.second.remotewinsize, i.second.localwinsize);
    }
}


#ifndef NDEBUG
void Guest2::PingProc(const Http2_header *header){
    LOGD(DHTTP2, "<guest2> ping: window size global: %d/%d\n", localwinsize, remotewinsize);
    return Http2Base::PingProc(header);
}
#endif
