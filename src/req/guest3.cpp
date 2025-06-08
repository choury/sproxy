//
// Created by 周威 on 2022/3/19.
//

#include "guest3.h"
#include "res/responser.h"
#include "misc/hook.h"
#include <assert.h>
#include <inttypes.h>

void Guest3::init() {
    cb = ISocketCallback::create()->onConnect([this](const sockaddr_storage&, uint32_t){
        connected();
    })->onRead([this](Buffer&& bb) -> size_t {
        HOOK_FUNC(this, statusmap, bb);
        LOGD(DHTTP3, "<guest3> (%s) read [%" PRIu64"]: len:%zu\n", dumpDest(this->rwer->getSrc()).c_str(), bb.id, bb.len);
        if(bb.len == 0){
            //fin
            if(ctrlid_remote && bb.id == ctrlid_remote){
                Error(PROTOCOL_ERR, HTTP3_ERR_CLOSED_CRITICAL_STREAM);
                return 0;
            }
            if(!statusmap.count(bb.id)){
                return 0;
            }
            LOGD(DHTTP3, "<guest3> [%" PRIu64 "]: end of stream\n", bb.id);
            ReqStatus& status = statusmap[bb.id];
            status.rw->push_data(Buffer{nullptr, bb.id});
            status.flags |= HTTP_REQ_COMPLETED;
            if(status.flags & HTTP_RES_COMPLETED) {
                status.cleanJob = AddJob(([this, id = bb.id]{Clean(id, NOERROR);}), 0, 0);
            }
            return 0;
        }

        size_t ret = 0;
        size_t len = 0;
        while((bb.len > 0) && (ret = Http3_Proc(bb))){
            len += ret;
        }
        return len;
    })->onWrite([this](uint64_t id){
        if(statusmap.count(id) == 0){
            return;
        }
        ReqStatus& status = statusmap[id];
        if(status.flags & (HTTP_RES_COMPLETED | HTTP_CLOSED_F | HTTP_RST)){
            return;
        }
        status.rw->pull(id);
    })->onError([this](int ret, int code){
        Error(ret, code);
    });
    rwer->SetCallback(cb);
}

void Guest3::connected() {
    std::shared_ptr<QuicBase> qrwer = std::dynamic_pointer_cast<QuicBase>(rwer);
    const unsigned char *data;
    unsigned int len;
    qrwer->getAlpn(&data, &len);
    if ((data && strncasecmp((const char*)data, "h3", len) != 0)) {
        LOGE("(%s) unknown protocol: %.*s\n", dumpDest(rwer->getSrc()).c_str(), len, data);
        return Server::deleteLater(PROTOCOL_ERR);
    }
    qrwer->setResetHandler([this](uint64_t id, uint32_t error){RstProc(id, error);});
    Init();
}

Guest3::Guest3(std::shared_ptr<QuicRWer> rwer): Requester(rwer) {
    init();
}

Guest3::Guest3(std::shared_ptr<QuicMer> rwer): Requester(rwer) {
    init();
    mitmProxy = true;
}

Guest3::~Guest3() {
}

void Guest3::AddInitData(const void *buff, size_t len) {
    auto qrwer = std::dynamic_pointer_cast<QuicBase>(rwer);
    iovec iov{(void*)buff, len};
    qrwer->walkPackets(&iov, 1);
}

void Guest3::Error(int ret, int code){
    LOGE("(%s): <guest3> error: %d/%d\n", dumpDest(rwer->getSrc()).c_str(), ret, code);
    deleteLater(ret);
}

size_t Guest3::Recv(Buffer&& bb){
    ReqStatus& status = statusmap.at(bb.id);
    assert((status.flags & HTTP_RES_COMPLETED) == 0);
    if(bb.len == 0){
        LOGD(DHTTP3, "<guest3> %" PRIu64" recv data [%" PRIu64"]: EOF\n",
             status.req->request_id, bb.id);
        SendData({nullptr, bb.id});
        status.flags |= HTTP_RES_COMPLETED;
        if(status.flags & HTTP_REQ_COMPLETED) {
            status.cleanJob = AddJob(([this, id = bb.id]{Clean(id, NOERROR);}), 0, 0);
        }
        return 0;
    }
    auto len = bb.len;
    if(status.req->ismethod("HEAD")){
        LOGD(DHTTP3, "<guest3> %" PRIu64" recv data [%" PRIu64"]: HEAD req discard body\n",
                status.req->request_id, bb.id);
        return len;
    }
    LOGD(DHTTP3, "<guest3> %" PRIu64 " recv data [%" PRIu64"]: %zu, cap: %d\n",
            status.req->request_id, bb.id, bb.len, (int)rwer->cap(bb.id));
    PushData(std::move(bb));
    return len;
}

void Guest3::ReqProc(uint64_t id, std::shared_ptr<HttpReqHeader> header) {
    LOGD(DHTTP3, "<guest3> %" PRIu64 " (%s) ReqProc %s\n",
         header->request_id, dumpDest(rwer->getSrc()).c_str(), header->geturl().c_str());
    if(statusmap.count(id)){
        LOGD(DHTTP3, "<guest3> ReqProc dup id: %" PRIu64"\n", id);
        Reset(id, HTTP3_ERR_STREAM_CREATION_ERROR);
        return;
    }
    if (mitmProxy) {
        strcpy(header->Dest.protocol, "quic");
    }

    auto _cb = response(id);
    statusmap[id] = ReqStatus{
        header,
        std::make_shared<MemRWer>(rwer->getSrc(), _cb),
        _cb,
    };
    ReqStatus& status = statusmap[id];
    distribute(status.req, status.rw, this);
}

bool Guest3::DataProc(Buffer& bb) {
    if(bb.len == 0)
        return true;
    if(statusmap.count(bb.id)){
        HOOK_FUNC(this, statusmap, bb);
        ReqStatus& status = statusmap[bb.id];
        if(status.flags & HTTP_REQ_COMPLETED){
            LOGD(DHTTP3, "<guest3> DateProc after closed, id: %" PRIu64"\n", bb.id);
            status.cleanJob = AddJob(([this, id = bb.id]{Clean(id, HTTP3_ERR_STREAM_CREATION_ERROR);}), 0, 0);
            return true;
        }
        if(status.rw->bufsize() < bb.len){
            LOGE("[%" PRIu64 "]: <guest3> (%" PRIu64") the host's buff is full (%s)\n",
                 status.req->request_id, bb.id, status.req->geturl().c_str());
            return false;
        }
        status.rw->push_data(std::move(bb));
    }else{
        LOGD(DHTTP3, "<guest3> DateProc not found id: %" PRIu64"\n", bb.id);
        Reset(bb.id, HTTP3_ERR_STREAM_CREATION_ERROR);
    }
    return true;
}

std::shared_ptr<IMemRWerCallback> Guest3::response(uint64_t id) {
    return IMemRWerCallback::create()->onHeader([this, id](std::shared_ptr<HttpResHeader> res){
        ReqStatus &status = statusmap.at(id);
        LOGD(DHTTP3, "<guest3> get response [%" PRIu64"]: %s\n", id, res->status);
        HttpLog(dumpDest(rwer->getSrc()), status.req, res);
        if(mitmProxy) {
            res->del("Strict-Transport-Security");
        }

        Block buff(BUF_LEN);
        size_t len = qpack_encoder.PackHttp3Res(res, buff.data(), BUF_LEN);
        size_t pre = variable_encode_len(HTTP3_STREAM_HEADERS) + variable_encode_len(len);
        char *p = (char *) buff.reserve(-pre);
        p += variable_encode(p, HTTP3_STREAM_HEADERS);
        p += variable_encode(p, len);
        SendData({std::move(buff), len + pre, id});
    })->onData([this, id](Buffer bb) -> size_t {
        bb.id = id;
        return Recv(std::move(bb));
    })->onWrite([this, id](uint64_t){
        rwer->Unblock(id);
    })->onSignal([this, id](Signal s) {
        ReqStatus& status = statusmap.at(id);
        LOGD(DHTTP3, "<guest3> signal [%d] %" PRIu64 ": %d\n",
            (int)id, status.req->request_id, (int)s);
        switch(s){
        case CHANNEL_ABORT:
            status.flags |= HTTP_CLOSED_F;
            status.cleanJob = AddJob(([this, id]{Clean(id, HTTP3_ERR_INTERNAL_ERROR);}), 0, 0);
            return;
        }
    })->onCap([this, id]() -> ssize_t {
        //这里是没办法准确计算cap的，因为rwer返回的可用量http3这里写的时候会再加头部数据
        //多出来的数据会放入quic的fullq队列中
        return rwer->cap(id);
    });
}

void Guest3::Clean(uint64_t id, uint32_t errcode) {
    if(statusmap.count(id) == 0){
        return;
    }

    ReqStatus& status = statusmap[id];
    if((status.flags & HTTP_RST) == 0 && ((status.flags&HTTP_REQ_COMPLETED) == 0 || (status.flags&HTTP_RES_COMPLETED) == 0)){
        Reset(id, errcode);
    }
    if((status.flags & HTTP_CLOSED_F) == 0){
        status.rw->push_signal(CHANNEL_ABORT);
    }
    statusmap.erase(id);
}

void Guest3::RstProc(uint64_t id, uint32_t errcode) {
    if(statusmap.count(id)){
        ReqStatus& status = statusmap[id];
        if(errcode){
            LOGE("[%" PRIu64 "]: <guest3> (%" PRIu64"): stream reset:%d flags:0x%x\n",
                 status.req->request_id, id, errcode, status.flags);
        }
        status.flags |= HTTP_RST;
        Clean(id, errcode);
    } else {
        LOGD(DHTTP3, "reset for no exist id: %" PRIu64"\n", id);
    }
}

void Guest3::GoawayProc(uint64_t id) {
    LOGD(DHTTP3, "<guest3> [%" PRIu64 "]: goaway\n", id);
    return deleteLater(NOERROR);
}

void Guest3::SendData(Buffer&& bb) {
    rwer->Send(std::move(bb));
}

uint64_t Guest3::CreateUbiStream() {
    return std::dynamic_pointer_cast<QuicBase>(rwer)->createUbiStream();
}

void Guest3::Reset(uint64_t id, uint32_t code) {
    return std::dynamic_pointer_cast<QuicBase>(rwer)->reset(id, code);
}

void Guest3::ErrProc(int errcode) {
    LOGE("(%s): Guest3 http3 error:0x%08x\n", dumpDest(rwer->getSrc()).c_str(), errcode);
    http3_flag |= HTTP3_FLAG_ERROR;
    deleteLater(errcode);
}

void Guest3::deleteLater(uint32_t errcode){
    http3_flag |= HTTP3_FLAG_CLEANNING;
    if((http3_flag & HTTP3_FLAG_GOAWAYED) == 0){
        Goaway(maxDataId);
    }
    for(auto& i: statusmap){
        if((i.second.flags & HTTP_CLOSED_F) == 0) {
            i.second.rw->push_signal(CHANNEL_ABORT);
        }
        i.second.flags |= HTTP_CLOSED_F;
    }
    std::dynamic_pointer_cast<QuicBase>(rwer)->close(errcode);
    return Server::deleteLater(errcode);
}


void Guest3::dump_stat(Dumper dp, void* param) {
    dp(param, "Guest3 %p, data id: %" PRIx64"\n"
            "local ctr:%" PRIx64", remote ctr:%" PRIx64", "
            "local eqpack:%" PRIx64", remote eqpack:%" PRIx64", local dqpack:%" PRIx64", remote dqpack:%" PRIx64"\n",
            this, maxDataId, ctrlid_local, ctrlid_remote,
            qpackeid_local, qpackeid_remote, qpackdid_local, qpackdid_remote);
    for(auto& i: statusmap){
        dp(param, "  0x%lx [%" PRIu64 "]: %s %s, time: %dms, flags: 0x%08x [%s]\n",
           i.first, i.second.req->request_id,
           i.second.req->method,
           i.second.req->geturl().c_str(),
           getmtime() - std::get<1>(i.second.req->tracker[0]),
           i.second.flags,
           i.second.req->get("User-Agent"));
    }
    rwer->dump_status(dp, param);
}

void Guest3::dump_usage(Dumper dp, void *param) {
    size_t req_usage  = 0;
    for(const auto& i: statusmap) {
        req_usage += sizeof(i.first) + sizeof(i.second);
        req_usage += i.second.req->mem_usage();
    }
    dp(param, "Guest3 %p: %zd, reqmap: %zd, rwer: %zd\n",
       this, sizeof(*this) + qpack_encoder.get_dynamic_table_size() + qpack_decoder.get_dynamic_table_size(),
       req_usage, rwer->mem_usage());
}
