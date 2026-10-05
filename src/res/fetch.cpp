#include "fetch.h"
#include "host.h"
#include "prot/memio.h"
#include "misc/job.h"

#include <string.h>

namespace {

struct State {
    std::function<void(std::shared_ptr<HttpResHeader> res, std::string resbody)> done;
    std::string body;
    std::shared_ptr<HttpResHeader> res;
    bool fired = false;
    std::shared_ptr<MemRWer> rw;
    std::shared_ptr<IMemRWerCallback> cb;
};

//完成/失败/超时的统一出口
void finish(std::shared_ptr<State> state) {
    if(!state->fired) {
        state->fired = true;
        state->done(state->res, std::move(state->body));
    }
    auto rw = state->rw;
    if(!rw) {
        return; //回收 job 已执行过
    }
    addjob_with_name([rw, state]{
        //延迟一拍执行:finish 常从 MemRWer 自身回调内进入,同步 push_signal 会重入
        rw->push_signal(Signal::CHANNEL_ABORT);
        //断开引用环(cb 闭包持 state → state 持 cb/rw),否则每个请求泄漏一套;
        //cb 可安全置空——MemRWer 经 weak lock 调用,执行期间自带强引用
        state->cb = nullptr;
        state->rw = nullptr;
    }, "http_fetch finish", 0, JOB_FLAGS_AUTORELEASE);
}

}

void http_fetch(std::shared_ptr<HttpReqHeader> req, const Destination& dest, std::string body,
                std::function<void(std::shared_ptr<HttpResHeader> res, std::string resbody)> done, uint32_t timeout_ms)
{
    if(!body.empty()) {
        req->set("Content-Length", body.size());
    }

    auto state = std::make_shared<State>();
    state->done = std::move(done);

    auto cb = IMemRWerCallback::create();
    cb->onHeader([state](std::shared_ptr<HttpResHeader> res) {
        state->res = std::move(res);
    })->onData([state](Buffer&& bb) {
        if(bb.len == 0) {
            finish(state);
            return 0;
        }
        if(state->body.size() + bb.len > 1024 * 1024) {
            state->body.clear();
            finish(state);
            return (int)bb.len;
        }
        state->body.append((const char*)bb.data(), bb.len);
        return (int)bb.len;
    })->onSignal([state](Signal) {
        finish(state); //res 为空(未收到头)或已收到的应答头
    })->onCap([]{
        return (size_t)BUF_LEN;
    })->onWrite([](uint64_t){});
    state->cb = cb;

    Destination local{};
    strcpy(local.hostname, "localhost");
    state->rw = std::make_shared<MemRWer>(local, dest, cb);
    addjob_with_name([state]{finish(state);}, "http_fetch timeout",
                     timeout_ms, JOB_FLAGS_AUTORELEASE);
    if(!body.empty()) {
        state->rw->push_data({body.data(), body.size()});
    }
    state->rw->push_data({nullptr});
    Host::distribute(req, dest, state->rw);
}
