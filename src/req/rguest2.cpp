#include "rguest2.h"
#include "prot/sslio.h"
#include "misc/job.h"

static const unsigned char alpn_protos_rproxy[] =
    "\x02r2";

size_t Rguest2::next_retry = 1000;

//这里传入的IRWerCallback只是占位，Guest2的构造函数会创建ISocketCallback, 并把它保存到cb
Rguest2::Rguest2(const Destination& dest, const std::string& name):
    Guest2(std::make_shared<SslRWer>(dest, IRWerCallback::create()->onError([](int, int){}))),
    dest(dest), name(name), starttime(getmtime())
{
    auto srwer = std::dynamic_pointer_cast<SslRWer>(rwer);
    srwer->set_alpn(alpn_protos_rproxy, sizeof(alpn_protos_rproxy)-1);
    std::dynamic_pointer_cast<ISocketCallback>(cb)->onConnect([this](const sockaddr_storage&, uint32_t){
        LOG("connected to rproxy server: %s\n", dumpDest(rwer->getDst()).c_str());
    });
}

size_t Rguest2::InitProc(Buffer& bb) {
    size_t ret = Guest2::InitProc(bb);
    if(ret <= 0) {
        return ret;
    }
    char preface[URLLIMIT];
    snprintf(preface, sizeof(preface), "GET /rproxy/%s HTTP/1.1" CRLF "Host: localhost" CRLF CRLF, name.c_str());

    auto req = UnpackHttpReq(preface);
    //注册先于任何请求到达，没有承载流(id=0)，PushPromise内部自开
    uint32_t pid = PushPromise(0, req);
    if(pid == UINT32_MAX){
        return ret; //已ErrProc
    }

    //在承诺流上交付承诺的响应
    auto res = HttpResHeader::create(S200, sizeof(S200), 0);
    Block rbuff(BUF_LEN);
    Http2_header* const rheader = (Http2_header*)rbuff.data();
    memset(rheader, 0, sizeof(*rheader));
    rheader->type = HTTP2_STREAM_HEADERS;
    rheader->flags = HTTP2_END_HEADERS_F | HTTP2_END_STREAM_F;

    set32(rheader->id, pid);
    size_t rlen = hpack_encoder.PackHttp2Res(res, rheader + 1, BUF_LEN - sizeof(Http2_header));
    if(rlen == 0){
        LOGE("http2 response header too long: %s\n", res->status);
        deleteLater(PROTOCOL_ERR);
        return ret;
    }
    set24(rheader->length, rlen);
    SendData(Buffer{std::move(rbuff), rlen + sizeof(Http2_header), pid});
    return ret;
}

void Rguest2::ReqProc(uint32_t id, std::shared_ptr<HttpReqHeader> req) {
    req->skip_authorize = !req->has("X-Delegate-Auth", "1");
    req->del("X-Delegate-Auth");
    Guest2::ReqProc(id, req);
}

void Rguest2::deleteLater(uint32_t errcode) {
    if(!respawned) {
        if(getmtime() - starttime > 1800000) {
            next_retry = 1000;
        } else {
            next_retry = std::min((size_t)32000, next_retry * 2);
        }
        LOG("rguest2 exit with code: %d, retry after %zds\n", (int)errcode, next_retry/1000);
        addjob_with_name([dest = dest, name = name]() {
            new Rguest2(dest, name);
        }, "Rguest2 respawn", next_retry, JOB_FLAGS_AUTORELEASE);
        respawned = true;
    }
    return Guest2::deleteLater(errcode);
}
