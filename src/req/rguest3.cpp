#include "rguest3.h"
#include "prot/quic/quicio.h"
#include "misc/job.h"

static const unsigned char alpn_protos_rproxy3[] =
    "\x02r3";

size_t Rguest3::next_retry = 1000;

Rguest3::Rguest3(const Destination& dest, const std::string& name):
    Guest3(std::make_shared<QuicRWer>(dest, IRWerCallback::create()->onError([](int, int){}))),
    dest(dest), name(name), starttime(getmtime())
{
    auto qrwer = std::dynamic_pointer_cast<QuicRWer>(rwer);
    qrwer->setAlpn(alpn_protos_rproxy3, sizeof(alpn_protos_rproxy3)-1);
    std::dynamic_pointer_cast<IQuicCallback>(cb)->onConnect([this](const sockaddr_storage&, uint32_t){
        LOG("connected to rproxy3 server: %s\n", dumpDest(rwer->getDst()).c_str());
        //注册请求等服务端MAX_PUSH_ID授权后推送(MaxPushIdProc)
        Http3Base::Init();
    });
}

void Rguest3::MaxPushIdProc(uint64_t) {
    uint64_t id = CreateBiStream(); //承载注册帧的流
    char preface[URLLIMIT];
    snprintf(preface, sizeof(preface), "GET /rproxy/%s HTTP/1.1" CRLF "Host: localhost" CRLF CRLF, name.c_str());

    auto req = UnpackHttpReq(preface);
    uint64_t pushid = PushPromise(id, req);
    if(pushid == UINT64_MAX){
        return; //已ErrProc
    }
    SendData({nullptr, id}); //fin

    //push stream = 流类型0x01 + Push ID + 承诺的响应
    uint64_t pid = std::dynamic_pointer_cast<QuicBase>(rwer)->createUbiStream();
    auto res = HttpResHeader::create(S200, sizeof(S200), 0);
    Block pbuff(BUF_LEN);
    size_t rlen = Qpack_encoder::PackHttp3Res(res, pbuff.data(), BUF_LEN);
    if(rlen == 0){
        LOGE("http3 response header too long: %s\n", res->status);
        return deleteLater(PROTOCOL_ERR);
    }
    size_t rpre = variable_encode_len(HTTP3_STREAM_TYPE_PUSH) + variable_encode_len(pushid)
                + variable_encode_len(HTTP3_STREAM_HEADERS) + variable_encode_len(rlen);
    char* pp = (char*)pbuff.reserve(-(int)rpre);
    QuicCursor pc(pp, rpre);
    pc.variable_encode(HTTP3_STREAM_TYPE_PUSH);
    pc.variable_encode(pushid);
    pc.variable_encode(HTTP3_STREAM_HEADERS);
    pc.variable_encode(rlen);
    SendData({std::move(pbuff), rpre + rlen, pid});
    SendData({nullptr, pid}); //fin
}

void Rguest3::ReqProc(uint64_t id, std::shared_ptr<HttpReqHeader> req) {
    req->skip_authorize = !req->has("X-Delegate-Auth", "1");
    req->del("X-Delegate-Auth");
    Guest3::ReqProc(id, req);
}

void Rguest3::deleteLater(uint32_t errcode) {
    if(!respawned) {
        if(getmtime() - starttime > 1800000) {
            next_retry = 1000;
        } else {
            next_retry = std::min((size_t)32000, next_retry * 2);
        }
        LOG("rguest3 exit with code: %d, retry after %zds\n", (int)errcode, next_retry/1000);
        addjob_with_name([dest = dest, name = name]() {
            new Rguest3(dest, name);
        }, "Rguest3 respawn", next_retry, JOB_FLAGS_AUTORELEASE);
        respawned = true;
    }
    return Guest3::deleteLater(errcode);
}
