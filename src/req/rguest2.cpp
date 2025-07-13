#include "rguest2.h"
#include "prot/sslio.h"

static const unsigned char alpn_protos_rproxy[] =
    "\x02r2";


//这里传入的IRWerCallback只是占位，Guest2的构造函数会创建ISocketCallback, 并把它保存到cb
Rguest2::Rguest2(const Destination* dest, const std::string& name):
    Guest2(std::make_shared<SslRWer>(dest->hostname, dest->port, Protocol::TCP,
                                     IRWerCallback::create()->onError([](int, int){}))),
    name(name)
{
    auto srwer = std::dynamic_pointer_cast<SslRWer>(rwer);
    srwer->set_alpn(alpn_protos_rproxy, sizeof(alpn_protos_rproxy)-1);
    std::dynamic_pointer_cast<ISocketCallback>(cb)->onConnect([this](const sockaddr_storage&, uint32_t){
        LOG("connected to rproxy server: %s\n", dumpDest(rwer->getDst()).c_str());
    });
}

size_t Rguest2::InitProc(Buffer& bb) {
    size_t ret = Guest2::InitProc(bb);
    if(ret > 0) {
        uint32_t id = OpenStream();
        char preface[URLLIMIT];
        snprintf(preface, sizeof(preface), "GET /rproxy/%s HTTP/1.1\r\nHost: localhost\r\n\r\n", name.c_str());

        auto req = UnpackHttpReq(preface);
        Block buff(BUF_LEN);
        Http2_header* const header = (Http2_header *)buff.data();
        memset(header, 0, sizeof(*header));
        header->type = HTTP2_STREAM_PUSH_PROMISE;
        header->flags = HTTP2_END_HEADERS_F | HTTP2_END_STREAM_F;

        set32(header->id, id);
        size_t len = hpack_encoder.PackHttp2Req(req, header+1, BUF_LEN - sizeof(Http2_header));
        set24(header->length, len);
        SendData(Buffer{std::move(buff), len + sizeof(Http2_header), id});
    }
    return ret;
}


void Rguest2::deleteLater(uint32_t errcode) {
    LOG("rproxy exit with code: %d\n", (int)errcode);
    exit(errcode);
}
