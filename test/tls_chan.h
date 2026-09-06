#ifndef TLS_CHAN_H__
#define TLS_CHAN_H__
//TLS层channel：mem-BIO驱动，握手与读写只经下层channel的字节流，不依赖
//socket，因此既可架在fd层上(普通TLS)，也可架在h2流上(隧道内层TLS)，
//嵌套层数不限。帧外标记输出：干净对端关闭打[tls] eof。
//另含echgen命令的ech_gen：生成服务端ech密钥文件，stdout打印可发布到
//DNS HTTPS RR的base64 retry configs(无ECH支持的构建返回-2)
#include "channel.h"

#include <string>
#include <memory>
#include <openssl/ssl.h>

int ech_gen(const std::string& file, const std::string& public_name);

struct TlsChannel final : Channel {
    std::unique_ptr<Channel> base;
    SSL_CTX* ssl_ctx = nullptr;
    SSL* ssl = nullptr;
    bool ok = false; //构造时握手成功(ech按预期接受)
    //在下层channel上跑TLS握手并接管。ech：空=普通TLS，"grease"=GREASE ECH，
    //"-"=占位跳过(只为指定后面的alpn)，其余=base64 ECHConfigList；
    //alpn：逗号分隔协议列表，空=不携带。成功后打印协商结果与对端证书
    //供脚本断言；失败打印原因并关闭整栈(ok=false)
    TlsChannel(std::unique_ptr<Channel> base, const std::string& sni,
               const std::string& ech, const std::string& alpn);
    ~TlsChannel() override;
    int read(void* buf, size_t n, int timeout_ms) override;
    int write(const void* buf, size_t n) override;
    void shutdown_wr() override; //发出close_notify，不等待对端回应
    void close() override;
private:
    int pump_write(); //排空wbio到下层channel，0成功-1失败
};

#endif
