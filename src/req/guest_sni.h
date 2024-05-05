#ifndef GUEST_SNI_H__
#define GUEST_SNI_H__

#include "guest.h"
#include <netinet/in.h>

class Guest_sni: public Guest{
    std::string host;
    std::string user_agent;
    size_t sniffer(Buffer&& bb);
    std::shared_ptr<HttpReq> forward(const char* hostname, Protocol prot);
public:
    // 这里必须要保留一个ctx的指针，是因为这个类在HttpServer中作为模版参数，需要和Guest的构造函数保持一致
    explicit Guest_sni(int fd, const sockaddr_storage* addr, SSL_CTX* ctx);
    explicit Guest_sni(std::shared_ptr<RWer> rwer, std::string host, std::string ua);
    size_t sniffer_quic(Buffer&& bb);
    virtual void response(void*, std::shared_ptr<HttpRes> res)override;
};

#endif
