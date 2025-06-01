#ifndef GUEST_SNI_H__
#define GUEST_SNI_H__

#include "guest.h"
#include <netinet/in.h>

class Guest_sni: public Guest{
    std::string host;
    std::string user_agent;
    std::list<Buffer> quic_init_packets;
    SSL_CTX* ctx = nullptr;
    size_t sniffer(Buffer&& bb);
    ReqStatus* forward(const char* hostname, Protocol prot, uint64_t id);
public:
    // 这里必须要保留一个ctx的指针，是因为这个类在HttpServer中作为模版参数，需要和Guest的构造函数保持一致
    explicit Guest_sni(int fd, const sockaddr_storage* addr, SSL_CTX* ctx, std::function<void(Server*)> df = [](Server*){});
    explicit Guest_sni(std::shared_ptr<RWer> rwer, std::string host, const char* ua);
    virtual ~Guest_sni() override;
    size_t sniffer_quic(Buffer&& bb);
};

#endif
