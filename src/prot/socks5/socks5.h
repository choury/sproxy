#ifndef SOCKS5_H__
#define SOCKS5_H__

#include "prot/netio.h"
#include <memory>

enum class Socks5State {
    Idle,
    GreetingSent,
    MethodSelected,
    AuthSent,
    AuthOk,
    RequestSent,
    Established,
    Error,
};

enum class Socks5Method : uint8_t {
    NoAuth = 0x00,
    UserPass = 0x02,
    NoAcceptable = 0xff,
};

enum class Socks5Cmd : uint8_t {
    Connect = 0x01,
    UdpAssociate = 0x03,
};

enum class Socks5AddrType : uint8_t {
    IPv4 = 0x01,
    Domain = 0x03,
    IPv6 = 0x04,
};

class Socks5RWer: public StreamRWer {
    Socks5State state = Socks5State::Idle;
    Destination server{};
    Destination dst{};
    std::unique_ptr<sockaddr_storage> bound_ss;
    std::shared_ptr<PacketRWer> udp_rwer;
    std::shared_ptr<IRWerCallback> udp_cb;
    size_t (Socks5RWer::*proc)(Buffer&& bb) = nullptr;

    size_t MethodSelectProc(Buffer&& bb);
    size_t AuthProc(Buffer&& bb);
    size_t ReplyProc(Buffer&& bb);
    size_t DefaultProc(Buffer&& bb);

    void SendGreeting();
    void SendAuth();
    void SendRequest();
    void Fail(int err);

protected:
    //size_t Proc(Buffer& bb);
    size_t ProcUdp(Buffer& bb);
    void SendUdpPayload(Buffer&& payload);
    void ConsumeRData(uint64_t id) override;
    void waitconnectHE(RW_EVENT events) override;

public:
    Socks5RWer(const Destination& server, const Destination& dst,
        std::shared_ptr<IRWerCallback> cb);

    bool IsConnected() override;
    void Send(Buffer&& bb) override;
    void dump_status(Dumper dp, void* param) override;
    size_t mem_usage() override;
};

#endif
