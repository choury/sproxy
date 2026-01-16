#include "socks5.h"

#include "misc/config.h"
#include "misc/defer.h"
#include "misc/net.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>

static constexpr uint8_t SOCKS5_VERSION = 0x05;
static constexpr uint8_t SOCKS5_AUTH_VERSION = 0x01;
static constexpr size_t SOCKS5_REPLY_HEAD_LEN = 4;
static constexpr size_t SOCKS5_UDP_HEAD_LEN = 4;

static const char* Socks5StateStrings[] = {
    "Idle",
    "GreetingSent",
    "MethodSelected",
    "AuthSent",
    "AuthOk",
    "RequestSent",
    "Established",
    "Error",
};

static size_t DecodeAddressPort(Buffer& bb, Socks5AddrType type, sockaddr_storage& out) {
    const uchar* data = (const uchar*)bb.data();
    size_t len = bb.len;
    memset(&out, 0, sizeof(out));

    if (type == Socks5AddrType::IPv4) {
        if (len < sizeof(in_addr) + 2) {
            return 0;
        }
        const in_addr* addr = (const in_addr*)data;
        auto* in = (sockaddr_in*)&out;
        in->sin_family = AF_INET;
        memcpy(&in->sin_addr, addr, sizeof(in->sin_addr));
        memcpy(&in->sin_port, data + sizeof(in_addr), sizeof(in->sin_port));

        size_t consumed = sizeof(in_addr) + 2;
        bb.reserve((int)consumed);
        return consumed;
    }
    if (type == Socks5AddrType::IPv6) {
        if (len < sizeof(in6_addr) + 2) {
            return 0;
        }
        const in6_addr* addr = (const in6_addr*)data;
        auto* in6 = (sockaddr_in6*)&out;
        in6->sin6_family = AF_INET6;
        memcpy(&in6->sin6_addr, addr, sizeof(in6->sin6_addr));
        memcpy(&in6->sin6_port, data + sizeof(in6_addr), sizeof(in6->sin6_port));

        size_t consumed = sizeof(in6_addr) + 2;
        bb.reserve((int)consumed);
        return consumed;
    }
    if (type == Socks5AddrType::Domain) {
        if (len < 1) {
            return 0;
        }
        size_t host_len = data[0];
        if (host_len == 0) {
            return 0;
        }
        if (len < 1 + host_len + 2) {
            return 0;
        }
        out.ss_family = AF_UNSPEC;
        size_t consumed = 1 + host_len + 2;
        bb.reserve((int)consumed);
        return consumed;
    }
    return 0;
}

Socks5RWer::Socks5RWer(const Destination& server, const Destination& dst, std::shared_ptr<IRWerCallback> cb):
    StreamRWer(server, std::move(cb)) {
    assert(this->protocol == Protocol::TCP);
    this->server = server;
    this->dst = dst;
    LOGD(DSOCKS, "<socks5> init: server=%s dst=%s\n", dumpDest(this->server).c_str(), dumpDest(this->dst).c_str());
}

size_t Socks5RWer::ProcUdp(Buffer& bb) {
    if (bb.len < SOCKS5_UDP_HEAD_LEN) {
        return 0;
    }
    const uchar* data = (const uchar*)bb.data();
    if (data[0] != 0x00 || data[1] != 0x00 || data[2] != 0x00) {
        LOGD(DSOCKS, "<socks5> udp invalid header: %02x %02x %02x\n",
             data[0], data[1], data[2]);
        Fail(PROTOCOL_ERR);
        size_t len = bb.len;
        bb.reserve((int)len);
        return len;
    }

    size_t total = bb.len;
    Socks5AddrType type = (Socks5AddrType)data[3];
    bb.reserve((int)SOCKS5_UDP_HEAD_LEN);

    sockaddr_storage dst_addr{};
    if (DecodeAddressPort(bb, type, dst_addr) == 0) {
        return 0;
    }

    LOGD(DSOCKS, "<socks5> udp recv: %s len:%zu\n", storage_ntoa(&dst_addr), bb.len);
    if (auto cb = callback.lock(); cb) {
        cb->readCB(std::move(bb));
    }
    return total;
}

void Socks5RWer::waitconnectHE(RW_EVENT events) {
    if (!!(events & RW_EVENT::ERROR) || !!(events & RW_EVENT::READEOF)) {
        int error = this->checkSocket(__PRETTY_FUNCTION__ );
        this->con_failed_job = UpdateJob(std::move(this->con_failed_job),
                                         ([this, error]{connectFailed(error);}), 0);
        return;
    }
    if (!!(events & RW_EVENT::WRITE)) {
        LOGD(DSOCKS, "<socks5> connected to server %s\n", dumpDest(server).c_str());
        con_failed_job.reset(nullptr);
        setEvents(RW_EVENT::READWRITE);
        stats = RWerStats::Connected;
        handleEvent = (void (Ep::*)(RW_EVENT))&Socks5RWer::defaultHE;

        SendGreeting();
        state = Socks5State::GreetingSent;
        if (opt.socks5_fast) {
            if(server.credit.user[0] != '\0' || server.credit.pass[0] != '\0') {
                SendAuth();
            }
            SendRequest();
        }
        proc = &Socks5RWer::MethodSelectProc;
    }
}

bool Socks5RWer::IsConnected() {
    return state == Socks5State::Established;
}

size_t Socks5RWer::MethodSelectProc(Buffer&& bb) {
    if (bb.len < 2) {
        return 0;
    }
    const uchar* data = (const uchar*)bb.data();
    if (data[0] != SOCKS5_VERSION) {
        Fail(PROTOCOL_ERR);
        return 0;
    }
    Socks5Method method = (Socks5Method)data[1];
    LOGD(DSOCKS, "<socks5> method select: %u\n", (unsigned)method);
    bb.reserve(2);
    switch (method) {
    case Socks5Method::NoAuth:
        state = Socks5State::MethodSelected;
        if (!opt.socks5_fast) {
            SendRequest();
        }
        proc = &Socks5RWer::ReplyProc;
        break;
    case Socks5Method::UserPass:
        state = Socks5State::MethodSelected;
        if (!opt.socks5_fast) {
            SendAuth();
        }
        proc = &Socks5RWer::AuthProc;
        break;
    default:
        Fail(PROTOCOL_ERR);
        break;
    }
    return 2;
}

size_t Socks5RWer::AuthProc(Buffer&& bb) {
    if (bb.len < 2) {
        return 0;
    }
    const uchar* data = (const uchar*)bb.data();
    if (data[0] != SOCKS5_AUTH_VERSION) {
        Fail(PROTOCOL_ERR);
        return 0;
    }
    if (data[1] != 0x00) {
        LOGD(DSOCKS, "<socks5> auth failed: %u\n", (unsigned)data[1]);
        Fail(data[1]);
        return 0;
    }
    LOGD(DSOCKS, "<socks5> auth ok\n");
    state = Socks5State::AuthOk;
    if (!opt.socks5_fast) {
        SendRequest();
    }
    proc = &Socks5RWer::ReplyProc;
    return 2;
}

size_t Socks5RWer::ReplyProc(Buffer&& bb) {
    if (bb.len < SOCKS5_REPLY_HEAD_LEN) {
        return 0;
    }
    size_t total = bb.len;
    const uchar* data = (const uchar*)bb.data();
    if (data[0] != SOCKS5_VERSION || data[2] != 0x00) {
        Fail(PROTOCOL_ERR);
        return 0;
    }
    if (data[1] != 0x00) {
        LOGD(DSOCKS, "<socks5> reply failed: %u\n", (unsigned)data[1]);
        Fail(data[1]);
        return 0;
    }

    Socks5AddrType type = (Socks5AddrType)data[3];
    sockaddr_storage reply_bound_ss{};
    bb.reserve((int)SOCKS5_REPLY_HEAD_LEN);
    if (DecodeAddressPort(bb, type, reply_bound_ss) == 0) {
        return 0;
    }

    if (isAnyAddress(&reply_bound_ss) && !addrs.empty()) {
        uint16_t port_n = 0;
        if (reply_bound_ss.ss_family == AF_INET) {
            port_n = ((sockaddr_in*)&reply_bound_ss)->sin_port;
        } else if (reply_bound_ss.ss_family == AF_INET6) {
            port_n = ((sockaddr_in6*)&reply_bound_ss)->sin6_port;
        }

        reply_bound_ss = addrs.front();

        if (reply_bound_ss.ss_family == AF_INET) {
            ((sockaddr_in*)&reply_bound_ss)->sin_port = port_n;
        } else if (reply_bound_ss.ss_family == AF_INET6) {
            ((sockaddr_in6*)&reply_bound_ss)->sin6_port = port_n;
        }
    }

    if (reply_bound_ss.ss_family == AF_INET) {
        auto* sin = (sockaddr_in*)&reply_bound_ss;
        if (sin->sin_port == 0) {
            sin->sin_port = htons(server.port);
        }
    } else if (reply_bound_ss.ss_family == AF_INET6) {
        auto* sin6 = (sockaddr_in6*)&reply_bound_ss;
        if (sin6->sin6_port == 0) {
            sin6->sin6_port = htons(server.port);
        }
    }

    LOGD(DSOCKS, "<socks5> reply ok: bound=%s\n", storage_ntoa(&reply_bound_ss));
    state = Socks5State::Established;
    proc = &Socks5RWer::DefaultProc;
    bound_ss = std::make_unique<sockaddr_storage>(reply_bound_ss);

    if (strcmp(dst.protocol, "udp") == 0 && !udp_rwer) {
        udp_cb = IRWerCallback::create()
            ->onRead([this](Buffer&& bb) {
                return ProcUdp(bb);
            })
            ->onError([this](int ret, int code) {
                ErrorHE(ret, code);
            });
        udp_rwer = std::make_shared<PacketRWer>(*bound_ss, Protocol::UDP, udp_cb);
    }
    connected(reply_bound_ss);
    return total - bb.len;
}

size_t Socks5RWer::DefaultProc(Buffer&& bb) {
    if (auto cb = callback.lock(); cb) {
        return cb->readCB(std::move(bb));
    }
    return 0;
}

void Socks5RWer::SendGreeting() {
    uint8_t methods = 1;
    Block buff(2 + methods);
    auto* data = (uchar*)buff.data();
    data[0] = SOCKS5_VERSION;
    data[1] = methods;
    Socks5Method method = (server.credit.user[0] != '\0' || server.credit.pass[0] != '\0') ?
        Socks5Method::UserPass : Socks5Method::NoAuth;
    data[2] = (uchar)method;
    LOGD(DSOCKS, "<socks5> send greeting: method=%u\n", (unsigned)method);
    StreamRWer::Send(Buffer{std::move(buff), 2 + (size_t)methods});
}

void Socks5RWer::SendAuth() {
    if (server.credit.user[0] == '\0' && server.credit.pass[0] == '\0') {
        Fail(PROTOCOL_ERR);
        return;
    }
    size_t username_len = strnlen(server.credit.user, sizeof(server.credit.user));
    size_t password_len = strnlen(server.credit.pass, sizeof(server.credit.pass));
    LOGD(DSOCKS, "<socks5> send auth: userlen=%zu\n", username_len);
    size_t len = 3 + username_len + password_len;
    Block buff(len);
    auto* data = (uchar*)buff.data();
    data[0] = SOCKS5_AUTH_VERSION;
    data[1] = (uchar)username_len;
    memcpy(data + 2, server.credit.user, username_len);
    data[2 + username_len] = (uchar)password_len;
    memcpy(data + 3 + username_len, server.credit.pass, password_len);
    StreamRWer::Send(Buffer{std::move(buff), len});
    state = Socks5State::AuthSent;
}

static size_t EncodeSocks5Address(Buffer& bb, const Destination& dst) {
    Socks5AddrType type = Socks5AddrType::Domain;
    const char* host = dst.hostname;
    size_t host_len = strnlen(host, DOMAINLIMIT);
    const char* host_ptr = host;
    char host_buf[DOMAINLIMIT];
    if (host_len >= 2 && host[0] == '[' && host[host_len - 1] == ']') {
        host_len -= 2;
        if (host_len >= DOMAINLIMIT) {
            return 0;
        }
        memcpy(host_buf, host + 1, host_len);
        host_buf[host_len] = '\0';
        host_ptr = host_buf;
    }
    in_addr ipv4{};
    in6_addr ipv6{};
    if (inet_pton(AF_INET, host_ptr, &ipv4) == 1) {
        type = Socks5AddrType::IPv4;
    } else if (inet_pton(AF_INET6, host_ptr, &ipv6) == 1) {
        type = Socks5AddrType::IPv6;
    } else {
        if (host_len == 0 || host_len > 255) {
            return 0;
        }
        type = Socks5AddrType::Domain;
    }
    size_t addr_len = (type == Socks5AddrType::IPv4) ? sizeof(ipv4) :
        (type == Socks5AddrType::IPv6) ? sizeof(ipv6) : (host_len + 1);
    size_t len = 1 + addr_len + 2;
    bb.reserve(-(int)len);
    auto* data = (uchar*)bb.mutable_data();
    data[0] = (uchar)type;
    if (type == Socks5AddrType::IPv4) {
        memcpy(data + 1, &ipv4, sizeof(ipv4));
    } else if (type == Socks5AddrType::IPv6) {
        memcpy(data + 1, &ipv6, sizeof(ipv6));
    } else {
        data[1] = (uchar)host_len;
        memcpy(data + 2, host_ptr, host_len);
    }
    set16(data + 1 + addr_len, dst.port);
    return len;
}

void Socks5RWer::SendRequest() {
    // 4 bytes header + 256 bytes address + 2 bytes port, 512 is enough
    Block buff((size_t)0, 512);
    Buffer bb(std::move(buff), 0);

    if (EncodeSocks5Address(bb, dst) == 0) {
        Fail(PROTOCOL_ERR);
        return;
    }

    bb.reserve(-3);
    auto* data = (uchar*)bb.mutable_data();
    data[0] = SOCKS5_VERSION;
    data[1] = (strcmp(dst.protocol, "udp") == 0) ?
        (uchar)Socks5Cmd::UdpAssociate : (uchar)Socks5Cmd::Connect;
    data[2] = 0x00;

    LOGD(DSOCKS, "<socks5> send request: cmd=%u dst=%s\n", (unsigned)data[1], dumpDest(dst).c_str());
    StreamRWer::Send(std::move(bb));
    state = Socks5State::RequestSent;
}

void Socks5RWer::SendUdpPayload(Buffer&& payload) {
    if (udp_rwer == nullptr) {
        LOGE("<socks5> udp relay not ready, drop it: [%d]: %zd\n", (int)payload.id, payload.len);
        return;
    }
    if(EncodeSocks5Address(payload, dst) == 0) {
        Fail(PROTOCOL_ERR);
        return;
    }
    payload.reserve(-3);
    auto* data = (uchar*)payload.mutable_data();
    data[0] = 0x00;
    data[1] = 0x00;
    data[2] = 0x00;

    LOGD(DSOCKS, "<socks5> udp send: %s len:%zu\n", dumpDest(dst).c_str(), payload.len);
    udp_rwer->Send(std::move(payload));
}

void Socks5RWer::Fail(int err) {
    state = Socks5State::Error;
    proc = nullptr;
    udp_cb = nullptr;
    ErrorHE(PROTOCOL_ERR, err);
}

void Socks5RWer::Send(Buffer&& bb) {
    if (stats == RWerStats::Error) {
        return;
    }
    if (state != Socks5State::Established) {
        LOGE("<socks5> send before established\n");
        return;
    }
    if (strcmp(dst.protocol, "udp") == 0) {
        if (bb.len == 0) {
            flags |= RWER_SHUTDOWN;
            return;
        }
        SendUdpPayload(std::move(bb));
    } else {
        StreamRWer::Send(std::move(bb));
    }
}

void Socks5RWer::ConsumeRData(uint64_t id) {
    assert(!(flags & RWER_READING));
    flags |= RWER_READING;
    defer([this]{ flags &= ~RWER_READING;});
    while (rb.length() > 0) {
        if (state == Socks5State::Error) {
            return;
        }
        Buffer wb = rb.get();
        wb.id = id;
        size_t ret = (this->*proc)(std::move(wb));
        if (ret == 0) {
            break;
        }
        rb.consume(ret);
    }
    if (rb.cap() == 0) {
        LOGD(DSOCKS, "<socks5> cap is full, stop reading\n");
        delEvents(RW_EVENT::READ);
    }
    if (rb.length() == 0 && isEof() && (flags & RWER_EOFDELIVED) == 0) {
        if (state == Socks5State::Established) {
            if (auto cb = callback.lock(); cb) {
                cb->readCB({nullptr, id});
            }
            flags |= RWER_EOFDELIVED;
        } else if (state != Socks5State::Error) {
            Fail(PROTOCOL_ERR);
        }
    }
}

void Socks5RWer::dump_status(Dumper dp, void* param) {
    dp(param, "Socks5RWer <%d> (%s -> %s): rlen: %zu, wlen: %zu, stats: %d, state: %s, event: %s, cb: %ld\n",
       getFd(), dumpDest(server).c_str(), dumpDest(dst).c_str(),
       rlength(0), wbuff.length(), (int)stats, Socks5StateStrings[(int)state], events_string[(int)getEvents()], callback.use_count());
    if(udp_rwer) {
        udp_rwer->dump_status(dp, param);
    }
}

size_t Socks5RWer::mem_usage() {
    size_t usage = sizeof(*this) + (rb.cap() + rb.length()) + wbuff.length();
    if(udp_rwer) {
        usage += udp_rwer->mem_usage();
    }
    return usage;
}
