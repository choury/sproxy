#ifndef QUIC_SERVER_H__
#define QUIC_SERVER_H__

#include "quicio.h"

class Quic_server: public Ep {
    SSL_CTX *ctx = nullptr;
    uint ssl_cert_version = 0;
    std::map<std::string, QuicRWer*> rwers;
    virtual void defaultHE(RW_EVENT events);
    void PushData(const sockaddr_storage* myaddr, const sockaddr_storage* hisaddr, const void* buff, size_t len);
public:
    Quic_server(int fd, SSL_CTX *ctx): Ep(fd),ctx(ctx) {
        assert(ctx);
        setEvents(RW_EVENT::READ);
        handleEvent = (void (Ep::*)(RW_EVENT))&Quic_server::defaultHE;
    }
    virtual ~Quic_server() override{
        SSL_CTX_free(ctx);
    };
    friend QuicRWer;
};

bool operator<(const sockaddr_storage& a, const sockaddr_storage& b);

class Guest_sni;
class Quic_sniServer: public Ep {
    std::map<sockaddr_storage, Guest_sni*> snis;
    virtual void defaultHE(RW_EVENT events);
public:
    explicit Quic_sniServer(int fd): Ep(fd) {
        setEvents(RW_EVENT::READ);
        handleEvent = (void (Ep::*)(RW_EVENT))&Quic_sniServer::defaultHE;
    }
    virtual ~Quic_sniServer() override{
    };
};

#endif
