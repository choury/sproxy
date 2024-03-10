#ifndef QUIC_SERVER_H__
#define QUIC_SERVER_H__

#include "quicio.h"

class Quic_server: public Ep {
    SSL_CTX *ctx = nullptr;
    std::map<std::string, QuicRWer*> rwers;
    virtual void defaultHE(RW_EVENT events);
public:
    Quic_server(int fd, SSL_CTX *ctx): Ep(fd),ctx(ctx) {
        assert(ctx);
        setEvents(RW_EVENT::READ);
        handleEvent = (void (Ep::*)(RW_EVENT))&Quic_server::defaultHE;
    }
    virtual ~Quic_server() override{
        SSL_CTX_free(ctx);
    };
    void PushDate(int fd, const sockaddr_storage* addr, const void* buff, size_t len);
    friend QuicRWer;
};

class Quic_sniServer: public Ep {
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
