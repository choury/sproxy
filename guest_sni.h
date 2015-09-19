#ifndef GUEST_SNI_H__
#define GUEST_SNI_H__

#include "peer.h"
#include <netinet/in.h>


class Guest_sni: public Peer{
    char sourceip[INET6_ADDRSTRLEN];
    uint16_t  sourceport;
    size_t readlen = 0;
    char rbuff [1024];
    virtual int showerrinfo(int ret, const char *)override;
    virtual void initHE(uint32_t events);
    virtual void defaultHE(uint32_t events);
    virtual void closeHE(uint32_t events);
    void close();
public:
    explicit Guest_sni ( int fd, sockaddr_in6 *myaddr);
};

#endif