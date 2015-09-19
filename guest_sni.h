#ifndef GUEST_SNI_H__
#define GUEST_SNI_H__

#include "guest.h"
#include <netinet/in.h>


class Guest_sni: public Guest{
    virtual void initHE(uint32_t events);
public:
    virtual void Response(Peer *who, HttpResHeader& res)override;
    explicit Guest_sni ( int fd, sockaddr_in6 *myaddr);
};

#endif