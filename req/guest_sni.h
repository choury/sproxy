#ifndef GUEST_SNI_H__
#define GUEST_SNI_H__

#include "guest.h"
#include <netinet/in.h>


class Guest_sni: public Guest{
    virtual void initHE(uint32_t events);
public:
    explicit Guest_sni(int fd, sockaddr_in6 *myaddr);
    virtual void response(HttpResHeader* res)override;
    virtual const char *getsrc(void* index)override;
};

#endif
