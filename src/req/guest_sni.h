#ifndef GUEST_SNI_H__
#define GUEST_SNI_H__

#include "guest.h"
#include <netinet/in.h>


class Guest_sni: public Guest{
public:
    explicit Guest_sni(int fd, const sockaddr_un *myaddr);
    virtual void response(HttpResHeader* res)override;
    virtual const char *getsrc(const void* index)override;
};

#endif
