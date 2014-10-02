#ifndef __DNS_H__
#define __DNS_H__

#include <bits/socket.h>
#include <vector>
#include "net.h"

class dns{
    unsigned int id;
    char host[DOMAINLIMIT];
    std::vector<sockaddr> addr;
};

#endif