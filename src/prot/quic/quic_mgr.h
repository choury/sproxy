#ifndef QUIC_MGR_H__
#define QUIC_MGR_H__

#include "quicio.h"

class QuicMgr{
    std::map<std::string, QuicRWer*> rwers;
public:
    void PushDate(int fd, const sockaddr_storage* addr, SSL_CTX *ctx, const void* buff, size_t len);
    friend QuicRWer;
};

#endif
