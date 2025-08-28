#ifndef DNS_H__
#define DNS_H__

#include "common/common.h"

#include <vector>
#include <netinet/in.h>
#if __APPLE__
#define BIND_8_COMPAT
#endif
#include <arpa/nameser.h>

typedef HEADER DNS_HDR;

struct Dns_Query{
    char domain[DOMAINLIMIT];
    sockaddr_storage ptr_addr;
    uint16_t type;
    uint16_t id;
    bool valid = false;
    Dns_Query(const char* domain, uint16_t type, uint16_t id);
    explicit Dns_Query(const char *buff, size_t len);
    int build(unsigned char *buf)const;
};


class Dns_Result{
    char domain[DOMAINLIMIT];
public:
    std::vector<sockaddr_storage> addrs;
    uint16_t  error = 0;
    uint16_t  type = 0;
    uint16_t  id = 0;
    uint32_t  ttl = 86400;
    explicit Dns_Result(const char* domain);
    explicit Dns_Result(const char* domain, const in_addr* addr);
    explicit Dns_Result(const char* domain, const in6_addr* addr);
    explicit Dns_Result(const char* buff, size_t len);
    int build(const Dns_Query* query, unsigned char *buf)const;
    static int buildError(const Dns_Query* query, unsigned char errcode, unsigned char *buf);
};

#endif
