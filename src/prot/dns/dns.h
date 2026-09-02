#ifndef DNS_H__
#define DNS_H__

#include "common/common.h"
#include "hook/reflect.h"

#include <vector>
#include <string>
#include <netinet/in.h>
#if __APPLE__
#define BIND_8_COMPAT
#endif
#include <arpa/nameser.h>

#ifndef ns_t_https
#define ns_t_https 65
#endif

typedef HEADER DNS_HDR;

struct Dns_Query{
    char domain[DOMAINLIMIT];
    sockaddr_storage ptr_addr;
    uint16_t type;
    uint16_t id;
    bool valid = false;
    Dns_Query(const char* domain, uint16_t type, uint16_t id);
    explicit Dns_Query(const char *buff, size_t len);
    //returns 0 if the buffer is too small
    int build(unsigned char *buf, size_t buf_len)const;
    void reflect(IVisitor& v) {
        reflect_all(domain, ptr_addr, type, id, valid);
    }
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
    //returns 0 if the buffer is too small; otherwise the built length
    int build(const Dns_Query* query, unsigned char *buf, size_t buf_len)const;
    static int buildError(const Dns_Query* query, unsigned char errcode, unsigned char *buf);
};

//从DNS响应报文中解析HTTPS RR(type 65)的ech参数(SvcParam key 5),
//多条记录的ech依次拼接为ECHConfigList。返回0表示报文完整(ech可能为空,
//rcode错误或无记录视为无ech),-1表示报文畸形。ttl返回应答记录的最小TTL
int parse_ech_configs(const char* buff, size_t len, std::string& ech_config_list, uint32_t* ttl);

#endif
