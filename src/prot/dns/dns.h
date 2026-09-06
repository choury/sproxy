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

//解析DNS报文question段的首个查询，返回0成功，-1表示报文畸形或无question
int get_dns_question(const char* buff, size_t len, char* domain, size_t domain_len, uint16_t* qtype);

//从DNS响应报文中解析HTTPS RR(type 65)的ech参数(SvcParam key 5),
//多条记录的ech依次拼接为ECHConfigList。返回0表示报文完整(ech可能为空,
//rcode错误或无记录视为无ech),-1表示报文畸形。ttl返回应答记录的最小TTL
int parse_ech_configs(const char* buff, size_t len, std::string& ech_config_list, uint32_t* ttl);

//就地改写DNS应答报文answer段中HTTPS RR(type 65)的SvcParam。
//flags无可执行项或报文畸形时原样返回len；改写只会使报文等长或变短，
//ancount不变，answer后的数据段随收缩前移。返回改写后的报文长度，
//返回长度之后的缓冲区内容未定义，调用方只应消费[0,返回值)区间
#define HTTPS_RR_STRIP_ECH   0x1  //删除ech参数(key 5)
#define HTTPS_RR_FAKE_V4HINT 0x2  //ipv4hint(key 4)整体替换为v4单地址
#define HTTPS_RR_FAKE_V6HINT 0x4  //ipv6hint(key 6)整体替换为v6单地址
#define HTTPS_RR_DROP_V6HINT 0x8  //丢弃ipv6hint(key 6)
size_t rewrite_https_rr(unsigned char* buff, size_t len, unsigned flags, const in_addr* v4, const in6_addr* v6);

#endif
