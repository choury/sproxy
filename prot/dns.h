#ifndef DNS_H__
#define DNS_H__

#include "base.h"
#include "misc/net.h"

#include <vector>
#include <list>
#include <string>

#include <unistd.h>
#include <time.h>
#include <netinet/in.h>

typedef struct DNS_HDR {
    uint16_t id;            // 查询序列号

#define  QR 0x8000          // 查询/应答 0/1
#define  OPCODE_STD 0       // 0:标准查询
#define  OPCODE_STR 0x0800  // 1:反向查询
#define  OPCODE_STA 0x1000  // 2:查询服务器状态
#define  AA 0x0400          // 授权应答标志
#define  TC 0x0200          // 截断标志
#define  RD 0x0100          // 递归查询标志
#define  RA 0x0080          // 允许递归标志

// 0 没有错误。
// 1 报文格式错误(Format error) - 服务器不能理解请求的报文。
// 2 服务器失败(Server failure) - 因为服务器的原因导致没办法处理这个请求。
// 3 名字错误(Name Error) - 只有对授权域名解析服务器有意义，指出解析的域名不存在。
// 4 没有实现(Not Implemented) - 域名服务器不支持查询类型。
// 5 拒绝(Refused) - 服务器由于设置的策略拒绝给出应答。
// 比如，服务器不希望对某些请求者给出应答，
// 或者服务器不希望进行某些操作（比如区域传送zone transfer）。

// 6-15 保留值，暂时未使用。
#define  RCODE_MASK 0x000F  // 应答码
    uint16_t flag;
    uint16_t numq;               // 问题个数
    uint16_t numa;               // 应答资源个数
    uint16_t numa1;              // 授权记录数
    uint16_t numa2;              // 额外资源记录数
} __attribute__((packed)) DNS_HDR;



class Dns_srv:public Con{
public:
    explicit Dns_srv(int fd);
    ~Dns_srv();
    virtual void DnshandleEvent(uint32_t events);
    int query(const char *host, int type, uint32_t id);
    virtual void dump_stat()override;
};


class Dns_Que{
public:
    std::string host;
    uint16_t type;
    uint16_t id;
    Dns_Que(const std::string& host, uint16_t type, uint16_t id);
    Dns_Que(const char *buff);
    int build(unsigned char *buf)const;
};


class Dns_Rr{
public:
    std::vector<sockaddr_un> addrs;
    uint16_t  id = 0;
    uint32_t  ttl = 0;
    Dns_Rr(const char *buff);
    Dns_Rr(const in_addr* addr);
    int build(const Dns_Que* query, unsigned char *buf)const;
};


typedef void (*DNSCBfunc)(void *, const char *hostname, std::list<sockaddr_un> addrs);
typedef void (*DNSRAWCB)(void *, const char *buff, size_t size);


void query(const char* host, DNSCBfunc func, void* param);
void query(const char* host, uint16_t type, DNSRAWCB func, void* parm);
void RcdDown(const char *hostname, const sockaddr_un &addr);

#endif
