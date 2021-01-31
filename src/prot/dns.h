#ifndef DNS_H__
#define DNS_H__

#include "common.h"
#include "misc/net.h"

#include <string>
#include <vector>
#include <netinet/in.h>

typedef struct DNS_HDR {
    uint16_t id;            // 查询序列号

#define  QR 0x8000u          // 查询/应答 0/1
#define  OPCODE_STD 0       // 0:标准查询
#define  OPCODE_STR 0x0800  // 1:反向查询
#define  OPCODE_STA 0x1000  // 2:查询服务器状态
#define  AA 0x0400          // 授权应答标志
#define  TC 0x0200          // 截断标志
#define  RD 0x0100u          // 递归查询标志
#define  RA 0x0080u          // 允许递归标志

// 0 没有错误。
// 1 报文格式错误(Format error) - 服务器不能理解请求的报文。
#define DNS_FORMAT_ERROR  1
// 2 服务器失败(Server failure) - 因为服务器的原因导致没办法处理这个请求。
#define DNS_SERVER_FAIL   2
// 3 名字错误(Name Error) - 只有对授权域名解析服务器有意义，指出解析的域名不存在。
#define DNS_NAME_ERROR    3
// 4 没有实现(Not Implemented) - 域名服务器不支持查询类型。
#define DNS_NOT_IMPLE     4
// 5 拒绝(Refused) - 服务器由于设置的策略拒绝给出应答。
// 比如，服务器不希望对某些请求者给出应答，
// 或者服务器不希望进行某些操作（比如区域传送zone transfer）。
#define DNS_REFUSE        5

// 6-15 保留值，暂时未使用。
#define  RCODE_MASK 0x000fu  // 应答码
    uint16_t flag;
    uint16_t numq;               // 问题个数
    uint16_t numa;               // 应答资源个数
    uint16_t numa1;              // 授权记录数
    uint16_t numa2;              // 额外资源记录数
} __attribute__((packed)) DNS_HDR;


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
public:
    char domain[DOMAINLIMIT];
    std::vector<sockaddr_storage> addrs;
    uint16_t  type = 0;
    uint16_t  id = 0;
    uint32_t  ttl = 0xffffffff;
    explicit Dns_Result(const char* domain);
    explicit Dns_Result(const char* domain, const in_addr* addr);
    explicit Dns_Result(const char* domain, const in6_addr* addr);
    explicit Dns_Result(const char* buff, size_t len);
    int build(const Dns_Query* query, unsigned char *buf)const;
    static int buildError(const Dns_Query* query, unsigned char errcode, unsigned char *buf);
};

#endif
