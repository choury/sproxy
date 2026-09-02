#ifndef RESOLVER_H__
#define RESOLVER_H__

#include "common/common.h"

#include <list>
#include <string>
#include <memory>
#include <netinet/in.h>

#define QARES       1
#define QAAAARES    2
#define QECHRES     4
#define RAWRESOLVER 8  //强制明文UDP解析(跳过DoH)，doh服务器自身的解析用它防递归

//query_host回调的返回：要么错误码(DNS rcode)，要么地址(带ttl)与ech配置。
//解析器实现与缓存结构(resolver.cpp内)不对外暴露
struct Host_Result{
    std::shared_ptr<void> param;
    int error = 0;
    std::list<sockaddr_storage> addrs;
    uint32_t ttl = 0;                       //缓存命中为剩余秒数，新解析为记录TTL
    std::string ech;                        //可信ech配置，无ech知识或负缓存时为空
};

typedef void (*DNSCB)(const Host_Result& result);
typedef void (*DNSRAWCB)(std::shared_ptr<void>, const char *buff, size_t size);

void query_host(const char* host, DNSCB func, std::shared_ptr<void> param, uint32_t flags = 0);
void query_dns(const char* host, int type, DNSRAWCB func, std::shared_ptr<void> param);
void query_raw(const void* data, size_t len, DNSRAWCB func, std::shared_ptr<void> param);
void RcdBlock(const char *hostname, const sockaddr_storage &addr);
//ECH握手被拒后，用retry configs更新ech缓存(len为0表示服务端已回退不支持ech)
void update_ech_cache(const char *hostname, const void* data, size_t len);
void dump_dns(Dumper dp, void* param);

#endif
