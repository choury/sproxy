#include "dns.h"
#include "job.h"
#include "common.h"

#include <unordered_map>
#include <list>
#include <string>

#include <string.h>
#include <errno.h>
#include <assert.h>


#define BUF_SIZE 1024

#define RESOLV_FILE "/etc/resolv.conf"
#define DNSPORT     53
#define DNSTIMEOUT  5000                // dns 超时时间(ms)


static uint16_t id_cur = 1;
static bool dns_inited = false;

std::vector<Dns_srv *> srvs;

class Dns_rcd{
    std::list<sockaddr_un> addrs;
public:
    uint16_t  ttl = 0;
    time_t gettime = 0;
    void push(sockaddr_un &&addr);
    void down(const sockaddr_un &addr);
    bool empty();
    std::vector<sockaddr_un> get();
};


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

typedef struct DNS_QER {
// 类型A，值是1，表示获取目标主机的IP地址。
// 类型CNAME，值是5，表示获得目标主机的别名。
// 类型PTR，值是12，表示反向查询。
// 类型aaaa，值是28，表示查询IPV6地址
    uint16_t type;
    uint16_t classes;            // 通常为1，表示获取因特网地址（IP地址）
} __attribute__((packed)) DNS_QER;


typedef struct DNS_RR {
    uint16_t type;
    uint16_t classes;
    uint32_t TTL;                // 缓存时间
    uint16_t rdlength;           // rdata 长度
} __attribute__((packed)) DNS_RR;

struct Dns_Req{
    DNSCBfunc func;
    void *param;
};

typedef struct Dns_State {
    uint16_t id;
    uint16_t times;
#define QARECORD     0x1
#define QAAAARECORD  0x2
#define GARECORD     0x10
#define GAAAARECORD  0x20
    uint16_t flags;
    char host[DOMAINLIMIT];
    Dns_rcd addr;
    std::list<Dns_Req> reqs;
} Dns_State;

std::unordered_map<uint16_t, Dns_State *> querying_index_id;
std::unordered_map<std::string, Dns_State *> querying_index_host;
std::unordered_map<std::string, Dns_rcd> rcd_cache;

void dns_expired(const char* host) {
    del_job((job_func)dns_expired, (void *)host);
    assert(rcd_cache.count(host));
    assert(time(nullptr) >= rcd_cache[host].gettime + rcd_cache[host].ttl);
    LOGD(DDNS, "%s: expired\n", host);
    rcd_cache.erase(host);
}


void Dns_rcd::push(sockaddr_un &&addr){
    addrs.push_back(std::move(addr));
}

void Dns_rcd::down(const sockaddr_un& addr) {
    for (auto i = addrs.begin(); i != addrs.end(); ++i) {
        switch (addr.addr.sa_family) {
        case AF_INET:
            if (memcmp(&addr.addr_in.sin_addr, &i->addr_in.sin_addr, sizeof(in_addr)) == 0) {
                addrs.erase(i);
                addrs.push_back(addr);
                return;
            }
        case AF_INET6:
            if (memcmp(&addr.addr_in6.sin6_addr, &i->addr_in6.sin6_addr, sizeof(in6_addr)) == 0) {
                addrs.erase(i);
                addrs.push_back(addr);
                return;
            }
        }
    }
}

std::vector<sockaddr_un> Dns_rcd::get() {
    std::vector<sockaddr_un> a;
    for(auto i : addrs){
        a.push_back(i);
    }
    return a;
}

bool Dns_rcd::empty() {
    return addrs.empty();
}


static unsigned char * getdomain(unsigned char *buf, unsigned char *p) {
#ifndef NDEBUG
    char buff[DOMAINLIMIT];
    int pos = 0;
#endif
    while (*p) {
        if (*p > 63) {
            unsigned char *q = buf+((*p & 0x3f) <<8) + *(p+1);
            getdomain(buf, q);
            return p+2;
        } else {
#ifndef NDEBUG
            pos += sprintf(buff+pos, "%.*s.", *p, p+1);
#endif
            p+= *p+1;
        }
    }
#ifndef NDEBUG
    LOGD(DDNS, "%s", buff);
#endif
    return p+1;
}


static unsigned char *getrr(
    unsigned char *buf,
    unsigned char *p,
    int num,
    Dns_rcd& rcd)
{
    int i;
    for (i = 0; i < num; ++i) {
        p = getdomain(buf, p);
        DNS_RR *dnsrr = (DNS_RR *)p;
        NTOHS(dnsrr->type);
        NTOHS(dnsrr->classes);
        NTOHL(dnsrr->TTL);
        NTOHS(dnsrr->rdlength);
        p+= sizeof(DNS_RR);
#ifndef NDEBUG
        char ipaddr[INET6_ADDRSTRLEN];
#endif
        switch (dnsrr->type) {
            sockaddr_un ip;
        case 1:
            ip.addr_in.sin_family = PF_INET;
            memcpy(&ip.addr_in.sin_addr, p, sizeof(in_addr));
            rcd.ttl = dnsrr->TTL > rcd.ttl? dnsrr->TTL:rcd.ttl;
            rcd.push(std::move(ip));
#ifndef NDEBUG
            LOGD(DDNS, " ==> %s [%d]\n", inet_ntop(PF_INET, p, ipaddr, sizeof(ipaddr)), dnsrr->TTL);
#endif
            break;
        case 2:
        case 5:
            getdomain(buf, p);
            break;
        case 28:
            ip.addr_in6.sin6_family = PF_INET6;
            memcpy(&ip.addr_in6.sin6_addr, p, sizeof(in6_addr));
            rcd.ttl = dnsrr->TTL > rcd.ttl? dnsrr->TTL:rcd.ttl;
            rcd.push(std::move(ip));
#ifndef NDEBUG
            LOGD(DDNS, "==> %s [%d]\n", inet_ntop(PF_INET6, p, ipaddr, sizeof(ipaddr)), dnsrr->TTL);
#endif
            break;
        }
        p+= dnsrr->rdlength;
    }
    return p;
}

static int dnsinit() {
    for (size_t i = 0; i < srvs.size(); ++i) {
        delete srvs[i];
    }
    srvs.clear();

    FILE *res_file = fopen(RESOLV_FILE, "r");
    if (res_file == NULL) {
        LOGE("[DNS] open resolv file:%s failed:%m\n", RESOLV_FILE);
        return 0;
    }
    char line[100];
    while (fscanf(res_file, "%99[^\n]\n", line)!= EOF) {
        char command[11], ipaddr[INET6_ADDRSTRLEN];
        sscanf(line, "%10s %45s", command, ipaddr);
        if (strcmp(command, "nameserver") == 0) {
            sockaddr_un addr;
            if (inet_pton(PF_INET, ipaddr, &addr.addr_in.sin_addr) == 1) {
                addr.addr_in.sin_family = PF_INET;
                addr.addr_in.sin_port = htons(DNSPORT);
            } else if (inet_pton(PF_INET6, ipaddr, &addr.addr_in6.sin6_addr) == 1) {
                addr.addr_in6.sin6_family = PF_INET6;
                addr.addr_in6.sin6_port = htons(DNSPORT);
            } else {
                LOGE("[DNS] %s is not a valid ip address\n", ipaddr);
                continue;
            }
            int fd = Connect(&addr, SOCK_DGRAM);
            if (fd == -1) {
                LOGE("[DNS] connecting  %s error:%m\n", ipaddr);
                continue;
            }
            new Dns_srv(fd);
        }
    }
    fclose(res_file);
    return srvs.size();
}

void query_back(Dns_State *dnsst){
    for(auto i: dnsst->reqs){
        i.func(i.param, dnsst->host, dnsst->addr.get());   //func 肯定不为空
    }
    del_job((job_func)query_back, dnsst);
    delete dnsst;
}

void query_timeout(uint16_t id){
    assert(querying_index_id.count(id));
    auto oldstate = querying_index_id[id];
    querying_index_id.erase(id);
    assert(querying_index_host.count(oldstate->host));
    querying_index_host.erase(oldstate->host);
    del_job((job_func)query_timeout, (void *)(size_t)id);
    int action;
    if (!oldstate->addr.empty()) {
        action = 1;
    } else  {           // 超时重试
        if(oldstate->times < 5) {
            LOG("[DNS] %s: time out, retry...\n", oldstate->host);
            action  = 2;
        } else {
            action = 3;
        }
    }
    for(auto i: oldstate->reqs){
        switch(action){
        case 1:
            i.func(i.param, oldstate->host, oldstate->addr.get());
            break;
        case 2:
            query(oldstate->host, i.func, i.param, oldstate->times + 1);
            break;
        case 3:
            i.func(i.param, oldstate->host, std::vector<sockaddr_un>());
        }
    }
    delete oldstate;
}

void query(const char *host , DNSCBfunc func, void *param, uint16_t times) {
    if(!dns_inited)
        dns_inited = dnsinit();
    
    if(querying_index_host.count(host)){
        querying_index_host[host]->reqs.push_back(Dns_Req{
            func, param
        });
        return;
    }
    
    Dns_State *dnsst = new Dns_State;
    dnsst->times = times;
    dnsst->reqs.push_back(Dns_Req{
            func, param
        });
    if(disable_ipv6){
        dnsst->flags = QAAAARECORD | GAAAARECORD;
    }else{
        dnsst->flags = 0;
    }
    dnsst->id = id_cur;
    snprintf(dnsst->host, sizeof(dnsst->host), "%s", host);

    sockaddr_un addr;
    if (inet_pton(PF_INET, host, &addr.addr_in.sin_addr) == 1) {
        addr.addr_in.sin_family = PF_INET;
        dnsst->addr.push(std::move(addr));
        add_job((job_func)query_back, dnsst, 0);
        return ;
    }

    if (inet_pton(PF_INET6, host, &addr.addr_in6.sin6_addr) == 1) {
        addr.addr_in6.sin6_family = PF_INET6;
        dnsst->addr.push(std::move(addr));
        add_job((job_func)query_back, dnsst, 0);
        return ;
    }

    if (rcd_cache.count(host)) {
        dnsst->addr = rcd_cache[host];
        add_job((job_func)query_back, dnsst, 0);
        if(dnsst->addr.gettime + dnsst->addr.ttl - time(nullptr) > 15){
            return ;
        }
        //刷新ttl
        Dns_State * newst = new Dns_State;
        newst->times = 0;
        newst->flags = dnsst->flags;
        newst->id = dnsst->id;
        snprintf(newst->host, sizeof(newst->host), "%s", host);
        dnsst = newst;
    }

    for (size_t i = times%srvs.size(); i < srvs.size(); ++i) {
        if (!(dnsst->flags & QARECORD) && srvs[i]->query(host, 1, dnsst->id)) {
            dnsst->flags |= QARECORD;
        }
        if (!(dnsst->flags & QAAAARECORD) && srvs[i]->query(host, 28, dnsst->id+1)) {
            dnsst->flags |= QAAAARECORD;
        }
        if((dnsst->flags & QARECORD) &&(dnsst->flags & QAAAARECORD)) {
            break;
        }
    }
    querying_index_id[dnsst->id] = dnsst;
    querying_index_host[host] = dnsst;
    add_job((job_func)query_timeout, (void *)(size_t)dnsst->id, DNSTIMEOUT);
    id_cur += 2;
}


void RcdDown(const char *hostname, const sockaddr_un &addr) {
    LOGD(DDNS, "down for %s: %s\n", hostname, getaddrstring(&addr));
    if (rcd_cache.count(hostname)) {
        return rcd_cache[hostname].down(addr);
    }
}

Dns_srv::Dns_srv(int fd):Con(fd) {
    updateEpoll(EPOLLIN);
    handleEvent = (void (Con::*)(uint32_t))&Dns_srv::DnshandleEvent;
    srvs.push_back(this);
}

Dns_srv::~Dns_srv(){
    for(auto i=srvs.begin(); i != srvs.end(); i++){
        if(this == *i){
            srvs.erase(i);
            return;
        }
    }
}


void Dns_srv::DnshandleEvent(uint32_t events) {
    unsigned char buf[BUF_SIZE];
    if (events & EPOLLIN) {
        int len = read(fd, buf, BUF_SIZE);

        if ( len <= 0 ) {
            LOGE("[DNS] read error: %m\n");
            return;
        }
        DNS_HDR *dnshdr = (DNS_HDR *)buf;
        NTOHS(dnshdr->id);
        NTOHS(dnshdr->flag);
        NTOHS(dnshdr->numq);
        NTOHS(dnshdr->numa);
        NTOHS(dnshdr->numa1);
        NTOHS(dnshdr->numa2);
    
        uint32_t flags=0;
        if (dnshdr->id & 1) {
            if (querying_index_id.count(dnshdr->id) == 0) {
                LOG("[DNS] Get a unkown id:%d\n", dnshdr->id);
                return;
            }
            flags |= GARECORD;
        } else {
            if (querying_index_id.count(dnshdr->id-1) == 0) {
                LOG("[DNS] Get a unkown id:%d\n", dnshdr->id);
                return;
            }
            dnshdr->id--;
            flags |= GAAAARECORD;
        }
        Dns_State *dnsst = querying_index_id[dnshdr->id];
        dnsst->flags |= flags;

        if ((dnshdr->flag & QR) == 0 || (dnshdr->flag & RCODE_MASK) != 0) {
            LOG("[DNS] ack error:%u\n", dnshdr->flag & RCODE_MASK);
        } else {
            unsigned char *p = buf+sizeof(DNS_HDR);
            for (int i = 0; i < dnshdr->numq; ++i) {
                p = getdomain(buf, p);
                LOGD(DDNS, "[%d]: \n", dnshdr->id);
                p+= sizeof(DNS_QER);
            }
            getrr(buf, p, dnshdr->numa, dnsst->addr);
        }
        if ((dnsst->flags & GARECORD) &&(dnsst->flags & GAAAARECORD)) {
            querying_index_id.erase(dnsst->id);
            querying_index_host.erase(dnsst->host);
            del_job((job_func)query_timeout, (void *)(size_t)dnsst->id);
            if (!dnsst->addr.empty()) {
                dnsst->addr.gettime = time(nullptr);
                rcd_cache[dnsst->host] =  dnsst->addr;
                add_job((job_func)dns_expired,
                        (void *)rcd_cache.find(dnsst->host)->first.c_str(),
                        dnsst->addr.ttl * 1000);
            }
            for(auto i: dnsst->reqs ){
                i.func(i.param, dnsst->host, dnsst->addr.get());
            }
            delete dnsst;
        }
    }
    if (events & EPOLLERR || events & EPOLLHUP) {
        int       error = 0;
        socklen_t errlen = sizeof(error);

        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, (void*)&error, &errlen) == 0) {
            LOG("[DNS] unkown error: %s\n", strerror(error));
        }
    }
}


int Dns_srv::query(const char *host, int type, uint32_t id) {
    unsigned char  buf[BUF_SIZE];
    unsigned char  *p;
    memset(buf, 0, BUF_SIZE);

    DNS_HDR  *dnshdr = (DNS_HDR *)buf;
    dnshdr->id = htons(id);
    dnshdr->flag = htons(RD);
    dnshdr->numq = htons(1);

    p = buf + sizeof ( DNS_HDR ) + 1;
    snprintf((char *)p, buf+sizeof(buf)-p, "%s", host);

    int i = 0;
    while ( p < ( buf + sizeof ( DNS_HDR ) + 1 + strlen ( host ) ) ) {
        if ( *p == '.' ) {
            *(p-i-1) = i;
            i = 0;
        } else {
            i++;
        }
        p++;
    }
    *(p-i-1) = i;

    DNS_QER  *dnsqer = (DNS_QER *)(buf+sizeof(DNS_HDR)+2+strlen(host));
    dnsqer->classes = htons(1);
    dnsqer->type = htons(type);

    int len = sizeof(DNS_HDR)+sizeof(DNS_QER)+strlen(host)+2;
    if (write(fd, buf, len)!= len) {
        LOGE("[DNS] write error: %m\n");
        return 0;
    }
    return id;
}
