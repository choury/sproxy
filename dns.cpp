#include "dns.h"
#include "common.h"

#include <unordered_map>
#include <list>
#include <string>

#include <string.h>
#include <errno.h>


//#define DEBUG_DNS

//#define IGNOREIPV6
#define BUF_SIZE 1024

#define RESOLV_FILE "/etc/resolv.conf"
#define DNSPORT     53
#define DNSTIMEOUT  5                // dns 超时时间(s)


static uint16_t id_cur = 1;
static bool dns_inited = false;

std::vector<Dns_srv *> srvs;

class Dns_rcd{
    std::list<std::pair<time_t, sockaddr_un>> addrs;
public:
    void push(sockaddr_un &&addr, uint32_t ttl);
    void down(const sockaddr_un &addr);
    bool empty();
    std::vector<sockaddr_un> get();
    void expired();
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

typedef struct _DNS_QER {
// 类型A，值是1，表示获取目标主机的IP地址。
// 类型CNAME，值是5，表示获得目标主机的别名。
// 类型PTR，值是12，表示反向查询。
// 类型aaaa，值是28，表示查询IPV6地址
    uint16_t type;
    uint16_t classes;            // 通常为1，表示获取因特网地址（IP地址）
} __attribute__((packed)) DNS_QER;


typedef struct _DNS_RR {
    uint16_t type;
    uint16_t classes;
    uint32_t TTL;                // 缓存时间
    uint16_t rdlength;           // rdata 长度
} __attribute__((packed)) DNS_RR;

typedef struct _DNS_STATE {
    uint16_t id;
    time_t reqtime;
    uint16_t times;
#define QARECORD     0x1
#define QAAAARECORD  0x2
#define GARECORD     0x10
#define GAAAARECORD  0x20
    uint16_t flags;
    DNSCBfunc func;
    void *param;
    char host[DOMAINLIMIT];
    Dns_rcd addr;
} DNS_STATE;

std::unordered_map<uint16_t, DNS_STATE *> rcd_index_id;
std::unordered_map<std::string, Dns_rcd> rcd_index_host;
std::list<DNS_STATE *> rcd_gotten_list;

void dnstick(void *) {
    for (auto i = rcd_index_host.begin(); i!= rcd_index_host.end();) {
        i->second.expired();
        if (i->second.empty()) {           // 超时失效
#ifdef DEBUG_DNS
            LOG("[DNS] %s: expired\n", i->first.c_str());
#endif
            i = rcd_index_host.erase(i);
        } else {
            i++;
        }
    }
    for (auto i : rcd_gotten_list){
        i->func(i->param, i->host, i->addr.get());
        delete i;
    }
    rcd_gotten_list.clear();

    for (auto i = rcd_index_id.begin(); i!= rcd_index_id.end();) {
        auto tmp=i++;
        auto oldstate = tmp->second;
        if (time(nullptr)-oldstate->reqtime>= DNSTIMEOUT) {
            rcd_index_id.erase(tmp);
            if (!oldstate->addr.empty()) {
                oldstate->func(oldstate->param, oldstate->host, oldstate->addr.get());
            } else  {           // 超时重试
                if(oldstate->times < 5) {
                    LOG("[DNS] %s: time out, retry...\n", oldstate->host);
                    query(oldstate->host, oldstate->func, oldstate->param, ++oldstate->times);
                } else {
                    oldstate->func(oldstate->param, oldstate->host, std::vector<sockaddr_un>());
                }
            }
            delete oldstate;
        }
    }
}



void Dns_rcd::push(sockaddr_un &&addr, uint32_t ttl){
    addrs.push_back(std::make_pair(time(NULL)+ttl, std::move(addr)));
}

void Dns_rcd::down(const sockaddr_un& addr) {
    for (auto i = addrs.begin(); i != addrs.end(); ++i) {
        switch (addr.addr.sa_family) {
        case AF_INET:
            if (memcmp(&addr.addr_in.sin_addr, &i->second.addr_in.sin_addr, sizeof(in_addr)) == 0) {
                time_t expire = i->first;
                addrs.erase(i);
                addrs.push_back(std::make_pair(expire, addr));
                return;
            }
        case AF_INET6:
            if (memcmp(&addr.addr_in6.sin6_addr, &i->second.addr_in6.sin6_addr, sizeof(in6_addr)) == 0) {
                time_t expire = i->first;
                addrs.erase(i);
                addrs.push_back(std::make_pair(expire, addr));
                return;
            }
        }
    }
}

std::vector<sockaddr_un> Dns_rcd::get() {
    std::vector<sockaddr_un> a;
    for(auto i : addrs){
        a.push_back(i.second);
    }
    return a;
}

bool Dns_rcd::empty() {
    return addrs.empty();
}


void Dns_rcd::expired() {
    time_t now = time(NULL);
    for (auto i = addrs.begin(); i != addrs.end(); ) {
        if(i->first < now){
            i = addrs.erase(i);
        }else{
            i++;
        }
    }
}




static unsigned char * getdomain(unsigned char *buf, unsigned char *p) {
    while (*p) {
        if (*p > 63) {
            unsigned char *q = buf+((*p & 0x3f) <<8) + *(p+1);
            getdomain(buf, q);
            return p+2;
        } else {
#ifdef DEBUG_DNS
            printf("%.*s.", *p, p+1);
#endif
            p+= *p+1;
        }
    }
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
#ifdef DEBUG_DNS
        printf(" ==> ");
        char ipaddr[INET6_ADDRSTRLEN];
#endif
        switch (dnsrr->type) {
            sockaddr_un ip;
        case 1:
            ip.addr_in.sin_family = PF_INET;
            memcpy(&ip.addr_in.sin_addr, p, sizeof(in_addr));
            rcd.push(std::move(ip), dnsrr->TTL);
#ifdef DEBUG_DNS
            printf("%s", inet_ntop(PF_INET, p, ipaddr, sizeof(ipaddr)));
#endif
            break;
        case 2:
        case 5:
            getdomain(buf, p);
            break;
        case 28:
            ip.addr_in6.sin6_family = PF_INET6;
            memcpy(&ip.addr_in6.sin6_addr, p, sizeof(in6_addr));
            rcd.push(std::move(ip), dnsrr->TTL);
#ifdef DEBUG_DNS
            printf("%s", inet_ntop(PF_INET6, p, ipaddr, sizeof(ipaddr)));
#endif
            break;
        }
        p+= dnsrr->rdlength;
#ifdef DEBUG_DNS
        printf(" [%d]\n", dnsrr->TTL);
#endif
    }
    return p;
}

static int dnsinit() {
    struct epoll_event event;
    event.events = EPOLLIN;
    for (size_t i = 0; i < srvs.size(); ++i) {
        delete srvs[i];
    }
    srvs.clear();

    FILE *res_file = fopen(RESOLV_FILE, "r");
    if (res_file == NULL) {
        LOG("[DNS] open resolv file:%s failed:%m\n", RESOLV_FILE);
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
                LOG("[DNS] %s is not a valid ip address\n", ipaddr);
                continue;
            }
            int fd = Connect(&addr, SOCK_DGRAM);
            if (fd == -1) {
                LOG("[DNS] connecting  %s error:%m\n", ipaddr);
                continue;
            }
            Dns_srv *srv = new Dns_srv(fd);
            srvs.push_back(srv);
            event.data.ptr = srv;
            epoll_ctl(efd, EPOLL_CTL_ADD, fd, &event);
        }
    }
    fclose(res_file);
    add_tick_func(dnstick, nullptr);
    return srvs.size();
}

void query(const char *host , DNSCBfunc func, void *param, uint16_t times) {
    if(!dns_inited)
        dns_inited = dnsinit();
    
    DNS_STATE *dnsst = new DNS_STATE;
    dnsst->func = func;
    dnsst->param = param;
    dnsst->times = times;
#ifndef IGNOREIPV6
    dnsst->flags = 0;
#else
    dnsst->flags = QAAAARECORD | GAAAARECORD;
#endif
    dnsst->id = id_cur;
    snprintf(dnsst->host, sizeof(dnsst->host), "%s", host);

    sockaddr_un addr;
    if (inet_pton(PF_INET, host, &addr.addr_in.sin_addr) == 1) {
        addr.addr_in.sin_family = PF_INET;
        dnsst->addr.push(std::move(addr), 0);
        rcd_gotten_list.push_back(dnsst);
        return ;
    }

    if (inet_pton(PF_INET6, host, &addr.addr_in6.sin6_addr) == 1) {
        addr.addr_in6.sin6_family = PF_INET6;
        dnsst->addr.push(std::move(addr), 0);
        rcd_gotten_list.push_back(dnsst);
        return ;
    }

    if (rcd_index_host.count(host)) {
        dnsst->addr = rcd_index_host[host];
        rcd_gotten_list.push_back(dnsst);
        return ;
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
    dnsst->reqtime = time(nullptr);
    rcd_index_id[dnsst->id] = dnsst;
    id_cur += 2;
}


void RcdDown(const char *hostname, const sockaddr_un &addr) {
    if (rcd_index_host.count(hostname)) {
        return rcd_index_host[hostname].down(addr);
    }
}

Dns_srv::Dns_srv(int fd):Con(fd) {
    handleEvent = (void (Con::*)(uint32_t))&Dns_srv::DnshandleEvent;
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
            if (rcd_index_id.count(dnshdr->id) == 0) {
                LOG("[DNS] Get a unkown id:%d\n", dnshdr->id);
                return;
            }
            flags |= GARECORD;
        } else {
            if (rcd_index_id.count(dnshdr->id-1) == 0) {
                LOG("[DNS] Get a unkown id:%d\n", dnshdr->id);
                return;
            }
            dnshdr->id--;
            flags |= GAAAARECORD;
        }
        DNS_STATE *dnsst = rcd_index_id[dnshdr->id];
        dnsst->flags |= flags;

        if ((dnshdr->flag & QR) == 0 || (dnshdr->flag & RCODE_MASK) != 0) {
            LOG("[DNS] ack error:%u\n", dnshdr->flag & RCODE_MASK);
        } else {
            unsigned char *p = buf+sizeof(DNS_HDR);
            for (int i = 0; i < dnshdr->numq; ++i) {
                p = getdomain(buf, p);
#ifdef DEBUG_DNS
                printf(" [%d]: \n", dnshdr->id);
#endif
                p+= sizeof(DNS_QER);
            }
            getrr(buf, p, dnshdr->numa, dnsst->addr);
        }
        if ((dnsst->flags & GARECORD) &&(dnsst->flags & GAAAARECORD)) {
            rcd_index_id.erase(dnsst->id);
            if (!dnsst->addr.empty()) {
                rcd_index_host[dnsst->host] = dnsst->addr;
                dnsst->func(dnsst->param, dnsst->host, dnsst->addr.get());
            } else {
                dnsst->func(dnsst->param, dnsst->host, std::vector<sockaddr_un>());
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


void flushdns() {
    rcd_index_host.clear();
}

