#include "dns.h"
#include "common.h"

#include <unordered_map>
#include <string>

#include <string.h>
#include <errno.h>


#ifndef NDEBUG
//#define DEBUG_DNS
#endif

#define IGNOREIPV6
#define BUF_SIZE 1024



static unsigned int id_cur = 1;
static bool dns_inited = false;

std::vector<Dns_srv *> srvs;


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
    unsigned int id;
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
    std::vector<sockaddr_un> addr;
} DNS_STATE;

std::unordered_map<int, DNS_STATE *> rcd_index_id;
std::unordered_map<std::string, Dns_rcd> rcd_index_host;

Dns_rcd::Dns_rcd(int result):result(result), gettime(time(NULL)) {
}

Dns_rcd::Dns_rcd(const std::vector<sockaddr_un>& addr):
    result(0), gettime(time(NULL)), addrs(addr) {
}


Dns_rcd::Dns_rcd(const sockaddr_un &addr):result(0), gettime(time(NULL)) {
    this->addrs.push_back(addr);
}

void Dns_rcd::Down(const sockaddr_un& addr) {
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
    std::vector<sockaddr_un>& addr)
{
    int i;
    for (i = 0; i < num; ++i) {
        p = getdomain(buf, p);
        DNS_RR *dnsrr = (DNS_RR *)p;
        NTOHS(dnsrr->type);
        NTOHS(dnsrr->classes);
        NTOHS(dnsrr->TTL);
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
            addr.push_back(ip);
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
            addr.push_back(ip);
#ifdef DEBUG_DNS
            printf("%s", inet_ntop(PF_INET6, p, ipaddr, sizeof(ipaddr)));
#endif
            break;
        }
        p+= dnsrr->rdlength;
#ifdef DEBUG_DNS
        printf("\n");
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
            Dns_srv *srv = new Dns_srv(fd);
            srvs.push_back(srv);
            event.data.ptr = srv;
            epoll_ctl(efd, EPOLL_CTL_ADD, fd, &event);
        }
    }
    fclose(res_file);
    return srvs.size();
}

void query(const char *host , DNSCBfunc func, void *param, uint16_t times) {
    if(!dns_inited)
        dns_inited = dnsinit();
    unsigned char buf[BUF_SIZE];
    if (inet_pton(PF_INET, host, buf) == 1) {
        sockaddr_un addr;
        addr.addr_in.sin_family = PF_INET;
        memcpy(&addr.addr_in.sin_addr, buf, sizeof(in_addr));
        return func(param, Dns_rcd(addr));
    }

    if (inet_pton(PF_INET6, host, buf) == 1) {
        sockaddr_un addr;
        addr.addr_in6.sin6_family = PF_INET6;
        memcpy(&addr.addr_in6.sin6_addr, buf, sizeof(in6_addr));
        return func(param, Dns_rcd(addr));
    }

    if (rcd_index_host.count(host)) {
        return func(param, rcd_index_host[host]);
    }

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

void dnstick() {
    for (auto i = rcd_index_host.begin(); i!= rcd_index_host.end();) {
        if (time(nullptr)-i->second.gettime>= DNSTTL) {           // 超时失效
            rcd_index_host.erase(i++);
        } else {
            i++;
        }
    }

    for (auto i = rcd_index_id.begin(); i!= rcd_index_id.end();) {
        auto tmp=i++;
        auto oldstate = tmp->second;
        if (time(nullptr)-oldstate->reqtime>= DNSTIMEOUT){
            rcd_index_id.erase(tmp);
            if (oldstate->addr.size()) {
                oldstate->func(oldstate->param, Dns_rcd(oldstate->addr));
            } else  {           // 超时重试
                if(oldstate->times < 5) {
                    LOGE("[DNS] %s: time out, retry...\n", oldstate->host);
                    query(oldstate->host, oldstate->func, oldstate->param, ++oldstate->times);
                } else {
                    oldstate->func(oldstate->param, Dns_rcd(DNS_ERR));
                }
            }
            delete oldstate;
        }
    }
}


int dnsstatus(char* buff) {
    int len;
    len = sprintf(buff, "dns cache:\r\n");
    for (auto i = rcd_index_host.begin(); i!= rcd_index_host.end();i++) {
        len += sprintf(buff+len, "[%s]:%u\r\n", i->first.c_str(),
                (uint)(DNSTTL -(time(nullptr)-i->second.gettime)));
    }
    len += sprintf(buff+len, "\r\ndns request:\r\n");
    for (auto i = rcd_index_id.begin(); i!= rcd_index_id.end();i++) {
        len += sprintf(buff+len, "[%s]:%d(%u)\r\n", i->second->host,
                (uint)(time(nullptr)-i->second->reqtime), i->second->times);
    }
    return len;
}



void RcdDown(const char *hostname, const sockaddr_un &addr) {
    if (rcd_index_host.count(hostname)) {
        return rcd_index_host[hostname].Down(addr);
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
            perror("[DNS] read");
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
                LOGE("[DNS] Get a unkown id:%d\n", dnshdr->id);
                return;
            }
            flags |= GARECORD;
        } else {
            if (rcd_index_id.count(dnshdr->id-1) == 0) {
                LOGE("[DNS] Get a unkown id:%d\n", dnshdr->id);
                return;
            }
            dnshdr->id--;
            flags |= GAAAARECORD;
        }
        DNS_STATE *dnsst = rcd_index_id[dnshdr->id];
        dnsst->flags |= flags;

        if ((dnshdr->flag & QR) == 0 || (dnshdr->flag & RCODE_MASK) != 0) {
            LOGE("[DNS] ack error:%u\n", dnshdr->flag & RCODE_MASK);
        } else {
            unsigned char *p = buf+sizeof(DNS_HDR);
            for (int i = 0; i < dnshdr->numq; ++i) {
                p = getdomain(buf, p);
#ifdef DEBUG_DNS
                printf(" :\n");
#endif
                p+= sizeof(DNS_QER);
            }
            getrr(buf, p, dnshdr->numa, dnsst->addr);
        }
        if ((dnsst->flags & GARECORD) &&(dnsst->flags & GAAAARECORD)) {
            rcd_index_id.erase(dnsst->id);
            if (dnsst->addr.size()) {
                rcd_index_host[dnsst->host] = Dns_rcd(dnsst->addr);
                dnsst->func(dnsst->param, Dns_rcd(dnsst->addr));
            } else {
                dnsst->func(dnsst->param, Dns_rcd(DNS_ERR));
            }
            delete dnsst;
        }
    }
    if (events & EPOLLERR || events & EPOLLHUP) {
        int       error = 0;
        socklen_t errlen = sizeof(error);

        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, (void*)&error, &errlen) == 0) {
            LOGE("[DNS] : %s\n", strerror(error));
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
        perror("[DNS] write");
        return 0;
    }
    return id;
}


void flushdns() {
    rcd_index_host.clear();
}


