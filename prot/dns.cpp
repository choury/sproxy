#include "dns.h"
#include "misc/job.h"
//#include "common.h"

#include <unordered_map>
#include <set>

#include <string.h>
#include <assert.h>


#define BUF_SIZE 1024

#define RESOLV_FILE "/etc/resolv.conf"
#define DNSPORT     53
#define DNSTIMEOUT  5000                // dns 超时时间(ms)


static uint16_t id_cur = 1;

class Dns_srv:public Con{
    char name[INET6_ADDRSTRLEN];
public:
    explicit Dns_srv(const char* name);
    ~Dns_srv();
    virtual void DnshandleEvent(uint32_t events);
    int query(const char *host, int type, uint32_t id);
    virtual void dump_stat()override;
};

std::vector<Dns_srv *> srvs;


struct Dns_Req{
    DNSCBfunc func;
    void *param;
};

struct Dns_Rcd{
    std::list<sockaddr_un> addrs;
    uint32_t  ttl;
    time_t gettime;
};

typedef struct Dns_Status {
    uint16_t id;
    uint16_t times;
#define QARECORD     0x1
#define QAAAARECORD  0x2
#define GARECORD     0x10
#define GAAAARECORD  0x20
    uint16_t flags;
    char host[DOMAINLIMIT];
    std::list<Dns_Req> reqs;
    Dns_Rcd rcd;
} Dns_Status;

typedef struct Dns_RawReq {
    char host[DOMAINLIMIT];
    uint16_t type;
    uint16_t id;
    uint16_t times;
    DNSRAWCB func;
    void *param;
} Dns_RawReq;

std::unordered_map<uint16_t, std::string> querying_index_id;
std::unordered_map<std::string, Dns_Status *> querying_index_host;
std::unordered_map<uint16_t, Dns_RawReq *> querying_raw_id;
std::unordered_map<std::string, Dns_Rcd> rcd_cache;

void dns_expired(const char* host) {
    del_job((job_func)dns_expired, (void *)host);
    assert(rcd_cache.count(host));
    LOGD(DDNS, "%s: expired\n", host);
    rcd_cache.erase(host);
}

void query_timeout(uint16_t id);
void query_back(Dns_Status *dnsst);

#ifdef __ANDROID__
#include <sys/system_properties.h>
static int dnsinit() {
    assert(srvs.empty());
    char ipaddr[PROP_VALUE_MAX];
    __system_property_get("net.dns1", ipaddr);
    if(strlen(ipaddr)) {
        try {
            new Dns_srv(ipaddr);
        } catch (...) {
        }
    }
    __system_property_get("net.dns2", ipaddr);
    if(strlen(ipaddr)){
        try{
            new Dns_srv(ipaddr);
        }catch(...){
        }
    }
    return srvs.size();
}
#else
static int dnsinit() {
    assert(srvs.empty());
    FILE *res_file = fopen(RESOLV_FILE, "r");
    if (res_file == NULL) {
        LOGE("[DNS] open resolv file:%s failed:%s\n", RESOLV_FILE, strerror(errno));
        return 0;
    }
    char line[100];
    while (fscanf(res_file, "%99[^\n]\n", line)!= EOF) {
        char command[11], ipaddr[INET6_ADDRSTRLEN];
        sscanf(line, "%10s %45s", command, ipaddr);
        if (strcmp(command, "nameserver") == 0) {
            try{
                new Dns_srv(ipaddr);
            }catch(...){
                continue;
            }
        }
    }
    fclose(res_file);
    return srvs.size();
}
#endif

void flushdns(){
    for(auto& i:rcd_cache){
       del_job((job_func)dns_expired, (void *)i.first.c_str());
    }
    rcd_cache.clear();
    for(auto i: querying_index_id){
        del_job((job_func)query_timeout, (void *)(long)i.first);
    }
    querying_index_id.clear();
    for(auto i: querying_index_host){
        delete i.second;
    }
    querying_index_host.clear();
    for(auto i: querying_raw_id){
        delete i.second;
    }
    querying_raw_id.clear();
}

void query_back(Dns_Status *dnsst){
    for(auto i: dnsst->reqs){
        i.func(i.param, dnsst->host, dnsst->rcd.addrs);   //func 肯定不为空
    }
    del_job((job_func)query_back, dnsst);
    delete dnsst;
}


static void query(Dns_Status* dnsst){
    assert(id_cur &1);
    while(srvs.size() == 0) {
        dnsinit();
        if (srvs.size() == 0) {
            sleep(5);
        }
    }
    dnsst->id = id_cur;
    if(disable_ipv6){
        dnsst->flags = QAAAARECORD | GAAAARECORD;
    }else{
        dnsst->flags = 0;
    }

    sockaddr_un addr;
    if (inet_pton(AF_INET, dnsst->host, &addr.addr_in.sin_addr) == 1) {
        addr.addr_in.sin_family = AF_INET;
        dnsst->rcd.addrs.push_back(addr);
        add_job((job_func)query_back, dnsst, 0);
        return ;
    }

    if (inet_pton(AF_INET6, dnsst->host, &addr.addr_in6.sin6_addr) == 1) {
        addr.addr_in6.sin6_family = AF_INET6;
        dnsst->rcd.addrs.push_back(addr);
        add_job((job_func)query_back, dnsst, 0);
        return ;
    }

    if (rcd_cache.count(dnsst->host)) {
        dnsst->rcd = rcd_cache[dnsst->host];
        add_job((job_func)query_back, dnsst, 0);
        if(dnsst->rcd.gettime + dnsst->rcd.ttl - time(nullptr) > 15){
            return ;
        }
        //刷新ttl
        Dns_Status * newst = new Dns_Status;
        newst->times = 0;
        newst->flags = dnsst->flags;
        newst->id = dnsst->id;
        strcpy(newst->host, dnsst->host);
        dnsst = newst;
    }

    for (size_t i = dnsst->times%srvs.size(); i < srvs.size(); ++i) {
        if (!(dnsst->flags & QARECORD) && srvs[i]->query(dnsst->host, 1, dnsst->id)) {
            dnsst->flags |= QARECORD;
        }
        if (!(dnsst->flags & QAAAARECORD) && srvs[i]->query(dnsst->host, 28, dnsst->id+1)) {
            dnsst->flags |= QAAAARECORD;
        }
        if((dnsst->flags & QARECORD) &&(dnsst->flags & QAAAARECORD)) {
            break;
        }
    }
    dnsst->times++;
    querying_index_id[dnsst->id] = dnsst->host;
    querying_index_host[dnsst->host] = dnsst;
    add_job((job_func)query_timeout, (void *)(size_t)dnsst->id, DNSTIMEOUT);
    id_cur += 2;
}


void query(const char *host , DNSCBfunc func, void *param) {
    if(querying_index_host.count(host)){
        querying_index_host[host]->reqs.push_back(Dns_Req{
            func, param
        });
        return;
    }
    
    Dns_Status *dnsst = new Dns_Status;
    dnsst->times = 0;
    dnsst->reqs.push_back(Dns_Req{
            func, param
        });

    snprintf(dnsst->host, sizeof(dnsst->host), "%s", host);
    query(dnsst);
}

static void query(Dns_RawReq* dnsreq){
    assert(id_cur &1);
    while(srvs.size() == 0) {
        dnsinit();
        if(srvs.size() == 0){
            sleep(5);
        }
    }
    dnsreq->id = id_cur;
    for (size_t i = dnsreq->times%srvs.size(); i < srvs.size(); ++i) {
        if(srvs[i]->query(dnsreq->host, dnsreq->type, id_cur))
            break;
    }

    dnsreq->times++;
    querying_raw_id[id_cur] = dnsreq;
    add_job((job_func)query_timeout, (void *)(size_t)id_cur, DNSTIMEOUT);
    id_cur += 2;
}

void query(const char *host , uint16_t type, DNSRAWCB func, void *param) {
    Dns_RawReq *dnsreq = new Dns_RawReq;
    snprintf(dnsreq->host, sizeof(dnsreq->host), "%s", host);
    dnsreq->type = type;
    dnsreq->times = 0;
    dnsreq->func = func;
    dnsreq->param = param;
    query(dnsreq);
}

void query_timeout(uint16_t id){
    assert(querying_index_id.count(id) || querying_raw_id.count(id));
    del_job((job_func)query_timeout, (void *)(size_t)id);
    if(querying_raw_id.count(id)){
        auto req = querying_raw_id[id];
        querying_raw_id.erase(id);

        if(req->times <= 5){
            LOG("[DNS] %s: raw query time out, retry...\n", req->host);
            query(req);
        }else{
            LOG("[DNS] %s: raw query time out\n", req->host);
            req->func(req->param, nullptr, 0);
            delete req;
        }
    }else{
        auto host = querying_index_id[id];
        querying_index_id.erase(id);
        assert(querying_index_host.count(host));
        auto status = querying_index_host[host];
        querying_index_host.erase(host);
        del_job((job_func)query_timeout, (void *)(size_t)id);
        if(status->rcd.addrs.empty() && status->times <= 5) {
            LOG("[DNS] %s: time out, retry...\n", status->host);
            query(status);
        }else{
            for(auto i: status->reqs){
                i.func(i.param, status->host, status->rcd.addrs);
            }
            delete status;
        }
    }
}

void RcdDown(const char *hostname, const sockaddr_un &addr) {
    LOG("[DNS] down for %s: %s\n", hostname, getaddrstring(&addr));
    if (rcd_cache.count(hostname)) {
        auto &addrs  = rcd_cache[hostname].addrs;
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
}

Dns_srv::Dns_srv(const char* name):Con(0){
    sockaddr_un addr;
    if (inet_pton(AF_INET, name, &addr.addr_in.sin_addr) == 1) {
        addr.addr_in.sin_family = AF_INET;
        addr.addr_in.sin_port = htons(DNSPORT);
    } else if (inet_pton(AF_INET6, name, &addr.addr_in6.sin6_addr) == 1) {
        addr.addr_in6.sin6_family = AF_INET6;
        addr.addr_in6.sin6_port = htons(DNSPORT);
    } else {
        LOGE("[DNS] %s is not a valid ip address\n", name);
        throw 0;
    }
    int fd = Connect(&addr, SOCK_DGRAM);
    if (fd == -1) {
        LOGE("[DNS] connecting  %s error:%s\n", name, strerror(errno));
        throw 0;
    }
    this->fd = fd;
    strcpy(this->name, name);
    LOGD(DDNS, "new dns server: %s\n", name);
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
    char buf[BUF_SIZE];
    if (events & EPOLLIN) {
        int len = read(fd, buf, BUF_SIZE);

        if ( len <= 0 ) {
            LOGE("[DNS] read error: %s\n", strerror(errno));
            return;
        }
        DNS_HDR *dnshdr = (DNS_HDR *)buf;
        uint16_t id = ntohs(dnshdr->id);

        if(querying_raw_id.count(id)){
            del_job((job_func)query_timeout, (void *)(size_t)id);
            Dns_RawReq *dnsreq =  querying_raw_id[id];
            querying_raw_id.erase(id);
            dnsreq->func(dnsreq->param, buf, len);
            delete dnsreq;
            return;
        }
        Dns_Rr dnsrcd(buf);
    
        uint32_t flags=0;
        if (id & 1) {
            if (querying_index_id.count(id) == 0) {
                LOG("[DNS] Get a unkown id:%d\n", id);
                return;
            }
            flags |= GARECORD;
        } else {
            id--;
            if (querying_index_id.count(id) == 0) {
                LOG("[DNS] Get a unkown id:%d\n", id);
                return;
            }
            flags |= GAAAARECORD;
        }
        auto host = querying_index_id[id];
        Dns_Status *dnsst = querying_index_host[host];
        dnsst->flags |= flags;

        if(dnsrcd.addrs.size()){
            for(auto i: dnsrcd.addrs){
                dnsst->rcd.addrs.push_back(i);
            }
            dnsst->rcd.gettime = time(0);
            dnsst->rcd.ttl = dnsrcd.ttl;
        }

        if ((dnsst->flags & GARECORD) &&(dnsst->flags & GAAAARECORD)) {
            del_job((job_func)query_timeout, (void *)(size_t)id);
            querying_index_id.erase(id);
            querying_index_host.erase(host);
            if (!dnsst->rcd.addrs.empty()) {
                dnsst->rcd.gettime = time(nullptr);
                rcd_cache[host] =  dnsst->rcd;
                add_job((job_func)dns_expired,
                        (void *)rcd_cache.find(host)->first.c_str(),
                        dnsst->rcd.ttl * 1000);
            }
            for(auto i: dnsst->reqs ){
                i.func(i.param, dnsst->host, dnsst->rcd.addrs);
            }
            delete dnsst;
        }
    }
    if (events & EPOLLERR || events & EPOLLHUP) {
        int       error = 0;
        socklen_t errlen = sizeof(error);

        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, (void*)&error, &errlen) == 0) {
            LOG("[DNS] unkown error: %s\n", strerror(error));
            delete this;
        }
    }
}


int Dns_srv::query(const char *host, int type, uint32_t id) {
    unsigned char  buf[BUF_SIZE];
    int len = Dns_Que(host, type, id).build(buf);
    if (write(fd, buf, len)!= len) {
        LOGE("[DNS] write error: %s\n", strerror(errno));
        delete this;
        return 0;
    }
    return id;
}

void Dns_srv::dump_stat(){
    LOG("Dns_srv %p: %s\n", this, name);
}


void dump_dns(){
    LOG("Dns querying:\n");
    for(auto i: querying_index_id){
       assert(querying_index_host.count(i.second));;
       LOG("    %d: %s\n", i.first, i.second.c_str());
    }
    LOG("Dns cache:\n");
    for(auto i: rcd_cache){
        LOG("    %s: %ld\n", i.first.c_str(), i.second.ttl+i.second.gettime-time(0));
        for(auto j: i.second.addrs){
            char ip[INET6_ADDRSTRLEN];
            switch(j.addr.sa_family){
            case AF_INET:
                inet_ntop(j.addr.sa_family, &j.addr_in.sin_addr, ip, sizeof(ip));
                break;
            case AF_INET6:
                inet_ntop(j.addr.sa_family, &j.addr_in6.sin6_addr, ip, sizeof(ip));
                break;
            default:
                LOGE("Wrong ip address type: %d\n", j.addr.sa_family);
                strcpy(ip, "UNKOWN");
            }
            LOG("        %s\n", ip);
        }
    }
}


typedef struct DNS_QUE {
// 1: A
// 2: NS
// 5: CNAME
// 6: SOA
// 11: WKS
// 12: PTR
// 13: HINFO
// 15: MX
// 28: AAAA
// 252: AXFR
// 255: ANY
    uint16_t type;
    uint16_t classes;            // 通常为1，表示获取因特网地址（IP地址）
} __attribute__((packed)) DNS_QUE;


typedef struct DNS_RR {
    uint16_t type;
    uint16_t classes;
    uint32_t TTL;                // 缓存时间
    uint16_t rdlength;           // rdata 长度
} __attribute__((packed)) DNS_RR;

static const unsigned char * getdomain(const DNS_HDR *hdr, const unsigned char *p, char* domain) {
    const unsigned char* buf = (const unsigned char *)hdr;
    while (*p) {
        if (*p > 63) {
            const unsigned char *q = buf+((*p & 0x3f) <<8) + *(p+1);
            getdomain(hdr, q, domain);
            return p+2;
        } else {
            memcpy(domain, p+1, *p);
            domain[*p]='.';
            domain[*p+1]=0;
            domain += *p+1;
            p+= *p+1;
        }
    }
    domain[-1] = 0;
    return p+1;
}

int putdomain(unsigned char *buf, const char *domain){
    unsigned char *p = buf+1;
    sprintf((char *)p, "%s", domain);

    int i = 0;
    while(*p){
        if ( *p == '.' ) {
            *(p-i-1) = i;
            i = 0;
        } else {
            i++;
        }
        p++;
    }
    *(p-i-1) = i;
    return p-buf+1;
}


Dns_Que::Dns_Que(const std::string& host, uint16_t type, uint16_t id):host(host), type(type), id(id) {

}

Dns_Que::Dns_Que(const char* buff) {
    const DNS_HDR *dnshdr = (const DNS_HDR*)buff;

    id = ntohs(dnshdr->id);
    char domain[DOMAINLIMIT];
    const unsigned char *p = getdomain(dnshdr, (const unsigned char *)(dnshdr+1), domain);
    host = (char *)domain;
    const DNS_QUE *que = (const DNS_QUE*)p;
    type = ntohs(que->type);
    assert(ntohs(que->classes) == 1);
}



int Dns_Que::build(unsigned char* buf)const {
    DNS_HDR  *dnshdr = (DNS_HDR *)buf;
    dnshdr->id = htons(id);
    dnshdr->flag = htons(RD);
    dnshdr->numq = htons(1);
    dnshdr->numa = 0;
    dnshdr->numa1 = 0;
    dnshdr->numa2 = 0;

    int len = sizeof(DNS_HDR);

    len += putdomain(buf+len, host.c_str());

    DNS_QUE  *que = (DNS_QUE *)(buf+len);
    que->classes = htons(1);
    que->type = htons(type);

    return len+sizeof(DNS_QUE);
}

Dns_Rr::Dns_Rr(const char* buff) {
    const DNS_HDR *dnshdr = (const DNS_HDR *)buff;
    id = ntohs(dnshdr->id);

    uint16_t flag = ntohs(dnshdr->flag);
    if ((flag & QR) == 0 || (flag & RCODE_MASK) != 0) {
        LOG("[DNS] ack error:%u\n", flag & RCODE_MASK);
        return;
    }
    const unsigned char *p = (const unsigned char *)(dnshdr +1);
    uint16_t numq = ntohs(dnshdr->numq);
    for (int i = 0; i < numq; ++i) {
        char domain[DOMAINLIMIT];
        p = (unsigned char *)getdomain(dnshdr, p, domain);
        LOGD(DDNS, "[%d]: \n", dnshdr->id);
        p+= sizeof(DNS_QUE);
    }
    uint16_t numa = ntohs(dnshdr->numa);
    for(int i = 0; i < numa; ++i) {
        char domain[DOMAINLIMIT];
        p = (unsigned char *)getdomain(dnshdr, p, domain);
        DNS_RR *dnsrr = (DNS_RR *)p;
        assert(ntohs(dnsrr->classes) == 1);

        uint32_t ttl = ntohl(dnsrr->TTL);
        this->ttl = ttl > this->ttl? ttl:this->ttl;

        p+= sizeof(DNS_RR);
#ifndef NDEBUG
        char ipaddr[INET6_ADDRSTRLEN];
#endif
        switch (ntohs(dnsrr->type)) {
            sockaddr_un ip;
        case 1:
            ip.addr_in.sin_family = AF_INET;
            memcpy(&ip.addr_in.sin_addr, p, sizeof(in_addr));
            addrs.push_back(ip);
#ifndef NDEBUG
            LOGD(DDNS, "%s ==> %s [%d]\n", domain, inet_ntop(AF_INET, p, ipaddr, sizeof(ipaddr)), ttl);
#endif
            break;
        case 2:
        case 5:
            getdomain(dnshdr, p, domain);
            break;
        case 28:
            ip.addr_in6.sin6_family = AF_INET6;
            memcpy(&ip.addr_in6.sin6_addr, p, sizeof(in6_addr));
            addrs.push_back(ip);
#ifndef NDEBUG
            LOGD(DDNS, "%s ==> %s [%d]\n", domain, inet_ntop(AF_INET6, p, ipaddr, sizeof(ipaddr)), ttl);
#endif
            break;
        }
        p+= ntohs(dnsrr->rdlength);
    }
}

Dns_Rr::Dns_Rr(const in_addr* addr){
    sockaddr_un ip;
    ip.addr_in.sin_family = AF_INET;
    memcpy(&ip.addr_in.sin_addr, addr, sizeof(in_addr));
    ttl = 0;
    addrs.push_back(ip);
}


int Dns_Rr::build(const Dns_Que* query, unsigned char* buf)const {
    int len = query->build(buf);
    DNS_HDR *dnshdr = (DNS_HDR *)buf;
    dnshdr->flag  = htons(QR|RD|RA);
    dnshdr->numa = 0;
    dnshdr->numa1 = 0;
    dnshdr->numa2 = 0;

    for(auto addr : addrs) {
        if(query->type == 1 && addr.addr_in.sin_family == AF_INET){
            len += putdomain(buf+len, query->host.c_str());
            DNS_RR* rr= (DNS_RR*)(buf + len);
            rr->classes = htons(1);
            rr->type = htons(1);
            rr->TTL = htonl(ttl);
            rr->rdlength = htons(sizeof(in_addr));
            memcpy(rr+1, &addr.addr_in.sin_addr, sizeof(in_addr));
            len += sizeof(DNS_RR) + sizeof(in_addr);
            dnshdr->numa ++;
        }
        if(query->type == 28 && addr.addr_in.sin_family == AF_INET6){
            len += putdomain(buf+len, query->host.c_str());
            DNS_RR* rr= (DNS_RR*)(buf + len);
            rr->classes = htons(1);
            rr->type = htons(28);
            rr->TTL = htonl(ttl);
            rr->rdlength = htons(sizeof(in6_addr));
            memcpy(rr+1, &addr.addr_in6.sin6_addr, sizeof(in6_addr));
            len += sizeof(DNS_RR) + sizeof(in6_addr);
            dnshdr->numa ++;
        }
    }
    HTONS(dnshdr->numa);
    return len;
}

