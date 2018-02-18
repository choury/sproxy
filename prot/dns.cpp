#include "dns.h"
#include "misc/job.h"
#include "misc/util.h"
#include "misc/simpleio.h"
#include "misc/index.h"
#include "common.h"

#include <unordered_map>
#include <set>

#include <string.h>
#include <errno.h>
#include <assert.h>


#define BUF_SIZE 1024

#define RESOLV_FILE "/etc/resolv.conf"
#define DNSPORT     53
#define DNSTIMEOUT  5000                // dns 超时时间(ms)


static uint16_t id_cur = 1;

class Dns_srv:public Server{
    char name[INET6_ADDRSTRLEN];
public:
    explicit Dns_srv(const char* name);
    virtual ~Dns_srv();
    void buffHE(const char* buffer, size_t len);
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
    time_t expire_time;
};

typedef struct Dns_Status {
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

Index2<uint16_t, std::string, Dns_Status *> querying_index;
std::unordered_map<uint16_t, Dns_RawReq *> querying_raw_id;
std::unordered_map<std::string, Dns_Rcd> rcd_cache;
std::multimap<int, std::string> expire_time;

int dns_expired(void* ) {
    time_t now = time(nullptr);
    std::set<std::string> should_expired;
    for(auto i =  expire_time.begin(); i!= expire_time.end(); ){
        if(now > i->first){
            should_expired.insert(i->second);
            i = expire_time.erase(i);
        }else{
            break;
        }
    }
    for(auto i : should_expired){
        if(rcd_cache.count(i) && now > rcd_cache[i].expire_time){
            LOGD(DDNS, "%s: expired\n", i.c_str());
            rcd_cache.erase(i);
        }
    }
    return 1;
}

int query_timeout(uint16_t id);
int query_back(Dns_Status *dnsst);

#ifdef __ANDROID__
extern std::vector<std::string> getDns();
static int dnsinit() {
    assert(srvs.empty());
    auto dns = getDns();
    try {
        for (auto i : dns) {
            LOG("[DNS] set dns server: %s\n", i.c_str());
            new Dns_srv(i.c_str());
        }
    }catch (...){

    }
    add_prejob(job_func(dns_expired), 0);
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
    add_prejob(job_func(dns_expired), 0);
    return srvs.size();
}
#endif

void flushdns(){
    while(!srvs.empty()){
        delete srvs.front();
    }
    rcd_cache.clear();
    for(auto i: querying_index.index1()){
        del_delayjob((job_func)query_timeout, (void *)(long)i.first);
        delete i.second->data;
    }
    querying_index.clear();
    for(auto i: querying_raw_id){
        delete i.second;
    }
    querying_raw_id.clear();
}

static void query(Dns_Status* dnsst){
    assert(id_cur &1);
    while(srvs.size() == 0) {
        dnsinit();
        if (srvs.size() == 0) {
            sleep(5);
        }
    }
    id_cur += 2;
    if(disable_ipv6){
        dnsst->flags = QAAAARECORD | GAAAARECORD;
    }else{
        dnsst->flags = 0;
    }

    sockaddr_un addr;
    if (inet_pton(AF_INET, dnsst->host, &addr.addr_in.sin_addr) == 1) {
        addr.addr_in.sin_family = AF_INET;
        dnsst->rcd.addrs.push_back(addr);
        for(auto i: dnsst->reqs){
            i.func(i.param, dnsst->host, dnsst->rcd.addrs);
        }
        delete dnsst;
        return;
    }

    if (inet_pton(AF_INET6, dnsst->host, &addr.addr_in6.sin6_addr) == 1) {
        addr.addr_in6.sin6_family = AF_INET6;
        dnsst->rcd.addrs.push_back(addr);
        for(auto i: dnsst->reqs){
            i.func(i.param, dnsst->host, dnsst->rcd.addrs);
        }
        delete dnsst;
        return;
    }

    if (rcd_cache.count(dnsst->host)) {
        auto& rcd = rcd_cache[dnsst->host];
        for(auto i: dnsst->reqs){
            i.func(i.param, dnsst->host, rcd.addrs);
        }
        if(rcd.expire_time - time(nullptr) > 15){
            delete dnsst;
            return;
        }
        //刷新ttl
        Dns_Status * newst = new Dns_Status;
        newst->times = 0;
        newst->flags = dnsst->flags;
        strcpy(newst->host, dnsst->host);
        delete dnsst;
        dnsst = newst;
    }

    for (size_t i = dnsst->times%srvs.size(); i < srvs.size(); ++i) {
        uint16_t flags = 0;
        if (!(dnsst->flags & QARECORD) && srvs[i]->query(dnsst->host, 1, id_cur)) {
            flags |= QARECORD;
        }
        if (!(dnsst->flags & QAAAARECORD) && srvs[i]->query(dnsst->host, 28, id_cur+1)) {
            flags |= QAAAARECORD;
        }
        dnsst->flags |= flags;
        if((dnsst->flags & QARECORD) &&(dnsst->flags & QAAAARECORD)) {
            break;
        }
        if(flags == 0){
            delete srvs[i];
            dnsst -> times ++;
            return query(dnsst);
        }
    }
    dnsst->times++;
    querying_index.Add(id_cur, dnsst->host, dnsst);
    add_delayjob((job_func)query_timeout, (void *)(size_t)id_cur, DNSTIMEOUT);
}


void query(const char* host , DNSCBfunc func, void* param) {
    if(querying_index.Get(host)){
        if(func){
            querying_index.Get(host)->data->reqs.push_back(Dns_Req{func, param});
        }
        return;
    }
    
    Dns_Status *dnsst = new Dns_Status;
    dnsst->times = 0;
    if(func){
        dnsst->reqs.push_back(Dns_Req{func, param});
    }

    snprintf(dnsst->host, sizeof(dnsst->host), "%s", host);
    query(dnsst);
}

void query_cancel(const char* host, DNSCBfunc func, void* param){
    if(querying_index.Get(host)){
        Dns_Status* status = querying_index.Get(host)->data;
        for(auto i = status->reqs.begin(); i!= status->reqs.end(); i++){
            if(i->func == func && i->param == param){
                status->reqs.erase(i);
                return;
            }
        }
    }
}

static void query(Dns_RawReq* dnsreq){
    assert(id_cur &1);
    while(srvs.size() == 0) {
        dnsinit();
        if(srvs.size() == 0){
            sleep(5);
        }
    }
    id_cur += 2;
    dnsreq->id = id_cur;
    for (size_t i = dnsreq->times%srvs.size(); i < srvs.size(); ++i) {
        if(srvs[i]->query(dnsreq->host, dnsreq->type, id_cur))
            break;
    }

    dnsreq->times++;
    querying_raw_id[id_cur] = dnsreq;
    add_delayjob((job_func)query_timeout, (void *)(size_t)id_cur, DNSTIMEOUT);
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

int query_timeout(uint16_t id){
    assert(querying_index.Get(id) || querying_raw_id.count(id));
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
        assert(querying_index.Get(id));
        auto status = querying_index.Get(id)->data;
        querying_index.Delete(id);
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
    return 0;
}

void RcdDown(const char *hostname, const sockaddr_un &addr) {
    LOG("[DNS] down for %s: %s\n", hostname, getaddrstring(&addr));
    if (rcd_cache.count(hostname)) {
        auto& addrs  = rcd_cache[hostname].addrs;
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

Dns_srv::Dns_srv(const char* name){
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
    rwer = new PacketRWer(fd, [this](int ret, int code){
        LOGE("DNS error: %d/%d\n", ret, code);
        delete this;
    });
    rwer->SetReadCB([this](size_t len){
        const char* data = rwer->data();
        buffHE(data, len);
        rwer->consume(data, len);
    });

    strcpy(this->name, name);
    LOGD(DDNS, "new dns server: %s\n", name);
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


void Dns_srv::buffHE(const char *buffer, size_t len) {
    Dns_Rr dnsrcd(buffer, len);
    uint16_t id = dnsrcd.id;

    if(querying_raw_id.count(id)){
        del_delayjob((job_func)query_timeout, (void *)(size_t)id);
        Dns_RawReq *dnsreq =  querying_raw_id[id];
        querying_raw_id.erase(id);
        dnsreq->func(dnsreq->param, buffer, len);
        delete dnsreq;
        return;
    }

    uint32_t flags=0;
    if (id & 1) {
        if (querying_index.Get(id) == nullptr) {
            LOG("[DNS] Get a unkown id:%d\n", id);
            return;
        }
        flags |= GARECORD;
    } else {
        id--;
        if (querying_index.Get(id) == nullptr) {
            LOG("[DNS] Get a unkown id:%d\n", id);
            return;
        }
        flags |= GAAAARECORD;
    }
    Dns_Status *dnsst = querying_index.Get(id)->data;
    dnsst->flags |= flags;

    if(dnsrcd.addrs.size()){
        for(auto i: dnsrcd.addrs){
            dnsst->rcd.addrs.push_back(i);
        }
        dnsst->rcd.expire_time = time(nullptr) + dnsrcd.ttl;
    }

    if ((dnsst->flags & GARECORD) &&(dnsst->flags & GAAAARECORD)) {
        del_delayjob((job_func)query_timeout, (void *)(size_t)id);
        querying_index.Delete(id);
        if (!dnsst->rcd.addrs.empty()) {
            rcd_cache[dnsst->host] = dnsst->rcd;
            expire_time.insert(std::make_pair(dnsst->rcd.expire_time, dnsst->host));
        }
        for(auto i: dnsst->reqs ){
            i.func(i.param, dnsst->host, dnsst->rcd.addrs);
        }
        delete dnsst;
    }
}

int Dns_srv::query(const char *host, int type, uint32_t id) {
    unsigned char*  buf = (unsigned char*)p_malloc(BUF_SIZE);
    int len = Dns_Que(host, type, id).build(buf);
    rwer->buffer_insert(rwer->buffer_end(), buf, len);
    return id;
}

void Dns_srv::dump_stat(){
    LOG("Dns_srv %p: %s\n", this, name);
}


void dump_dns(){
    LOG("Dns querying:\n");
    for(auto i: querying_index.index1()){
       LOG("    %d: %s\n", i.first, i.second->data->host);
    }
    LOG("Dns cache:\n");
    for(auto i: rcd_cache){
        LOG("    %s: %ld\n", i.first.c_str(), i.second.expire_time - time(0));
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

static const unsigned char * getdomain(const DNS_HDR *hdr, const unsigned char *p, size_t len, char* domain) {
    const unsigned char* buf = (const unsigned char *)hdr;
    while (p < (unsigned char*)hdr + len && *p) {
        if (*p > 63) {
            const unsigned char *q = buf+((*p & 0x3f) <<8) + *(p+1);
            getdomain(hdr, q, len, domain);
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

static std::string reverse(std::string str){
    std::string::size_type split = 0;
    std::string result;
    while((split = str.find_last_of(".")) != std::string::npos){
        result += str.substr(split+1) + '.';
        str = str.substr(0, split);
    }
    result += str;
    return result;
}

#define IPV4_PTR_PREFIX "arpa.in-addr."
#define IPV6_PTR_PREFIX "arpa.ip6."

Dns_Que::Dns_Que(const char* buff, size_t len) {
    const DNS_HDR *dnshdr = (const DNS_HDR*)buff;

    id = ntohs(dnshdr->id);
    char domain[DOMAINLIMIT];
    const unsigned char *p = getdomain(dnshdr, (const unsigned char *)(dnshdr+1), len, domain);
    host = (char *)domain;
    const DNS_QUE *que = (const DNS_QUE*)p;
    type = ntohs(que->type);
    assert(ntohs(que->classes) == 1);
    if(type == 12){
        std::string ptr = reverse(host);
        if(startwith(ptr.c_str(), IPV4_PTR_PREFIX)){
            ptr = ptr.substr(sizeof(IPV4_PTR_PREFIX) - 1);
            ptr_addr.addr.sa_family = AF_INET;
            if(inet_pton(AF_INET, ptr.c_str(), &ptr_addr.addr_in.sin_addr) != 1){
                LOGE("[DNS] wrong ptr format: %s", host.c_str());
                return;
            }
        }else if(startwith(ptr.c_str(), IPV6_PTR_PREFIX)){
            ptr = ptr.substr(sizeof(IPV6_PTR_PREFIX) - 1);
            host.clear();
            for(size_t i = 0; i< ptr.length(); i++){
                if(i&1){
                    host += ptr[i];
                }
                if(i%8 == 0){
                    host += ':';
                }
            }
            ptr_addr.addr.sa_family = AF_INET6;
            if(inet_pton(AF_INET6, ptr.c_str(), &ptr_addr.addr_in6.sin6_addr) != 1){
                LOGE("[DNS] wrong ptr format: %s", host.c_str());
                return;
            }
        }else{
            LOGE("unkown ptr request: %s", host.c_str());
        }
    }
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

Dns_Rr::Dns_Rr() {
}

Dns_Rr::Dns_Rr(const char* buff, size_t len) {
    const DNS_HDR *dnshdr = (const DNS_HDR *)buff;
    id = ntohs(dnshdr->id);

    const unsigned char *p = (const unsigned char *)(dnshdr +1);
    uint16_t numq = ntohs(dnshdr->numq);
    uint16_t flag = ntohs(dnshdr->flag);
    assert(numq && (flag & QR));
    for (int i = 0; i < numq; ++i) {
        char domain[DOMAINLIMIT];
        p = (unsigned char *)getdomain(dnshdr, p, len, domain);
        LOGD(DDNS, "[%d]:\n", dnshdr->id);
        p+= sizeof(DNS_QUE);

        if((flag & RCODE_MASK) != 0) {
            LOG("[DNS] ack error: %s: %u\n", domain, uint32_t(flag & RCODE_MASK));
        }
    }
    if((flag & RCODE_MASK) !=0 ){
        return;
    }
    uint16_t numa = ntohs(dnshdr->numa);
    for(int i = 0; i < numa; ++i) {
        char domain[DOMAINLIMIT];
        p = (unsigned char *)getdomain(dnshdr, p, len, domain);
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
            getdomain(dnshdr, p, len, domain);
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
    if(addr) {
        sockaddr_un ip;
        ip.addr_in.sin_family = AF_INET;
        memcpy(&ip.addr_in.sin_addr, addr, sizeof(in_addr));
        addrs.push_back(ip);
    }
}

Dns_Rr::Dns_Rr(const char *rDns, bool):rDns(rDns) {
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
    if(query->type == 12){
        len += putdomain(buf+len, query->host.c_str());
        DNS_RR* rr= (DNS_RR*)(buf + len);
        rr->classes = htons(1);
        rr->type = htons(12);
        rr->TTL = htonl(ttl);
        int rdlength = putdomain((unsigned char *)(rr+1), rDns.c_str());
        rr->rdlength = htons(rdlength);
        len += sizeof(DNS_RR) + rdlength;
        dnshdr->numa ++;
    }
    HTONS(dnshdr->numa);
    return len;
}

int Dns_Rr::buildError(const Dns_Que* query, unsigned char errcode, unsigned char *buf){
    int len = query->build(buf);
    DNS_HDR *dnshdr = (DNS_HDR *)buf;
    dnshdr->flag  = htons(QR|RD|RA|errcode);
    dnshdr->numa = 0;
    dnshdr->numa1 = 0;
    dnshdr->numa2 = 0;
    return len;
}
