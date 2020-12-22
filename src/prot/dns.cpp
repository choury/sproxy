#include "dns.h"
#include "misc/util.h"
#include "misc/simpleio.h"
#include "misc/index.h"
#include "misc/config.h"
#include "common.h"

#include <unordered_map>
#include <set>

#include <string.h>
#include <errno.h>
#include <assert.h>


#define BUF_SIZE 1024

#define DNSPORT     53
#define DNSTIMEOUT  10000            // dns 超时时间(ms)


static uint16_t id_cur = 1;

class Dns_srv:public Server{
    sockaddr_storage addr;
public:
    explicit Dns_srv(const sockaddr_storage* server);
    virtual ~Dns_srv() override;
    bool valid();
    void buffHE(const char* buffer, size_t len);
    int query(const char *host, uint16_t type, uint16_t id);
    virtual void dump_stat(Dumper dp, void* param) override;
};

static std::vector<Dns_srv *> srvs;


struct Dns_Req{
    DNSCBfunc func;
    void*     param;
};

struct Dns_Rcd{
    std::list<sockaddr_storage> addrs;
    time_t get_time;
    uint32_t ttl;
};

typedef struct Dns_Status {
    char host[DOMAINLIMIT];
    uint16_t times;
#define QARECORD     0x1U
#define QAAAARECORD  0x2U
#define GARECORD     0x10U
#define GAAAARECORD  0x20U
    uint16_t flags;
    std::list<Dns_Req> reqs;
    Dns_Rcd rcd;
    Job* timeout_job;
} Dns_Status;

typedef struct Dns_RawReq {
    char host[DOMAINLIMIT];
    uint16_t times;
    uint16_t type;
    uint16_t id;
    DNSRAWCB func;
    void *param;
    Job* timeout_job;
} Dns_RawReq;

Index2<uint16_t, std::string, Dns_Status *> querying_index;
std::unordered_map<uint16_t, Dns_RawReq *> querying_raw_id;
std::unordered_map<std::string, Dns_Rcd> rcd_cache;
//std::multimap<int, std::string> expire_time;

/*
int dns_expired() {
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
    }
    return 1;
}

int dns_expired(const std::string& host){
    time_t __attribute__((unused)) now = time(nullptr);
    auto i = rcd_cache.find(host);
    if(i != rcd_cache.end()){
        LOGD(DDNS, "%s expired (%ld)\n", host.c_str(), i->second.get_time + i->second.ttl);
        rcd_cache.erase(i);
    }else{
        LOGE("[DNS] expired %s not found\n", host.c_str());
    }
    return 0;
}
*/

void query_timeout(uint16_t id);

#ifdef __ANDROID__
extern std::vector<std::string> getDns();
void getDnsConfig(struct DnsConfig* config){
    std::vector<std::string> dns = getDns();
    int get = 0;
    for(const auto& i: dns){
        if(get == 3){
            break;
        }
        if(storage_aton(i.c_str(), DNSPORT, &config->server[get]) == 1){
            get++;
        }else{
            LOGE("[DNS] %s is not a valid ip address\n", i.c_str());
        }
    }
    config->namecount = get;
}

#else
#define RESOLV_FILE "/etc/resolv.conf"
void getDnsConfig(struct DnsConfig* config){
    config->namecount = 0;
    FILE *res_file = fopen(RESOLV_FILE, "r");
    if (res_file == NULL) {
        LOGE("[DNS] open resolv file:%s failed:%s\n", RESOLV_FILE, strerror(errno));
        return;
    }
    int get = 0;
    char line[100];
    while (fscanf(res_file, "%99[^\n]\n", line)!= EOF) {
        if(get == 3){
            break;
        }
        char command[11], ipaddr[INET6_ADDRSTRLEN];
        sscanf(line, "%10s %45s", command, ipaddr);
        if (strcmp(command, "nameserver") == 0) {
            if(storage_aton(ipaddr, DNSPORT, &config->server[get]) == 1){
                get++;
            } else {
                LOGE("[DNS] %s is not a valid ip address\n", ipaddr);
            }
        }
    }
    fclose(res_file);
    config->namecount = get;
}
#endif

static int dnsinit() {
    assert(srvs.empty());
    DnsConfig config;
    getDnsConfig(&config);
    for(int i =0;i< config.namecount; i++) {
        LOG("[DNS] set dns server: %s\n", getaddrstring(&config.server[i]));
        Dns_srv* ds = new Dns_srv(&config.server[i]);
        if(!ds->valid()){
            ds->deleteLater(PEER_LOST_ERR);
        }
    }
    return srvs.size();
}

void flushdns(){
    for(auto i: srvs){
        i->deleteLater(NOERROR);
    }
    srvs.clear();
    rcd_cache.clear();
}

static void query(Dns_Status* dnsst){
    assert(id_cur &1U);
    if(srvs.empty()) {
        dnsinit();
    }
    id_cur += 2;
    if(!opt.ipv6_enabled){
        dnsst->flags = QAAAARECORD | GAAAARECORD;
    }else{
        dnsst->flags = 0;
    }

    sockaddr_storage addr;
    if(storage_aton(dnsst->host, 0, &addr) == 1){
        dnsst->rcd.addrs.push_back(addr);
        for(auto i: dnsst->reqs){
            i.func(i.param, dnsst->rcd.addrs);
        }
        delete dnsst;
        return;
    }

    if (rcd_cache.count(dnsst->host) && !dnsst->reqs.empty()) {
        auto& rcd = rcd_cache[dnsst->host];
        for(auto i: dnsst->reqs){
            i.func(i.param, rcd.addrs);
        }
        if(rcd.get_time + rcd.ttl > time(nullptr) + 15U){
            delete dnsst;
            return;
        }
        //刷新ttl
        dnsst->times = 0;
        dnsst->reqs.clear();
    }

    if (srvs.empty()) {
        goto ret;
    }

    for (size_t i = 0; i < srvs.size(); i++) {
        size_t index = (i + dnsst->times) % srvs.size();
        if (!(dnsst->flags & QARECORD) && srvs[index]->query(dnsst->host, 1, id_cur)) {
            dnsst->flags |= QARECORD;
        }
        if (!(dnsst->flags & QAAAARECORD) && srvs[index]->query(dnsst->host, 28, id_cur+1)) {
            dnsst->flags |= QAAAARECORD;
        }
        if((dnsst->flags & QARECORD) &&(dnsst->flags & QAAAARECORD)) {
            break;
        }
    }
ret:
    dnsst->times++;
    dnsst->timeout_job = AddJob(std::bind(query_timeout, id_cur), DNSTIMEOUT, 0);
    querying_index.Add(id_cur, dnsst->host, dnsst);
}


void query(const char* host, DNSCBfunc func, void* param) {
    if(querying_index.Get(host)){
        if(func){
            querying_index.Get(host)->data->reqs.push_back(Dns_Req{func, param});
        }
        return;
    }
    
    Dns_Status *dnsst = new Dns_Status;
    strncpy(dnsst->host, host, sizeof(dnsst->host));
    dnsst->times = 0;
    if(func){
        dnsst->reqs.push_back(Dns_Req{func, param});
    }
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
    assert(id_cur &1U);
    if(srvs.empty()) {
        dnsinit();
    }
    id_cur += 2;
    dnsreq->id = id_cur;
    if(srvs.empty()){
        goto ret;
    }

    for (size_t i = 0; i < srvs.size(); i++) {
        size_t index = (i + dnsreq->times)%srvs.size();
        if(srvs[index]->query(dnsreq->host, dnsreq->type, id_cur))
            break;
    }
ret:
    dnsreq->times++;
    dnsreq->timeout_job = AddJob(std::bind(query_timeout, id_cur), DNSTIMEOUT, 0);
    querying_raw_id[id_cur] = dnsreq;
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
    if(querying_index.Get(id)){
        auto status = querying_index.Get(id)->data;
        querying_index.Delete(id);
        DelJob(&status->timeout_job);
        if(status->rcd.addrs.empty() && status->times <= 3) {
            LOG("[DNS] %s: time out, retry...\n", status->host);
            query(status);
        }else{
            for(auto i: status->reqs){
                i.func(i.param, status->rcd.addrs);
            }
            delete status;
        }
        return;
    }
    if(querying_raw_id.count(id)){
        auto req = querying_raw_id[id];
        querying_raw_id.erase(id);
        DelJob(&req->timeout_job);

        if(req->times <= 3){
            LOG("[DNS] %s: raw query time out, retry...\n", req->host);
            query(req);
        }else{
            LOG("[DNS] %s: raw query time out\n", req->host);
            req->func(req->param, nullptr, 0);
            delete req;
        }
        return;
    }
    abort();
}

void RcdDown(const char *hostname, const sockaddr_storage &addr) {
    LOG("[DNS] down for %s: %s\n", hostname, getaddrstring(&addr));
    auto cmpfunc = [](const sockaddr_storage& a, const sockaddr_storage& b) -> bool {
        if(a.ss_family != b.ss_family){
            return false;
        }
        if(a.ss_family == AF_INET6){
            const sockaddr_in6* a6 = (const sockaddr_in6*)&a;
            const sockaddr_in6* b6 = (const sockaddr_in6*)&b;
            return memcmp(&a6->sin6_addr, &b6->sin6_addr, sizeof(in6_addr)) == 0;
        }
        if(a.ss_family == AF_INET) {
            const sockaddr_in* a4 = (const sockaddr_in*)&a;
            const sockaddr_in* b4 = (const sockaddr_in*)&b;
            return memcmp(&a4->sin_addr, &b4->sin_addr, sizeof(in_addr)) == 0;
        }
        return false;
    };
    if (rcd_cache.count(hostname)) {
        auto& addrs  = rcd_cache[hostname].addrs;
        for (auto i = addrs.begin(); i != addrs.end(); ++i) {
            if(cmpfunc(addr, *i)){
                addrs.erase(i);
                addrs.push_back(addr);
                return;
            }
        }
    }
}

Dns_srv::Dns_srv(const sockaddr_storage* server){
    //sockaddr_storage addr;
    memcpy(&addr, server, sizeof(sockaddr_storage));
    int fd = Connect(&addr, SOCK_DGRAM);
    if (fd == -1) {
        LOGE("[DNS] connecting  %s error:%s\n", getaddrstring(&addr), strerror(errno));
        return;
    }
    rwer = new PacketRWer(fd, [this](int ret, int code){
        LOGE("DNS error: %d/%d\n", ret, code);
        deleteLater(code);
    });
    rwer->SetReadCB([this](size_t len){
        const char* data = rwer->rdata();
        buffHE(data, len);
        rwer->consume(data, len);
    });

    LOGD(DDNS, "new dns server: %s\n", getaddrstring(&addr));
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

bool Dns_srv::valid(){
    return rwer != nullptr;
}


void Dns_srv::buffHE(const char *buffer, size_t len) {
    Dns_Rr dnsrr(buffer, len);
    uint16_t id = dnsrr.id;

    if(querying_raw_id.count(id)){
        Dns_RawReq *dnsreq =  querying_raw_id[id];
        DelJob(&dnsreq->timeout_job);
        querying_raw_id.erase(id);
        dnsreq->func(dnsreq->param, buffer, len);
        delete dnsreq;
        return;
    }

    uint32_t flags=0;
    if (id & 1U) {
        flags |= GARECORD;
    } else {
        id--;
        flags |= GAAAARECORD;
    }
    if (querying_index.Get(id) == nullptr) {
        if(!dnsrr.addrs.empty()){
            Dns_Rcd rcd{{}, time(0), 10};
            for(auto i: dnsrr.addrs){
                rcd.addrs.push_back(i);
            }
            rcd_cache[dnsrr.domain] = rcd;
        }
        LOG("[DNS] Get a unkown id:%d [%s]\n", id, dnsrr.domain);
        return;
    }
    Dns_Status *dnsst = querying_index.Get(id)->data;
    dnsst->flags |= flags;

    if(!dnsrr.addrs.empty()){
        for(auto i: dnsrr.addrs){
            dnsst->rcd.addrs.push_back(i);
        }
        dnsst->rcd.get_time = time(nullptr);
        dnsst->rcd.ttl = dnsrr.ttl;
    }

    if ((dnsst->flags & GARECORD) && (dnsst->flags & GAAAARECORD)) {
        DelJob(&dnsst->timeout_job);
        querying_index.Delete(id);
        if (!dnsst->rcd.addrs.empty()) {
            rcd_cache[dnsst->host] = dnsst->rcd;
        }
        for(auto i: dnsst->reqs ){
            i.func(i.param, dnsst->rcd.addrs);
        }
        delete dnsst;
    }
}

int Dns_srv::query(const char *host, uint16_t type, uint16_t id) {
    unsigned char* const buf = (unsigned char*)p_malloc(BUF_SIZE);
    int len = Dns_Que(host, type, id).build(buf);
    rwer->buffer_insert(rwer->buffer_end(), write_block{buf, (size_t)len, 0});
    return id;
}

void Dns_srv::dump_stat(Dumper dp, void* param){
    dp(param, "Dns_srv %p: %s\n", this, getaddrstring(&addr));
}

void dump_dns(Dumper dp, void* param){
    dp(param, "Dns querying:\n");
    for(auto i: querying_index.index1()){
       dp(param, "    %d: %s\n", i.first, i.second->data->host);
    }
    dp(param, "Dns cache:\n");
    for(const auto& i: rcd_cache){
        dp(param, "    %s: %ld\n", i.first.c_str(), i.second.get_time + i.second.ttl - time(0));
        for(auto j: i.second.addrs){
            dp(param, "        %s\n", getaddrstring(&j));
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
    unsigned char rdata[0];
} __attribute__((packed)) DNS_RR;

static const unsigned char * getdomain(const DNS_HDR *hdr, const unsigned char *p, size_t len, char* domain) {
    const unsigned char* buf = (const unsigned char *)hdr;
    while (p < (unsigned char*)hdr + len && *p) {
        if (*p > 63) {
            const unsigned char *q = buf+((*p & 0x3f) <<8U) + *(p+1);
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

static int putdomain(unsigned char *buf, const char *domain){
    unsigned char *p = buf+1;
    strcpy((char*)p, domain);

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


Dns_Que::Dns_Que(const std::string& host, uint16_t type, uint16_t id):host(host), type(type), id(id), valid(true) {
}

static std::string reverse(std::string str){
    std::string::size_type split = 0;
    std::string result;
    while((split = str.find_last_of('.')) != std::string::npos){
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
            std::string ipstr = ptr.substr(sizeof(IPV4_PTR_PREFIX) - 1);
            if(storage_aton(ipstr.c_str(), 0, &ptr_addr) != 1){
                LOGE("[DNS] wrong ptr format: %s\n", host.c_str());
                return;
            }
        }else if(startwith(ptr.c_str(), IPV6_PTR_PREFIX)){
            ptr = ptr.substr(sizeof(IPV6_PTR_PREFIX) - 1);
            std::string ipstr;
            for(size_t i = 1; i<= ptr.length(); i++){
                if(i&1u){
                    ipstr += ptr[i-1];
                }
                if(i%8 == 0){
                    ipstr += ':';
                }
            }
            if(storage_aton(ipstr.c_str(), 0, &ptr_addr) != 1){
                LOGE("[DNS] wrong ptr format: %s\n", host.c_str());
                return;
            }
        }else{
            LOGE("unkown ptr request: %s\n", host.c_str());
            return;
        }
    }
    if(!host.empty() && id != 0){
        valid = true;
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

    return len + sizeof(DNS_QUE);
}

Dns_Rr::Dns_Rr(const char* buff, size_t len) {
    if(len < sizeof(DNS_HDR)){
        LOGE("[DNS] incompleted DNS response\n");
        id = 0;
        return;
    }
    const DNS_HDR *dnshdr = (const DNS_HDR *)buff;
    id = ntohs(dnshdr->id);
    uint16_t numq = ntohs(dnshdr->numq);
    uint16_t flag = ntohs(dnshdr->flag);
    const unsigned char *p = (const unsigned char *)(dnshdr +1);
    assert(numq && (flag & QR));
    for (int i = 0; i < numq; ++i) {
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
        p = (unsigned char *)getdomain(dnshdr, p, len, domain);
        DNS_RR *dnsrr = (DNS_RR *)p;
        assert(ntohs(dnsrr->classes) == 1);

        uint32_t ttl = ntohl(dnsrr->TTL);
        this->ttl = std::max(ttl, this->ttl);

        p+= sizeof(DNS_RR);
#ifndef NDEBUG
        char ipaddr[INET6_ADDRSTRLEN];
#endif
        switch (ntohs(dnsrr->type)) {
            sockaddr_storage ip;
        case 1:{
            memset(&ip, 0, sizeof(ip));
            sockaddr_in* ip4 = (sockaddr_in*)&ip;
            ip4->sin_family = AF_INET;
            memcpy(&ip4->sin_addr, p, sizeof(in_addr));
            addrs.push_back(ip);
#ifndef NDEBUG
            LOGD(DDNS, "%s ==> %s [%d]\n", domain, inet_ntop(AF_INET, p, ipaddr, sizeof(ipaddr)), ttl);
#endif
            break;
        }
        case 2:
        case 5:
            getdomain(dnshdr, p, len, domain);
            break;
        case 28:{
            memset(&ip, 0, sizeof(ip));
            sockaddr_in6* ip6 = (sockaddr_in6*)&ip;
            ip6->sin6_family = AF_INET6;
            memcpy(&ip6->sin6_addr, p, sizeof(in6_addr));
            addrs.push_back(ip);
#ifndef NDEBUG
            LOGD(DDNS, "%s ==> %s [%d]\n", domain, inet_ntop(AF_INET6, p, ipaddr, sizeof(ipaddr)), ttl);
#endif
            break;
        }
        default:
            break;
        }
        p+= ntohs(dnsrr->rdlength);
    }
}

Dns_Rr::Dns_Rr(const char *domain, const in_addr* addr){
    strcpy(this->domain, domain);
    if(addr) {
        sockaddr_storage ip;
        memset(&ip, 0, sizeof(ip));
        sockaddr_in* ip4 = (sockaddr_in*)&ip;
        ip4->sin_family = AF_INET;
        ip4->sin_addr = *addr;
        addrs.push_back(ip);
    }
}

Dns_Rr::Dns_Rr(const char *domain, const in6_addr* addr){
    strcpy(this->domain, domain);
    if(addr) {
        sockaddr_storage ip;
        memset(&ip, 0, sizeof(ip));
        sockaddr_in6* ip6 = (sockaddr_in6*)&ip;
        ip6->sin6_family = AF_INET6;
        ip6->sin6_addr = *addr;
        addrs.push_back(ip);
    }
}


Dns_Rr::Dns_Rr(const char *domain) {
    strcpy(this->domain, domain);
}


int Dns_Rr::build(const Dns_Que* query, unsigned char* buf)const {
    int len = query->build(buf);
    DNS_HDR *dnshdr = (DNS_HDR *)buf;
    dnshdr->flag  = htons(QR|RD|RA);
    dnshdr->numa = 0;
    dnshdr->numa1 = 0;
    dnshdr->numa2 = 0;

    for(auto addr : addrs) {
        if(query->type == 1 && addr.ss_family == AF_INET){
            len += putdomain(buf+len, query->host.c_str());
            DNS_RR* rr= (DNS_RR*)(buf + len);
            rr->classes = htons(1);
            rr->type = htons(1);
            rr->TTL = htonl(ttl);
            rr->rdlength = htons(sizeof(in_addr));
            sockaddr_in* addr4 = (sockaddr_in*)&addr;
            memcpy(rr->rdata, &addr4->sin_addr, sizeof(in_addr));
            len += sizeof(DNS_RR) + sizeof(in_addr);
            dnshdr->numa ++;
        }
        if(query->type == 28 && addr.ss_family == AF_INET6){
            len += putdomain(buf+len, query->host.c_str());
            DNS_RR* rr= (DNS_RR*)(buf + len);
            rr->classes = htons(1);
            rr->type = htons(28);
            rr->TTL = htonl(ttl);
            rr->rdlength = htons(sizeof(in6_addr));
            sockaddr_in6* addr6 = (sockaddr_in6*)&addr;
            memcpy(rr->rdata, &addr6->sin6_addr, sizeof(in6_addr));
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
        int rdlength = putdomain(rr->rdata, domain);
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
