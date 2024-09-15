#include "dns.h"
#include "misc/util.h"
#include <string.h>
#include <assert.h>

typedef struct DNS_QUE {
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
    while (p < (unsigned char*)hdr + len && *p) {
        if (*p > 63) {
            const unsigned char* buf = (const unsigned char *)hdr;
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
    if(p == (uchar*)(hdr + 1)){
        domain[0] = 0;
    }else{
        domain[-1] = 0;
    }
    return p+1;
}

static int putdomain(unsigned char *buf, const char *domain){
    if(domain[0] == '.' || domain[0] == 0){
        *buf = 0;
        return 1;
    }
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
    if(i == 0)
        return p-buf;
    else
        return p-buf+1;
}

Dns_Query::Dns_Query(const char* domain, uint16_t type, uint16_t id):  type(type), id(id), valid(true) {
    strcpy(this->domain, domain);
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

static bool is_valid(const char* domain) {
    while(*domain) {
        //'_' is only for srv
        if((*domain >= 'a' && *domain <= 'z') ||
        (*domain >= 'A' && *domain <= 'Z') ||
        (*domain >= '0' && *domain <= '9') ||
        *domain == '-' || *domain == '_' || *domain == '.' ){
            domain++;
            continue;
        }
        return false;
    }
    return true;
}

Dns_Query::Dns_Query(const char* buff, size_t len) {
    if(len < sizeof(DNS_HDR)){
        return;
    }
    const DNS_HDR *dnshdr = (const DNS_HDR*)buff;

    id = ntohs(dnshdr->id);
    const unsigned char *p = getdomain(dnshdr, (const unsigned char *)(dnshdr+1), len, domain);
    if(!is_valid(domain)) {
        return;
    }
    const DNS_QUE *que = (const DNS_QUE*)p;
    if(ntohs(que->classes) != ns_c_in) {
        return;
    }
    type = ntohs(que->type);
    if(type == ns_t_ptr){
        std::string ptr = reverse(domain);
        if(startwith(ptr.c_str(), IPV4_PTR_PREFIX)){
            std::string ipstr = ptr.substr(sizeof(IPV4_PTR_PREFIX) - 1);
            if(storage_aton(ipstr.c_str(), 0, &ptr_addr) != 1){
                LOGD(DDNS, "[DNS] wrong ptr format: %s\n", domain);
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
                LOGD(DDNS, "[DNS] wrong ptr format: %s\n", domain);
                return;
            }
        }else{
            LOGD(DDNS, "unkown ptr request: %s\n", domain);
            return;
        }
    }
    if(id != 0){
        valid = true;
    }
}



int Dns_Query::build(unsigned char* buf) const {
    DNS_HDR  *dnshdr = (DNS_HDR *)buf;
    memset(dnshdr, 0, sizeof(DNS_HDR));
    dnshdr->id = htons(id);
    dnshdr->rd = 1;
    dnshdr->qdcount = htons(1);

    int len = sizeof(DNS_HDR);

    len += putdomain(buf+len, domain);

    DNS_QUE  *que = (DNS_QUE *)(buf+len);
    que->classes = htons(ns_c_in);
    que->type = htons(type);

    return len + sizeof(DNS_QUE);
}

Dns_Result::Dns_Result(const char* buff, size_t len): id(0) {
    if(len < sizeof(DNS_HDR)){
        error = ns_r_formerr;
        LOGE("[DNS] incomplete DNS response\n");
        return;
    }
    const DNS_HDR *dnshdr = (const DNS_HDR *)buff;
    uint16_t numq = ntohs(dnshdr->qdcount);
    const unsigned char *p = (const unsigned char *)(dnshdr +1);
    assert(numq && dnshdr->qr);
    for (int i = 0; i < numq; ++i) {
        p = (unsigned char *)getdomain(dnshdr, p, len, domain);
        if((const char*)p + sizeof(DNS_QUE) - buff > (int)len){
            error = ns_r_formerr;
            LOGE("[DNS] <%d> numq overflow\n", ntohs(dnshdr->id));
            return;
        }
        DNS_QUE* que = (DNS_QUE*)p;
        type = ntohs(que->type);
        p+= sizeof(DNS_QUE);
        LOGD(DDNS, "[%d] response for %s, type: %d:\n", ntohs(dnshdr->id), domain, type);
    }
    if(dnshdr->rcode !=0){
        error = dnshdr->rcode;
        LOG("[DNS] <%d> ack error: %s: %u\n", ntohs(dnshdr->id), domain, error);
        return;
    }
    uint16_t numa = ntohs(dnshdr->ancount);
    for(int i = 0; i < numa; ++i) {
        p = (unsigned char *)getdomain(dnshdr, p, len, domain);
        if((const char*)p + sizeof(DNS_RR) - buff > (int)len){
            error = ns_r_formerr;
            LOGE("[DNS] <%d> numa overflow\n", ntohs(dnshdr->id));
            return;
        }
        DNS_RR *dnsrr = (DNS_RR*)p;
        assert(ntohs(dnsrr->classes) == ns_c_in);
        uint32_t ttl = ntohl(dnsrr->TTL);

        p+= sizeof(DNS_RR);
        char __attribute__((unused)) ipaddr[INET6_ADDRSTRLEN] = {0};
        switch (ntohs(dnsrr->type)) {
            sockaddr_storage ip;
        case ns_t_a:{
            memset(&ip, 0, sizeof(ip));
            sockaddr_in* ip4 = (sockaddr_in*)&ip;
            ip4->sin_family = AF_INET;
            memcpy(&ip4->sin_addr, p, sizeof(in_addr));
            addrs.push_back(ip);
            LOGD(DDNS, "A: %s ==> %s [%d]\n", domain, inet_ntop(AF_INET, p, ipaddr, sizeof(ipaddr)), ttl);
            break;
        }
        case ns_t_ns: {
            char ns[DOMAINLIMIT];
            getdomain(dnshdr, p, len, ns);
            LOGD(DDNS, "NS: %s ==> %s [%d]\n", domain, ns, ttl);
            break;
        }
        case ns_t_cname: {
            char cname[DOMAINLIMIT];
            getdomain(dnshdr, p, len, cname);
            LOGD(DDNS, "CNAME: %s ==> %s [%d]\n", domain, cname, ttl);
            break;
        }
        case ns_t_aaaa:{
            memset(&ip, 0, sizeof(ip));
            sockaddr_in6* ip6 = (sockaddr_in6*)&ip;
            ip6->sin6_family = AF_INET6;
            memcpy(&ip6->sin6_addr, p, sizeof(in6_addr));
            addrs.push_back(ip);
            LOGD(DDNS, "AAAA: %s ==> %s [%d]\n", domain, inet_ntop(AF_INET6, p, ipaddr, sizeof(ipaddr)), ttl);
            break;
        }
        default:
            break;
        }
        this->ttl = std::min(ttl, this->ttl);
        p+= ntohs(dnsrr->rdlength);
    }
    id = ntohs(dnshdr->id);
}

Dns_Result::Dns_Result(const char *domain, const in_addr* addr): type(ns_t_a), ttl(0){
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

Dns_Result::Dns_Result(const char *domain, const in6_addr* addr): type(ns_t_aaaa), ttl(0){
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


Dns_Result::Dns_Result(const char *domain): ttl(0) {
    strcpy(this->domain, domain);
}

int Dns_Result::build(const Dns_Query* query, unsigned char* buf)const {
    int len = query->build(buf);
    DNS_HDR *dnshdr = (DNS_HDR *)buf;
    dnshdr->qr = 1;
    dnshdr->rd = 1;
    dnshdr->ra = 1;

    for(auto addr : addrs) {
        if(query->type == ns_t_a && addr.ss_family == AF_INET){
            len += putdomain(buf+len, query->domain);
            DNS_RR* rr= (DNS_RR*)(buf + len);
            rr->classes = htons(ns_c_in);
            rr->type = htons(ns_t_a);
            rr->TTL = htonl(ttl);
            rr->rdlength = htons(sizeof(in_addr));
            sockaddr_in* addr4 = (sockaddr_in*)&addr;
            memcpy(rr->rdata, &addr4->sin_addr, sizeof(in_addr));
            len += sizeof(DNS_RR) + sizeof(in_addr);
            dnshdr->ancount ++;
        }
        if(query->type == ns_t_aaaa && addr.ss_family == AF_INET6){
            len += putdomain(buf+len, query->domain);
            DNS_RR* rr= (DNS_RR*)(buf + len);
            rr->classes = htons(ns_c_in);
            rr->type = htons(ns_t_aaaa);
            rr->TTL = htonl(ttl);
            rr->rdlength = htons(sizeof(in6_addr));
            sockaddr_in6* addr6 = (sockaddr_in6*)&addr;
            memcpy(rr->rdata, &addr6->sin6_addr, sizeof(in6_addr));
            len += sizeof(DNS_RR) + sizeof(in6_addr);
            dnshdr->ancount ++;
        }
    }
    if(query->type == ns_t_ptr){
        len += putdomain(buf+len, query->domain);
        DNS_RR* rr= (DNS_RR*)(buf + len);
        rr->classes = htons(ns_c_in);
        rr->type = htons(ns_t_ptr);
        rr->TTL = htonl(ttl);
        int rdlength = putdomain(rr->rdata, domain);
        rr->rdlength = htons(rdlength);
        len += sizeof(DNS_RR) + rdlength;
        dnshdr->ancount ++;
    }
    HTONS(dnshdr->ancount);
    return len;
}

int Dns_Result::buildError(const Dns_Query* query, unsigned char errcode, unsigned char *buf){
    int len = query->build(buf);
    DNS_HDR *dnshdr = (DNS_HDR *)buf;
    dnshdr->qr = 1;
    dnshdr->rd = 1;
    dnshdr->ra = 1;
    dnshdr->rcode = errcode;
    return len;
}

