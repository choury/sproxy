#include "dns.h"
#include "misc/net.h"
#include "misc/cursor.h"
#include <string.h>

#include <optional>
#include <string>

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

//DNS报文游标：在通用游标上叠加DNS原语
//base为报文起点指针，作为压缩指针绝对偏移的基准，永不变化
class DnsCursor: public cursor {
    const unsigned char* base;
    //报文总长 = 已消费(data()-base) + 剩余(length())，advance一增一减和不变
    size_t packet_len() const {
        return length() + (data() - base);
    }
    //仅供derive：位置游标与基准分别指定，保证子游标的base仍是报文起点
    DnsCursor(const cursor& pos, const unsigned char* pkt): cursor(pos), base(pkt) {}
public:
    DnsCursor(const void* buff, size_t len):
        cursor(buff, len), base(static_cast<const unsigned char*>(buff)) {}
    DnsCursor(void* buff, size_t len):
        cursor(buff, len), base(static_cast<const unsigned char*>(buff)) {}

    //按报文内绝对偏移派生子游标(压缩指针用)；偏移0(ID字段)或越界返回nullopt
    //base必须保持报文起点：链式压缩时内层指针仍按报文绝对偏移解析
    std::optional<DnsCursor> derive(size_t offset) const {
        if(offset == 0 || offset >= packet_len()){
            return std::nullopt;
        }
        return DnsCursor(cursor(base + offset, packet_len() - offset), base);
    }

    //解析一个域名并越过它；返回值不带尾部'.'，失败返回nullopt
    //plen为祖先递归已积累的长度，用于约束拼接后的总长
    std::optional<std::string> getdomain(int depth = 0, size_t plen = 0) {
        if(depth > 16){
            return std::nullopt;
        }
        std::string domain;
        while(length() && *data()) {
            unsigned char l = *data();
            if(l > 63) {
                //压缩指针：从报文起点派生子游标，不做指针回退
                if(length() < 2){
                    return std::nullopt;
                }
                size_t offset = ((l & 0x3fu) << 8) | data()[1];
                auto child = derive(offset);
                if(!child){
                    return std::nullopt;
                }
                auto rest = child->getdomain(depth + 1, plen + domain.size());
                if(!rest || !advance(2)){
                    return std::nullopt;
                }
                if(rest->empty() && !domain.empty()) {
                    domain.pop_back(); //指针指向根标签：去掉父级尾点
                }
                domain += *rest; //父级尾点保留作标签分隔符
                return domain;
            }
            if(length() < (size_t)l + 1){
                return std::nullopt;
            }
            if(plen + domain.size() + l + 1 >= DOMAINLIMIT){
                return std::nullopt;
            }
            domain.append((const char*)data() + 1, l);
            domain.push_back('.');
            advance(l + 1);
        }
        if(!length()){
            return std::nullopt; //缺少根标签
        }
        advance(1);
        if(!domain.empty()){
            domain.pop_back();
        }
        return domain;
    }

    //将域名编码为标签序列写入游标；空间不足或标签超长(>63)时返回false
    //写入的字节数由调用方经游标length()前后差获得
    bool putdomain(const char* domain) {
        if(domain[0] == '.' || domain[0] == 0){
            return write<unsigned char>(0);
        }
        const char* p = domain;
        while(*p){
            const char* dot = strchr(p, '.');
            size_t l = dot ? dot - p : strlen(p);
            if(l == 0 || l > 63) {
                return false;
            }
            if(!write<unsigned char>((unsigned char)l) || !write_data(p, l)) {
                return false;
            }
            p += l;
            if(!dot) {
                break;
            }
            p++; //跳过'.'
        }
        return write<unsigned char>(0);
    }
};

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
    DnsCursor packet(buff, len);
    const DNS_HDR* dnshdr = packet.read<DNS_HDR>();
    if(dnshdr == nullptr){
        return;
    }
    id = ntohs(dnshdr->id);
    auto name = packet.getdomain();
    if(!name || !is_valid(name->c_str())) {
        return;
    }
    strcpy(domain, name->c_str());
    const DNS_QUE* que = packet.read<DNS_QUE>();
    if(que == nullptr || ntohs(que->classes) != ns_c_in){
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



int Dns_Query::build(unsigned char* buf, size_t buf_len) const {
    DnsCursor c(buf, buf_len);
    DNS_HDR* dnshdr = c.write<DNS_HDR>();
    if(dnshdr == nullptr){
        LOGE("[DNS] buffer too small to build query: %zd\n", buf_len);
        return 0;
    }
    dnshdr->id = htons(id);
    dnshdr->rd = 1;
    dnshdr->qdcount = htons(1);

    if(!c.putdomain(domain)){
        LOGE("[DNS] buffer too small to build query: %zd\n", buf_len);
        return 0;
    }
    DNS_QUE* que = c.write<DNS_QUE>();
    if(que == nullptr){
        return 0;
    }
    que->classes = htons(ns_c_in);
    que->type = htons(type);

    return (int)(buf_len - c.length());
}

Dns_Result::Dns_Result(const char* buff, size_t len): id(0) {
    DnsCursor packet(buff, len);
    const DNS_HDR* dnshdr = packet.read<DNS_HDR>();
    if(dnshdr == nullptr){
        error = ns_r_formerr;
        LOGE("[DNS] incomplete DNS response\n");
        return;
    }
    if(ntohs(dnshdr->qdcount) == 0 || !dnshdr->qr){
        error = ns_r_formerr;
        LOGE("[DNS] <%d> malformed response header\n", ntohs(dnshdr->id));
        return;
    }
    uint16_t numq = ntohs(dnshdr->qdcount);
    for (int i = 0; i < numq; ++i) {
        auto name = packet.getdomain();
        if(!name){
            error = ns_r_formerr;
            LOGE("[DNS] <%d> numq formerr\n", ntohs(dnshdr->id));
            return;
        }
        strcpy(domain, name->c_str());
        const DNS_QUE* que = packet.read<DNS_QUE>();
        if(que == nullptr){
            error = ns_r_formerr;
            LOGE("[DNS] <%d> numq overflow\n", ntohs(dnshdr->id));
            return;
        }
        type = ntohs(que->type);
        LOGD(DDNS, "[%d] response for %s, type: %d:\n", ntohs(dnshdr->id), domain, type);
    }
    if(dnshdr->rcode !=0){
        error = dnshdr->rcode;
        LOG("[DNS] <%d> ack error: %s: %u\n", ntohs(dnshdr->id), domain, error);
        return;
    }
    uint16_t numa = ntohs(dnshdr->ancount);
    for(int i = 0; i < numa; ++i) {
        auto name = packet.getdomain();
        if(!name){
            error = ns_r_formerr;
            LOGE("[DNS] <%d> numa formerr\n", ntohs(dnshdr->id));
            return;
        }
        strcpy(domain, name->c_str());
        const DNS_RR* dnsrr = packet.read<DNS_RR>();
        if(dnsrr == nullptr){
            error = ns_r_formerr;
            LOGE("[DNS] <%d> numa overflow\n", ntohs(dnshdr->id));
            return;
        }
        if(ntohs(dnsrr->classes) != ns_c_in){
            error = ns_r_formerr;
            return;
        }
        uint32_t ttl = ntohl(dnsrr->TTL);
        uint16_t rdlength = ntohs(dnsrr->rdlength);
        if(packet.length() < rdlength){
            error = ns_r_formerr;
            LOGE("[DNS] <%d> rdlength overflow\n", ntohs(dnshdr->id));
            return;
        }
        char __attribute__((unused)) ipaddr[INET6_ADDRSTRLEN] = {0};
        switch (ntohs(dnsrr->type)) {
        case ns_t_a:{
            if(rdlength < sizeof(in_addr)) break;
            sockaddr_storage ip;
            memset(&ip, 0, sizeof(ip));
            sockaddr_in* ip4 = (sockaddr_in*)&ip;
            ip4->sin_family = AF_INET;
            memcpy(&ip4->sin_addr, packet.data(), sizeof(in_addr));
            addrs.push_back(ip);
            LOGD(DDNS, "A: %s ==> %s [%d]\n", domain, inet_ntop(AF_INET, packet.data(), ipaddr, sizeof(ipaddr)), ttl);
            break;
        }
        case ns_t_ns: {
            DnsCursor rc = packet; //rdata内的名字用子游标解析，主游标按rdlength跳过
            if(auto ns = rc.getdomain()) {
                LOGD(DDNS, "NS: %s ==> %s [%d]\n", domain, ns->c_str(), ttl);
            }
            break;
        }
        case ns_t_cname: {
            DnsCursor rc = packet;
            if(auto cname = rc.getdomain()) {
                LOGD(DDNS, "CNAME: %s ==> %s [%d]\n", domain, cname->c_str(), ttl);
            }
            break;
        }
        case ns_t_aaaa:{
            if(rdlength < sizeof(in6_addr)) break;
            sockaddr_storage ip;
            memset(&ip, 0, sizeof(ip));
            sockaddr_in6* ip6 = (sockaddr_in6*)&ip;
            ip6->sin6_family = AF_INET6;
            memcpy(&ip6->sin6_addr, packet.data(), sizeof(in6_addr));
            addrs.push_back(ip);
            LOGD(DDNS, "AAAA: %s ==> %s [%d]\n", domain, inet_ntop(AF_INET6, packet.data(), ipaddr, sizeof(ipaddr)), ttl);
            break;
        }
        default:
            break;
        }
        this->ttl = std::min(ttl, this->ttl);
        packet.advance(rdlength);
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

//在query->build写好的报文头部设置响应标志位
//头指针借用buf起点：游标只前进，对已写区域的回借不属于游标操作
static DNS_HDR* set_response_flags(unsigned char* buf) {
    DNS_HDR* dnshdr = (DNS_HDR*)buf;
    dnshdr->qr = 1;
    dnshdr->rd = 1;
    dnshdr->ra = 1;
    return dnshdr;
}

int Dns_Result::build(const Dns_Query* query, unsigned char* buf, size_t buf_len) const {
    int len = query->build(buf, buf_len);
    if(len == 0){
        return 0;
    }
    DNS_HDR* dnshdr = set_response_flags(buf);
    DnsCursor c(buf, buf_len);
    c.advance(len);

    for(auto addr : addrs) {
        if(query->type == ns_t_a && addr.ss_family == AF_INET){
            //试探-提交：子游标上确认整条RR放得下，再正式写入(提交后write不会再失败)
            DnsCursor trial = c;
            if(!trial.putdomain(query->domain) ||
               trial.length() < sizeof(DNS_RR) + sizeof(in_addr))
            {
                break;
            }
            c.putdomain(query->domain);
            DNS_RR* rr = c.write<DNS_RR>();
            rr->classes = htons(ns_c_in);
            rr->type = htons(ns_t_a);
            rr->TTL = htonl(ttl);
            rr->rdlength = htons(sizeof(in_addr));
            sockaddr_in* addr4 = (sockaddr_in*)&addr;
            c.write(addr4->sin_addr);
            dnshdr->ancount ++;
        }
        if(query->type == ns_t_aaaa && addr.ss_family == AF_INET6){
            DnsCursor trial = c;
            if(!trial.putdomain(query->domain) ||
               trial.length() < sizeof(DNS_RR) + sizeof(in6_addr))
            {
                break;
            }
            c.putdomain(query->domain);
            DNS_RR* rr = c.write<DNS_RR>();
            rr->classes = htons(ns_c_in);
            rr->type = htons(ns_t_aaaa);
            rr->TTL = htonl(ttl);
            rr->rdlength = htons(sizeof(in6_addr));
            sockaddr_in6* addr6 = (sockaddr_in6*)&addr;
            c.write(addr6->sin6_addr);
            dnshdr->ancount ++;
        }
    }
    if(query->type == ns_t_ptr){
        DnsCursor trial = c;
        if(trial.putdomain(query->domain) && trial.length() >= sizeof(DNS_RR)){
            //rdata中的名字再派生子游标试写，写入前后length()差即精确rdlength
            DnsCursor rdata = trial;
            rdata.advance(sizeof(DNS_RR));
            size_t before = rdata.length();
            if(rdata.putdomain(domain)){
                size_t rdlength = before - rdata.length();
                c.putdomain(query->domain);
                DNS_RR* rr = c.write<DNS_RR>();
                rr->classes = htons(ns_c_in);
                rr->type = htons(ns_t_ptr);
                rr->TTL = htonl(ttl);
                rr->rdlength = htons(rdlength);
                c.putdomain(domain);
                dnshdr->ancount ++;
            }
        }
    }
    HTONS(dnshdr->ancount);
    return (int)(buf_len - c.length());
}

int Dns_Result::buildError(const Dns_Query* query, unsigned char errcode, unsigned char *buf){
    int len = query->build(buf, BUF_LEN);
    if(len == 0){
        return 0;
    }
    DNS_HDR* dnshdr = set_response_flags(buf);
    dnshdr->rcode = errcode;
    return len;
}

