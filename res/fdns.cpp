#include "fdns.h"
#include "prot/dns.h"
#include "req/requester.h"
#include "misc/strategy.h"
#include "misc/util.h"
#include "misc/index.h"

static Index2<uint32_t, std::string, void*> fdns_records;

static std::weak_ptr<FDns> fdns;
static in_addr_t fake_ip = 0 ;

FDns::FDns() {
    if(fake_ip == 0){
        fake_ip = ntohl(inet_addr("10.1.0.1"));
        fdns_records.Add(fake_ip, "VPN", nullptr);
    }
}

FDns::~FDns() {
}

void* FDns::request(HttpReqHeader* req){
    statusmap[req_id]= FDnsStatus{
        req->src,
        req->index,
        0
    };
    delete req;
    return reinterpret_cast<void*>(req_id++);
}

int32_t FDns::bufleft(void*) {
    return 1024*1024;
}

static uint32_t getFip(const sockaddr_un& addr){
    uint32_t fip = 0;
    switch(addr.addr.sa_family){
    case AF_INET:
        fip = ntohl(addr.addr_in.sin_addr.s_addr);
        break;
    case AF_INET6:
        fip = ntohl(getMapped(addr.addr_in6.sin6_addr).s_addr);
        break;
    default:
        assert(0);
    }
    return fip;
}

void FDns::Send(const void* buff, size_t size, void* index) {
    Dns_Que que((const char *)buff, size);
    LOGD(DDNS, "FQuery %s [%d]: %d\n", que.host.c_str(), que.id, que.type);
    uint32_t id = (uint32_t)(long)index;
    if(statusmap.count(id)){
        Dns_Rr* rr = nullptr;
        FDnsStatus &status = statusmap[id];
        status.dns_id = que.id;
        if(que.type == 12){
            auto record = fdns_records.Get(getFip(que.ptr_addr));
            if(record){
                rr = new Dns_Rr(record->t2.c_str());
            }
        }
        if(que.type == 1 || que.type == 28) {
            strategy stra = getstrategy(que.host.c_str());
            if (stra.s == Strategy::direct) {
                query(que.host.c_str(), nullptr, nullptr);
            }
            if(que.type == 1){
                in_addr addr = getInet(que.host);
                rr = new Dns_Rr(que.host.c_str(), &addr);
            }else{
                in6_addr addr = getInet6(que.host);
                rr = new Dns_Rr(que.host.c_str(), &addr);
            }
        }
        if(rr == nullptr){
            query(que.host.c_str(), que.type, ResponseCb, reinterpret_cast<void*>(id));
            return;
        }
        assert(!status.req_ptr.expired());
        unsigned char* const buff = (unsigned char *)p_malloc(BUF_LEN);
        status.req_ptr.lock()->Send(buff, rr->build(&que, buff), status.req_index);
        status.req_ptr.lock()->finish(NOERROR | DISCONNECT_FLAG, status.req_index);
        statusmap.erase(id);
        delete rr;
        return;
    }
}

void FDns::ResponseCb(void* param, const char* buff, size_t size) {
    uint32_t id = (uint32_t)(long)param;
    if(!fdns.expired() && fdns.lock()->statusmap.count(id)){
        FDnsStatus& status = fdns.lock()->statusmap[id];
        assert(!status.req_ptr.expired());
        if(buff){
            LOGD(DDNS, "[FQuery] raw response [%d]\n", status.dns_id);
            DNS_HDR *dnshdr = (DNS_HDR*)buff;
            dnshdr->id = htons(status.dns_id);
            status.req_ptr.lock()->Send(buff, size, status.req_index);
        }
        status.req_ptr.lock()->finish(NOERROR | DISCONNECT_FLAG, status.req_index);
        fdns.lock()->statusmap.erase(id);
    }
}


void FDns::finish(uint32_t flags, void* index) {
    uint32_t id = (uint32_t)(long)index;
    assert(statusmap.count(id));
    uint8_t errcode = flags & ERROR_MASK;
    if(errcode || (flags & DISCONNECT_FLAG)){
        statusmap.erase(id);
    }
}

void FDns::writedcb(const void*){
}

void FDns::deleteLater(uint32_t errcode) {
    if(!fdns.expired() && fdns.lock() == shared_from_this()){
        fdns = std::weak_ptr<FDns>();
    }
    for(const auto& i: statusmap){
        assert(!i.second.req_ptr.expired());
        i.second.req_ptr.lock()->finish(errcode, i.second.req_index);
    }
    statusmap.clear();
    return Peer::deleteLater(errcode);
}


void FDns::dump_stat(Dumper dp, void* param) {
    dp(param, "FDns %p, id: %d:\n", this, req_id);
    for(const auto& i: statusmap){
        dp(param, "0x%x: %p, %p\n", i.first, i.second.req_ptr.lock().get(), i.second.req_index);
    }
}



std::weak_ptr<FDns> FDns::getfdns() {
    if(fdns.expired()){
       fdns = std::dynamic_pointer_cast<FDns>((new FDns())->shared_from_this());
    }
    return fdns;
}

std::string FDns::getRdns(const sockaddr_un& addr) {
    auto record = fdns_records.Get(getFip(addr));
    if(record){
        return record->t2;
    }else{
        return getaddrstring(&addr);
    }
}


in_addr FDns::getInet(std::string hostname) {
    in_addr addr;

    if(hostname.find_first_of('.') == std::string::npos){
        addr.s_addr = inet_addr("10.1.0.1");
    }else if(fdns_records.Get(hostname)){
        addr.s_addr = htonl(fdns_records.Get(hostname)->t1);
    }else{
        fake_ip++;
        addr.s_addr= htonl(fake_ip);
        fdns_records.Add(fake_ip, hostname, nullptr);
    }
    return addr;
}

in6_addr FDns::getInet6(std::string hostname) {
    return mapIpv4(getInet(std::move(hostname)));
}
