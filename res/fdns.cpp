#include "fdns.h"
#include "prot/dns.h"
#include "req/requester.h"
#include "misc/strategy.h"
#include "misc/util.h"
#include "misc/index.h"

static Index2<uint32_t, std::string, void*> fdns_records;

static FDns *fdns = nullptr;
static in_addr_t fake_ip = 0 ;

FDns::FDns() {
    if(fake_ip == 0){
        fake_ip = ntohl(inet_addr("10.1.0.1"));
        fdns_records.Add(fake_ip, "VPN", nullptr);
    }
}

FDns::~FDns() {
    fdns = (fdns == this) ? nullptr: fdns;
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


ssize_t FDns::Send(void* buff, size_t size, void* index) {
    Dns_Que que((const char *)buff, size);
    p_free(buff);
    LOGD(DDNS, "FQuery %s [%d]: %d\n", que.host.c_str(), que.id, que.type);
    uint32_t id = (uint32_t)(long)index;
    if(statusmap.count(id)){
        Dns_Rr* rr = nullptr;
        FDnsStatus &status = statusmap[id];
        status.dns_id = que.id;
        if(que.type == 12 && que.ptr_addr.addr.sa_family == AF_INET){
            uint32_t ip = ntohl(que.ptr_addr.addr_in.sin_addr.s_addr);
            auto record = fdns_records.Get(ip);
            if(record){
                rr = new Dns_Rr(record->t2.c_str());
            }
        }
        if(que.type == 1) {
            std::string ignore;
            if (getstrategy(que.host.c_str(), ignore) == Strategy::direct) {
                query(que.host.c_str(), nullptr, nullptr);
            }
            in_addr addr = getInet(que.host);
            rr = new Dns_Rr(que.host.c_str(), &addr);
        }
        if(que.type == 28){
            rr = new Dns_Rr(que.host.c_str());
        }
        if(rr == nullptr){
            query(que.host.c_str(), que.type, DNSRAWCB(ResponseCb), reinterpret_cast<void*>(id));
            return size;
        }
        unsigned char * buff = (unsigned char *)p_malloc(BUF_LEN);
        status.req_ptr->Send(buff, rr->build(&que, buff), status.req_index);
        status.req_ptr->finish(NOERROR | DISCONNECT_FLAG, status.req_index);
        fdns->statusmap.erase(id);
        delete rr;
        return size;
    }
    return 0;
}

void FDns::ResponseCb(void* param, const char* buff, size_t size) {
    uint32_t id = (uint32_t)(long)param;
    if(fdns && fdns->statusmap.count(id)){
        FDnsStatus& status = fdns->statusmap[id];
        if(buff){
            LOGD(DDNS, "[FQuery] raw response [%d]\n", status.dns_id);
            DNS_HDR *dnshdr = (DNS_HDR*)buff;
            dnshdr->id = htons(status.dns_id);
            status.req_ptr->Send(buff, size, status.req_index);
        }
        status.req_ptr->finish(NOERROR | DISCONNECT_FLAG, status.req_index);
        fdns->statusmap.erase(id);
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

void FDns::writedcb(void*){
}

void FDns::deleteLater(uint32_t errcode) {
    fdns = (fdns == this) ? nullptr: fdns;
    for(auto i: statusmap){
        i.second.req_ptr->finish(errcode, i.second.req_index);
    }
    statusmap.clear();
    return Peer::deleteLater(errcode);
}


void FDns::dump_stat(Dumper dp, void* param) {
    dp(param, "FDns %p, id: %d:\n", this, req_id);
    for(auto i: statusmap){
        dp(param, "0x%x: %p, %p\n", i.first, i.second.req_ptr, i.second.req_index);
    }
}



FDns* FDns::getfdns() {
    if(fdns == nullptr){
       fdns = new FDns;
    }
    return fdns;
}

std::string FDns::getRdns(const struct in_addr* addr) {
    static char sip[INET_ADDRSTRLEN];
    uint32_t fip = ntohl(addr->s_addr);
    auto record = fdns_records.Get(fip);
    if(record){
        return record->t2;
    }else{
        return inet_ntop(AF_INET, addr, sip, sizeof(sip));
    }
}


in_addr FDns::getInet(std::string hostname) {
    in_addr addr;

    if(hostname.find_first_of(".") == std::string::npos){
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
