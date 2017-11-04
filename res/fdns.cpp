#include "prot/dns.h"
#include "req/requester.h"
#include "misc/strategy.h"
#include "fdns.h"

static binmap<uint32_t, std::string> fdns_records;

static FDns *fdns = nullptr;
static in_addr_t fake_ip = 0 ;

FDns::FDns() {
    if(fake_ip == 0){
        fake_ip = ntohl(inet_addr("10.0.0.2"));
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
    Dns_Que que((const char *)buff);
    p_free(buff);
    LOGD(DDNS, "FQuery %s [%d]: %d\n", que.host.c_str(), que.id, que.type);
    uint32_t id = (uint32_t)(long)index;
    if(statusmap.count(id)){
        Dns_Rr* rr = nullptr;
        FDnsStatus &status = statusmap[id];
        status.dns_id = que.id;
        if(que.type == 12 && que.ptr_addr.addr.sa_family == AF_INET){
            uint32_t ip = ntohl(que.ptr_addr.addr_in.sin_addr.s_addr);
            if(fdns_records.count(ip)){
                rr = new Dns_Rr(fdns_records[ip].c_str(), true);
            }
        }
        if(que.type == 1) {
            std::string ignore;
            if (getstrategy(que.host.c_str(), ignore) == Strategy::direct) {
                query(que.host.c_str(), nullptr, nullptr);
            }
            in_addr addr = getInet(que.host);
            rr = new Dns_Rr(&addr);
        }
        if(que.type == 28){
            rr = new Dns_Rr();
        }
        if(rr == nullptr){
            query(que.host.c_str(), que.type, DNSRAWCB(ResponseCb), reinterpret_cast<void*>(id));
            return size;
        }
        unsigned char * buff = (unsigned char *)p_malloc(BUF_LEN);
        status.req_ptr->Send(buff, rr->build(&que, buff), status.req_index);
        status.req_ptr->finish(NOERROR, status.req_index);
        fdns->statusmap.erase(id);
        delete rr;
        return size;
    }
    return 0;
}

void FDns::ResponseCb(uint32_t id, const char* buff, size_t size) {
    if(fdns && fdns->statusmap.count(id)){
        FDnsStatus& status = fdns->statusmap[id];
        if(buff){
            LOGD(DDNS, "[FQuery] raw response [%d]\n", status.dns_id);
            DNS_HDR *dnshdr = (DNS_HDR*)buff;
            dnshdr->id = htons(status.dns_id);
            status.req_ptr->Send(buff, size, status.req_index);
        }
        status.req_ptr->finish(NOERROR, status.req_index);
        fdns->statusmap.erase(id);
    }
}


bool FDns::finish(uint32_t flags, void* index) {
    uint32_t id = (uint32_t)(long)index;
    assert(statusmap.count(id));
    uint8_t errcode = flags & ERROR_MASK;
    if(errcode == VPN_AGED_ERR){
        FDnsStatus& status = statusmap[id];
        status.req_ptr->finish(errcode, status.req_index);
        statusmap.erase(id);
        return false;
    }
    if(errcode){
        statusmap.erase(id);
        return false;
    }
    return true;
}

void FDns::deleteLater(uint32_t errcode) {
    fdns = (fdns == this) ? nullptr: fdns;
    for(auto i: statusmap){
        i.second.req_ptr->finish(errcode, i.second.req_index);
    }
    statusmap.clear();
    return Peer::deleteLater(errcode);
}


void FDns::dump_stat() {
    LOG("FDns %p, id: %d:\n", this, req_id);
    for(auto i: statusmap){
        LOG("0x%x: %p, %p\n", i.first, i.second.req_ptr, i.second.req_index);
    }
}



FDns * FDns::getfdns() {
    if(fdns == nullptr){
       fdns = new FDns;
    }
    return fdns;
}

const char * FDns::getRdns(const struct in_addr* addr) {
    static char sip[INET_ADDRSTRLEN];
    uint32_t fip = ntohl(addr->s_addr);
    if(fdns_records.count(fip)){
        return fdns_records[fip].c_str();
    }else{
        return inet_ntop(AF_INET, addr, sip, sizeof(sip));
    }
}


in_addr FDns::getInet(std::string hostname) {
    in_addr addr;

    if(hostname.find_first_of(".") == std::string::npos){
        addr.s_addr = inet_addr("10.0.0.1");
    }else if(fdns_records.count(hostname)){
        addr.s_addr = htonl(fdns_records[hostname]);
    }else{
        addr.s_addr= htonl(fake_ip);
        fdns_records.insert(fake_ip++, hostname);
    }
    return addr;
}
