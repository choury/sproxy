#include "fdns.h"
#include "prot/dns.h"
#include "req/requester.h"
#include "misc/strategy.h"
#include "misc/util.h"
#include "misc/index.h"

#include <inttypes.h>

static Index2<uint32_t, std::string, void*> fdns_records;

static FDns* fdns = nullptr;
static in_addr_t fake_ip = 0 ;

static in_addr getInet(std::string hostname) {
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

static in6_addr getInet6(std::string hostname) {
    return mapIpv4(getInet(std::move(hostname)));
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
            abort();
    }
    return fip;
}

std::string getRdns(const sockaddr_un& addr) {
    auto record = fdns_records.Get(getFip(addr));
    if(record){
        return record->t2;
    }else{
        return getaddrstring(&addr);
    }
}

FDns::FDns() {
    if(fake_ip == 0){
        fake_ip = ntohl(inet_addr("10.1.0.1"));
        fdns_records.Add(fake_ip, "VPN", nullptr);
    }
    rwer = new NullRWer();
}

FDns::~FDns() {
    if(fdns && fdns == this){
        fdns = nullptr;
    }
}

void FDns::request(HttpReq* req, Requester*){
    uint32_t id = req->header->request_id;
    HttpRes* res = new HttpRes(new HttpResHeader(H200));
    statusmap[id]= FDnsStatus{req, res};
    req->response(res);
    req->setHandler([this, res, id](Channel::signal s){
        if(s == Channel::CHANNEL_SHUTDOWN){
            res->trigger(Channel::CHANNEL_ABORT);
        }
        statusmap.erase(id);
    });
    req->attach((Channel::recv_const_t)std::bind(&FDns::Send, this, id, _1, _2), []{return 512;});
}


struct FDns_req{
    uint64_t id;
    Dns_Que  que;
};

void FDns::Send(uint32_t id, const void* buff, size_t size) {
    if(statusmap.count(id)){
        FDnsStatus &status = statusmap[id];
        FDns_req* req = new FDns_req{id, Dns_Que((const char *)buff, size)};
        if(!req->que.valid){
            char out[size*2];
            for(size_t i = 0; i < size; i++){
                sprintf(out+i*2, "%02X", ((unsigned char*)buff)[i]);
            }
            LOGE("invalid dns request [%zd]: %s\n", size, out);
            delete req;
            return;
        }
        LOGD(DDNS, "FQuery %s [%d]: %d\n", req->que.host.c_str(), req->que.id, req->que.type);
        Dns_Rr* rr = nullptr;
        if(req->que.type == 12){
            auto record = fdns_records.Get(getFip(req->que.ptr_addr));
            if(record){
                rr = new Dns_Rr(record->t2.c_str());
            }
        }else if(req->que.type == 1 || req->que.type == 28) {
            strategy stra = getstrategy(req->que.host.c_str());
            if (stra.s == Strategy::direct) {
                query(req->que.host.c_str(), DnsCb, req);
                return;
            }
            if(req->que.type == 1){
                in_addr addr = getInet(req->que.host);
                rr = new Dns_Rr(req->que.host.c_str(), &addr);
            }else{
                in6_addr addr = getInet6(req->que.host);
                rr = new Dns_Rr(req->que.host.c_str(), &addr);
            }
        }
        if(rr == nullptr) {
            query(req->que.host.c_str(), req->que.type, RawCb, req);
            return;
        }
        unsigned char *const buff = (unsigned char *) p_malloc(BUF_LEN);
        status.res->send(buff, rr->build(&req->que, buff));
        delete req;
        delete rr;
    }
}

void FDns::DnsCb(void *param, std::list<sockaddr_un> addrs) {
    FDns_req* req = (FDns_req*)param;
    if(fdns && fdns->statusmap.count(req->id)){
        FDnsStatus& status = fdns->statusmap[req->id];
        Dns_Rr* rr = nullptr;
        if(addrs.empty()){
            rr = new Dns_Rr(req->que.host.c_str());
        }else if(req->que.type == 1){
            in_addr addr = getInet(req->que.host);
            rr = new Dns_Rr(req->que.host.c_str(), &addr);
        }else{
            in6_addr addr = getInet6(req->que.host);
            rr = new Dns_Rr(req->que.host.c_str(), &addr);
        }
        unsigned char *const buff = (unsigned char *) p_malloc(BUF_LEN);
        status.res->send(buff, rr->build(&req->que, buff));
    }
    delete req;
}

void FDns::RawCb(void* param, const char* buff, size_t size) {
    FDns_req* req = (FDns_req*)param;
    if(fdns && fdns->statusmap.count(req->id)){
        FDnsStatus& status = fdns->statusmap[req->id];
        if(buff){
            LOGD(DDNS, "[FQuery] raw response [%d]\n", req->que.id);
            DNS_HDR *dnshdr = (DNS_HDR*)buff;
            dnshdr->id = htons(req->que.id);
            status.res->send(buff, size);
        }else {
            LOGD(DDNS, "[FQuery] raw response [%d] error\n", req->que.id);
            Dns_Rr rr(req->que.host.c_str());
            unsigned char *const buff = (unsigned char *) p_malloc(BUF_LEN);
            status.res->send(buff, rr.buildError(&req->que, DNS_SERVER_FAIL, buff));
        }
    }
    delete req;
}

void FDns::deleteLater(uint32_t errcode) {
    if(fdns && fdns == this){
        fdns = nullptr;
    }
    for(const auto& i: statusmap){
        i.second.res->trigger(Channel::CHANNEL_ABORT);
    }
    statusmap.clear();
    return Server::deleteLater(errcode);
}


void FDns::dump_stat(Dumper dp, void* param) {
    dp(param, "FDns %p\n", this);
    for(const auto& i: statusmap){
        dp(param, "%" PRIu64 ": %s\n",
                i.second.req->header->request_id,
                i.second.req->header->geturl().c_str());
    }
}



FDns* FDns::getfdns() {
    if(!fdns){
       fdns = new FDns();
    }
    return fdns;
}




