#include "prot/dns.h"
#include "req/requester.h"
#include "fdns.h"


binmap<uint32_t, std::string> fdns_records;

static FDns *fdns = nullptr;

void* FDns::request(HttpReqHeader&& req){
    statusmap[req_id]= FDnsStatus{
        req.src,
        req.index,
        0
    };
    return reinterpret_cast<void*>(req_id++);
}


ssize_t FDns::Write(void* buff, size_t size, void* index) {
    Dns_Que que((char *)buff);
    p_free(buff);
    LOGD(DDNS, "Query %s: %d\n", que.host.c_str(), que.type);
    uint32_t id = (uint32_t)(long)index;
    if(statusmap.count(id)){
        FDnsStatus& status = statusmap[id];
        status.dns_id = que.id;
        if(que.type != 1 && que.type != 28){
            query(que.host.c_str(), que.type, DNSRAWCB(ResponseCb), reinterpret_cast<void*>(id));
            return size;
        }
        in_addr addr;
        if(que.type == 1){
            if(fdns_records.count(que.host)){
                addr.s_addr = htonl(fdns_records[que.host]);
            }else{
                addr.s_addr= htonl(fake_ip);
                fdns_records.insert(fake_ip++, que.host);
            }
        }
        Dns_Rr rr(&addr);
        unsigned char * buff = (unsigned char *)p_malloc(BUF_LEN);
        status.req_ptr->Write(buff, rr.build(&que, buff), status.req_index);
    }
    return size;
}

void FDns::ResponseCb(uint32_t id, const char* buff, size_t size) {
    if(fdns && fdns->statusmap.count(id)){
        FDnsStatus& status = fdns->statusmap[id];
        if(buff){
            DNS_HDR *dnshdr = (DNS_HDR*)buff;
            dnshdr->id = htons(status.dns_id);
            status.req_ptr->Write(buff, size, status.req_index);
        }
    }
}

void FDns::clean(uint32_t errcode, void* index) {
    return;
}



FDns * FDns::getfdns() {
    if(fdns == nullptr){
       fdns = new FDns;
    }
    return fdns;
}


