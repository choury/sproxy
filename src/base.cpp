#include "base.h"
#include "misc/util.h"
#include "misc/job.h"
#include "misc/config.h"
#include "prot/rwer.h"
#include "prot/dns.h"

#include <map>
#include <stdarg.h>
#include <unistd.h>
#include <assert.h>
#include <signal.h>

static std::map<Server*, std::shared_ptr<Server>> servers;

Server::Server(){
    servers.emplace(this, std::shared_ptr<Server>(this));
}

Server::~Server() {
    delete rwer;
}


void Server::deleteLater(uint32_t) {
    if(rwer){
        rwer->Close([this](){
            servers.erase(this);
        });
    }else{
        servers.erase(this);
    }
}

void Peer::Send(const void* buff, size_t size, void* index) {
    Send(p_memdup(buff, size), size, index);
}

void Peer::Send(void* buff, size_t size, void* index) {
    Send((const void*)buff, size, index);
    p_free(buff);
}

void Peer::writedcb(const void*) {
    if(rwer){
        rwer->EatReadData();
    }
}

extern int efd;
void releaseall() {
    servers.clear();
    if(efd){
        close(efd);
        efd = 0;
    }
}

extern void dump_dns(Dumper dp, void* param);
extern void dump_job(Dumper dp, void* param);

void dump_stat(Dumper dp, void* param){
    dp(param, "======================================\n");
    dp(param, "Proxy server: %s\n", dumpDest(&opt.Server));
    dp(param, "--------------------------------------\n");
    for(auto i: servers){
        i.first->dump_stat(dp, param);
        dp(param, "--------------------------------------\n");
    }
    dump_dns(dp, param);
    dp(param, "--------------------------------------\n");
    dump_job(dp, param);
    dp(param, "======================================\n");
}

static void LogDump(void*, const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    VLOG(LOG_INFO, fmt, ap);
    va_end(ap);
}

void dump_stat(){
    dump_stat(LogDump, nullptr);
}
