#include "base.h"
#include "misc/util.h"
#include "misc/job.h"
#include "misc/config.h"

#include <set>
#include <stdarg.h>
#include <unistd.h>

static std::set<Server*> servers;

Server::Server(){
    servers.emplace(this);
}

Server::~Server() {
    delete rwer;
    servers.erase(this);
}


void Server::deleteLater(uint32_t) {
    if(rwer){
        rwer->Close([this](){
            delete this;
        });
    }else{
        delete this;
    }
}

void releaseall() {
    auto serversCopy = servers;
    for(auto i: serversCopy){
        delete i;
    }
    servers.clear();
}

extern void dump_dns(Dumper dp, void* param);
extern void dump_job(Dumper dp, void* param);

void dump_stat(Dumper dp, void* param){
    dp(param, "======================================\n");
    dp(param, "Proxy server: %s\n", dumpDest(&opt.Server));
    dp(param, "--------------------------------------\n");
    for(auto i: servers){
        i->dump_stat(dp, param);
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
