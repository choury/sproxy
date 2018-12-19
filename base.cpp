#include "base.h"
#include "misc/util.h"
#include "misc/job.h"
#include "prot/rwer.h"
#include "prot/dns.h"

#include <set>
#include <stdarg.h>
#include <unistd.h>
#include <assert.h>
#include <signal.h>

static std::set<std::shared_ptr<Server>> servers;

Server::Server(){
    servers.insert(std::shared_ptr<Server>(this));
}

Server::~Server() {
    delete rwer;
}


void Server::deleteLater(uint32_t) {
    if(rwer){
        rwer->Close([this](){
            servers.erase(std::dynamic_pointer_cast<Server>(shared_from_this()));
        });
    }else{
        servers.erase(std::dynamic_pointer_cast<Server>(shared_from_this()));
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
        rwer->addEvents(RW_EVENT::READ);
        rwer->TrigRead();
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
    char buff[DOMAINLIMIT];
    getproxy(buff, sizeof(buff));
    dp(param, "Proxy server: %s\n", buff);
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

void dump_stat(int sig){
    dump_stat(LogDump, nullptr);
    if(sig != SIGUSR1){
        signal(sig, SIG_DFL);
        kill(getpid(), sig);
    }
}

int setproxy(const char* proxy){
    if(spliturl(proxy, SPROT, SHOST, nullptr, &SPORT)){
        return -1;
    }

    if(SPORT == 0){
        SPORT = 443;
    }
    if(SPROT[0] == 0){
        strcpy(SPROT, "https");
    }
    flushproxy2(true);
    return 0;
}

int getproxy(char *buff, size_t buflen){
    if(SHOST[0] == 0) {
        buff[0] = 0;
        return 1;
    }else{
        assert(SPROT[0]);
        return snprintf(buff, buflen, "%s://%s:%d", SPROT, SHOST, SPORT)+1;
    }
}
