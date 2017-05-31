#include "misc/strategy.h"
#include "misc/job.h"
#include "vpn.h"

#include "req/guest_vpn.h"

#include <signal.h>
//#include <sys/epoll.h>
#include <openssl/ssl.h>



int efd = 0;

int daemon_mode = 0;
int use_http2 = 1;
int ignore_cert_error = 0;
int disable_ipv6 = 0;
char SHOST[DOMAINLIMIT];
uint16_t SPORT;
Protocol SPROT;
char auth_string[DOMAINLIMIT] = {0};
const char *cafile =  nullptr;
const char *index_file = nullptr;
uint32_t debug = 0;


int vpn_start(const struct VpnConfig* vpn){
    signal(SIGPIPE, SIG_IGN);
    signal(SIGCHLD, SIG_IGN);
#ifndef __ANDROID__
    signal(SIGABRT, dump_trace);
#endif
    signal(SIGUSR1, dump_stat);
    disable_ipv6 = vpn->disable_ipv6;
    ignore_cert_error = vpn->ignore_cert_error;
    if(setproxy(vpn->server)){
        LOGE("wrong server format\n");
        return -1;
    }
    loadsites();
    SSL_library_init();    // SSL初库始化
    SSL_load_error_strings();  // 载入所有错误信息
    efd = epoll_create(10000);
    if(efd < 0){
        LOGE("epoll_create: %s\n", strerror(errno));
        return -1;
    }
    new Guest_vpn(vpn->fd);
    LOGOUT("Accepting connections ...\n");
    while (1) {
        int c;
        struct epoll_event events[200];
        if ((c = epoll_wait(efd, events, 200, do_job())) < 0) {
            if (errno != EINTR) {
                LOGE("epoll wait %s\n", strerror(errno));
                return 6;
            }
            continue;
        }
        for (int i = 0; i < c; ++i) {
            Con *con = (Con *)events[i].data.ptr;
            (con->*con->handleEvent)(events[i].events);
        }
    }
    return 0;
}

void vpn_stop(){
    releaseall();
}
