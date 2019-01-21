#include "vpn.h"
#include "prot/dns.h"
#include "misc/strategy.h"
#include "misc/job.h"
#include "misc/util.h"

#include "req/guest_vpn.h"

#include <string.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <openssl/ssl.h>



int efd = 0;

int daemon_mode = 0;
int use_http2 = 1;
int ignore_cert_error = 0;
int disable_ipv6 = 0;
char SPROT[DOMAINLIMIT];
char SHOST[DOMAINLIMIT];
uint16_t SPORT;
char auth_string[DOMAINLIMIT] = {0};
char rewrite_auth[DOMAINLIMIT] = {0};
const char *cafile =  nullptr;
const char *index_file = nullptr;
int autoindex = 0;
uint32_t debug = 0;
uint32_t vpn_contiune;

#define VPN_RESET 1u
#define VPN_RELOAD 2u
uint32_t vpn_action = 0;

int vpn_start(const struct VpnConfig* vpn){
    signal(SIGPIPE, SIG_IGN);
    signal(SIGCHLD, SIG_IGN);
    setvbuf(stdout, nullptr, _IOLBF, BUFSIZ);
#if Backtrace_FOUND
    signal(SIGABRT, dump_trace);
#endif
    signal(SIGUSR1, dump_stat);
    daemon_mode = vpn->daemon_mode;
    disable_ipv6 = vpn->disable_ipv6;
    ignore_cert_error = vpn->ignore_cert_error;
    if(setproxy(vpn->server)){
        LOGE("wrong server format\n");
        return -1;
    }
    LOG("set server to: %s\n", vpn->server);
    reloadstrategy();
    SSL_library_init();    // SSL初库始化
    SSL_load_error_strings();  // 载入所有错误信息
    if (daemon_mode && daemon(1, 0) < 0) {
        fprintf(stderr, "start daemon error:%s\n", strerror(errno));
        return -1;
    }
    efd = epoll_create1(EPOLL_CLOEXEC);
    if(efd < 0){
        LOGE("epoll_create: %s\n", strerror(errno));
        return -1;
    }
    Base64Encode(vpn->secret, strlen(vpn->secret), rewrite_auth);
    LOG("set encoded secret to: %s\n", rewrite_auth);

    new VPN_nanny(vpn->fd);
    vpn_contiune = 1;
    LOG("Accepting connections ...\n");
    while (vpn_contiune) {
        if(vpn_action & VPN_RESET){
            flushdns();
            flushproxy2(false);
            vpn_action &= ~VPN_RESET;
        }
        if(vpn_action & VPN_RELOAD){
            reloadstrategy();
            vpn_action &= ~VPN_RELOAD;
        }
        int c;
        struct epoll_event events[200];
        if ((c = epoll_wait(efd, events, 200, do_delayjob())) <= 0) {
            if (c != 0 && errno != EINTR) {
                LOGE("epoll_wait %s\n", strerror(errno));
                return 6;
            }
            continue;
        }
        do_prejob();
        for (int i = 0; i < c; ++i) {
            Ep *ep = (Ep *)events[i].data.ptr;
            (ep->*ep->handleEvent)(convertEpoll(events[i].events));
        }
        do_postjob();
    }
    LOG("VPN exiting ...\n");
    releaseall();
    flushdns();
    return 0;
}


void vpn_stop(){
    vpn_contiune = 0;
}


void vpn_reset(){
    vpn_action |= VPN_RESET;
}

void vpn_reload(){
    vpn_action |= VPN_RELOAD;
}
