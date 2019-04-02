#include "vpn.h"
#include "prot/dns.h"
#include "misc/strategy.h"
#include "misc/util.h"
#include "misc/job.h"

#include "req/guest_vpn.h"

#include <string.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <openssl/ssl.h>

int efd = 0;
uint32_t debug = 0;
uint32_t vpn_contiune;

#define VPN_RESET 1u
#define VPN_RELOAD 2u
uint32_t vpn_action = 0;

int vpn_start(int fd){
    signal(SIGPIPE, SIG_IGN);
    signal(SIGCHLD, SIG_IGN);
    setvbuf(stdout, nullptr, _IOLBF, BUFSIZ);
#if Backtrace_FOUND
    signal(SIGABRT, dump_trace);
#endif
    signal(SIGHUP, (sig_t)reloadstrategy);
    signal(SIGUSR1, (sig_t)(void(*)())dump_stat);
    reloadstrategy();
    SSL_library_init();    // SSL初库始化
    SSL_load_error_strings();  // 载入所有错误信息
    efd = epoll_create1(EPOLL_CLOEXEC);
    if(efd < 0){
        LOGE("epoll_create: %s\n", strerror(errno));
        return -1;
    }
    new VPN_nanny(fd);
    vpn_contiune = 1;
    LOG("Accepting connections ...\n");
    while (vpn_contiune) {
        if(vpn_action & VPN_RESET){
            flushdns();
            flushproxy2(0);
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
        for (int i = 0; i < c; ++i) {
            Ep *ep = (Ep *)events[i].data.ptr;
            (ep->*ep->handleEvent)(convertEpoll(events[i].events));
        }
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
