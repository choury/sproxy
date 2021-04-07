#include "vpn.h"
#include "req/guest_vpn.h"

#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <openssl/ssl.h>

int efd = 0;
volatile uint32_t vpn_contiune = 1;

int vpn_start(int fd){
    prepare();
    efd = epoll_create1(EPOLL_CLOEXEC);
    if(efd < 0){
        LOGE("epoll_create: %s\n", strerror(errno));
        return -1;
    }
    new Vpn_server(fd);
    LOG("Accepting connections ...\n");
    while (vpn_contiune) {
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
    flushdns();
    flushproxy2();
    releaseall();
    return 0;
}


void vpn_stop(){
    vpn_contiune = 0;
}