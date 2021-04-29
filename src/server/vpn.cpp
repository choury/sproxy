#include "vpn.h"
#include "req/guest_vpn.h"
#ifdef WITH_RPC
#include "req/cli.h"
#endif

#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <openssl/ssl.h>

volatile uint32_t vpn_contiune = 1;

int vpn_start(int fd){
    prepare();
#ifdef WITH_RPC
    if(opt.socket){
        int svsk_cli = ListenUnix(opt.socket);
        if(svsk_cli < 0){
            return -1;
        }
        new Cli_server(svsk_cli);
    }
#endif
    Vpn_server s(fd);
    LOG("Accepting connections ...\n");
    vpn_contiune = 1;
    while (vpn_contiune) {
        uint32_t msec = do_delayjob();
        if(event_loop(msec) < 0){
            break;
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
