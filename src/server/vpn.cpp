#include "vpn.h"
#include "req/guest_vpn.h"
#include "req/cli.h"

#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <openssl/ssl.h>

volatile uint32_t vpn_contiune = 1;

int vpn_start(int fd){
    if(opt.admin && strlen(opt.admin) > 0){
        int svsk_cli = -1;
        if(strncmp(opt.admin, "tcp:", 4) == 0){
            svsk_cli = ListenNet(SOCK_STREAM, atoi(opt.admin+4));
        }else{
            svsk_cli = ListenUnix(opt.admin);
        }
        if(svsk_cli < 0){
            return -1;
        }
        new Cli_server(svsk_cli);
    }
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
    neglect();
    return 0;
}


void vpn_stop(){
    vpn_contiune = 0;
}
