#include "vpn.h"
#include "req/guest_vpn.h"
#include "req/cli.h"

#include <string.h>
#include <unistd.h>

int vpn_start(int fd){
    Cli_server* cli = nullptr;
    if(opt.admin && strlen(opt.admin) > 0){
        int svsk_cli = -1;
        if(strncmp(opt.admin, "tcp:", 4) == 0){
            svsk_cli = ListenNet(SOCK_STREAM, "[::]", atoi(opt.admin+4));
        }else{
            svsk_cli = ListenUnix(opt.admin);
        }
        if(svsk_cli < 0){
            return -1;
        }
        cli = new Cli_server(svsk_cli);
    }
    new Guest_vpn(fd);
    LOG("Accepting connections ...\n");
    will_contiune = 1;
    while (will_contiune) {
        uint32_t msec = do_delayjob();
        if(event_loop(msec) < 0){
            break;
        }
    }
    LOG("VPN exiting ...\n");
    neglect();
    delete cli;
    return 0;
}


void vpn_stop(){
    will_contiune = 0;
}
