#include "vpn.h"
#include "req/guest_vpn.h"
#include "req/cli.h"

#include <string.h>
#include <unistd.h>

int vpn_start(int fd){
    std::shared_ptr<Cli_server> cli;
    if(opt.admin.hostname[0]){
        int svsk_cli = -1;
        if(opt.admin.port){
            sockaddr_storage addr;
            if(storage_aton(opt.admin.hostname, opt.admin.port, &addr) == 0) {
                LOGE("failed to parse admin addr: %s\n", opt.admin.hostname);
                return -1;
            }
            svsk_cli = ListenTcp(&addr);
        }else{
            svsk_cli = ListenUnix(opt.admin.hostname);
        }
        if(svsk_cli < 0){
            return -1;
        }
        cli = std::make_shared<Cli_server>(svsk_cli);
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
    return 0;
}


void vpn_stop(){
    will_contiune = 0;
}
