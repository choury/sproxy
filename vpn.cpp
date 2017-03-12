#include "misc/strategy.h"
#include "misc/job.h"
#include "vpn.h"

#include "req/guest_vpn.h"

#include <signal.h>
#include <sys/epoll.h>
#include <openssl/ssl.h>



int efd;

int daemon_mode = 0;
int use_http2 = 1;
int udp_mode = 0;
int ignore_cert_error = 0;
int disable_ipv6 = 0;
char SHOST[DOMAINLIMIT] = {0};
uint16_t SPORT = 0;
Protocol SPROT = Protocol::TCP;
char auth_string[DOMAINLIMIT] = {0};
const char *cafile =  nullptr;
const char *index_file = nullptr;
uint32_t debug = DVPN;


int vpn_start(int fd){
    signal(SIGPIPE, SIG_IGN);
    signal(SIGCHLD, SIG_IGN);
    signal(SIGABRT, dump_trace);
    loadsites();
    SSL_library_init();    // SSL初库始化
    SSL_load_error_strings();  // 载入所有错误信息
    efd = epoll_create(10000);
    new Guest_vpn(fd);
    LOGOUT("Accepting connections ...\n");
    while (1) {
        int c;
        struct epoll_event events[200];
        if ((c = epoll_wait(efd, events, 200, do_job())) < 0) {
            if (errno != EINTR) {
                perror("epoll wait");
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
