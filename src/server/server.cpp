#include "req/guest_sni.h"
#ifdef HAVE_QUIC
#include "prot/quic/quic_server.h"
#endif
#include "req/cli.h"
#include "misc/job.h"
#include "misc/config.h"
#include "prot/tls.h"

#include <errno.h>
#include <unistd.h>
#include <assert.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

//do nothing, useful for vpn only
int protectFd(int){
    return 1;
}

int main(int argc, char **argv) {
    parseConfig(argc, argv);
    if(opt.cert.crt && opt.cert.key) {
        SSL_CTX * ctx = initssl(opt.quic_mode, nullptr);
#ifdef HAVE_QUIC
        if(opt.quic_mode){
            struct sockaddr_storage addr;
            if(storage_aton(opt.CHOST, opt.CPORT, &addr) == 0) {
                return -1;
            }
            int svsk_quic = ListenUdp(&addr);
            if(svsk_quic <  0) {
                return -1;
            }
            SetRecvPKInfo(svsk_quic, &addr);
            new Quic_server(svsk_quic, ctx);
        }else {
#else
            assert(opt.quic_mode == 0);
        {
#endif
            int svsk_https = ListenTcp(opt.CHOST, opt.CPORT);
            if (svsk_https < 0) {
                return -1;
            }
            new Http_server<Guest>(svsk_https, ctx);
        }
    }else{
#ifdef HAVE_QUIC
        if(opt.quic_mode && opt.sni_mode) {
            int svsk_sni = ListenTcp(opt.CHOST, opt.CPORT);
            if (svsk_sni < 0) {
                return -1;
            }
            new Quic_sniServer(svsk_sni);
        }else if(opt.sni_mode) {
#else
        if(opt.sni_mode) {
#endif
            int svsk_sni = ListenTcp(opt.CHOST, opt.CPORT);
            if (svsk_sni < 0) {
                return -1;
            }
            new Http_server<Guest_sni>(svsk_sni, nullptr);
        }else{
            int svsk_http = ListenTcp(opt.CHOST, opt.CPORT);
            if (svsk_http < 0) {
                return -1;
            }
            new Http_server<Guest>(svsk_http, nullptr);
        }
    }
    Cli_server* cli = nullptr;
    if(opt.admin && strlen(opt.admin) > 0){
        int svsk_cli = -1;
        if(strncmp(opt.admin, "tcp:", 4) == 0){
            svsk_cli = ListenTcp("[::]", atoi(opt.admin+4));
        }else{
            svsk_cli = ListenUnix(opt.admin);
        }
        if(svsk_cli < 0){
            return -1;
        }
        cli = new Cli_server(svsk_cli);
    }
    LOG("Accepting connections ...\n");
    while (will_contiune) {
        uint32_t msec = do_delayjob();
        if(event_loop(msec) < 0){
            return 6;
        }
    }
    LOG("Sproxy exiting ...\n");
    neglect();
    delete cli;
}
