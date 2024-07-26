#include "req/guest_sni.h"
#ifdef HAVE_QUIC
#include "prot/quic/quic_server.h"
#endif
#include "req/cli.h"
#include "req/rguest2.h"
#include "misc/job.h"
#include "misc/config.h"
#include "prot/tls.h"

#include <unistd.h>
#include <assert.h>
#include <openssl/err.h>

//do nothing, useful for vpn only
int protectFd(int){
    return 1;
}

int main(int argc, char **argv) {
    parseConfig(argc, argv);
    std::vector<std::shared_ptr<Ep>> servers;
    std::shared_ptr<Rguest2> r2;
    if(opt.rproxy_mode) {
        r2 = std::make_shared<Rguest2>(&opt.Server);
    }else {
        if(opt.ssl_mode) {
            int svsk_ssl = ListenTcp(opt.CHOST, opt.CPORT);
            if (svsk_ssl < 0) {
                return -1;
            }
            if(opt.sni_mode) {
                servers.emplace_back(std::make_shared<Http_server<Guest_sni>>(svsk_ssl, nullptr));
                LOG("listen on %s:%d for ssl sni\n", opt.CHOST, (int)opt.CPORT);
            }else {
                SSL_CTX * ctx = initssl(false, nullptr);
                servers.emplace_back(std::make_shared<Http_server<Guest>>(svsk_ssl, ctx));
                LOG("listen on %s:%d for ssl\n", opt.CHOST, (int)opt.CPORT);
            }
        }
#ifdef HAVE_QUIC
        if(opt.quic_mode ) {
            struct sockaddr_storage addr;
            if(storage_aton(opt.CHOST, opt.CPORT, &addr) == 0) {
                return -1;
            }
            int svsk_quic = ListenUdp(&addr);
            if(svsk_quic <  0) {
                return -1;
            }
            SetRecvPKInfo(svsk_quic, &addr);
            if(opt.sni_mode) {
                servers.emplace_back(std::make_shared<Quic_sniServer>(svsk_quic));
                LOG("listen on %s:%d for quic snil\n", opt.CHOST, (int)opt.CPORT);
            }else {
                SSL_CTX * ctx = initssl(true, nullptr);
                servers.emplace_back(std::make_shared<Quic_server>(svsk_quic, ctx));
                LOG("listen on %s:%d for quic\n", opt.CHOST, (int)opt.CPORT);
            }
        }
#endif
        if(!opt.ssl_mode && !opt.sni_mode && !opt.quic_mode){
            int svsk_http = ListenTcp(opt.CHOST, opt.CPORT);
            if (svsk_http < 0) {
                return -1;
            }
            servers.emplace_back(std::make_shared<Http_server<Guest>>(svsk_http, nullptr));
            LOG("listen on %s:%d for http\n", opt.CHOST, (int)opt.CPORT);
        }
    }
    if(opt.admin && strlen(opt.admin) > 0){
        int svsk_cli = -1;
        if(strncmp(opt.admin, "tcp:", 4) == 0){
            std::string addr = opt.admin + 4;
            if(addr.find(':') != std::string::npos) {
                Destination dest;
                parseDest(addr.c_str(), &dest);
                svsk_cli = ListenTcp(dest.hostname, dest.port);
            } else {
                svsk_cli = ListenTcp("[::]", atoi(addr.c_str()));
            }
        }else{
            svsk_cli = ListenUnix(opt.admin);
        }
        if(svsk_cli < 0){
            return -1;
        }
        servers.emplace_back(std::make_shared<Cli_server>(svsk_cli));
        LOG("listen on %s for admin\n", opt.admin);
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
}
