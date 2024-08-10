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
        if(opt.http.hostname[0]){
            sockaddr_storage addr;
            if(storage_aton(opt.http.hostname, opt.http.port, &addr) == 0) {
                LOGE("failed to parse http addr: %s\n", opt.http.hostname);
                return -1;
            }
            int svsk_http = ListenTcp(&addr);
            if (svsk_http < 0) {
                return -1;
            }
            servers.emplace_back(std::make_shared<Http_server<Guest>>(svsk_http, nullptr));
            LOG("listen on %s:%d for http\n", opt.http.hostname, (int)opt.http.port);
        }
        if(opt.ssl.hostname[0]) {
            sockaddr_storage addr;
            if(storage_aton(opt.ssl.hostname, opt.ssl.port, &addr) == 0) {
                LOGE("failed to parse ssl addr: %s\n", opt.ssl.hostname);
                return -1;
            }
            int svsk_ssl = ListenTcp(&addr);
            if (svsk_ssl < 0) {
                return -1;
            }
            if(opt.sni_mode) {
                servers.emplace_back(std::make_shared<Http_server<Guest_sni>>(svsk_ssl, nullptr));
                LOG("listen on %s:%d for ssl sni\n", opt.ssl.hostname, (int)opt.ssl.port);
            }else {
                SSL_CTX * ctx = initssl(false, nullptr);
                servers.emplace_back(std::make_shared<Http_server<Guest>>(svsk_ssl, ctx));
                LOG("listen on %s:%d for ssl\n", opt.ssl.hostname, (int)opt.ssl.port);
            }
        }
#ifdef HAVE_QUIC
        if(opt.quic.hostname[0]) {
            sockaddr_storage addr;
            if(storage_aton(opt.quic.hostname, opt.quic.port, &addr) == 0) {
                LOGE("failed to parse quic addr: %s\n", opt.quic.hostname);
                return -1;
            }
            int svsk_quic = ListenUdp(&addr);
            if(svsk_quic <  0) {
                return -1;
            }
            SetRecvPKInfo(svsk_quic, &addr);
            if(opt.sni_mode) {
                servers.emplace_back(std::make_shared<Quic_sniServer>(svsk_quic));
                LOG("listen on %s:%d for quic snil\n", opt.quic.hostname, (int)opt.quic.port);
            }else {
                SSL_CTX * ctx = initssl(true, nullptr);
                servers.emplace_back(std::make_shared<Quic_server>(svsk_quic, ctx));
                LOG("listen on %s:%d for quic\n", opt.quic.hostname, (int)opt.quic.port);
            }
        }
#endif
    }
    if(opt.admin.hostname[0]){
        int svsk_cli = -1;
        if(opt.admin.port == 0){
            svsk_cli = ListenUnix(opt.admin.hostname);
        }else{
            sockaddr_storage addr;
            if(storage_aton(opt.admin.hostname, opt.admin.port, &addr) == 0) {
                LOGE("failed to parse admin addr: %s\n", opt.admin.hostname);
                return -1;
            }
            svsk_cli = ListenTcp(&addr);
        }
        if(svsk_cli < 0){
            return -1;
        }
        if(opt.admin.port) {
            LOG("listen on %s:%d for admin\n", opt.admin.hostname, (int)opt.admin.port);
        } else {
            LOG("listen on %s for admin\n", opt.admin.hostname);
        }
        servers.emplace_back(std::make_shared<Cli_server>(svsk_cli));
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
