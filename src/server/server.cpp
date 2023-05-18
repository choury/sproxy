#include "req/guest_sni.h"
#ifdef HAVE_QUIC
#include "req/guest3.h"
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

static std::vector<const char*>& get_alpn_list() {
    static std::vector<const char*> alpn_list;
    alpn_list.clear();
    if(opt.quic_mode) {
        alpn_list.push_back("h3");
    }
    if(!opt.disable_http2) {
        alpn_list.push_back("h2");
    }
    alpn_list.push_back("http/1.1");
    alpn_list.push_back(nullptr);
    return alpn_list;
}

int ssl_callback_ServerName(SSL *ssl, int*, void*){
    const char *servername = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
    if (servername) {
        //TODO: new sni mode
    }
    return 0;
}

int main(int argc, char **argv) {
    parseConfig(argc, argv);
    if(opt.cert && opt.key){
        SSL_CTX * ctx = initssl(opt.quic_mode, get_alpn_list().data());
#ifdef HAVE_QUIC
        if(opt.quic_mode){
            int svsk_quic = ListenNet(SOCK_DGRAM, opt.CHOST, opt.CPORT);
            if(svsk_quic <  0) {
                return -1;
            }
            new Quic_server(svsk_quic, ctx);
        }else {
#else
            assert(opt.quic_mode == 0);
        {
#endif
            int svsk_https = ListenNet(SOCK_STREAM, opt.CHOST, opt.CPORT);
            if (svsk_https < 0) {
                return -1;
            }
            new Http_server<Guest>(svsk_https, ctx);
        }
    }else{
        if(opt.sni_mode) {
            int svsk_sni = ListenNet(SOCK_STREAM, opt.CHOST, opt.CPORT);
            if (svsk_sni < 0) {
                return -1;
            }
            new Http_server<Guest_sni>(svsk_sni, nullptr);
        }else{
            int svsk_http = ListenNet(SOCK_STREAM, opt.CHOST, opt.CPORT);
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
            svsk_cli = ListenNet(SOCK_STREAM, "[::]", atoi(opt.admin+4));
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
