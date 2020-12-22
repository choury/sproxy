#include "req/guest_sni.h"
#include "misc/net.h"
#include "misc/job.h"
#include "misc/config.h"

#include <unistd.h>
#include <assert.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

int efd = 0;

template<class T>
class Http_server: public Ep{
    virtual void defaultHE(RW_EVENT events){
        if (!!(events & RW_EVENT::ERROR)) {
            LOGE("Http server: %d\n", checkSocket(__PRETTY_FUNCTION__));
            return;
        }
        if (!!(events & RW_EVENT::READ)) {
            int clsk;
            struct sockaddr_in6 myaddr;
            socklen_t temp = sizeof(myaddr);
#ifdef SOCK_CLOEXEC
            if ((clsk = accept4(getFd(), (struct sockaddr*)&myaddr, &temp, SOCK_CLOEXEC)) < 0) {
#else
            if ((clsk = accept(getFd(), (struct sockaddr*)&myaddr, &temp)) < 0) {
#endif
                LOGE("accept error:%s\n", strerror(errno));
                return;
            }

            SetTcpOptions(clsk, (const sockaddr_storage*)&myaddr);
            new T(clsk);
        } else {
            LOGE("unknown error\n");
        }
    }
public:
    explicit Http_server(int fd):Ep(fd){
        setEvents(RW_EVENT::READ);
        handleEvent = (void (Ep::*)(RW_EVENT))&Http_server::defaultHE;
    }
    virtual void dump_stat(){
        LOG("Http_server %p\n", this);
    }
};

class Https_server: public Ep {
    SSL_CTX *ctx;
    virtual void defaultHE(RW_EVENT events) {
        if (!!(events & RW_EVENT::ERROR)) {
            LOGE("Https server: %d\n", checkSocket(__PRETTY_FUNCTION__));
            return;
        }
        if (!!(events & RW_EVENT::READ)) {
            int clsk;
            struct sockaddr_in6 myaddr;
            socklen_t temp = sizeof(myaddr);
#ifdef SOCK_CLOEXEC
            if ((clsk = accept4(getFd(), (struct sockaddr *)&myaddr, &temp, SOCK_CLOEXEC)) < 0) {
#else
            if ((clsk = accept(getFd(), (struct sockaddr *)&myaddr, &temp)) < 0) {
#endif
                LOGE("accept error:%s\n", strerror(errno));
                return;
            }

            SetTcpOptions(clsk, (const sockaddr_storage*)&myaddr);
            new Guest(clsk, ctx);
        } else {
            LOGE("unknown error\n");
            return;
        }
    }
public:
    virtual ~Https_server() override{
        SSL_CTX_free(ctx);
    };
    Https_server(int fd, SSL_CTX *ctx): Ep(fd),ctx(ctx) {
        setEvents(RW_EVENT::READ);
        handleEvent = (void (Ep::*)(RW_EVENT))&Https_server::defaultHE;
    }
    virtual void dump_stat(){
        LOG("Https_server %p\n", this);
    }
};

//do nothing, useful for vpn only
int protectFd(int){
    return 1;
}

static int select_alpn_cb(SSL *ssl,
                          const unsigned char **out, unsigned char *outlen,
                          const unsigned char *in, unsigned int inlen, void *arg)
{
    (void)ssl;
    (void)arg;
    std::set<std::string> proset;
    const unsigned char *p = in;
    while ((size_t)(p-in) < inlen) {
        uint8_t len = *p++;
        proset.insert(std::string((const char *)p, len));
        p += len;
    }
    if (!opt.disable_http2 && proset.count("h2")) {
        *out = (unsigned char *)"h2";
        *outlen = strlen((char *)*out);
        return SSL_TLSEXT_ERR_OK;
    }
    if (proset.count("http/1.1")) {
        *out = (unsigned char *)"http/1.1";
        *outlen = strlen((char *)*out);
        return SSL_TLSEXT_ERR_OK;
    }
    LOGE("Can't select a protocol\n");
    return SSL_TLSEXT_ERR_ALERT_FATAL;
}

static int generate_cookie(SSL *ssl, unsigned char *cookie, unsigned int *cookie_len) {
    struct sockaddr_in6 myaddr;
    (void)BIO_dgram_get_peer(SSL_get_rbio(ssl), &myaddr);
    char ip[46];
    inet_ntop(AF_INET6, &myaddr.sin6_addr, ip, sizeof(ip));
    *cookie_len = sprintf((char *)cookie, "[%s]:%d", ip, ntohs(myaddr.sin6_port));
    return 1;
}

#if OPENSSL_VERSION_NUMBER < 0x10100000L
static int verify_cookie(SSL *ssl, unsigned char *cookie, unsigned int cookie_len){
#else
static int verify_cookie(SSL *ssl, const unsigned char *cookie, unsigned int cookie_len){
#endif
    struct sockaddr_in6 myaddr;
    (void)BIO_dgram_get_peer(SSL_get_rbio(ssl), &myaddr);
    return strncmp((char *)cookie, storage_ntoa((sockaddr_storage *)&myaddr), cookie_len)==0;
}

void ssl_callback_ServerName(SSL *ssl){
    const char *servername = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
    if (servername) {
        //TODO: new sni mode
    }
}

SSL_CTX* initssl(int udp, const char *ca, const char *cert, const char *key){
    assert(cert && key);

    SSL_CTX *ctx = nullptr;
    if(udp){
        ctx = SSL_CTX_new(DTLS_server_method());

        if (ctx == nullptr) {
            ERR_print_errors_fp(stderr);
            return nullptr;
        }
        SSL_CTX_set_cookie_generate_cb(ctx, generate_cookie);
        SSL_CTX_set_cookie_verify_cb(ctx, verify_cookie);
        SSL_CTX_set_options(ctx, SSL_OP_COOKIE_EXCHANGE);
    }else{
#if OPENSSL_VERSION_NUMBER < 0x10100000L
        ctx = SSL_CTX_new(SSLv23_server_method());
#else
        ctx = SSL_CTX_new(TLS_server_method());
#endif
        if (ctx == nullptr) {
            ERR_print_errors_fp(stderr);
            return nullptr;
        }
    }

    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3); // 去除支持SSLv2 SSLv3
    SSL_CTX_set_options(ctx, SSL_OP_NO_COMPRESSION);
    SSL_CTX_set_options(ctx, SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION);
    SSL_CTX_set_options(ctx, SSL_OP_SINGLE_ECDH_USE);
    SSL_CTX_set_options(ctx, SSL_OP_NO_TICKET);
    SSL_CTX_set_options(ctx, SSL_OP_CIPHER_SERVER_PREFERENCE);
    SSL_CTX_set_cipher_list(ctx, DEFAULT_CIPHER_LIST);
    SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY);
    SSL_CTX_set_mode(ctx, SSL_MODE_RELEASE_BUFFERS);

    /*
    EC_KEY *ecdh = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    SSL_CTX_set_tmp_ecdh(ctx, ecdh);
    EC_KEY_free(ecdh);
    */
    SSL_CTX_set_ecdh_auto(ctx, 1);
    
    if (ca && SSL_CTX_load_verify_locations(ctx, ca, NULL) != 1)
        ERR_print_errors_fp(stderr);

    if (SSL_CTX_set_default_verify_paths(ctx) != 1)
        ERR_print_errors_fp(stderr);

    //加载证书和私钥
    if (SSL_CTX_use_certificate_file(ctx, cert, SSL_FILETYPE_PEM) != 1) {
        ERR_print_errors_fp(stderr);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM) != 1) {
        ERR_print_errors_fp(stderr);
    }

    if (SSL_CTX_check_private_key(ctx) != 1) {
        ERR_print_errors_fp(stderr);
    }

    SSL_CTX_set_verify_depth(ctx, 10);
    SSL_CTX_set_tlsext_servername_callback(ctx, ssl_callback_ServerName);
    SSL_CTX_set_alpn_select_cb(ctx, select_alpn_cb, nullptr);
    SSL_CTX_set_read_ahead(ctx, 1);
    return ctx;
}

int main(int argc, char **argv) {
    parseConfig(argc, argv);
    prepare();
    openlog("sproxy", LOG_PID | LOG_PERROR, LOG_LOCAL0);
#if __linux__
    efd = epoll_create1(EPOLL_CLOEXEC);
#elif __APPLE__
    efd = kqueue();
#else
#error "Only macOS and linux are supported"
#endif
    if(opt.cert && opt.key){
        SSL_CTX * ctx = initssl(0, opt.cafile, opt.cert, opt.key);
        opt.CPORT = opt.CPORT?opt.CPORT:443;
        int svsk_https;
        if ((svsk_https = Listen(SOCK_STREAM, opt.CPORT)) < 0) {
            return -1;
        }
        new Https_server(svsk_https, ctx);
    }else{
        if(opt.sni_mode){
            opt.CPORT = opt.CPORT?opt.CPORT:443;
            int svsk_sni;
            if ((svsk_sni = Listen(SOCK_STREAM, 443)) < 0) {
                return -1;
            }
            new Http_server<Guest_sni>(svsk_sni);
        }else{
            opt.CPORT = opt.CPORT?opt.CPORT:80;
            int svsk_http;
            if ((svsk_http = Listen(SOCK_STREAM, opt.CPORT)) < 0) {
                return -1;
            }
            new Http_server<Guest>(svsk_http);
        }
    }
    LOG("Accepting connections ...\n");
    while (true) {
        int c;
#if __linux__
        struct epoll_event events[200];
        if ((c = epoll_wait(efd, events, 200, do_delayjob())) <= 0) {
            if (c != 0 && errno != EINTR) {
                LOGE("epoll_wait: %s\n", strerror(errno));
                return 6;
            }
            continue;
        }
        for (int i = 0; i < c; ++i) {
            LOGD(DEVENT, "handle event %s\n", events_string[int(convertEpoll(events[i].events))]);
            Ep *ep = (Ep *)events[i].data.ptr;
            (ep->*ep->handleEvent)(convertEpoll(events[i].events));
        }
#endif
#if __APPLE__
        struct kevent events[200];
        uint32_t msec = do_delayjob();
        struct timespec timeout{msec/1000, (msec%1000)*1000000};
        if((c = kevent(efd, NULL, 0, events, 200, &timeout)) <= 0){
            if (c != 0 && errno != EINTR) {
                LOGE("kevent: %s\n", strerror(errno));
                return 6;
            }
            continue;
        }
        std::map<Ep*, RW_EVENT> events_merged;
        for(int i = 0; i < c; ++i){
            LOGD(DEVENT, "handle event %lu: %s\n", events[i].ident, events_string[int(convertKevent(events[i]))]);
            Ep *ep = (Ep*)events[i].udata;
            if(events_merged.count(ep)){
                events_merged[ep] = events_merged[ep] | convertKevent(events[i]);
            }else{
                events_merged[ep] = convertKevent(events[i]);
            }
        }
        for(const auto& i: events_merged){
            (i.first->*i.first->handleEvent)(i.second);
        }
#endif
    }
}
