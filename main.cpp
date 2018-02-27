#include "req/guest_sni.h"
#include "misc/rudp.h"
#include "misc/net.h"
#include "misc/job.h"
#include "misc/strategy.h"
#include "misc/util.h"

#include <set>

#include <unistd.h>
#include <assert.h>
#include <fcntl.h>
#include <signal.h>
#include <getopt.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

int efd = 0;
int daemon_mode = 0;
int use_http2 = 1;
int ignore_cert_error = 0;
int disable_ipv6 = 0;
static uint16_t CPORT = 0;
char SPROT[DOMAINLIMIT] = {0};
char SHOST[DOMAINLIMIT] = {0};
uint16_t SPORT = 0;
char auth_string[DOMAINLIMIT] = {0};
char rewrite_auth[DOMAINLIMIT] = {0};
const char *cafile =  nullptr;
const char *index_file = nullptr;
int autoindex = 0;
uint32_t debug = 0;

static int sni_mode = 0;
static int rudp_mode = 0;
static const char *cert = nullptr;
static const char *key = nullptr;

template<class T>
class Http_server: public Ep{
    virtual void defaultHE(uint32_t events){
        if (events & EPOLLERR || events & EPOLLHUP) {
            LOGE("Http server: %d\n", Checksocket(fd));
            return;
        }
        if (events & EPOLLIN) {
            int clsk;
            struct sockaddr_in6 myaddr;
            socklen_t temp = sizeof(myaddr);
            if ((clsk = accept(fd, (struct sockaddr*)&myaddr, &temp)) < 0) {
                LOGE("accept error:%s\n", strerror(errno));
                return;
            }

            int flags = fcntl(clsk, F_GETFL, 0);
            if (flags < 0) {
                LOGE("fcntl error:%s\n", strerror(errno));
                close(clsk);
                return;
            }

            fcntl(clsk, F_SETFL, flags | O_NONBLOCK);
            new T(clsk, (const sockaddr_un*)&myaddr);
        } else {
            LOGE("unknown error\n");
        }
    }
public:
    explicit Http_server(int fd):Ep(fd){
        setEpoll(EPOLLIN);
        handleEvent = (void (Ep::*)(uint32_t))&Http_server::defaultHE;
    }
    virtual void dump_stat(){
        LOG("Http_server %p\n", this);
    }
};

class Https_server: public Ep {
    SSL_CTX *ctx;
    virtual void defaultHE(uint32_t events) {
        if (events & EPOLLERR || events & EPOLLHUP) {
            LOGE("Https server: %d\n", Checksocket(fd));
            return;
        }
        if (events & EPOLLIN) {
            int clsk;
            struct sockaddr_in6 myaddr;
            socklen_t temp = sizeof(myaddr);
            if ((clsk = accept(fd, (struct sockaddr *)&myaddr, &temp)) < 0) {
                LOGE("accept error:%s\n", strerror(errno));
                return;
            }

            int flags = fcntl(clsk, F_GETFL, 0);
            if (flags < 0) {
                LOGE("fcntl error:%s\n", strerror(errno));
                close(clsk);
                return;
            }
            fcntl(clsk, F_SETFL, flags | O_NONBLOCK);

            new Guest(clsk, (const sockaddr_un*)&myaddr, ctx);
        } else {
            LOGE("unknown error\n");
            return;
        }
    }
public:
    virtual ~Https_server(){
        SSL_CTX_free(ctx);
    };
    Https_server(int fd, SSL_CTX *ctx): Ep(fd),ctx(ctx) {
        setEpoll(EPOLLIN);
        handleEvent = (void (Ep::*)(uint32_t))&Https_server::defaultHE;
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
    if (proset.count("h2")) {
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
    return strncmp((char *)cookie, getaddrstring((sockaddr_un *)&myaddr), cookie_len)==0;
}

void ssl_callback_ServerName(SSL *ssl){
    const char *servername = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
    if (servername) {
        //TODO: new sni mode
    }
}

static struct option long_options[] = {
    {"autoindex",   no_argument,       0, 'i'},
    {"cafile",      required_argument, 0,  0 },
    {"cert",        required_argument, 0,  0 },
    {"daemon",      no_argument,       0, 'D'},
    {"disable-ipv6",no_argument,       0,  0 },
    {"http1",       no_argument,       0, '1'},
    {"help",        no_argument,       0, 'h'},
    {"index",       required_argument, 0,  0 },
    {"insecure",    no_argument,       0, 'k'},
    {"key",         required_argument, 0,  0 },
    {"port",        required_argument, 0, 'p'},
    {"rewrite_auth",required_argument, 0, 'r'},
    {"rudp",        no_argument,       0,  0 },
    {"secret",      required_argument, 0, 's'},
    {"sni",         no_argument,       0,  0 },
#ifndef NDEBUG
    {"debug-epoll", no_argument,   0,  0 },
    {"debug-dns",   no_argument,   0,  0 },
    {"debug-http2", no_argument,   0,  0 },
    {"debug-job",   no_argument,   0,  0 },
    {"debug-hpack", no_argument,   0,  0 },
    {"debug-rudp",  no_argument,   0,  0 },
    {"debug-all",   no_argument,   0,  0 },
#endif
    {0,         0,                 0,  0 }
};

const char *option_detail[] = {
    "Enables or disables the directory listing output",
    "CA certificate for server (ssl)",
    "Certificate file for server (ssl)",
    "Run as daemon",
    "Disable ipv6 when querying dns",
    "Use http/1.1 only",
    "Print this usage",
    "Index file for path (when as a http(s) server)",
    "Ignore the cert error of server (SHOULD NOT DO IT)",
    "Private key file name (ssl)",
    "The port to listen, default is 80 but 443 for ssl/sni",
    "rewrite the auth info (user:password) to proxy server",
    "RUDP modle (experiment)",
    "Set a user and passwd for proxy (user:password), default is none.",
    "Act as a sni proxy",
#ifndef NDEBUG
    "debug-epoll",
    "\tdebug-dns",
    "debug-http2",
    "\tdebug-job",
    "debug-hpack",
    "debug-rudp",
    "\tdebug-all",
#endif
};

void usage(const char * programe){
    printf("Usage: %s [host:port]\n" , programe);
    for(int i =0; long_options[i].name;i++){
        if(long_options[i].val){
            printf("-%c, ", long_options[i].val);
        }else{
            printf("    ");
        }
        printf("--%s\t%s\n", long_options[i].name, option_detail[i]);
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
        ctx = SSL_CTX_new(SSLv23_server_method());
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

    EC_KEY *ecdh = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    SSL_CTX_set_tmp_ecdh(ctx, ecdh);
    EC_KEY_free(ecdh);
    
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

static int parseConfig(int argc, char **argv){
    while (1) {
        int option_index = 0;
        int c = getopt_long(argc, argv, "D1hikr:s:p:",
            long_options, &option_index);
        if (c == -1)
            break;
        switch (c) {
        case 0:
            if(strcmp(long_options[option_index].name, "cafile") == 0){
                cafile = optarg;
                printf("long option  cacert: %s\n", cafile);
            }else if(strcmp(long_options[option_index].name, "cert") == 0){
                cert = optarg;
                printf("long option  cert: %s\n", cert);
            }else if(strcmp(long_options[option_index].name, "key") == 0){
                key = optarg;
                printf("long option  key: %s\n", key);
            }else if(strcmp(long_options[option_index].name, "index") == 0){
                index_file = optarg;
                printf("long option  index file: %s\n", index_file);
            }else if(strcmp(long_options[option_index].name, "disable-ipv6") == 0){
                disable_ipv6 = 1;
                printf("long option  disable-ipv6\n");
            }else if(strcmp(long_options[option_index].name, "sni") == 0){
                sni_mode = 1;
                printf("long option sni\n");
            }else if(strcmp(long_options[option_index].name, "rudp") == 0){
                rudp_mode = 1;
                printf("long option rudp\n");
            }else if(strcmp(long_options[option_index].name, "debug-epoll") == 0){
                debug |= DEPOLL;
                printf("long option debug-epoll\n");
            }else if(strcmp(long_options[option_index].name, "debug-dns") == 0){
                debug |= DDNS;
                printf("long option debug-dns\n");
            }else if(strcmp(long_options[option_index].name, "debug-http2") == 0){
                debug |= DHTTP2;
                printf("long option debug-http2\n");
            }else if(strcmp(long_options[option_index].name, "debug-job") == 0){
                debug |= DJOB;
                printf("long option debug-job\n");
            }else if(strcmp(long_options[option_index].name, "debug-hpack") == 0){
                debug |= DHPACK;
                printf("long option debug-hpack\n");
            }else if(strcmp(long_options[option_index].name, "debug-rudp") == 0){
                debug |= DRUDP;
                printf("long option debug-rudp\n");
            }else if(strcmp(long_options[option_index].name, "debug-all") == 0){
                debug = (uint32_t)(-1);
                printf("long option debug-all\n");
            }
            break;

        case '1':
            use_http2 = 0;
            printf("option http1\n");
            break;

        case 'D':
            daemon_mode = 1;
            printf("option daemon\n");
            break;

        case 'k':
            ignore_cert_error = 1;
            printf("option insecure\n");
            break;

        case 'p':
            CPORT = atoi(optarg);
            printf("option port with value '%d'\n", CPORT);
            break;

        case 'r':
            Base64Encode(optarg, strlen(optarg), rewrite_auth);
            printf("option rewrite-auth with value '%s'\n", rewrite_auth);
            break;

        case 's':
            Base64Encode(optarg, strlen(optarg), auth_string);
            printf("option secret with value '%s'\n", auth_string);
            break;

        case 'i':
            autoindex = 1;
            printf("option autoindex\n");
            break;
        case 'h':
            printf("option help\n");
            usage(argv[0]);
            return 1;
        case '?':
            return -1;

        default:
            usage(argv[0]);
            return -1;
        }
    }

    if( optind != argc && optind+1 != argc){
        usage(argv[0]);
        return -1;
    }

    if (optind < argc) {
        if(setproxy(argv[optind])){
            LOGE("wrong server format\n");
            return -1;
        }
        char proxy[DOMAINLIMIT];
        getproxy(proxy, sizeof(proxy));
        printf("server %s\n", proxy);
    }
    return 0;
}

int main(int argc, char **argv) {
    if(parseConfig(argc, argv)){
       return -1;
    }
    main_argv = argv;
    signal(SIGPIPE, SIG_IGN);
    signal(SIGCHLD, SIG_IGN);
    signal(SIGABRT, dump_trace);
    signal(SIGUSR1, dump_stat);
#ifndef NODEBUG
    signal(SIGUSR2, exit);
#endif
    reloadstrategy();
    SSL_library_init();    // SSL初库始化
    SSL_load_error_strings();  // 载入所有错误信息
    efd = epoll_create(10000);
    setvbuf(stdout, NULL, _IOLBF, BUFSIZ);
    if (daemon_mode && daemon(1, 0) < 0) {
        fprintf(stderr, "start daemon error:%s\n", strerror(errno));
        return -1;
    }
    if(rudp_mode){
        int svsk_rudp;
        CPORT = CPORT?CPORT:443;
        if((svsk_rudp = Listen(SOCK_DGRAM, CPORT)) < 0){
            return -1;
        }
        new Rudp_server(svsk_rudp, CPORT);
    }else if(cert && key){
        SSL_CTX * ctx = initssl(0, cafile, cert, key);
        CPORT = CPORT?CPORT:443;
        int svsk_https;
        if ((svsk_https = Listen(SOCK_STREAM, CPORT)) < 0) {
            return -1;
        }
        new Https_server(svsk_https, ctx);
    }else{
        if(sni_mode){
            CPORT = CPORT?CPORT:443;
            int svsk_sni;
            if ((svsk_sni = Listen(SOCK_STREAM, 443)) < 0) {
                return -1;
            }
            new Http_server<Guest_sni>(svsk_sni);
        }else{
            CPORT = CPORT?CPORT:80;
            int svsk_http;
            if ((svsk_http = Listen(SOCK_STREAM, CPORT)) < 0) {
                return -1;
            }
            new Http_server<Guest>(svsk_http);
        }
    }
    LOG("Accepting connections ...\n");
    while (1) {
        int c;
        struct epoll_event events[200];
        if ((c = epoll_wait(efd, events, 200, do_delayjob())) < 0) {
            if (errno != EINTR) {
                perror("epoll wait");
                return 6;
            }
            continue;
        }
        do_prejob();
        for (int i = 0; i < c; ++i) {
            Ep *ep = (Ep *)events[i].data.ptr;
            (ep->*ep->handleEvent)(events[i].events);
        }
        do_postjob();
    }
    return 0;
}

