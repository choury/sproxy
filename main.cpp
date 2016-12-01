#include "guest_s.h"
#include "guest_sni.h"
#include "guest_s2.h"
#include "dtls.h"
#include "net.h"

#include <set>

#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <getopt.h>
#include <arpa/inet.h>
#include <openssl/err.h>
#include <openssl/bio.h>

int efd;

int daemon_mode = 0;
int use_http2 = 1;
int udp_mode = 0;
int sni_mode = 0;
int ignore_cert_error = 0;
uint16_t CPORT = 0;
char SHOST[DOMAINLIMIT] = {0};
uint16_t SPORT = 0;
Protocol SPROT = Protocol::TCP;
char auth_string[DOMAINLIMIT] = {0};
const char *cafile =  nullptr;
const char *cert = nullptr;
const char *key = nullptr;
const char *index_file = nullptr;
uint32_t debug = 0;

template<class T>
class Http_server: public Server{
    virtual void defaultHE(uint32_t events){
        if (events & EPOLLIN) {
            int clsk;
            struct sockaddr_in6 myaddr;
            socklen_t temp = sizeof(myaddr);
            if ((clsk = accept(fd, (struct sockaddr*)&myaddr, &temp)) < 0) {
                LOGE("accept error:%m\n");
                return;
            }

            int flags = fcntl(clsk, F_GETFL, 0);
            if (flags < 0) {
                LOGE("fcntl error:%m\n");
                close(clsk);
                return;
            }

            fcntl(clsk, F_SETFL, flags | O_NONBLOCK);
            new T(clsk, &myaddr);
        } else {
            LOGE("unknown error\n");
        }
    }
public:
    Http_server(int fd):Server(fd){}
};

class Https_server: public Server {
    SSL_CTX *ctx;
    virtual void defaultHE(uint32_t events) {
        if (events & EPOLLIN) {
            int clsk;
            struct sockaddr_in6 myaddr;
            socklen_t temp = sizeof(myaddr);
            if ((clsk = accept(fd, (struct sockaddr *)&myaddr, &temp)) < 0) {
                LOGE("accept error:%m\n");
                return;
            }

            int flags = fcntl(clsk, F_GETFL, 0);
            if (flags < 0) {
                LOGE("fcntl error:%m\n");
                close(clsk);
                return;
            }
            fcntl(clsk, F_SETFL, flags | O_NONBLOCK);

            /* 基于ctx 产生一个新的SSL */
            SSL *ssl = SSL_new(ctx);
            /* 将连接用户的socket 加入到SSL */
            SSL_set_fd(ssl, clsk);
            new Guest_s(clsk, &myaddr, new Ssl(ssl));
        } else {
            LOGE("unknown error\n");
            return;
        }
    }
public:
    virtual ~Https_server(){
        SSL_CTX_free(ctx);
    };
    Https_server(int fd, SSL_CTX *ctx): Server(fd),ctx(ctx) {}
};


class Dtls_server: public Server {
    SSL_CTX *ctx;
    virtual void defaultHE(uint32_t events) {
        if (events & EPOLLIN) {
            BIO *bio = BIO_new_dgram(fd, BIO_NOCLOSE);
            SSL *ssl = SSL_new(ctx);
            SSL_set_bio(ssl, bio, bio);
            struct sockaddr_in6 myaddr;
            memset(&myaddr, 0, sizeof(myaddr));
            SSL_set_accept_state(ssl);
#if OPENSSL_VERSION_NUMBER < 0x10100000L
            if(DTLSv1_listen(ssl, &myaddr)<=0)
                goto error;
            (void)BIO_ctrl_set_connected(bio, 0, &myaddr);
#else
            if(DTLSv1_listen(ssl, (BIO_ADDR *)&myaddr)<=0){
                goto error;
            }
            (void)BIO_ctrl_set_connected(bio, &myaddr);
#endif
            if(connect(fd, (struct sockaddr*)&myaddr, sizeof(struct sockaddr_in6))){
                LOGE("connect error: %m\n");
                goto error;
            }
            /* Set new fd and set BIO to connected */
            new Guest_s(fd, &myaddr, new Dtls(ssl));
            
            fd = socket(AF_INET6, SOCK_DGRAM, 0);
            assert(fd > 0);
            Bind_any(fd, CPORT);
            updateEpoll(EPOLLIN);
            return;
error:
            SSL_free(ssl);
        }
    }
public:
    virtual ~Dtls_server(){
        SSL_CTX_free(ctx);
    };
    Dtls_server(int fd, SSL_CTX *ctx): Server(fd),ctx(ctx) {}
};


static int select_alpn_cb(SSL *ssl,
                          const unsigned char **out, unsigned char *outlen,
                          const unsigned char *in, unsigned int inlen, void *arg)
{
    (void)ssl;
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
    return strcmp((char *)cookie, getaddrstring((sockaddr_un *)&myaddr))==0;
}


static struct option long_options[] = {
    {"cafile",  required_argument, 0,  0 },
    {"cert",    required_argument, 0,  0 },
    {"daemon",  no_argument,       0, 'D'},
    {"dtls",    no_argument,       0, 'u'},
    {"http1",   no_argument,       0, '1'},
    {"help",    no_argument,       0, 'h'},
    {"index",   required_argument, 0,  0 },
    {"insecure",no_argument,       0, 'k'},
    {"key",     required_argument, 0,  0 },
    {"port",    required_argument, 0, 'p'},
    {"secret",  required_argument, 0, 's'},
    {"sni",     no_argument,       0,  0 },
#ifndef NDEBUG
    {"debug-epoll", no_argument,   0,  0 },
    {"debug-dns",   no_argument,   0,  0 },
    {"debug-dtls",  no_argument,   0,  0 },
#endif
    {0,         0,                 0,  0 }
};

const char *option_detail[] = {
    "CA certificate for server (ssl/dtls)",
    "Certificate file for server (ssl/dtls)",
    "Run as daemon",
    "UDP mode (dtls)",
    "Use http/1.1 only (SHOULD NOT USE IT WITH dtls)",
    "Print this usage",
    "Index file for path (when as a http(s) server)",
    "Ignore the cert error of server (SHOULD NOT DO IT)",
    "Private key file name (ssl/dtls)",
    "The port to listen, default is 80 but 443 for ssl/dtls/sni",
    "Set a user and passwd for proxy (user:password), default is none.",
    "Act as a sni proxy",
#ifndef NDEBUG
    "debug-epoll",
    "\tdebug-dns",
    "debug-dtls",
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
    SSL_CTX_set_alpn_select_cb(ctx, select_alpn_cb, nullptr);
    SSL_CTX_set_read_ahead(ctx, 1);
    return ctx;
}

int main(int argc, char **argv) {
    while (1) {
        int option_index = 0;
        int c = getopt_long(argc, argv, "Du1hks:p:",
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
            }else if(strcmp(long_options[option_index].name, "sni") == 0){
                sni_mode = 1;
                printf("long option sni\n");
            }else if(strcmp(long_options[option_index].name, "debug-epoll") == 0){
                debug |= DEPOLL;
                printf("long option debug-epoll\n");
            }else if(strcmp(long_options[option_index].name, "debug-dns") == 0){
                debug |= DDNS;
                printf("long option debug-dns\n");
            }else if(strcmp(long_options[option_index].name, "debug-dtls") == 0){
                debug |= DDTLS;
                printf("long option debug-dtls\n");
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

        case 'u':
            udp_mode = 1;
            printf("option udp\n");
            break;

        case 'k':
            ignore_cert_error = 1;
            printf("option insecure\n");
            break;

        case 'p':
            CPORT = atoi(optarg);
            printf("option port with value '%d'\n", CPORT);
            break;

        case 's':
            Base64Encode(optarg, strlen(optarg), auth_string);
            printf("option secret with value '%s'\n", auth_string);
            break;
        case 'h':
            printf("option help\n");
            usage(argv[0]);
            return 0;
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
        char protocol[DOMAINLIMIT];
        if(spliturl(argv[optind], protocol, SHOST, nullptr, &SPORT)){
            LOGOUT("wrong server format\n");
            return -1;
        }
        if(SPORT == 0){
            SPORT = 443;
        }
        if(strlen(protocol) == 0 ||
            strcasecmp(protocol, "ssl") == 0)
        {
            SPROT = Protocol::TCP;
        }else if(strcasecmp(protocol, "dtls") == 0){
            SPROT = Protocol::UDP;
        }else{
            LOGOUT("Only \"ssl://\" and \"dtls://\" protocol are supported!\n");
            return -1;
        }
        printf("server %s:%d \n", SHOST, SPORT);
    }
    main_argv = argv;
    
    signal(SIGPIPE, SIG_IGN);
    signal(SIGCHLD, SIG_IGN);
    signal(SIGABRT, dump_trace);
    loadsites();
    SSL_library_init();    // SSL初库始化
    SSL_load_error_strings();  // 载入所有错误信息
    efd = epoll_create(10000);
    if(cert && key){
        SSL_CTX * ctx = initssl(udp_mode, cafile, cert, key);
        CPORT = CPORT?CPORT:443;
        if(udp_mode){
            int svsk_udp;
            if((svsk_udp = socket(AF_INET6, SOCK_DGRAM, 0)) < 0){
                LOGOUT("socket error:%m\n");
                return -1;
            }
            if(Bind_any(svsk_udp, CPORT))
                return -1;
            new Dtls_server(svsk_udp, ctx);
        }else{
            int svsk_tcp;
            if ((svsk_tcp = Listen(CPORT)) < 0) {
                return -1;
            }
            new Https_server(svsk_tcp, ctx);
        }
    }else{
        if(sni_mode){
            CPORT = CPORT?CPORT:443;
            int sni_svsk;
            if ((sni_svsk = Listen(443)) < 0) {
                return -1;
            }
            new Http_server<Guest_sni>(sni_svsk);
        }else{
            CPORT = CPORT?CPORT:80;
            int http_svsk;
            if ((http_svsk = Listen(CPORT)) < 0) {
                return -1;
            }
            new Http_server<Guest>(http_svsk);
        }
    }
    LOGOUT("Accepting connections ...\n");
    if (daemon_mode && daemon(1, 0) < 0) {
        LOGOUT("start daemon error:%m\n");
    }
    while (1) {
        int c;
        struct epoll_event events[200];
        if ((c = epoll_wait(efd, events, 200, 50)) < 0) {
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
        tick();
    }
    return 0;
}

