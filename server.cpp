#include "guest_s.h"
#include "net.h"

#include <set>

#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <arpa/inet.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

int efd;
int daemon_mode = 0;

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
            new Guest_s(clsk, &myaddr, ssl);
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
            struct sockaddr_in6 myaddr;
            memset(&myaddr, 0, sizeof(myaddr));
            BIO *bio = BIO_new_dgram(fd, BIO_NOCLOSE);
            SSL *ssl = SSL_new(ctx);
            int client_fd = 0;
            SSL_set_bio(ssl, bio, bio);
            if(DTLSv1_listen(ssl, &myaddr)<=0)
                goto error;
            client_fd = socket(AF_INET6, SOCK_DGRAM, 0);
            if(Bind_any(client_fd, SPORT))
                goto error;
            if(connect(client_fd, (struct sockaddr*)&myaddr, sizeof(struct sockaddr_in6))){
                LOGE("connect error: %m\n");
                goto error;
            }
            /* Set new fd and set BIO to connected */
            BIO_set_fd(bio, client_fd, BIO_NOCLOSE);
            BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_CONNECTED, 0, &myaddr);
            new Guest_s(client_fd, &myaddr, ssl);
            return;
error:
            if(client_fd > 0)
                close(client_fd);
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
    while (p-in < inlen) {
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

static int verify_cookie(SSL *ssl, unsigned char *cookie, unsigned int cookie_len){
    struct sockaddr_in6 myaddr;
    (void)BIO_dgram_get_peer(SSL_get_rbio(ssl), &myaddr);
    return strcmp((char *)cookie, getaddrstring((sockaddr_un *)&myaddr))==0;
}

void usage(const char * programe){
    printf("Usage: %s [-p port] [-k ca path] [-h] <CERT> <PRIVATE_KEY>\n"
           "       -p: The port to listen, default is 443.\n"
           "       -k: A optional intermediate CA certificate.\n"
           "       -u: UDP mode.\n"
           "       -D: Run as a daemon.\n"
           "       -h: Print this.\n"
           , programe);
}



int main(int argc, char **argv) {
    int oc;
    bool udp_mode = false;
    const char *capath = nullptr;
    while((oc = getopt(argc, argv, "p:uhk:D")) != -1)
    {
        switch(oc){
        case 'p':
            SPORT = atoi(optarg);
            break;
        case 'k':
            capath = optarg;
            break;
        case 'u':
            udp_mode = true;
            break;
        case 'D':
            daemon_mode = 1;
            break;
        case 'h':
            usage(argv[0]);
            return 0;
        case '?':
            usage(argv[0]);
            return -1;
        }
    }
    if (argc < optind + 2) {
        usage(argv[0]);
        return -1;
    }
    SSL_library_init();    // SSL初库始化
    SSL_load_error_strings();  // 载入所有错误信息

    SSL_CTX *ctx = nullptr;
    if(udp_mode){
        ctx = SSL_CTX_new(DTLS_server_method());

        if (ctx == NULL) {
            ERR_print_errors_fp(stderr);
            return 1;
        }
        SSL_CTX_set_cookie_generate_cb(ctx, generate_cookie);
        SSL_CTX_set_cookie_verify_cb(ctx, verify_cookie);
        SSL_CTX_set_options(ctx, SSL_OP_COOKIE_EXCHANGE);
    }else{
        ctx = SSL_CTX_new(SSLv23_server_method());
        if (ctx == NULL) {
            ERR_print_errors_fp(stderr);
            return 1;
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
    
    if (capath && SSL_CTX_load_verify_locations(ctx, capath, NULL) != 1)
        ERR_print_errors_fp(stderr);

    if (SSL_CTX_set_default_verify_paths(ctx) != 1)
        ERR_print_errors_fp(stderr);

    //加载证书和私钥
    if (SSL_CTX_use_certificate_file(ctx, argv[optind], SSL_FILETYPE_PEM) != 1) {
        ERR_print_errors_fp(stderr);
        return 1;
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, argv[optind+1], SSL_FILETYPE_PEM) != 1) {
        ERR_print_errors_fp(stderr);
        return 1;
    }

    if (SSL_CTX_check_private_key(ctx) != 1) {
        ERR_print_errors_fp(stderr);
        return 1;
    }

    SSL_CTX_set_verify_depth(ctx, 10);
    SSL_CTX_set_alpn_select_cb(ctx, select_alpn_cb, nullptr);
    SSL_CTX_set_read_ahead(ctx, 1);

    signal(SIGPIPE, SIG_IGN);
    signal(SIGCHLD, SIG_IGN);
    signal(SIGTERM, sighandle);
    loadsites();
    efd = epoll_create(10000);
    if(udp_mode){
        int svsk_udp;
        if((svsk_udp = socket(PF_INET6, SOCK_DGRAM, 0)) < 0){
            LOGOUT("socket error:%m\n");
            return -1;
        }
        if(Bind_any(svsk_udp, SPORT))
            return -1;
        new Dtls_server(svsk_udp, ctx);
    }else{
        int svsk_tcp;
        if ((svsk_tcp = Listen(SPORT)) < 0) {
            return -1;
        }
        new Https_server(svsk_tcp, ctx);
    }
    LOGOUT("Accepting connections ...\n");
    if (daemon_mode && daemon(1, 0) < 0) {
        LOGOUT("start daemon error:%m\n");
    }
    while (1) {
        int c;
        struct epoll_event events[200];
        if ((c = epoll_wait(efd, events, 200, 5000)) < 0) {
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
        dnstick();
        hosttick();
    }
    return 0;
}

