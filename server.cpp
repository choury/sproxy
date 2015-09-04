#include "guest_s.h"
#include "net.h"

#include <set>

#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <arpa/inet.h>
#include <openssl/err.h>

int efd;

static int select_alpn_cb(SSL* ssl,
                           const unsigned char **out, unsigned char *outlen,
                           const unsigned char *in, unsigned int inlen, void *arg)
{
    (void)ssl;
    std::set<std::string> proset;
    while (*in) {
        uint8_t len = *in++;
        proset.insert(std::string((const char*)in, len));
        in+= len;
    }
    if (proset.count("h2")) {
        *out = (unsigned char*)"h2";
        *outlen = strlen((char*)*out);
        return SSL_TLSEXT_ERR_OK;
    }
    if (proset.count("http/1.1")) {
        *out = (unsigned char*)"http/1.1";
        *outlen = strlen((char*)*out);
        return SSL_TLSEXT_ERR_OK;
    }
    LOGE("Can't select a protocol\n");
    return SSL_TLSEXT_ERR_ALERT_FATAL;
}

int main(int argc, char** argv) {
    SSL_library_init();    // SSL初库始化
    SSL_load_error_strings();  // 载入所有错误信息
    SSL_CTX* ctx = SSL_CTX_new(SSLv23_server_method());
    if (ctx == NULL) {
        ERR_print_errors_fp(stderr);
        return 1;
    }
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2|SSL_OP_NO_SSLv3);  // 去除支持SSLv2 SSLv3
    SSL_CTX_set_options(ctx, SSL_OP_NO_COMPRESSION);
    SSL_CTX_set_options(ctx, SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION);
    SSL_CTX_set_options(ctx, SSL_OP_SINGLE_ECDH_USE);
    SSL_CTX_set_options(ctx, SSL_OP_NO_TICKET);
    SSL_CTX_set_options(ctx, SSL_OP_CIPHER_SERVER_PREFERENCE);
    SSL_CTX_set_cipher_list(ctx, DEFAULT_CIPHER_LIST);
    SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY);
    SSL_CTX_set_mode(ctx, SSL_MODE_RELEASE_BUFFERS);

    EC_KEY* ecdh = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    SSL_CTX_set_tmp_ecdh(ctx, ecdh);
    EC_KEY_free(ecdh);

    if (SSL_CTX_load_verify_locations(ctx, "/home/choury/keys/ca.pem", NULL) != 1)
        ERR_print_errors_fp(stderr);

    if (SSL_CTX_set_default_verify_paths(ctx) != 1)
        ERR_print_errors_fp(stderr);


    //加载证书和私钥
    if (SSL_CTX_use_certificate_file(ctx, "/home/choury/keys/ssl.crt", SSL_FILETYPE_PEM) != 1) {
        ERR_print_errors_fp(stderr);
        return 1;
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, "/home/choury/keys/ssl.key", SSL_FILETYPE_PEM) != 1) {
        ERR_print_errors_fp(stderr);
        return 1;
    }

    if (SSL_CTX_check_private_key(ctx) != 1) {
        ERR_print_errors_fp(stderr);
        return 1;
    }

    SSL_CTX_set_verify_depth(ctx, 10);
    SSL_CTX_set_alpn_select_cb(ctx, select_alpn_cb, nullptr);
    

    signal(SIGPIPE, SIG_IGN);
    signal(SIGCHLD, SIG_IGN);
    efd = epoll_create(10000);
    struct epoll_event event;
    
    int svsk_tcp;
    if ((svsk_tcp = Listen(SOCK_STREAM, SPORT)) < 0) {
        return -1;
    }
    event.data.ptr = NULL;
    event.events = EPOLLIN;
    epoll_ctl(efd, EPOLL_CTL_ADD, svsk_tcp, &event);

    LOGOUT("Accepting connections ...\n");
#ifndef DEBUG
    if (daemon(1, 0) < 0) {
        LOGOUT("start daemon error:%s\n", strerror(errno));
    }
#endif
    while (1) {
        int c;
        struct epoll_event events[20];
        if ((c = epoll_wait(efd, events, 20, 5000)) < 0) {
            if (errno != EINTR) {
                perror("epoll wait");
                return 6;
            }
            continue;
        }
        for (int i = 0; i < c; ++i) {
            if (events[i].data.ptr == NULL) {
                if (events[i].events & EPOLLIN) {
                    int clsk;
                    struct sockaddr_in6 myaddr;
                    socklen_t temp = sizeof(myaddr);
                    if ((clsk = accept(svsk_tcp, (struct sockaddr*)&myaddr, &temp)) < 0) {
                        perror("accept error");
                        continue;
                    }

                    int flags = fcntl(clsk, F_GETFL, 0);
                    if (flags < 0) {
                        perror("fcntl error");
                        close(clsk);
                        continue;
                    }
                    fcntl(clsk, F_SETFL, flags | O_NONBLOCK);

                    /* 基于ctx 产生一个新的SSL */
                    SSL* ssl = SSL_new(ctx);
                    /* 将连接用户的socket 加入到SSL */
                    SSL_set_fd(ssl, clsk);
                    Guest_s* guest = new Guest_s(clsk, &myaddr, ssl);
                    /* 建立SSL 连接*/
                    int ret = SSL_accept(ssl);
                    if (ret != 1) {
                        if (guest->showerrinfo(ret, "ssl accept error")) {
                            guest->clean(guest, SSL_SHAKEHAND_ERR);
                        }
                        continue;
                    }
                    guest->shakedhand();

                } else {
                    perror("unknown error");
                    return 7;
                }
            } else {
                Con* con = (Con*)events[i].data.ptr;
                (con->*con->handleEvent)(events[i].events);
            }
        }
        if(c < 5) {
            dnstick();
            hosttick();
        }
    }
    SSL_CTX_free(ctx);
    close(svsk_tcp);
    return 0;
}

