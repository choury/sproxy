#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>


#include "guest_s.h"
#include "dns.h"

#define NEXT_PROTO_STRING \
    "\x8""http/1.1" \
    "\x8""choury/1"

int efd;

int ssl_set_npn_callback(SSL* s,
                         const unsigned char** data,
                         unsigned int* len,
                         void* arg) {
  *data = (const unsigned char*)NEXT_PROTO_STRING;
  *len = strlen(NEXT_PROTO_STRING);
  return SSL_TLSEXT_ERR_OK;
}


int main(int argc, char** argv) {
    int svsk, clsk;

    SSL_library_init();    // SSL初库始化
    SSL_load_error_strings();  // 载入所有错误信息
    SSL_CTX* ctx = SSL_CTX_new(SSLv23_server_method());
    if (ctx == NULL) {
        ERR_print_errors_fp(stderr);
        return 1;
    }
    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2|SSL_OP_NO_SSLv3);  // 去除支持SSLv2 SSLv3

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
    SSL_CTX_set_next_protos_advertised_cb(ctx, ssl_set_npn_callback, NULL);

    if ((svsk = socket(AF_INET6, SOCK_STREAM, 0)) < 0) {
        LOGOUT("socket error:%s\n", strerror(errno));
        return 2;
    }

    int flag = 1;
    if (setsockopt(svsk, SOL_SOCKET, SO_REUSEADDR, &flag, sizeof(flag)) < 0) {
        LOGOUT("setsockopt:%s\n", strerror(errno));
        return 3;
    }

    struct sockaddr_in6 myaddr;
    bzero(&myaddr, sizeof(myaddr));
    myaddr.sin6_family = AF_INET6;
    myaddr.sin6_port = htons(SPORT);
    myaddr.sin6_addr = in6addr_any;

    if (bind(svsk, (struct sockaddr*)&myaddr, sizeof(myaddr)) < 0) {
        LOGOUT("bind error:%s\n", strerror(errno));
        return 4;
    }
    if (listen(svsk, 10000) < 0) {
        LOGOUT("listen error:%s\n", strerror(errno));
        return 5;
    }

    signal(SIGPIPE, SIG_IGN);
    signal(SIGCHLD, SIG_IGN);
    struct epoll_event event;
    efd = epoll_create(10000);
    event.data.ptr = NULL;
    event.events = EPOLLIN;
    epoll_ctl(efd, EPOLL_CTL_ADD, svsk, &event);

    if (dnsinit() <= 0) {
        LOGOUT("Dns Init failed\n");
        return -1;
    }
    LOGOUT("Accepting connections ...\n");
    
    if (daemon(1, 0) < 0) {
        LOGOUT("start daemon error:%s\n", strerror(errno));
    }
    
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
                    socklen_t temp = sizeof(myaddr);
                    if ((clsk = accept(svsk, (struct sockaddr*)&myaddr, &temp)) < 0) {
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

                    Guest_s* guest = new Guest_s(clsk, ssl);

                    /* 建立SSL 连接*/
                    int ret = SSL_accept(ssl);
                    if (ret != 1) {
                        if (guest->showerrinfo(ret, "ssl accept error")) {
                            guest->clean(guest);
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
        if(c == 0) {
            dnstick();
        }
    }
    SSL_CTX_free(ctx);
    close(svsk);
    return 0;
}

