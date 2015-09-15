#include "guest.h"
#include "net.h"

#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>

int efd;


class Http_server: public Server{
    virtual void defaultHE(uint32_t events){
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
            new Guest(clsk, &myaddr);
        } else {
            LOGE("unknown error\n");
        }
    }
public:
    Http_server(int fd):Server(fd){};
};

#ifdef _ANDROID_
int Java_com_choury_sproxy_Client_main(JNIEnv *env, jobject, jstring s) {
    const char* srvaddr = (env)->GetStringUTFChars(s, 0);

#else
int main(int argc, char** argv) {
    if (argc != 2) {
        LOGOUT("Usage: %s Server[:port]\n", basename(argv[0]));
        return -1;
    }
    const char *srvaddr = argv[1];
#endif
    spliturl(srvaddr, SHOST, nullptr, &SPORT);
    SSL_library_init();    // SSL初库始化
    SSL_load_error_strings();  // 载入所有错误信息

    signal(SIGPIPE, SIG_IGN);
    efd = epoll_create(10000);
    
    int svsk;
    if ((svsk = Listen(SOCK_STREAM, CPORT)) < 0) {
        return -1;
    }
    new Http_server(svsk);

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
                LOGE("epoll wait:%s\n", strerror(errno));
                return 4;
            }
            continue;
        }

        for (int i = 0; i < c; ++i) {
            Con* con = (Con*)events[i].data.ptr;
            (con->*con->handleEvent)(events[i].events);
        }
        
        if(c < 5) {
            dnstick();
            hosttick();
            proxy2tick();
        }
    }

    close(svsk);
    return 0;
}

