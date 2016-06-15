#include "guest.h"
#include "guest_sni.h"
#include "net.h"

#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <errno.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>

int efd;
int daemon_mode = 0;
uint16_t CPORT = 3333;

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

void usage(const char * programe){
    printf("Usage: %s [-t] [-p port] [-s user:passwd ] [-h] server[:port] -D\n"
           "       -p: The port to listen, default is 3333.\n"
           "       -t: Run as a transparent proxy, it will disable -p.\n"
           "       -s: Set a user and passwd for client, default is none.\n"
           "       -D: Run as a daemon.\n"
           "       -h: Print this.\n"
           , programe);
}

int main(int argc, char** argv) {
    int oc;
    bool istrans  = false;
    while((oc = getopt(argc, argv, "p:ths:D")) != -1)
    {
        switch(oc){
        case 'p':
            CPORT = atoi(optarg);
            break;
        case 't':
            istrans = true;
            break;
        case 's':
            auth_string = (char *)malloc((strlen(optarg)+2)*4/3+1);
            Base64Encode(optarg, strlen(optarg), auth_string);
            break;
        case 'h':
            usage(argv[0]);
            return 0;
        case 'D':
            daemon_mode = 1;
            break;
        case '?':
            usage(argv[0]);
            return -1;
        }
    }
    if (argc <= optind) {
        usage(argv[0]);
        return -1;
    }
    spliturl(argv[optind], SHOST, nullptr, &SPORT);
    SSL_library_init();    // SSL初库始化
    SSL_load_error_strings();  // 载入所有错误信息

    signal(SIGPIPE, SIG_IGN);
    signal(SIGCHLD, SIG_IGN);
    loadsites();
    efd = epoll_create(10000);
    if(istrans){
        CPORT = 80;
        int sni_svsk;
        if ((sni_svsk = Listen(443)) < 0) {
            return -1;
        }
        new Http_server<Guest_sni>(sni_svsk);
    }
    int http_svsk;
    if ((http_svsk = Listen(CPORT)) < 0) {
        return -1;
    }
    new Http_server<Guest>(http_svsk);
    
    LOGOUT("Accepting connections ...\n");
    if (daemon_mode && daemon(1, 0) < 0) {
        LOGOUT("start daemon error:%m\n");
    }
    while (1) {
        int c;
        struct epoll_event events[200];
        if ((c = epoll_wait(efd, events, 200, 5000)) < 0) {
            if (errno != EINTR) {
                LOGE("epoll wait:%m\n");
                return 4;
            }
            continue;
        }

        for (int i = 0; i < c; ++i) {
            Con* con = (Con*)events[i].data.ptr;
            (con->*con->handleEvent)(events[i].events);
        }
        
        dnstick();
        hosttick();
        proxy2tick();
    }
    return 0;
}


