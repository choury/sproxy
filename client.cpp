#include <unistd.h>
#include <cerrno>
#include <signal.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <arpa/inet.h>

#include <list>

#include "common.h"


using std::list;

list <Guest *> guestlist;


int main(int argc, char** argv)
{
    int svsk, clsk;
    SSL_library_init();    //SSL初库始化
    SSL_load_error_strings();  //载入所有错误信息
    
    if ((svsk = socket(AF_INET6, SOCK_STREAM, 0)) < 0) {
        perror("socket error");
        return 1;
    }

    int flag = 1;
    if (setsockopt(svsk, SOL_SOCKET, SO_REUSEADDR, &flag, sizeof(flag)) < 0) {
        perror("setsockopt");
        return 2;
    }

    struct sockaddr_in6 myaddr;
    bzero(&myaddr, sizeof(myaddr));
    myaddr.sin6_family = AF_INET6;
    myaddr.sin6_port = htons(CPORT);
    myaddr.sin6_addr = in6addr_any;

    if (bind(svsk, (struct sockaddr*)&myaddr, sizeof(myaddr)) < 0) {
        perror("bind error");
        return 2;
    }
    if (listen(svsk, 10000) < 0) {
        perror("listen error");
        return 3;
    }

    signal(SIGPIPE, SIG_IGN);
    fprintf(stderr, "Accepting connections ...\n");
    int efd = epoll_create(10000);
    struct epoll_event event;
    event.data.ptr = NULL;
    event.events = EPOLLIN;
    epoll_ctl(efd, EPOLL_CTL_ADD, svsk, &event);
    struct epoll_event events[20];
    while (1) {
        int i, c;
        if ((c = epoll_wait(efd, events, 20, -1)) < 0) {
            if (errno != EINTR) {
                perror("epoll wait");
                return 4;
            }
            continue;
        }
        for (i = 0; i < c; ++i) {
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
                    Guest* guest = new Guest(clsk,efd);
                    
                    guestlist.push_back(guest);

                    event.data.ptr = guest;
                    event.events = EPOLLIN;
                    epoll_ctl(efd, EPOLL_CTL_ADD, clsk, &event);
                } else {
                    perror("unknown error");
                    return 5;
                }
            } else {
                Peer * peer = (Peer*)events[i].data.ptr;
                peer->handleEvent(events[i].events); 
            }
        }
        for(auto i=guestlist.begin();i!=guestlist.end();){
            if((*i)->candelete()){
                delete *i;
                guestlist.erase(i++);
            }else{
                ++i;
            }
        }
    }
    close(svsk);
    return 0;
}




