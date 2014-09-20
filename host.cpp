#include <string.h>
#include <stdio.h>
#include <sys/epoll.h>

#include "host.h"
#include "guest.h"
#include "threadpool.h"



Host::Host(int efd, Guest* guest ,const char *hostname,int port): guest(guest) {

    this->efd = efd;
    this->fd=0;
    this->status=preconnect_s;
    write_len = 0;

    strcpy(this->hostname, hostname);
    this->targetport=port;


    

    addtask((taskfunc)connectHost,this,0);
    peerlist.push_back(this);
}


void Host::handleEvent(uint32_t events) {
    struct epoll_event event;
    event.data.ptr = this;

    if(status == wantclose_s || status == close_s)
        return;

    if (events & EPOLLIN ) {
        int bufleft = guest->bufleft();

        if (bufleft == 0) {
            fprintf(stderr, "The guest's write buff is full\n");
            epoll_ctl(efd, EPOLL_CTL_DEL, fd, NULL);
            return;
        }

        char buff[1024 * 1024];
        int ret = Read(buff, bufleft);

        if (ret <= 0) {
            guest->clean();
            return;
        }

        guest->Write(buff, ret);

    }

    if (events & EPOLLOUT) {
        if (write_len) {
            int ret = Write();
            if (ret <= 0) {
                perror("host write");
                guest->clean();
                return;
            }

            if (fulled) {
                guest->peercanwrite();
                fulled = false;
            }

        }

        if (write_len == 0) {
            event.events = EPOLLIN;
            epoll_ctl(efd, EPOLL_CTL_MOD, fd, &event);
        }

    }

    if (events & EPOLLERR || events & EPOLLHUP) {
        guest->clean();
    }

}



void Host::clean() {
    pthread_mutex_lock(&lock);
    
    if(guest){
        guest->host=NULL;
        guest->clean();
    }
    guest=NULL;
    
    if(status != preconnect_s) {
        status = close_s;
    } else {
        status = wantclose_s;
    }
    epoll_ctl(efd,EPOLL_CTL_DEL,fd,NULL);
    pthread_mutex_unlock(&lock);
}


bool Host::candelete() {
    return status==close_s;
}

Host* Host::gethost(Host* exist, const char* hostname, int port, int efd, Guest* guest) {
    if (exist == NULL) {
        Host* newhost = new Host(efd, guest,hostname,port);
        return newhost;
    } else if (exist->targetport == port && strcasecmp(exist->hostname, hostname) == 0) {
        return exist;
    } else {
        Host* newhost = new Host(exist->efd, exist->guest,hostname,port);
        exist->clean();
        return newhost;
    }
}
