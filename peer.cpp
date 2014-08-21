#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <linux/netfilter_ipv4.h>

#include "common.h"
#include "parse.h"
#include "threadpool.h"

#define Min(x,y) ((x)<(y)?(x):(y))


Peer::Peer() {

}

Peer::Peer(int fd, int efd): fd(fd), efd(efd) {

};



Peer::~Peer() {
    if(fd) {
        close(fd);
    }
}

int Peer::Read(char* buff, size_t size) {
    return read(fd, buff, size);
}


int Peer::Write(const char* buff, size_t size) {

    int len = Min(size, bufleft());
    memcpy(wbuff + write_len, buff, len);
    write_len += len;

    struct epoll_event event;
    event.data.ptr = this;
    event.events = EPOLLIN | EPOLLOUT;
    epoll_ctl(efd, EPOLL_CTL_MOD, fd, &event);
    return len;
}

int Peer::Write() {
    int ret = write(fd, wbuff, write_len);

    if (ret < 0) {
        return ret;
    }

    if (ret == 0) {
        if (errno == 0)
            return 0;
        else
            return -1;
    }

    if (ret != write_len) {
        memmove(wbuff, wbuff + ret, write_len - ret);
        write_len -= ret;
    } else {
        write_len = 0;
    }

    return ret;
}

size_t Peer::bufleft() {
    if (sizeof(wbuff) == write_len)
        fulled = true;

    return sizeof(wbuff) - write_len;
}


Guest::Guest(int fd, int efd): Peer(fd, efd) {
    struct sockaddr_in6 sa;
    socklen_t len = sizeof(sa);

    if (getpeername(fd, (struct sockaddr*)&sa, &len)) {
        perror("getpeername");
        strcpy(sourceip, "Unknown IP");
    } else {
        inet_ntop(AF_INET6, &sa.sin6_addr, sourceip, sizeof(sourceip));
        sourceport = ntohs(sa.sin6_port);
    }

    struct sockaddr_in  Dst;

    socklen_t sin_size = sizeof(Dst);

    struct sockaddr_in6 Dst6;

    socklen_t sin6_size = sizeof(Dst6);

    int socktype;

    if ((getsockopt(fd, SOL_IP, SO_ORIGINAL_DST, &Dst, &sin_size) || (socktype = AF_INET, 0)) &&
            (getsockopt(fd, SOL_IPV6, SO_ORIGINAL_DST, &Dst6, &sin6_size) || (socktype = AF_INET6, 0))) {
        perror("getsockopt error");
        strcpy(destip, "Unkown IP");
        destport = CPORT;
    } else {
        switch(socktype) {
        case AF_INET:
            inet_ntop(socktype, &Dst.sin_addr, destip, INET6_ADDRSTRLEN);
            destport = ntohs(Dst.sin_port);
            break;

        case AF_INET6:
            inet_ntop(socktype, &Dst6.sin6_addr, destip, INET6_ADDRSTRLEN);
            destport = ntohs(Dst6.sin6_port);
            break;
        }
    }

}


void Guest::connected() {
    if (status == connect_s) {
        Write(connecttip, strlen(connecttip));
    }
}

bool Guest::candelete() {
    return status == close_s && write_len == 0;
}



void Guest::handleEvent(uint32_t events) {
    struct epoll_event event;
    event.data.ptr = this;

    int ret;

    if (events & EPOLLIN) {
        char buff[1024 * 1024];

        switch (status) {
        case start_s:
            if (read_len == 4096) {
                fprintf(stderr, "([%s]:%d): too large header\n",
                        sourceip, sourceport);
                clean();
                break;
            }

            ret = Read(rbuff + read_len, 4096 - read_len);

            if (ret <= 0) {
                clean();
                break;
            }

            read_len += ret;

            if (char* headerend = strnstr(rbuff, CRLF CRLF, read_len)) {
                headerend += strlen(CRLF CRLF);
                size_t headerlen = headerend - rbuff;

                try {
                    Http http(rbuff);

                    if (headerlen != read_len) {       //除了头部还读取到了其他内容
                        read_len -= headerlen;
                        memmove(rbuff, headerend, read_len);
                    } else {
                        read_len = 0;
                    }
                    bool shouldproxy=false;
                    if (destport == CPORT) {
                        if(http.checkproxy()) {
                            host = Proxy::getproxy(host, efd, this);
                            host->Write(buff, http.getstring(buff,true));
                            host->Write(rbuff, read_len);
                            read_len = 0;
                            status = proxy_s;
                            fprintf(stdout, "([%s]:%d): PROXY %s %s\n",
                                    sourceip, sourceport,
                                    http.method, http.url);
                            break;
                        }
                    } else if(destport == HTTPPORT) {
                        strcpy(http.hostname, http.getval("Host").c_str());
                        strcpy(http.path, http.url);
                        sprintf(http.url, "http://%s%s", http.hostname , http.path);
                        http.port = HTTPPORT;
                        shouldproxy=true;
                    } else {
                        fprintf(stderr,"Unkown Port\n");
                        clean();
                        return;
                    }

                    fprintf(stdout, "([%s]:%d): %s %s\n",
                            sourceip, sourceport,
                            http.method, http.url);


                    if ( http.ismethod("GET") ||  http.ismethod("HEAD") ) {
                        if(shouldproxy) {
                            host=Proxy::getproxy(host,efd,this);
                        } else {
                            host = Host::gethost(host, http.hostname, http.port, efd, this);
                        }
                        host->Write(buff, http.getstring(buff,shouldproxy));
                        status = start_s;
                    } else if (http.ismethod("POST") ) {
                        int writelen=http.getstring(buff,shouldproxy);
                        char* lenpoint;
                        if ((lenpoint = strstr(buff, "Content-Length:")) == NULL) {
                            fprintf(stderr, "([%s]:%d): unsported post version\n",
                                    sourceip, sourceport);
                            clean();
                            break;
                        }

                        sscanf(lenpoint + 15, "%u", &expectlen);
                        expectlen -= read_len;

                        if(shouldproxy) {
                            host=Proxy::getproxy(host,efd,this);
                        } else {
                            host = Host::gethost(host, http.hostname, http.port, efd, this);
                        }
                        host->Write(buff, writelen);
                        host->Write(rbuff, read_len);
                        read_len = 0;
                        status = post_s;

                    } else if (http.ismethod("CONNECT")) {
                        if(shouldproxy) {
                            host=Proxy::getproxy(host,efd,this);
                        } else {
                            host = Host::gethost(host, http.hostname, http.port, efd, this);
                        }
                        status = connect_s;

                    } else if (http.ismethod("LOADPLIST")) {
                        if (loadproxysite() > 0) {
                            Write(LOADBSUC, strlen(LOADBSUC));
                        } else {
                            Write(H404, strlen(H404));
                        }

                        status = start_s;
                    } else if (http.ismethod("ADDPSITE")) {
                        addpsite(http.url);
                        Write(ADDBTIP, strlen(ADDBTIP));
                        status = start_s;
                    } else if(http.ismethod("GLOBALPROXY")) {
                        if(globalproxy()) {
                            Write(EGLOBLETIP, strlen(EGLOBLETIP));
                        } else {
                            Write(DGLOBLETIP, strlen(DGLOBLETIP));
                        }
                    }
                } catch(...) {
                    clean();
                    return;
                }

            }

            break;

        case post_s:
            ret = Read(buff , Min(host->bufleft(), expectlen));

            if (ret <= 0 || host == NULL) {
                clean();
                break;
            }

            expectlen -= ret;
            host->Write(buff, ret);

            if (expectlen == 0) {
                status = start_s;
            }

            break;

        case connect_s:
        case proxy_s:
            ret = Read(buff, host->bufleft());

            if (ret <= 0 || host == NULL) {
                clean();
                break;
            }

            host->Write(buff, ret);
            break;

        default:
            break;
        }
    }

    if (events & EPOLLOUT) {
        int ret;

        switch (status) {
        case close_s:
            ret = Write();

            if (ret < 0) {
                perror("guest write");
                clean();
                write_len = 0;
                return;
            }

            break;

        default:
            ret = Write();

            if (ret < 0) {
                perror("guest write");
                clean();
                write_len = 0;
                return;
            }

            if (write_len == 0) {
                event.events = EPOLLIN;
                epoll_ctl(efd, EPOLL_CTL_MOD, fd, &event);
            }

            if (fulled) {
                if (host)
                    host->bufcanwrite();

                fulled = false;
            }
        }
    }


    if (events & EPOLLERR || events & EPOLLHUP) {
        int       error = 0;
        socklen_t errlen = sizeof(error);

        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, (void*)&error, &errlen) == 0) {
            fprintf(stderr, "([%s]:%d): guest error:%s\n",
                    sourceip, sourceport, strerror(error));
        }

        clean();
        write_len = 0;
    }
}

void Guest::clean() {
    status = close_s;

    if (host) {
        host->disattach();
    }

    host = NULL;

    if (write_len) {
        struct epoll_event event;
        event.data.ptr = this;
        event.events = EPOLLOUT;
        epoll_ctl(efd, EPOLL_CTL_MOD, fd, &event);
    }
}


void Guest::setHosttoNull(){
    host=NULL;
}

void connectHost(Host * host) {
    int hostfd = ConnectTo(host->hostname, host->targetport);

    if (hostfd < 0) {
        fprintf(stderr, "connect to %s error\n", host->hostname);
        host->clean();
        return;
    }


    int flags = fcntl(hostfd, F_GETFL, 0);
    if (flags < 0) {
        perror("fcntl error");
        host->clean();
        return ;
    }
    fcntl(hostfd,F_SETFL,flags | O_NONBLOCK);
    
    pthread_mutex_lock(&host->lock);
    if(host->guest) {
        
        host->fd = hostfd;
        host->guest->connected();
        struct epoll_event event;
        event.data.ptr = host;
        event.events = EPOLLIN | EPOLLOUT;
        epoll_ctl(host->efd, EPOLL_CTL_ADD, host->fd, &event);
    } else {
        host->clean();
    }
    pthread_mutex_unlock(&host->lock);
}


Host::Host(int efd, Guest* guest ,const char *hostname,int port): guest(guest) {

    this->efd = efd;
    this->fd=0;

    strcpy(this->hostname, hostname);
    this->targetport=port;
    
    pthread_mutexattr_t mutexattr;
    pthread_mutexattr_init(&mutexattr);
    pthread_mutexattr_settype(&mutexattr,
        PTHREAD_MUTEX_RECURSIVE_NP);
    pthread_mutex_init(&lock, &mutexattr);
    pthread_mutexattr_destroy(&mutexattr);

    addtask((taskfunc)connectHost,this,0);

    write_len = 0;
}

Host::~Host(){
    pthread_mutex_destroy(&lock);
}

void Host::handleEvent(uint32_t events) {
    struct epoll_event event;
    event.data.ptr = this;

    if (guest == NULL) {
        clean();
        return;
    }

    if (events & EPOLLIN) {
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

            if (ret < 0) {
                perror("host write");
                guest->clean();
                return;
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


void Host::disattach() {
    pthread_mutex_lock(&lock);
    if(guest){
        guest->setHosttoNull();
        guest = NULL;
    }
    pthread_mutex_unlock(&lock);
}

void Host::bufcanwrite() {
    struct epoll_event event;
    event.data.ptr = this;
    event.events = EPOLLIN | EPOLLOUT;
    epoll_ctl(efd, EPOLL_CTL_ADD, fd, &event);
}

void Host::clean() {
    disattach();
    delete this;
}


Host* Host::gethost(Host* exist, const char* hostname, int port, int efd, Guest* guest) {
    if (exist == NULL) {
        Host* newhost = new Host(efd, guest,hostname,port);
        return newhost;
    } else if (exist->targetport == port && strcasecmp(exist->hostname, hostname) == 0) {
        return exist;
    } else {
        Host* newhost = new Host(exist->efd, exist->guest,hostname,port);
        exist->disattach();
        return newhost;
    }
}


Guest_s::Guest_s(int fd, int efd, SSL* ssl): Guest(fd, efd), ssl(ssl) {
    status = accept_s;
}


int Guest_s::Read(char* buff, size_t size) {
    return SSL_read(ssl, buff, size);
}


int Guest_s::Write() {
    int ret = SSL_write(ssl, wbuff, write_len);

    if (ret <= 0) {
        return ret;
    }

    if (ret != write_len) {
        memmove(wbuff, wbuff + ret, write_len - ret);
        write_len -= ret;
    } else {
        write_len = 0;
    }

    return ret;
}

void Guest_s::connected() {
    Guest::connected();

    if (status == accept_s) {
        status = start_s;
        epoll_event event;
        event.data.ptr = this;
        event.events = EPOLLIN;
        epoll_ctl(efd, EPOLL_CTL_MOD, fd, &event);
    }
}

Guest_s::~Guest_s() {
    SSL_shutdown(ssl);
    SSL_free(ssl);
}

void Guest_s::handleEvent(uint32_t events) {
    struct epoll_event event;
    event.data.ptr = this;

    int ret;

    if (events & EPOLLIN) {
        char buff[1024 * 1024];

        switch (status) {
        case accept_s:
            ret = SSL_accept(ssl);

            if (ret != 1) {
                int error = SSL_get_error(ssl, ret);

                switch (error) {
                case SSL_ERROR_WANT_READ:
                    event.events = EPOLLIN;
                    epoll_ctl(efd, EPOLL_CTL_MOD, fd, &event);
                    break;

                case SSL_ERROR_WANT_WRITE:
                    event.events = EPOLLOUT;
                    epoll_ctl(efd, EPOLL_CTL_MOD, fd, &event);
                    break;

                case SSL_ERROR_SYSCALL:
                    fprintf(stderr, "([%s]:%d): ssl_accept error:%s\n",
                            sourceip, sourceport, strerror(errno));
                    clean();
                    break;

                default:
                    fprintf(stderr, "([%s]:%d):ssl_accept error:%s\n",
                            sourceip, sourceport, ERR_error_string(error, NULL));
                    clean();
                    break;
                }

                break;
            }

            connected();
            break;

        case start_s:
            if (read_len == 4096) {
                fprintf(stderr, "([%s]:%d): too large header\n", sourceip, sourceport);
                clean();
                break;
            }

            ret = Read(rbuff + read_len, 4096 - read_len);

            if (ret <= 0) {
                int error = SSL_get_error(ssl, ret);

                if (error == SSL_ERROR_WANT_READ) {
                    break;
                } else if (error == SSL_ERROR_SYSCALL) {
                    fprintf(stderr, "([%s]:%d): guest_s read:%s\n",
                            sourceip, sourceport, strerror(errno));
                } else if (error != SSL_ERROR_ZERO_RETURN) {
                    fprintf(stderr, "([%s]:%d): guest_s read:%s\n",
                            sourceip, sourceport, ERR_error_string(error, NULL));
                }

                clean();
                break;
            }

            read_len += ret;


            if (char* headerend = strnstr(rbuff, CRLF CRLF, read_len)) {
                headerend += strlen(CRLF CRLF);

                size_t headerlen = headerend - rbuff;

                try {
                    Http http (rbuff);

                    if (headerlen != read_len) {       //除了头部还读取到了其他内容
                        read_len -= headerlen;
                        memmove(rbuff, headerend, read_len);
                    } else {
                        read_len = 0;
                    }

                    fprintf(stdout, "([%s]:%d): %s %s\n",
                            sourceip, sourceport,
                            http.method, http.url);

                    int writelen=http.getstring(buff,false);

                    if (http.url[0] == '/') {
                        printf("%s", buff);
                        const char* welcome = "Welcome\n";
                        Guest::Write(buff, parse200(strlen(welcome), buff));
                        Guest::Write(welcome, strlen(welcome));
                        break;
                    }


                    if (http.ismethod("GET" ) || http.ismethod("HEAD") ) {
                        host = host->gethost(host, http.hostname, http.port, efd, this);
                        host->Write(buff, writelen);
                        status = start_s;
                    } else if (http.ismethod("POST") ) {

                        char* lenpoint;
                        if ((lenpoint = strstr(buff, "Content-Length:")) == NULL) {
                            fprintf(stderr, "([%s]:%d): unsported post version\n", sourceip, sourceport);
                            clean();
                            break;
                        }

                        sscanf(lenpoint + 15, "%u", &expectlen);
                        expectlen -= read_len;

                        host = host->gethost(host, http.hostname, http.port, efd, this);
                        host->Write(buff, writelen);
                        host->Write(rbuff, read_len);
                        read_len = 0;
                        status = post_s;

                    } else if (http.ismethod("CONNECT")) {
                        host = host->gethost(host, http.hostname, http.port, efd, this);
                        status = connect_s;

                    } else {
                        fprintf(stderr, "([%s]:%d): unknown method:%s\n",
                                sourceip, sourceport, http.method);
                        clean();
                    }
                } catch(...) {
                    clean();
                    return;
                }
            }

            break;

        case post_s:
            ret = Read(buff, Min(host->bufleft(), expectlen));

            if (ret <= 0 || host == NULL) {
                int error = SSL_get_error(ssl, ret);

                if (error == SSL_ERROR_WANT_READ) {
                    break;
                } else if (error == SSL_ERROR_SYSCALL) {
                    fprintf(stderr, "([%s]:%d): guest_s read:%s\n",
                            sourceip, sourceport, strerror(errno));
                } else if (error != SSL_ERROR_ZERO_RETURN) {
                    fprintf(stderr, "([%s]:%d): guest_s read:%s\n",
                            sourceip, sourceport, ERR_error_string(error, NULL));
                }

                clean();
                break;
            }

            expectlen -= ret;
            host->Write(buff, ret);

            if (expectlen == 0) {
                status = start_s;
            }

            break;

        case connect_s:
            ret = Read(buff, host->bufleft());

            if (ret <= 0 || host == NULL) {
                int error = SSL_get_error(ssl, ret);

                if (error == SSL_ERROR_WANT_READ) {
                    break;
                } else if (error == SSL_ERROR_SYSCALL) {
                    fprintf(stderr, "([%s]:%d): guest_s read:%s\n",
                            sourceip, sourceport, strerror(errno));
                } else if (error != SSL_ERROR_ZERO_RETURN) {
                    fprintf(stderr, "([%s]:%d): guest_s read:%s\n",
                            sourceip, sourceport, ERR_error_string(error, NULL));
                }

                clean();
                break;
            }

            host->Write(buff, ret);
            break;

        default:
            break;
        }
    }

    if (events & EPOLLOUT) {
        int ret;

        switch (status) {
        case accept_s:
            ret = SSL_accept(ssl);

            if (ret != 1) {
                int error = SSL_get_error(ssl, ret);

                switch (error) {
                case SSL_ERROR_WANT_READ:
                    event.events = EPOLLIN;
                    epoll_ctl(efd, EPOLL_CTL_MOD, fd, &event);
                    break;

                case SSL_ERROR_WANT_WRITE:
                    event.events = EPOLLOUT;
                    epoll_ctl(efd, EPOLL_CTL_MOD, fd, &event);
                    break;

                case SSL_ERROR_SYSCALL:
                    fprintf(stderr, "([%s]:%d): ssl_accept error:%s\n",
                            sourceip, sourceport, strerror(errno));
                    clean();
                    break;

                default:
                    fprintf(stderr, "([%s]:%d):ssl_accept error:%s\n",
                            sourceip, sourceport, ERR_error_string(error, NULL));
                    clean();
                    break;
                }

                break;
            }

            connected();
            break;

        case close_s:
            ret = Write();

            if (ret <= 0) {
                int error = SSL_get_error(ssl, ret);

                if (error == SSL_ERROR_WANT_WRITE) {
                    break;
                } else if (error == SSL_ERROR_SYSCALL) {
                    fprintf(stderr, "([%s]:%d): guest_s write:%s\n",
                            sourceip, sourceport, strerror(errno));
                } else if (error != SSL_ERROR_ZERO_RETURN) {
                    fprintf(stderr, "([%s]:%d): guest_s write:%s\n",
                            sourceip, sourceport, ERR_error_string(error, NULL));
                }

                write_len = 0;
                return;
            }

            break;

        default:
            ret = Write();

            if (ret <= 0) {
                int error = SSL_get_error(ssl, ret);

                if (error == SSL_ERROR_WANT_WRITE) {
                    break;
                } else if (error == SSL_ERROR_SYSCALL) {
                    fprintf(stderr, "([%s]:%d): guest_s write:%s\n",
                            sourceip, sourceport, strerror(errno));
                } else if (error != SSL_ERROR_ZERO_RETURN) {
                    fprintf(stderr, "([%s]:%d): guest_s write:%s\n",
                            sourceip, sourceport, ERR_error_string(error, NULL));
                }

                clean();
                write_len = 0;
                break;
            }

            if (write_len == 0) {
                event.events = EPOLLIN;
                epoll_ctl(efd, EPOLL_CTL_MOD, fd, &event);
            }

            if (fulled) {
                if (host)
                    host->bufcanwrite();

                fulled = false;
            }
        }
    }

    if (events & EPOLLERR || events & EPOLLHUP) {
        int       error = 0;
        socklen_t errlen = sizeof(error);

        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, (void*)&error, &errlen) == 0) {
            fprintf(stderr, "([%s]:%d): guest_s error:%s\n",
                    sourceip, sourceport, strerror(error));
        }

        clean();
        write_len = 0;
    }
}

Proxy::Proxy(int efd,Guest *guest):Host(efd,guest,SHOST,SPORT) {}


Host* Proxy::getproxy(Host* exist, int efd, Guest* guest) {
    if (exist == NULL) {
        return new Proxy(efd, guest);
    } else if (dynamic_cast<Proxy*>(exist)) {
        return exist;
    } else {
        Proxy* newproxy = new Proxy(efd, guest);
        exist->disattach();
        return newproxy;
    }
}

int Proxy::Write() {
    int ret = SSL_write(ssl, wbuff, write_len);

    if (ret <= 0) {
        return ret;
    }

    if (ret != write_len) {
        memmove(wbuff, wbuff + ret, write_len - ret);
        write_len -= ret;
    } else {
        write_len = 0;
    }

    return ret;
}

int Proxy::Read(char* buff, size_t size) {
    return SSL_read(ssl, buff, size);
}


void Proxy::connected() {
    epoll_event event;
    event.data.ptr = this;
    status = connect_s;

    if (write_len) {
        int ret = Write();

        if (ret <= 0) {
            guest->clean();
            return;
        }
    }

    if (write_len == 0) {
        event.events = EPOLLIN;
    } else {
        event.events = EPOLLIN | EPOLLOUT;
    }

    epoll_ctl(efd, EPOLL_CTL_MOD, fd, &event);
}

void Proxy::handleEvent(uint32_t events) {
    struct epoll_event event;
    event.data.ptr = this;

    if (guest == NULL) {
        clean();
        return;
    }

    if (events & EPOLLIN) {
        int ret;
        int bufleft = guest->bufleft();

        switch (status) {
        case wait_s:
            ret = SSL_connect(ssl);

            if (ret != 1) {
                switch (SSL_get_error(ssl, ret)) {
                case SSL_ERROR_WANT_READ:
                    event.events = EPOLLIN;
                    break;

                case SSL_ERROR_WANT_WRITE:
                    event.events = EPOLLOUT;
                    break;

                default:
                    ERR_print_errors_fp(stderr);
                    guest->clean();
                    return;
                }

                status = wait_s;
                epoll_ctl(efd, EPOLL_CTL_MOD, fd, &event);
                break;
            }

            connected();
            break;

        case connect_s:
            if (bufleft == 0) {
                fprintf(stderr, "The guest's write buff is full\n");
                epoll_ctl(efd, EPOLL_CTL_DEL, fd, NULL);
                return;
            }

            char buff[1024 * 1024];
            ret = Read(buff, bufleft);

            if (ret <= 0) {
                int error = SSL_get_error(ssl, ret);

                if (error == SSL_ERROR_WANT_READ) {
                    break;
                } else if (error == SSL_ERROR_SYSCALL) {
                    fprintf(stderr, "proxy read:%s\n", strerror(errno));
                } else if (error != SSL_ERROR_ZERO_RETURN) {
                    fprintf(stderr, "proxy read:%s\n", ERR_error_string(error, NULL));
                }

                guest->clean();
                return;
            }

            guest->Write(buff, ret);
            break;

        default:
            break;
        }

    }

    if (events & EPOLLOUT) {
        int ret;

        switch (status) {
        case start_s:
            ctx = SSL_CTX_new(SSLv23_client_method());

            if (ctx == NULL) {
                ERR_print_errors_fp(stderr);
                guest->clean();
                return;
            }

            ssl = SSL_new(ctx);
            SSL_set_fd(ssl, fd);

        case wait_s:
            ret = SSL_connect(ssl);

            if (ret != 1) {
                switch (SSL_get_error(ssl, ret)) {
                case SSL_ERROR_WANT_READ:
                    event.events = EPOLLIN;
                    break;

                case SSL_ERROR_WANT_WRITE:
                    event.events = EPOLLOUT | EPOLLIN;
                    break;

                default:
                    ERR_print_errors_fp(stderr);
                    guest->clean();
                    return;
                }

                status = wait_s;
                epoll_ctl(efd, EPOLL_CTL_MOD, fd, &event);
                break;
            }

            connected();
            break;

        case connect_s:
            ret = Write();

            if (ret <= 0) {
                int error = SSL_get_error(ssl, ret);

                if (error == SSL_ERROR_WANT_WRITE) {
                    break;
                } else if (error == SSL_ERROR_SYSCALL) {
                    fprintf(stderr, "proxy write:%s\n", strerror(errno));
                } else if (error != SSL_ERROR_ZERO_RETURN) {
                    fprintf(stderr, "proxy write:%s\n", ERR_error_string(error, NULL));
                }

                guest->clean();
                return;
            }

            if (write_len == 0) {
                event.data.ptr = this;
                event.events = EPOLLIN;
                epoll_ctl(efd, EPOLL_CTL_MOD, fd, &event);
            }

            break;

        default:
            break;
        }

    }

    if (events & EPOLLERR || events & EPOLLHUP) {
        guest->clean();
    }
}



Proxy::~Proxy() {
    if (ssl) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
    }

    if (ctx) {
        SSL_CTX_free(ctx);
    }
}

