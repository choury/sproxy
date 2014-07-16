#include <pthread.h>

#include <unistd.h>
#include <arpa/inet.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "common.h"
#include "parse.h"

#define Min(x,y) ((x)<(y)?(x):(y))


Peer::Peer()
{
}

Peer::Peer(int fd, int efd): fd(fd), efd(efd), status(start_s), write_len(0), fulled(false)
{
};



Peer::~Peer()
{
    close(fd);
}

int Peer::Read(char* buff, size_t size)
{
    return read(fd, buff, size);
}


int Peer::Write(const char* buff, size_t size)
{

    int len = Min(size, bufleft());
    memcpy(wbuff + write_len, buff, len);
    write_len += len;

    struct epoll_event event;
    event.data.ptr = this;
    event.events = EPOLLIN | EPOLLOUT;
    epoll_ctl(efd, EPOLL_CTL_MOD, fd, &event);
    return len;
}

int Peer::Write()
{
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

size_t Peer::bufleft()
{
    if (sizeof(wbuff) == write_len)
        fulled = true;
    return sizeof(wbuff) - write_len;
}

Guest::Guest(int fd, int efd): Peer(fd, efd), host(NULL), read_len(0), expectlen(0)
{

}



void Guest::connected()
{
    if (status == connect_s) {
        Write(connecttip, strlen(connecttip));
    }
}

bool Guest::candelete()
{
    return status == close_s && write_len == 0;
}



void Guest::handleEvent(uint32_t events)
{
    struct epoll_event event;
    event.data.ptr = this;

    struct sockaddr_in6 sa;
    socklen_t len = sizeof(sa);
    char ipAddr[100];
    if (getpeername(fd, (struct sockaddr*)&sa, &len)) {
        perror("getpeername");
        clean();
        return;
    } else {
        inet_ntop(AF_INET6, &sa.sin6_addr, ipAddr, sizeof(ipAddr));
    }

    int ret;
    if (events & EPOLLIN) {
        char buff[1024 * 1024];
        switch (status) {
        case start_s:
            if (read_len == 4096) {
                fprintf(stderr, "([%s]:%d): too large header\n",
                        ipAddr, ntohs(sa.sin6_port));
                clean();
                break;
            }
            ret = Read(rbuff + read_len, 4096 - read_len);
            if (ret <= 0) {
                clean();
                break;
            }

            read_len += ret;


            char* headerend;
            if ((headerend = strnstr(rbuff, CRLF CRLF, read_len))) {
                headerend += strlen(CRLF CRLF);

                char method[20];
                char url[URLLIMIT] = {0};
                sscanf(rbuff, "%s%*[ ]%[^\r\n ]", method, url);


                char path[URLLIMIT];
                char hostname[DOMAINLIMIT];
                int port;

                if (spliturl(url, hostname, path, &port)) {
                    fprintf(stderr, "wrong url format\n");
                    clean();
                    break;
                }
                try {
                    if (checkproxy(hostname)) {
                        fprintf(stdout, "([%s]:%d):PROXY %s %s\n",
                                ipAddr, ntohs(sa.sin6_port), method, url);
                        host = Proxy::getproxy(host, efd, this);
                        host->Write(rbuff, read_len);
                        read_len = 0;
                        status = proxy_s;
                        break;
                    } else {
                        fprintf(stdout, "([%s]:%d):%s %s\n",
                                ipAddr, ntohs(sa.sin6_port), method, url);

                        char* headerbegin = strstr(rbuff, CRLF) + strlen(CRLF);

                        sprintf(buff, "%s %s HTTP/1.1" CRLF "%.*s",
                                method, path, headerend - headerbegin, headerbegin);

                        size_t headerlen = headerend - rbuff;
                        if (headerlen != read_len) {       //除了头部还读取到了其他内容
                            read_len -= headerlen;
                            memmove(rbuff, headerend, read_len);
                        } else {
                            read_len = 0;
                        }
                    }

                    if (strcasecmp(method, "GET") == 0 || strcasecmp(method, "HEAD") == 0) {

                        host = Host::gethost(host, hostname, port, efd, this);
                        host->Write(buff, strlen(buff));
                        status = start_s;
                    } else if (strcasecmp(method, "POST") == 0) {
                        char* lenpoint;
                        if ((lenpoint = strstr(buff, "Content-Length:")) == NULL) {
                            fprintf(stderr, "unsported post version\n");
                            clean();
                            break;
                        }
                        sscanf(lenpoint + 15, "%u", &expectlen);
                        expectlen -= read_len;
                        int writelen = strlen(buff);
                        memcpy(buff + writelen, rbuff, read_len);
                        writelen +=  read_len;
                        read_len = 0;
                        host = Host::gethost(host, hostname, port, efd, this);
                        host->Write(buff, writelen);


                        status = post_s;

                    } else if (strcasecmp(method, "CONNECT") == 0) {
                        host = Host::gethost(host, hostname, port, efd, this);
                        status = connect_s;

                    } else if (strcasecmp(method, "LOADPLIST") == 0) {
                        if (loadproxysite() > 0) {
                            Write(LOADBSUC, strlen(LOADBSUC));
                        } else {
                            Write(H404, strlen(H404));
                        }
                        status = start_s;
                    } else if (strcasecmp(method, "ADDPSITE") == 0) {
                        addpsite(url);
                        Write(ADDBTIP, strlen(ADDBTIP));
                        status = start_s;
                    } else {
                        fprintf(stderr, "unknown method:%s\n", method);
                        clean();
                    }
                } catch (...) {
                    clean();
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
            fprintf(stderr, "guest error:%s\n", strerror(error));
        }
        clean();
    }
}

void Guest::clean()
{
    status = close_s;
    if (host) {
        host->disconnect();
    }
    host = NULL;
    if (write_len) {
        struct epoll_event event;
        event.data.ptr = this;
        event.events = EPOLLOUT;
        epoll_ctl(efd, EPOLL_CTL_MOD, fd, &event);
    }
}

void Guest::cleanhost()
{
    if (host) {
        delete host;
        host = NULL;
    }
    clean();
}


Host::Host(int efd, Guest* guest, int port, const char* host) throw(int): port(port), guest(guest)
{

    int hostfd = ConnectTo(host, port);
    if (hostfd < 0) {
        fprintf(stderr, "connect to %s error\n", host);
        throw 0;
    }

    fd = hostfd;
    this->efd = efd;
    this->status = start_s;

    strcpy(this->host, host);
    write_len = 0;

    struct epoll_event event;
    event.data.ptr = this;
    event.events = EPOLLOUT;
    epoll_ctl(efd, EPOLL_CTL_ADD, fd, &event);
}


void Host::handleEvent(uint32_t events)
{
    struct epoll_event event;
    event.data.ptr = this;
    if (guest == NULL) {
        delete this;
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
            guest->cleanhost();
            return;
        }
        guest->Write(buff, ret);

    }
    if (events & EPOLLOUT) {
        int error = 0;
        socklen_t len = sizeof(int);
        switch (status) {
        case start_s:
            if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &len)) {
                perror("getsokopt");
                guest->cleanhost();
                return;
            }
            if (error != 0) {
                fprintf(stderr, "connect to %s:%s\n", host, strerror(error));
                guest->cleanhost();
                return;
            }
            guest->connected();
            status = connect_s;

        case connect_s:
            if (write_len) {
                int ret = Write();
                if (ret < 0) {
                    perror("host write");
                    guest->cleanhost();
                    return;
                }
            }

            if (write_len == 0) {
                event.events = EPOLLIN;
                epoll_ctl(efd, EPOLL_CTL_MOD, fd, &event);
            }
        default:
            break;
        }

    }
    if (events & EPOLLERR || events & EPOLLHUP) {
        guest->cleanhost();
    }
}


void Host::disconnect()
{
    guest = NULL;
}

void Host::bufcanwrite()
{
    struct epoll_event event;
    event.data.ptr = this;
    event.events = EPOLLIN | EPOLLOUT;
    epoll_ctl(efd, EPOLL_CTL_ADD, fd, &event);
}

void Host::clean()
{

}


Host* Host::gethost(Host* exist, const char* host, int port, int efd, Guest* guest) throw(int)
{
    if (exist == NULL) {
        Host* newhost = new Host(efd, guest, port, host);
        return newhost;
    } else if (exist->port == port && strcasecmp(exist->host, host) == 0) {
        return exist;
    } else {
        Host* newhost = new Host(exist->efd, exist->guest, port, host);
        exist->disconnect();
        return newhost;
    }
}


Guest_s::Guest_s(int fd, int efd, SSL* ssl): Guest(fd, efd), ssl(ssl)
{
    status = accept_s;
}


int Guest_s::Read(char* buff, size_t size)
{
    return SSL_read(ssl, buff, size);
}


int Guest_s::Write()
{
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

void Guest_s::connected()
{
    Guest::connected();
    if (status == accept_s) {
        status = start_s;
        epoll_event event;
        event.data.ptr = this;
        event.events = EPOLLIN;
        epoll_ctl(efd, EPOLL_CTL_MOD, fd, &event);
    }
}

Guest_s::~Guest_s()
{
    SSL_shutdown(ssl);
    SSL_free(ssl);
}

void Guest_s::handleEvent(uint32_t events)
{
    struct epoll_event event;
    event.data.ptr = this;

    struct sockaddr_in6 sa;
    char ipAddr[100];
    socklen_t len = sizeof(sa);
    if (getpeername(fd, (struct sockaddr*)&sa, &len)) {
        perror("getpeername");
        clean();
        return;
    } else {
        inet_ntop(AF_INET6, &sa.sin6_addr, ipAddr, sizeof(ipAddr));
    }


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
                            ipAddr, ntohs(sa.sin6_port), strerror(errno));
                    clean();
                    break;
                default:
                    fprintf(stderr, "([%s]:%d):ssl_accept error:%s\n",
                            ipAddr, ntohs(sa.sin6_port), ERR_error_string(error, NULL));
                    clean();
                    break;
                }
                break;
            }
            connected();
            break;
        case start_s:
            if (read_len == 4096) {
                fprintf(stderr, "([%s]:%d): too large header\n", ipAddr, ntohs(sa.sin6_port));
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
                            ipAddr, ntohs(sa.sin6_port), strerror(errno));
                } else if (error != SSL_ERROR_ZERO_RETURN) {
                    fprintf(stderr, "([%s]:%d): guest_s read:%s\n",
                            ipAddr, ntohs(sa.sin6_port), ERR_error_string(error, NULL));
                }
                clean();
                break;
            }

            read_len += ret;


            char* headerend;
            if ((headerend = strnstr(rbuff, CRLF CRLF, read_len))) {
                headerend += strlen(CRLF CRLF);

                char method[20];
                char url[URLLIMIT] = {0};
                sscanf(rbuff, "%s%*[ ]%[^\r\n ]", method, url);

                fprintf(stdout, "([%s]:%d):%s %s\n",
                        ipAddr, ntohs(sa.sin6_port), method, url);

                char path[URLLIMIT];
                char hostname[DOMAINLIMIT];
                int port;

/*                if (url[0] == '/') {
                    strcpy(path, url);
                    strcpy(hostname, "localhost");
                    port = 8080;
                    break;
                } else */
                if (spliturl(url, hostname, path, &port)) {
                    fprintf(stderr, "wrong url format\n");
                    clean();
                    break;
                }
                
                char* headerbegin = strstr(rbuff, CRLF) + strlen(CRLF);
                sprintf(buff, "%s %s HTTP/1.1" CRLF "%.*s",
                        method, path, headerend - headerbegin, headerbegin);

                size_t headerlen = headerend - rbuff;
                if (headerlen != read_len) {       //除了头部还读取到了其他内容
                    read_len -= headerlen;
                    memmove(rbuff, headerend, read_len);
                } else {
                    read_len = 0;
                }


                try {
                    if (strcasecmp(method, "GET") == 0 || strcasecmp(method, "HEAD") == 0) {
                        host = host->gethost(host, hostname, port, efd, this);
                        host->Write(buff, strlen(buff));
                        status = start_s;
                    } else if (strcasecmp(method, "POST") == 0) {
                        char* lenpoint;
                        if ((lenpoint = strstr(buff, "Content-Length:")) == NULL) {
                            fprintf(stderr, "unsported post version\n");
                            clean();
                            break;
                        }
                        sscanf(lenpoint + 15, "%u", &expectlen);
                        expectlen -= read_len;

                        int writelen = strlen(buff);
                        memcpy(buff + writelen, rbuff, read_len);
                        writelen +=  read_len;
                        read_len = 0;
                        host = host->gethost(host, hostname, port, efd, this);
                        host->Write(buff, writelen);
                        status = post_s;

                    } else if (strcasecmp(method, "CONNECT") == 0) {
                        host = host->gethost(host, hostname, port, efd, this);
                        status = connect_s;

                    } else {
                        fprintf(stderr, "unknown method:%s\n", method);
                        clean();
                    }
                } catch (...) {
                    clean();
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
                            ipAddr, ntohs(sa.sin6_port), strerror(errno));
                } else if (error != SSL_ERROR_ZERO_RETURN) {
                    fprintf(stderr, "([%s]:%d): guest_s read:%s\n",
                            ipAddr, ntohs(sa.sin6_port), ERR_error_string(error, NULL));
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
                            ipAddr, ntohs(sa.sin6_port), strerror(errno));
                } else if (error != SSL_ERROR_ZERO_RETURN) {
                    fprintf(stderr, "([%s]:%d): guest_s read:%s\n",
                            ipAddr, ntohs(sa.sin6_port), ERR_error_string(error, NULL));
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
                            ipAddr, ntohs(sa.sin6_port), strerror(errno));
                    clean();
                    break;
                default:
                    fprintf(stderr, "([%s]:%d):ssl_accept error:%s\n",
                            ipAddr, ntohs(sa.sin6_port), ERR_error_string(error, NULL));
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
                            ipAddr, ntohs(sa.sin6_port), strerror(errno));
                } else if (error != SSL_ERROR_ZERO_RETURN) {
                    fprintf(stderr, "([%s]:%d): guest_s write:%s\n",
                            ipAddr, ntohs(sa.sin6_port), ERR_error_string(error, NULL));
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
                            ipAddr, ntohs(sa.sin6_port), strerror(errno));
                } else if (error != SSL_ERROR_ZERO_RETURN) {
                    fprintf(stderr, "([%s]:%d): guest_s write:%s\n",
                            ipAddr, ntohs(sa.sin6_port), ERR_error_string(error, NULL));
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
                    ipAddr, ntohs(sa.sin6_port),strerror(error));
        }
        clean();
    }
}

Proxy::Proxy(int efd, Guest* guest) throw(int): Host(efd, guest, SPORT, SHOST), ssl(NULL), ctx(NULL)
{
}

Host* Proxy::getproxy(Host* exist, int efd, Guest* guest)throw(int)
{
    if (exist == NULL) {
        return new Proxy(efd, guest);
    } else if (dynamic_cast<Proxy*>(exist)) {
        return exist;
    } else {
        Proxy* newproxy = new Proxy(efd, guest);
        exist->disconnect();
        return newproxy;
    }
}

int Proxy::Write()
{
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

int Proxy::Read(char* buff, size_t size)
{
    return SSL_read(ssl, buff, size);
}


void Proxy::connected()
{
    epoll_event event;
    event.data.ptr = this;
    status = connect_s;
    if (write_len) {
        int ret = Write();
        if (ret <= 0) {
            guest->cleanhost();
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

void Proxy::handleEvent(uint32_t events)
{
    struct epoll_event event;
    event.data.ptr = this;

    if (guest == NULL) {
        delete this;
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
                    guest->cleanhost();
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
                }
                if (error != SSL_ERROR_ZERO_RETURN) {
                    fprintf(stderr, "proxy read:%s\n", ERR_error_string(error, NULL));
                }
                guest->cleanhost();
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
        int error = 0;
        socklen_t len = sizeof(int);
        switch (status) {
        case start_s:
            if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &len)) {
                perror("getsokopt");
                guest->cleanhost();
                return;
            }
            if (error != 0) {
                fprintf(stderr, "connect to proxy:%s\n", strerror(error));
                guest->cleanhost();
                return;
            }
            ctx = SSL_CTX_new(SSLv23_client_method());
            if (ctx == NULL) {
                ERR_print_errors_fp(stderr);
                guest->cleanhost();
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
                    guest->cleanhost();
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
                }
                if (error != SSL_ERROR_ZERO_RETURN) {
                    fprintf(stderr, "proxy write:%s\n", ERR_error_string(error, NULL));
                }
                guest->cleanhost();
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
        guest->cleanhost();
    }
}



Proxy::~Proxy()
{
    if (ssl) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
    }
    if (ctx) {
        SSL_CTX_free(ctx);
    }
}

