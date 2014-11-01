#include <errno.h>
#include <sys/epoll.h>
#include <openssl/err.h>

#include "net.h"
#include "guest_s.h"
#include "host.h"
#include "parse.h"



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

void Guest_s::shakedhand() {
    const unsigned char *data;
    unsigned int len;
    SSL_get0_next_proto_negotiated(ssl,&data,&len);
    if(data) {
        if(strncasecmp((const char*)data,"spdy/3.1",len)==0) {
            protocol=spdy3_1;
        } else {
            LOGE( "([%s]:%d): unknown protocol:%.*s\n",sourceip, sourceport,len,data);
            clean();
            return;
        }
    }

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
    unsigned int len;

    if (events & EPOLLIN) {
        char buff[1024 * 1024];

        if(status != accept_s) {
            len=sizecanread();
            if(len<0) {
                LOGE("([%s]:%d):connecting to host lost\n",sourceip, sourceport);
                clean();
                return;
            } else if(len == 0) {
                LOGE( "([%s]:%d): The buff is full\n",sourceip, sourceport);
                epoll_ctl(efd, EPOLL_CTL_DEL, fd, NULL);
                return;
            }
            ret=Read(buff, len);
            if (ret <= 0) {
                int error = SSL_get_error(ssl, ret);
                switch(error){
                case SSL_ERROR_WANT_READ:
                    return;
                case SSL_ERROR_ZERO_RETURN:
                    break;
                case SSL_ERROR_SYSCALL:
                    LOGE( "([%s]:%d): guest_s read:%s\n",
                          sourceip, sourceport, strerror(errno));
                    break;
                default:
                    LOGE( "([%s]:%d): guest_s read:%s\n",
                          sourceip, sourceport, ERR_error_string(error, NULL));
                    break;
                }

                clean();
                return;
            }
        }

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
                    LOGE( "([%s]:%d): ssl_accept error:%s\n",
                          sourceip, sourceport, strerror(errno));
                    clean();
                    return;

                default:
                    LOGE( "([%s]:%d):ssl_accept error:%s\n",
                          sourceip, sourceport, ERR_error_string(error, NULL));
                    clean();
                    return;
                }

                break;
            }

            shakedhand();
            break;

        case start_s:
            memcpy(rbuff+write_len,buff,ret);
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

                    LOG("([%s]:%d): %s %s\n",
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
                        host = Host::gethost(host, http.hostname, http.port, efd, this);
                        host->Write(buff, writelen);
                        status = start_s;
                    } else if (http.ismethod("POST") ) {

                        char* lenpoint;
                        if ((lenpoint = strstr(buff, "Content-Length:")) == NULL) {
                            LOGE( "([%s]:%d): unsported post version\n", sourceip, sourceport);
                            clean();
                            return;
                        }

                        sscanf(lenpoint + 15, "%u", &expectlen);
                        expectlen -= read_len;

                        host = Host::gethost(host, http.hostname, http.port, efd, this);
                        host->Write(buff, writelen);
                        host->Write(rbuff, read_len);
                        read_len = 0;
                        status = post_s;

                    } else if (http.ismethod("CONNECT")) {
                        host = Host::gethost(host, http.hostname, http.port, efd, this);
                        status = connect_s;

                    } else {
                        LOGE( "([%s]:%d): unknown method:%s\n",
                              sourceip, sourceport, http.method);
                        clean();
                        return;
                    }
                } catch(...) {
                    clean();
                    return;
                }
            }

            break;

        case post_s:
            expectlen -= ret;
            host->Write(buff, ret);

            if (expectlen == 0) {
                status = start_s;
            }

            break;

        case connect_s:
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
                    LOGE( "([%s]:%d): ssl_accept error:%s\n",
                          sourceip, sourceport, strerror(errno));
                    clean();
                    return;

                default:
                    LOGE( "([%s]:%d):ssl_accept error:%s\n",
                          sourceip, sourceport, ERR_error_string(error, NULL));
                    clean();
                    return;
                }

                break;
            }

            shakedhand();
            break;

        case close_s:
            if(write_len == 0) {
                delete this;
                return;
            }
            ret = Write();

            if (ret <= 0) {
                int error = SSL_get_error(ssl, ret);

                if (error == SSL_ERROR_WANT_WRITE) {
                    break;
                } else if (error == SSL_ERROR_SYSCALL) {
                    LOGE( "([%s]:%d): guest_s write:%s\n",
                          sourceip, sourceport, strerror(errno));
                } else if (error != SSL_ERROR_ZERO_RETURN) {
                    LOGE( "([%s]:%d): guest_s write:%s\n",
                          sourceip, sourceport, ERR_error_string(error, NULL));
                }

                write_len = 0;
                return;
            }

            break;

        default:
            if(write_len) {
                ret = Write();

                if (ret <= 0) {
                    int error = SSL_get_error(ssl, ret);

                    if (error == SSL_ERROR_WANT_WRITE) {
                        break;
                    } else if (error == SSL_ERROR_SYSCALL) {
                        LOGE( "([%s]:%d): guest_s write:%s\n",
                              sourceip, sourceport, strerror(errno));
                    } else if (error != SSL_ERROR_ZERO_RETURN) {
                        LOGE( "([%s]:%d): guest_s write:%s\n",
                              sourceip, sourceport, ERR_error_string(error, NULL));
                    }

                    write_len = 0;
                    clean();
                    return;
                }

                if (host)
                    host->writedcb();
            }

            if (write_len == 0) {
                event.events = EPOLLIN;
                epoll_ctl(efd, EPOLL_CTL_MOD, fd, &event);
            }

        }
    }

    if (events & EPOLLERR || events & EPOLLHUP) {
        int       error = 0;
        socklen_t errlen = sizeof(error);

        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, (void*)&error, &errlen) == 0) {
            LOGE( "([%s]:%d): guest_s error:%s\n",
                  sourceip, sourceport, strerror(error));
        }

        write_len = 0;
        clean();
    }

}
