#include <sys/epoll.h>
#include <openssl/err.h>

#include "proxy.h"
#include "guest.h"



Proxy::Proxy(int efd,Guest *guest):Host(efd,guest,SHOST,SPORT) {}


Host* Proxy::getproxy(Host* exist, int efd, Guest* guest) {
    if (exist == NULL) {
        return new Proxy(efd, guest);
    } else if (dynamic_cast<Proxy*>(exist)) {
        return exist;
    } else {
        Proxy* newproxy = new Proxy(efd, guest);
        exist->clean();
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
            clean();
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

    if( status == close_s)
        return;

    if( guest == NULL) {
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
                    clean();
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
                LOGE( "The guest's write buff is full\n");
                epoll_ctl(efd, EPOLL_CTL_DEL, fd, NULL);
            }

            char buff[1024 * 1024];
            ret = Read(buff, bufleft);

            if (ret <= 0) {
                int error = SSL_get_error(ssl, ret);

                if (error == SSL_ERROR_WANT_READ) {
                    break;
                } else if (error == SSL_ERROR_SYSCALL) {
                    LOGE( "proxy read:%s\n", strerror(errno));
                } else if (error != SSL_ERROR_ZERO_RETURN) {
                    LOGE( "proxy read:%s\n", ERR_error_string(error, NULL));
                }

                clean();
                return;
            }

            guest->Write(buff, ret);
            break;

        default:
            break;
        }

    }

    if (events & EPOLLOUT) {
        int ret,error;
        socklen_t len=sizeof(error);
        switch (status) {
        case start_s:
            if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &len)) {
                perror("proxy getsokopt");
                clean();
                return;
            }

            if (error != 0) {
                LOGE( "connect to proxy:%s\n", strerror(error));
                if(reconnect()<0) {
                    clean();
                }
                return;
            }
            ctx = SSL_CTX_new(SSLv23_client_method());

            if (ctx == NULL) {
                ERR_print_errors_fp(stderr);
                clean();
                return;
            }
            SSL_CTX_set_options(ctx,SSL_OP_NO_SSLv2|SSL_OP_NO_SSLv3); //去除支持SSLv2 SSLv3
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
                    clean();
                    return;
                }

                status = wait_s;
                epoll_ctl(efd, EPOLL_CTL_MOD, fd, &event);
                break;
            }

            connected();
            break;

        case connect_s:
            if(write_len) {
                ret = Write();

                if (ret <= 0) {
                    int error = SSL_get_error(ssl, ret);

                    if (error == SSL_ERROR_WANT_WRITE) {
                        break;
                    } else if (error == SSL_ERROR_SYSCALL) {
                        LOGE( "proxy write:%s\n", strerror(errno));
                    } else if (error != SSL_ERROR_ZERO_RETURN) {
                        LOGE( "proxy write:%s\n", ERR_error_string(error, NULL));
                    }

                    clean();
                    return;
                }

                if (fulled) {
                    guest->peercanwrite();
                    fulled = false;
                }
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
        LOGE("proxy unkown error: %s\n",strerror(errno));
        clean();
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
