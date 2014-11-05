#include <errno.h>
#include <sys/epoll.h>
#include <openssl/err.h>

#include "net.h"
#include "guest_s.h"
#include "host.h"
#include "parse.h"
#include "spdy.h"


Guest_s::Guest_s(int fd, int efd, SSL* ssl): Guest(fd, efd), ssl(ssl) {
    struct epoll_event event;
    event.data.ptr = this;
    event.events = EPOLLIN | EPOLLOUT;
    epoll_ctl(efd, EPOLL_CTL_MOD, fd, &event);

    handleEvent=(void (Con::*)(uint32_t))&Guest_s::shakehandHE;
}

Guest_s::~Guest_s() {
    SSL_shutdown(ssl);
    SSL_free(ssl);
}

int Guest_s::Read(void* buff, size_t size) {
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
    epoll_event event;
    event.data.ptr = this;
    event.events = EPOLLIN;
    epoll_ctl(efd, EPOLL_CTL_MOD, fd, &event);
    handleEvent=(void (Con::*)(uint32_t))&Guest::getheaderHE;

    if(data) {
        if(strncasecmp((const char*)data,"spdy/3.1",len)==0) {
            handleEvent=(void (Con::*)(uint32_t))&Guest_s::spdyHE;
        } else {
            LOGE( "([%s]:%d): unknown protocol:%.*s\n",sourceip, sourceport,len,data);
            clean();
            return;
        }
    }
}

int Guest_s::showerrinfo(int ret, const char* s) {
    epoll_event event;
    event.data.ptr = this;
    int error = SSL_get_error(ssl, ret);
    switch(error) {
    case SSL_ERROR_WANT_READ:
        event.events = EPOLLIN ;
        epoll_ctl(efd, EPOLL_CTL_MOD, fd, &event);
        return 0;
    case SSL_ERROR_WANT_WRITE:
        event.events = EPOLLOUT;
        epoll_ctl(efd, EPOLL_CTL_MOD, fd, &event);
        return 0;
    case SSL_ERROR_ZERO_RETURN:
        break;
    case SSL_ERROR_SYSCALL:
        LOGE( "([%s]:%d): %s:%s\n",
              sourceip, sourceport,s, strerror(errno));
        break;
    default:
        LOGE( "([%s]:%d): %s:%s\n",
              sourceip, sourceport,s, ERR_error_string(error, NULL));
    }
    return 1;
}



void Guest_s::shakehandHE(uint32_t events) {
    if ((events & EPOLLIN)|| (events & EPOLLOUT)) {
        int ret = SSL_accept(ssl);
        if (ret != 1) {
            if(showerrinfo(ret,"ssl accept error")) {
                clean();
            }
        } else {
            shakedhand();
        }
    }

    if (events & EPOLLERR || events & EPOLLHUP) {
        int       error = 0;
        socklen_t errlen = sizeof(error);

        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, (void*)&error, &errlen) == 0) {
            LOGE( "([%s]:%d): guest_s error:%s\n",
                  sourceip, sourceport, strerror(error));
        }
        clean();
    }
}


void Guest_s::spdyHE(uint32_t events) {
    if(events & EPOLLIN) {
        int len=sizeof(rbuff)-read_len;
        if(len == 0) {
            LOGE( "([%s]:%d): The header is too long\n",sourceip, sourceport);
            epoll_ctl(efd, EPOLL_CTL_DEL, fd, NULL);
            return;
        }
        int ret=Read(rbuff+read_len, len);
        if(ret<=0 ) {
            if(showerrinfo(ret,"spdy read error")) {
                clean();
            }
            return;
        }

        read_len+=ret;
    }
    if(read_len >= sizeof(spdy_head)) {
        spdy_head head;
        memcpy(&head,rbuff,sizeof(head));
        memmove(rbuff,rbuff+sizeof(head),read_len-sizeof(head));
        read_len-=sizeof(head);
        if(head.c==1) {
            spdy_cframe_head *chead=(spdy_cframe_head *)&head;
            NTOHS(chead->version);
            NTOHS(chead->type);
            expectlen=get24(chead->length);
            switch(chead->type) {
            case 1:
                handleEvent=(void (Con::*)(uint32_t))&Guest_s::spdysynHE;
                break;
            default:
                printf("get a spdy ctrl frame:%d\n",chead->type);
                handleEvent=(void (Con::*)(uint32_t))&Guest_s::spdyctrlframedefultHE;
                break;
            }
            if(read_len) {
                (this ->*handleEvent) (events&(~EPOLLIN));
            }
        } else {
            spdy_dframe_head *dhead=(spdy_dframe_head *)&head;
            NTOHL(dhead->id);
            char *buff=new char[get24(dhead->length)];
            Read(buff,get24(dhead->length));
            spdy_cframe_head rsthead;
            memset(&rsthead,0,sizeof(rsthead));
            rsthead.c=1;
            rsthead.version=htons(3);
            rsthead.type=htons(3);
//            rsthead.length=htonl(8);
            Peer::Write(&rsthead,sizeof(rsthead));

            rst_frame rstframe;
            memset(&rstframe,0,sizeof(rstframe));
            rstframe.code=htonl(INVALID_STREAM);
            rstframe.id=htonl(dhead->id);
            Peer::Write(&rstframe,sizeof(rstframe));

        }
    }
    Guest::defaultHE(events&(~EPOLLIN));
}

void Guest_s::spdysynHE(uint32_t events) {
    if(events & EPOLLIN) {
        int len=sizeof(rbuff)-read_len;
        if(len == 0) {
            LOGE( "([%s]:%d): The header is too long\n",sourceip, sourceport);
            epoll_ctl(efd, EPOLL_CTL_DEL, fd, NULL);
            return;
        }
        int ret=Read(rbuff+read_len, len);
        if(ret<=0 ) {
            if(showerrinfo(ret,"spdy syn read error")) {
                clean();
            }
            return;
        }

        read_len+=ret;
    }
    if(read_len >= expectlen) {
        syn_frame *sframe=(syn_frame*)rbuff;
        NTOHL(sframe->id);
        char headbuff[8192];
        spdy_inflate(rbuff+sizeof(syn_frame),expectlen-sizeof(syn_frame),headbuff,sizeof(headbuff));
        Http http(headbuff,SPDY);
        printf("%.*s",http.getstring(headbuff),headbuff);
        
    }
}



void Guest_s::spdyctrlframedefultHE(uint32_t events) {
    if(events & EPOLLIN) {
        int len=sizeof(rbuff)-read_len;
        if(len == 0) {
            LOGE( "([%s]:%d): The header is too long\n",sourceip, sourceport);
            epoll_ctl(efd, EPOLL_CTL_DEL, fd, NULL);
            return;
        }
        int ret=Read(rbuff+read_len, len);
        if(ret<=0 ) {
            if(showerrinfo(ret,"spdy syn read error")) {
                clean();
            }
            return;
        }

        read_len+=ret;
    }

    if(read_len >= expectlen) {
        memmove(rbuff,rbuff+expectlen,expectlen);
        read_len-=expectlen;
        expectlen=0;
        handleEvent=(void (Con::*)(uint32_t))&Guest_s::spdyHE;
        if(read_len) {
            (this ->*handleEvent) (events&(~EPOLLIN));
        }
    }
}


