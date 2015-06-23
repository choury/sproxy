#include "guest_s.h"
#include "host.h"
#include "host2.h"
#include "file.h"
#include "cgi.h"

#include <openssl/err.h>

Guest_s::Guest_s(int fd, struct sockaddr_in6 *myaddr, SSL* ssl): Guest(fd, myaddr), ssl(ssl) {
    struct epoll_event event;
    event.data.ptr = this;
    event.events = EPOLLIN | EPOLLOUT;
    epoll_ctl(efd, EPOLL_CTL_MOD, fd, &event);

    handleEvent = (void (Con::*)(uint32_t))&Guest_s::shakehandHE;
}

Guest_s::~Guest_s() {
    if (ssl) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
    }
}

ssize_t Guest_s::Read(void* buff, size_t size) {
    return SSL_read(ssl, buff, size);
}

ssize_t Guest_s::Write(const void* buff, size_t size) {
    return Peer::Write(this, buff, size);
}


ssize_t Guest_s::Write(Peer* who, const void* buff, size_t size) {
    if(handleEvent == &Guest_s::defaultHE_h2) {
        Http2_header header;
        memset(&header, 0, sizeof(header));
        if(idmap.left.count(who)){
            set32(header.id, idmap.left.find(who)->second);
        }else{
            who->clean(this);
            return -1;
        }
        set24(header.length, size);
        if(size == 0) {
            header.flags = END_STREAM_F;
        }
        header.type = 0;
        Peer::Write(who, &header, sizeof(header));
    }
    return Peer::Write(who, buff, size);
}


ssize_t Guest_s::Write() {
    ssize_t ret = SSL_write(ssl, wbuff, writelen);

    if (ret <= 0) {
        return ret;
    }

    if ((size_t)ret != writelen) {
        memmove(wbuff, wbuff + ret, writelen - ret);
        writelen -= ret;
    } else {
        writelen = 0;
    }

    return ret;
}



void Guest_s::shakedhand() {
    epoll_event event;
    event.data.ptr = this;
    event.events = EPOLLIN;
    epoll_ctl(efd, EPOLL_CTL_MOD, fd, &event);
    handleEvent = (void (Con::*)(uint32_t))&Guest_s::defaultHE;

    const unsigned char *data;
    unsigned int len;
    SSL_get0_alpn_selected(ssl, &data, &len);
    if (data) {
        if (strncasecmp((const char*)data, "h2", len) == 0) {
            handleEvent = (void (Con::*)(uint32_t))&Guest_s::defaultHE_h2;
            return;
        }
    }
}


void Guest_s::defaultHE_h2(uint32_t events)
{
    if (events & EPOLLERR || events & EPOLLHUP) {
        int       error = 0;
        socklen_t errlen = sizeof(error);

        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, (void*)&error, &errlen) == 0) {
            LOGE("([%s]:%d): guest_s error:%s\n",
                  sourceip, sourceport, strerror(error));
        }
        clean(this);
        return;
    }
    
    if (events & EPOLLIN) {
        (this->*Http2_Proc)();
    }

    if (events & EPOLLOUT) {
        if (writelen) {
            int ret = Write();
            if (ret <= 0) {
                if (showerrinfo(ret, "guest_s write error")) {
                    clean(this);
                }
                return;
            }
        }

        if (writelen == 0) {
            struct epoll_event event;
            event.data.ptr = this;
            event.events = EPOLLIN;
            epoll_ctl(efd, EPOLL_CTL_MOD, fd, &event);
        }
    }
}


int Guest_s::showerrinfo(int ret, const char* s) {
    epoll_event event;
    event.data.ptr = this;
    int error = SSL_get_error(ssl, ret);
    ERR_clear_error();
    switch (error) {
    case SSL_ERROR_WANT_READ:
        return 0;
    case SSL_ERROR_WANT_WRITE:
        event.events = EPOLLIN|EPOLLOUT;
        epoll_ctl(efd, EPOLL_CTL_MOD, fd, &event);
        return 0;
    case SSL_ERROR_ZERO_RETURN:
        break;
    case SSL_ERROR_SYSCALL:
        LOGE("([%s]:%d): %s:%s\n",
              sourceip, sourceport, s, strerror(errno));
        break;
    default:
        LOGE("([%s]:%d): %s:%s\n",
              sourceip, sourceport, s, ERR_error_string(error, NULL));
    }
    return 1;
}



void Guest_s::shakehandHE(uint32_t events) {
    if ((events & EPOLLIN)|| (events & EPOLLOUT)) {
        int ret = SSL_do_handshake(ssl);
        if (ret != 1) {
            if (showerrinfo(ret, "ssl accept error")) {
                clean(this);
            }
        } else {
            shakedhand();
        }
    }

    if (events & EPOLLERR || events & EPOLLHUP) {
        int       error = 0;
        socklen_t errlen = sizeof(error);

        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, (void*)&error, &errlen) == 0) {
            LOGE("([%s]:%d): guest_s error:%s\n",
                  sourceip, sourceport, strerror(error));
        }
        clean(this);
    }
}

void Guest_s::ErrProc(int errcode) {
    Guest::ErrProc(errcode);
}


void Guest_s::ReqProc(HttpReqHeader& req) {
    if(req.id){
        LOG("([%s]:%d):[%d] %s %s\n", sourceip, sourceport, req.id, req.method, req.url);
        if(strcmp(req.hostname, getenv("HOSTNAME"))){
            idmap.insert(decltype(idmap)::value_type(new Host2(req, this), req.id));
        }else {
            if(req.parse()){
                LOG("([%s]:%d):[%d] parse url failed\n", sourceip, sourceport, req.id);
                throw 0;
            }
            idmap.insert(decltype(idmap)::value_type(new File(req, this), req.id));
        }
        return;
    } else {
        LOG("([%s]:%d): %s %s\n", sourceip, sourceport, req.method, req.url);
        if (req.url[0] == '/') {
            if(req.parse()){
                LOG("([%s]:%d): parse url failed\n", sourceip, sourceport);
                throw 0;
            }
            if (strcmp(req.extname,".so") == 0) {
                Cgi::getcgi(req, this);
            } else {
                File::getfile(req,this);
            }
        } else {
            Host::gethost(req, this);
        }
    }
}

void Guest_s::RstProc(Http2_header* header) {
    uint id = get32(header->id);
    uint error_code = get32(header+1);
    LOGE("([%s]:%d): reset stream [%d]: %d\n", sourceip, sourceport, id, error_code);
    
    if(idmap.right.count(id)){
        idmap.right.find(id)->second->clean(this);
        idmap.right.erase(id);
    }
}


void Guest_s::GoawayProc(Http2_header* header) {
    clean(this);
}


ssize_t Guest_s::DataProc(Http2_header* header) {
    return get24(header->length);
}


void Guest_s::Response(Peer *who, HttpResHeader& res){
    if(handleEvent == &Guest_s::defaultHE_h2) {
        if(idmap.left.count(who)){
            res.id = idmap.left.find(who)->second;
        }else{
            who->clean(this);
            return;
        }
        res.del("Transfer-Encoding");
        res.del("Connection");
        writelen+=res.getframe(wbuff+writelen, &index_table);
        struct epoll_event event;
        event.data.ptr = this;
        event.events = EPOLLIN | EPOLLOUT;
        epoll_ctl(efd, EPOLL_CTL_MOD, fd, &event);
    }else{
        Guest::Response(who, res);
    }
}

void Guest_s::clean(Peer* who) {
    if(handleEvent == &Guest_s::defaultHE_h2) {
        if(who == this) {
            Peer::clean(who);
        }else{
            idmap.left.erase(who);
        }
    }else {
        Peer::clean(who);
    }
}


