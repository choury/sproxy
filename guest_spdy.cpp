#include "guest_spdy.h"
#include "parse.h"
#include "spdy_type.h"

Guest_spdy::Guest_spdy(Guest_s* copy):Guest_s(copy) {
    handleEvent=(void (Con::*)(uint32_t))&Guest_spdy::defaultHE;

}

Guest_spdy::~Guest_spdy() {

}


void Guest_spdy::clean(Peer* who) {
    if(who==this) {
        for(auto i:host2id) {
            bindex.del(this,i.first);
            delete i.second;
        }
        host2id.clear();
        id2host.clear();

        struct epoll_event event;
        event.data.ptr = this;
        event.events = EPOLLOUT;
        epoll_ctl(efd, EPOLL_CTL_MOD, fd, &event);
        handleEvent=(void (Con::*)(uint32_t))&Guest_spdy::closeHE;
        return;
    }

    bindex.del(this,who);
    if(host2id.count(who)) {
        Hostinfo *hostinfo=host2id[who];
        if(id2host.count(hostinfo->id)) {
            rst_frame rframe;
            memset(&rframe,0,sizeof(rframe));
            rframe.head.magic=CTRL_MAGIC;
            rframe.head.type=htons(RST_TYPE);
            set24(rframe.head.length,8);
            rframe.code=0;
            rframe.id=htonl(hostinfo->id);
            Peer::Write(this,&rframe,sizeof(rframe));

            id2host.erase(hostinfo->id);
        }
        host2id.erase(who);
        delete hostinfo;
    }
}

void Guest_spdy::clean(Hostinfo* hostinfo) {
    id2host.erase(hostinfo->id);
}


void Guest_spdy::connected(void* who) {
    Host *host=(Host*)who;
    if(host->req.ismethod("CONNECT")) {
        if(host2id.count(host)) {
            char tmp[200];
            strcpy(tmp,connecttip);
            HttpResHeader res(tmp);
            writelen+=res.getframe(wbuff+writelen,&destream,host2id[host]->id);
        }
    }

    struct epoll_event event;
    event.data.ptr = this;
    event.events = EPOLLIN | EPOLLOUT;
    if(epoll_ctl(efd, EPOLL_CTL_MOD, fd, &event) && errno == ENOENT) {
        epoll_ctl(efd, EPOLL_CTL_ADD, fd, &event);
    }
}



ssize_t Guest_spdy::Write(Peer* who, const void* buff, size_t size) {
    if(who == this) {
        return Guest::Write(this,buff,size);
    }
    if(host2id.count(who)) {
        Hostinfo *hostinfo=host2id[who];
        ssize_t len=hostinfo->Write(buff,size);
        (hostinfo->*hostinfo->Http_Proc)();
        return len;
    } else {
        who->clean(this);
    }
    return 0;
}

ssize_t Guest_spdy::Read(void* buff, size_t size) {
    return Guest_s::Read(buff, size);
}


void Guest_spdy::ErrProc(int errcode,uint32_t id) {
    if(errcode<=0 && showerrinfo(errcode,"guest_spdy read error")) {
        clean(this);
        return;
    }
    if(errcode>0) {
        LOGE("([%s]:%d): guest_spdy get a error code:%d,and id:%u\n",
             sourceip,sourceport,errcode,id);
        clean(this);
        return;
    }
}


void Guest_spdy::defaultHE(uint32_t events) {
    struct epoll_event event;
    event.data.ptr = this;

    if (events & EPOLLIN ) {
        (this->*Spdy_Proc)();
    }
    if (events & EPOLLOUT) {
        if(writelen) {
            int ret = Guest_s::Write();
            if (ret <= 0 ) {
                if( showerrinfo(ret,"guest_spdy write error")) {
                    clean(this);
                }
                return;
            }
        }

        if(writelen==0) {
            event.events = EPOLLIN;
            epoll_ctl(efd, EPOLL_CTL_MOD, fd, &event);
        }
    }

    if (events & EPOLLERR || events & EPOLLHUP) {
        int       error = 0;
        socklen_t errlen = sizeof(error);

        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, (void*)&error, &errlen) == 0) {
            LOGE( "([%s]:%d): guest_spdy error:%s\n",
                  sourceip, sourceport, strerror(error));
        }
        clean(this);
    }
}

void Guest_spdy::Response(HttpResHeader& res, uint32_t id) {
    writelen+=res.getframe(wbuff+writelen,&destream,id);

    struct epoll_event event;
    event.data.ptr = this;
    event.events = EPOLLIN | EPOLLOUT;
    epoll_ctl(efd, EPOLL_CTL_MOD, fd, &event);
}


void Guest_spdy::CFrameProc(syn_frame* sframe) {
    NTOHL(sframe->id);
    HttpReqHeader req(sframe,&instream);
//    req.port=80;

    LOG( "([%s]:%d)[%u]: %s %s\n",sourceip, sourceport,sframe->id,req.method,req.url);

    if ( req.ismethod("GET") ||  req.ismethod("POST") || req.ismethod("CONNECT") ) {
        Host *host=Host::gethost(req,this);
        host2id[host]=new Hostinfo(sframe->id,this,host);
        id2host[sframe->id]=host;
    } else {
        LOGE( "([%s]:%d): unsported method:%s\n",sourceip, sourceport,req.method);
        rst_frame rframe;
        memset(&rframe,0,sizeof(rframe));
        rframe.head.magic=CTRL_MAGIC;
        rframe.head.type=htons(RST_TYPE);
        set24(rframe.head.length,8);
        rframe.code=htonl(PROTOCOL_ERROR);
        rframe.id=htonl(sframe->id);
        Peer::Write(this,&rframe,sizeof(rframe));
    }
}



void Guest_spdy::CFrameProc(rst_frame* rframe) {
    NTOHL(rframe->id);
    NTOHL(rframe->code);
    if(id2host.count(rframe->id)){
        Host *host=id2host[rframe->id];
        bindex.del(host,this);
        delete host2id[host];
        host2id.erase(host);
        id2host.erase(rframe->id);

    }
}


void Guest_spdy::CFrameProc(goaway_frame* gframe) {
    NTOHL(gframe->id);
    NTOHL(gframe->code);
    LOG("([%s]:%d): The peer goaway %u:%u\n",sourceip, sourceport,
        gframe->id,gframe->code);
    clean(this);
}


ssize_t Guest_spdy::DFrameProc(uint32_t id, size_t size) {
    if(id2host.count(id)) {
        Host *host=id2host[id];
        char buff[HEADLENLIMIT];
        size_t len=Min(size,sizeof(buff));
        len=Read(buff,len);
        if(len <= 0) {
            ErrProc(len,id);
            return 0;
        }
        return host->Write(this,buff,size);
    }
    return -1;
}


Hostinfo::Hostinfo() {

}


Hostinfo::Hostinfo(uint32_t id,Guest_spdy *guest,Host *host):id(id),guest(guest),host(host) {

}


Hostinfo::~Hostinfo() {

}



ssize_t Hostinfo::Write(const void* buff, size_t size) {
    size_t len=Min(size,sizeof(wbuff)-writelen);
    memcpy(wbuff+writelen,buff,len);
    writelen += len;
    return len;
}



ssize_t Hostinfo::Read(void* buff, size_t size) {
    size_t len=Min(size,writelen);
    memcpy(buff,wbuff,len);
    memmove(wbuff,wbuff+len,writelen-len);
    writelen -= len;
    return len;
}


void Hostinfo::ErrProc(int errcode) {
    return;
}

void Hostinfo::ResProc(HttpResHeader& res) {
    res.del("Connection");
    res.del("Keep-Alive");
    res.del("Transfer-Encoding");
    guest->Response(res,id);
}


ssize_t Hostinfo::DataProc(const void* buff, size_t size) {
    spdy_dframe_head dhead;
    memset(&dhead,0,sizeof(dhead));
    dhead.id=htonl(id);
    set24(dhead.length,size);
    if(size) {
        guest->Write(guest,&dhead,sizeof(dhead));
        return guest->Write(guest,buff,size);
    } else {
        dhead.flag=FLAG_FIN;
        guest->Write(guest,&dhead,sizeof(dhead));
        guest->clean(this);
        if(host)
            host->clean(guest);
        host=nullptr;
        return 0;
    }
}

