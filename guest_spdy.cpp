#include "guest_spdy.h"
#include "parse.h"
#include "spdy_type.h"

Guest_spdy::Guest_spdy(Guest_s* copy):Guest_s(copy) {
    handleEvent=(void (Con::*)(uint32_t))&Guest_spdy::defaultHE;

}

Guest_spdy::~Guest_spdy() {

}


size_t Guest_spdy::bufleft() {
    size_t realleft= Peer::bufleft();
    if(realleft <= HEADLENLIMIT)
        return 0;
    return realleft-HEADLENLIMIT;
}

void Guest_spdy::clean(Peer* who) {
    bindex.del(this,who);

    if(who==this) {
        for(auto i:id2host) {
            i.second->clean(this);
        }

        id2host.clear();
        struct epoll_event event;
        event.data.ptr = this;
        event.events = EPOLLOUT;
        if(epoll_ctl(efd, EPOLL_CTL_MOD, fd, &event) && errno == ENOENT) {
            epoll_ctl(efd, EPOLL_CTL_ADD, fd, &event);
        }
        handleEvent=(void (Con::*)(uint32_t))&Guest_spdy::closeHE;
        return;
    }

    Host_spdy *host = dynamic_cast<Host_spdy *>(who);
    if(id2host.count(host->id)) {
        Reset(host->id,0);
        id2host.erase(host->id);

    }
}


void Guest_spdy::Reset(uint32_t id,uint32_t errcode) {
    rst_frame rframe;
    memset(&rframe,0,sizeof(rframe));
    rframe.head.magic=CTRL_MAGIC;
    rframe.head.type=htons(RST_TYPE);
    set24(rframe.head.length,8);
    rframe.code=htonl(errcode);
    rframe.id=htonl(id);
    Peer::Write(this,&rframe,sizeof(rframe));
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

    (this->*Spdy_Proc)();
    if(writelen) {
        int ret = Guest_s::Write();
        if (ret <= 0 ) {
            if( showerrinfo(ret,"guest_spdy write error")) {
                clean(this);
            }
            return;
        }
        for(auto i:id2host) {
            i.second->writedcb();
        }
    }
    
    if (writelen == 0) {
        event.events = EPOLLIN;
        epoll_ctl(efd, EPOLL_CTL_MOD, fd, &event);
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
    try {
        HttpReqHeader req(sframe,&instream);
//        req.port=80;

        LOG( "([%s]:%d)[%u]: %s %s\n",sourceip, sourceport,sframe->id,req.method,req.url);

        if ( req.ismethod("GET") ||  req.ismethod("POST") || req.ismethod("CONNECT") ) {
            bindex.del(this);
            id2host[sframe->id]=new Host_spdy(sframe->id,req,this);
        } else {
            LOGE( "([%s]:%d): unsported method:%s\n",sourceip, sourceport,req.method);
            Reset(sframe->id,PROTOCOL_ERROR);
        }
    } catch(...) {
        clean(this);
        return;
    }
}



void Guest_spdy::CFrameProc(rst_frame* rframe) {
    NTOHL(rframe->id);
    NTOHL(rframe->code);
    if(id2host.count(rframe->id)) {
        Host_spdy *host=id2host[rframe->id];
        host->clean(this);
        id2host.erase(rframe->id);
    }
}


void Guest_spdy::CFrameProc(ping_frame* pframe) {
    Guest::Write(this,pframe,sizeof(ping_frame));
}


void Guest_spdy::CFrameProc(goaway_frame* gframe) {
    NTOHL(gframe->id);
    NTOHL(gframe->code);
    LOG("([%s]:%d): The peer goaway %u:%u\n",sourceip, sourceport,
        gframe->id,gframe->code);
    clean(this);
}


ssize_t Guest_spdy::DFrameProc(void* buff, size_t size, uint32_t id) {
    if(id2host.count(id)) {
        Host_spdy *host=id2host[id];
        return host->Write(this,buff,size);
    }
    return -1;
}

Host_spdy::Host_spdy(uint32_t id, HttpReqHeader& req, Guest* guest):
    Host(req, guest,req.ismethod("CONNECT")?ALWAYS:HTTPHEAD),id(id) {
    writelen= req.getstring(wbuff);
}


void Host_spdy::waitconnectHE(uint32_t events) {
    Guest_spdy *guest=dynamic_cast<Guest_spdy *>(bindex.query(this));
    if( guest == NULL) {
        clean(this);
        return;
    }
    if (events & EPOLLOUT) {
        int error;
        socklen_t len=sizeof(error);
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &len)) {
            LOGE("getsokopt error: %s\n",strerror(error));
            clean(this);
            return;
        }
        if (error != 0) {
            LOGE("connect to %s: %s\n",this->hostname, strerror(error));
            if(connect()<0) {
                clean(this);
            }
            return;
        }

        struct epoll_event event;
        event.data.ptr = this;
        event.events = EPOLLIN | EPOLLOUT;
        epoll_ctl(efd, EPOLL_CTL_MOD, fd, &event);

        if(req.ismethod("CONNECT")) {
            HttpResHeader res(connecttip);
            guest->Response(res,id);
        }
        handleEvent=(void (Con::*)(uint32_t))&Host_spdy::defaultHE;
    }
    if (events & EPOLLERR || events & EPOLLHUP) {
        LOGE("connect to %s: %s\n",this->hostname, strerror(errno));
        if(connect()<0) {
            clean(this);
        }
    }
}


void Host_spdy::ResProc(HttpResHeader& res) {
    Guest_spdy *guest=dynamic_cast<Guest_spdy *>(bindex.query(this));
    if( guest == NULL) {
        clean(this);
        return;
    }

    res.del("Connection");
    res.del("Keep-Alive");
    res.del("Transfer-Encoding");
    guest->Response(res,id);
}


ssize_t Host_spdy::DataProc(const void* buff, size_t size) {
    Guest *guest=dynamic_cast<Guest *>(bindex.query(this));
    if( guest == NULL) {
        clean(this);
        return -1;
    }

    if(guest->bufleft()<size) {
        LOGE( "The guest's write buff is full\n");
        epoll_ctl(efd, EPOLL_CTL_DEL, fd, NULL);
        return -1;
    }

    spdy_dframe_head dhead;
    memset(&dhead,0,sizeof(dhead));
    dhead.id=htonl(id);
    set24(dhead.length,size);
    if(size) {
        guest->Write(this,&dhead,sizeof(dhead));
        return guest->Write(this,buff,size);
    } else {
        dhead.flag=FLAG_FIN;
        guest->Write(this,&dhead,sizeof(dhead));
        guest->clean(this);
        clean(this);
        return 0;
    }
}

