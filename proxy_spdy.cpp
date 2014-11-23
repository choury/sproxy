#include <errno.h>
#include "proxy_spdy.h"
#include "spdy_type.h"
#include "spdy_zlib.h"

Proxy_spdy *proxy_spdy= nullptr;

Proxy_spdy::Proxy_spdy(Proxy *copy,Guest *guest):Proxy(copy) {
    spdy_inflate_init(&instream);
    spdy_deflate_init(&destream);
    
    HttpReqHeader *req=this->req;
    this->req=nullptr;
    Request(req,guest);
    guest->connected("PROXY");
}

void Proxy_spdy::clean(Peer *who)
{
    if(who==this) {
        if(proxy_spdy == this) {
            proxy_spdy = nullptr;
        }
        struct epoll_event event;
        event.data.ptr = this;
        event.events = EPOLLOUT;
        epoll_ctl(efd, EPOLL_CTL_MOD, fd, &event);
        handleEvent=(void (Con::*)(uint32_t))&Proxy_spdy::closeHE;
        return;
    }
    if(guest2id.count(who)) {
        uint32_t id=guest2id[who];
        rst_frame rframe;
        rframe.id=id;
        rframe.code=0;
        Peer::Write(nullptr,&rframe,sizeof(rframe));
        
        guest2id.erase(who);
        id2guest.erase(id);
    }
}

void Proxy_spdy::Request(HttpReqHeader* req,Guest* guest)
{
    char buff[HEALLENLIMIT];
    spdy_cframe_head *chead=(spdy_cframe_head *)(wbuff+writelen);
    memset(chead,0,sizeof(*chead));
    writelen+=sizeof(*chead);
    chead->magic = CTRL_MAGIC;
    chead->type=htonl(SYN_TYPE);
    if(strcmp(req->method,"POST")) {
        chead->flag = FLAG_FIN;
    }
    
    
    syn_frame *sframe=(syn_frame *)(wbuff+writelen);
    writelen+=sizeof(*sframe);
    memset(sframe,0,sizeof(*sframe));
    sframe->id=curid;
    
    int len=req->getstring(buff,SPDY);
    len=spdy_deflate(&destream,buff,len,wbuff+writelen,bufleft());
    writelen+=len;
    set24(chead->length,sizeof(syn_frame)+len);
    
    
    Peer::Write(guest,"",0);
    guest2id[guest]=curid;
    id2guest[curid]=guest;
    curid+=2;
    if(this->req){
        delete this->req;
    }
    this->req=req;
}


Host* Proxy_spdy::getproxy_spdy(HttpReqHeader* req,Guest* guest) {
    Host *exist=(Host *)bindex.query(guest);
    if(exist && exist != proxy_spdy) {
        exist->clean(guest);
    }
    proxy_spdy->Request(req,guest);
    guest->connected("PROXY");
    return proxy_spdy;
}


void Proxy_spdy::defaultHE(uint32_t events) {
    struct epoll_event event;
    event.data.ptr = this;
    if (events & EPOLLIN ) {
        int ret = Read(rbuff, sizeof(rbuff));
        if (ret <= 0) {
            if(showerrinfo(ret,"proxy_spdy write error")) {
                clean(this);
            }
            return;
        }
        readlen+=ret;
//        readlen=FrameProc(rbuff,readlen);
    }
    if (events & EPOLLOUT) {
        if (writelen) {
            int ret = Proxy::Write();
            if (ret <= 0) {
                if(showerrinfo(ret,"proxy_spdy write error")) {
                    clean(this);
                }
                return;
            }
        }

        if (writelen == 0) {
            event.events = EPOLLIN;
            epoll_ctl(efd, EPOLL_CTL_MOD, fd, &event);
        }

    }

    if (events & EPOLLERR || events & EPOLLHUP) {
        LOGE("host unkown error: %s\n",strerror(errno));
        clean(this);
    }
}
