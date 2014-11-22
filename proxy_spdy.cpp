#include <errno.h>
#include "proxy_spdy.h"
#include "spdy_type.h"
#include "spdy_zlib.h"

Proxy_spdy *proxy_spdy= nullptr;

Proxy_spdy::Proxy_spdy(Proxy *copy):Proxy(copy){
    spdy_inflate_init(&instream);
    spdy_deflate_init(&destream);
}

void Proxy_spdy::clean(Peer *who)
{
    if(who==this){
        if(proxy_spdy == this){
            proxy_spdy = nullptr;
        }
        struct epoll_event event;
        event.data.ptr = this;
        event.events = EPOLLOUT;
        epoll_ctl(efd, EPOLL_CTL_MOD, fd, &event);
        handleEvent=(void (Con::*)(uint32_t))&Proxy_spdy::closeHE;
        return;
    }
    if(guest2id.count(who)){
        uint32_t id=guest2id[who];
        rst_frame rframe;
        rframe.id=id;
        rframe.code=0;
        Peer::Write(nullptr,&rframe,sizeof(rframe));
    }
}

bool Proxy_spdy::openframe(Guest* guest, HttpReqHeader* http)
{
    char buff[HEALLENLIMIT];
    int len=http->getstring(buff,SPDY);
    spdy_cframe_head *chead=(spdy_cframe_head *)(wbuff+writelen);
    writelen+=sizeof(*chead);
    chead->magic = CTRL_MAGIC;
    chead->type=htonl(SYN_TYPE);
    chead->flag = FLAG_FIN;
    syn_frame *sframe=(syn_frame *)(wbuff+writelen);
    writelen+=sizeof(*sframe);
    memset(sframe,0,sizeof(*sframe));
    sframe->id=curid;
    len=spdy_deflate(&destream,buff,len,wbuff+writelen,bufleft());
    writelen+=len;
    set24(chead->length,sizeof(syn_frame)+len);
    Peer::Write(guest,"",0);
    guest2id[guest]=curid;
    curid+=2;
}


Host* Proxy_spdy::getproxy_spdy(Guest* guest, HttpReqHeader* http){
    Host *exist=(Host *)bindex.query(guest);
    if(exist != proxy_spdy){
        exist->clean(guest);
    }
    if(proxy_spdy->openframe(guest,http)==false)
        throw 0;
    return proxy_spdy;
}


void Proxy_spdy::defaultHE(uint32_t events){
    struct epoll_event event;
    event.data.ptr = this;
    if (events & EPOLLIN ) {
        char buff[1024];
        int ret = Read(buff, sizeof(buff));
        if(ret == 0){
            clean(this);
            return;
        }
    }
    if (events & EPOLLOUT) {
        if (writelen) {
            int ret = Proxy::Write();
            if (ret <= 0) {
                if(showerrinfo(ret,"host write error")) {
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
