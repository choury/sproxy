#include <errno.h>
#include "proxy_spdy.h"
#include "spdy_type.h"
#include "spdy_zlib.h"

Proxy_spdy *proxy_spdy= nullptr;

Proxy_spdy::Proxy_spdy(Proxy *copy,Guest *guest):Proxy(copy) {
    bindex.add(this,guest);
    
    Request(req,guest);
    guest->connected();
}

ssize_t Proxy_spdy::Read(void* buff, size_t size){
    return Proxy::Read(buff, size);
}


void Proxy_spdy::clean(Peer *who)
{
    if(who==this) {
        if(proxy_spdy == this) {
            proxy_spdy = nullptr;
        }
        
        for(auto i:id2guest){
            i.second->clean(this);
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
        memset(&rframe,0,sizeof(rframe));
        rframe.head.magic=CTRL_MAGIC;
        rframe.head.type=htons(RST_TYPE);
        set24(rframe.head.length,8);
        rframe.id=htonl(id);
        Peer::Write(nullptr,&rframe,sizeof(rframe));
        
        guest2id.erase(who);
        id2guest.erase(id);
    }
}

void Proxy_spdy::Request(HttpReqHeader &req,Guest* guest)
{
    writelen+=req.getframe(wbuff+writelen,&destream,curid);
    
    struct epoll_event event;
    event.data.ptr = this;
    event.events = EPOLLIN | EPOLLOUT;
    epoll_ctl(efd, EPOLL_CTL_MOD, fd, &event);
    
    guest2id[guest]=curid;
    id2guest[curid]=guest;
    curid+=2;
    this->req=req;
}


Host* Proxy_spdy::getproxy_spdy(HttpReqHeader &req,Guest* guest) {
    Host *exist=(Host *)bindex.query(guest);
    if(exist && exist != proxy_spdy) {
        exist->clean(guest);
    }
    proxy_spdy->Request(req,guest);
    guest->connected();
    bindex.add(proxy_spdy,guest);
    return proxy_spdy;
}

void Proxy_spdy::defaultHE(uint32_t events) {
    struct epoll_event event;
    event.data.ptr = this;
    if (events & EPOLLIN ) {
        (this->*Spdy_Proc)();
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


void Proxy_spdy::ErrProc(int errcode,uint32_t id){
    if(errcode<=0 && showerrinfo(errcode,"proxy_spdy read error")){
        clean(this);
        return;
    }
    if(errcode>0){
        LOGE("proxy_spdy get a error code:%d,and id:%u\n",errcode,id);
        clean(this);
        return;
    }
}


void Proxy_spdy::CFrameProc(syn_reply_frame* sframe){
    HttpResHeader res(sframe,&instream);
    res.add("Transfer-Encoding","chunked");
    
    
    NTOHL(sframe->id);
    if(id2guest.count(sframe->id)==0){
        return;
    }
    Guest *guest=(Guest *)id2guest[sframe->id];
    char buff[HEADLENLIMIT];
    guest->Write(this,buff,res.getstring(buff));
}

void Proxy_spdy::CFrameProc(goaway_frame*){
    clean(this);
}



ssize_t Proxy_spdy::DFrameProc(uint32_t id,size_t size){
    if(id2guest.count(id)==0){
        return -1;
    }
    Guest *guest=(Guest *)id2guest[id];
    char buff[HEADLENLIMIT];
    size_t len=Min(size,sizeof(buff));
    ssize_t readlen=size;
    if(readlen){
        readlen=Read(buff,len);
        if(readlen <= 0){
            ErrProc(readlen,id);
            return 0;
        }
    }
    char chunkbuf[20];
    int chunklen;
    sprintf(chunkbuf,"%lx" CRLF "%n",readlen,&chunklen);
    guest->Write(this,chunkbuf,chunklen);
    guest->Write(this,buff,readlen);
    guest->Write(this,CRLF,strlen(CRLF));
    if(size==0){
        id2guest.erase(id);
        guest2id.erase(guest);
        guest->clean(this);
    }
    return readlen;
}

