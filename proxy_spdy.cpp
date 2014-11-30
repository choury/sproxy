#include <errno.h>
#include "proxy_spdy.h"
#include "spdy_type.h"
#include "spdy_zlib.h"

Proxy_spdy *proxy_spdy= nullptr;

Proxy_spdy::Proxy_spdy(Proxy *copy,Guest *guest):Proxy(copy) {
    bindex.add(this,guest);
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
        rframe.id=id;
        rframe.code=0;
        Peer::Write(nullptr,&rframe,sizeof(rframe));
        
        guest2id.erase(who);
        id2guest.erase(id);
    }
}

void Proxy_spdy::Request(HttpReqHeader* req,Guest* guest)
{
    char buff[HEADLENLIMIT];
    spdy_cframe_head *chead=(spdy_cframe_head *)(wbuff+writelen);
    memset(chead,0,sizeof(*chead));
    writelen+=sizeof(*chead);
    chead->magic = CTRL_MAGIC;
    chead->type=htons(SYN_TYPE);
    if(strcmp(req->method,"POST")) {
        chead->flag = FLAG_FIN;
    }
    
    
    syn_frame *sframe=(syn_frame *)(wbuff+writelen);
    writelen+=sizeof(*sframe);
    memset(sframe,0,sizeof(*sframe));
    sframe->id=htonl(curid);
    sframe->priority=3;
    
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

void Proxy_spdy::ErrProc(uint32_t errcode){
    LOGE("Get a Err:%u\n",errcode);
}


Host* Proxy_spdy::getproxy_spdy(HttpReqHeader* req,Guest* guest) {
    Host *exist=(Host *)bindex.query(guest);
    if(exist && exist != proxy_spdy) {
        exist->clean(guest);
    }
    proxy_spdy->Request(req,guest);
    guest->connected("PROXY");
    bindex.add(proxy_spdy,guest);
    return proxy_spdy;
}


void Proxy_spdy::defaultHE(uint32_t events) {
    struct epoll_event event;
    event.data.ptr = this;
    if (events & EPOLLIN ) {
        readlen = Read(rbuff, sizeof(rbuff));
        if (readlen <= 0) {
            if(showerrinfo(readlen,"proxy_spdy write error")) {
                clean(this);
            }
            return;
        }
        (this->*Proc)(rbuff,readlen,(void (Spdy::*)(uint32_t))&Proxy_spdy::ErrProc);
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

void Proxy_spdy::FrameProc(syn_reply_frame* sframe){
    NTOHL(sframe->id);
    if(id2guest.count(sframe->id)==0){
        return;
    }
    Guest *guest=(Guest *)id2guest[sframe->id];
    char *p=(char *)(sframe+1);
    char buff[HEADLENLIMIT];
    spdy_inflate(&instream,p,spdy_getlen-sizeof(*sframe),buff,sizeof(buff));
    HttpResHeader res(buff);
    res.del("Content-Length");
    res.add("Transfer-Encoding","chunked");
    guest->Write(this,buff,res.getstring(buff,HTTP));
}

void Proxy_spdy::FrameProc(goaway_frame*){
    clean(this);
}



void Proxy_spdy::FrameProc(void* buff, size_t buflen){
    if(id2guest.count(stream_id)==0){
        return;
    }
    Guest *guest=(Guest *)id2guest[stream_id];
    char chunkbuf[20];
    int chunklen;
    sprintf(chunkbuf,"%lx" CRLF "%n",buflen,&chunklen);
    guest->Write(this,chunkbuf,chunklen);
    guest->Write(this,buff,buflen);
    guest->Write(this,CRLF,strlen(CRLF));
}

