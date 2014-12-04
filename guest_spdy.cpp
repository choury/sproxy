#include "guest_spdy.h"
#include "host.h"
#include "parse.h"
#include "spdy_type.h"
#include "spdy_zlib.h"

Guest_spdy::Guest_spdy(Guest_s* copy):Guest_s(copy) {
    handleEvent=(void (Con::*)(uint32_t))&Guest_spdy::defaultHE;

}

Guest_spdy::~Guest_spdy() {

}



ssize_t Guest_spdy::Write(const void* buf, size_t len,uint32_t id,uint8_t flag) {
    spdy_dframe_head dhead;
    dhead.id=htonl(id);
    dhead.flag=flag;
    set24(dhead.length,len);
    Guest::Write(this,&dhead,sizeof(dhead));
    return Guest::Write(this,buf,len);
}

void Guest_spdy::clean(Peer* who) {
    if(who==this) {
        for(auto i:host2id) {
            bindex.del(this,i.first);
        }

        struct epoll_event event;
        event.data.ptr = this;
        event.events = EPOLLOUT;
        epoll_ctl(efd, EPOLL_CTL_MOD, fd, &event);

        handleEvent=(void (Con::*)(uint32_t))&Guest_spdy::closeHE;
    } else {
        bindex.del(this,who);
        if(host2id.count(who)) {
            Hostinfo *hostinfo=&host2id[who];

            spdy_cframe_head chead;
            memset(&chead,0,sizeof(chead));
            chead.magic=CTRL_MAGIC;
            chead.type=htons(RST_TYPE);
            set24(chead.length,sizeof(rst_frame));
            Peer::Write(this,&chead,sizeof(chead));

            rst_frame rframe;
            memset(&rframe,0,sizeof(rframe));
            rframe.code=0;
            rframe.id=htonl(hostinfo->id);
            Peer::Write(this,&rframe,sizeof(rframe));

            host2id.erase(who);
        }
    }
}

ssize_t Guest_spdy::Write(Peer* who, const void* buff, size_t size) {
    if(host2id.count(who)) {
        Hostinfo *hostinfo=&host2id[who];
        return (this->*hostinfo->Write)(hostinfo,buff,size);
    } else {
        who->clean(this);
    }
    return 0;
}

ssize_t Guest_spdy::HeaderWrite(Hostinfo* hostinfo, const void* buff, size_t size) {
//TODO 这里要做边界检查
    memcpy(hostinfo->buff+readlen,buff,size);
    hostinfo->readlen+=size;
    if (char* headerend = strnstr(hostinfo->buff, CRLF CRLF,hostinfo->readlen)) {
        headerend += strlen(CRLF CRLF);
        size_t headerlen = headerend - hostinfo->buff;
        HttpResHeader res(hostinfo->buff);
        if(res.getval("Transfer-Encoding")!= nullptr) {
            hostinfo->Write=&Guest_spdy::ChunkLWrite;
        } else if(res.getval("Content-Length")!=nullptr) {
            sscanf(res.getval("Content-Length"),"%u",&hostinfo->expectlen);
            hostinfo->Write=&Guest_spdy::FixLenWrite;
        } else {

        }

        writelen+=res.getframe(wbuff+writelen,&destream,hostinfo->id);
        
        struct epoll_event event;
        event.data.ptr = this;
        event.events = EPOLLIN | EPOLLOUT;
        epoll_ctl(efd, EPOLL_CTL_MOD, fd, &event);
        
        
        if(headerlen != hostinfo->readlen) {
            size_t leftlen = hostinfo->readlen-headerlen;
            hostinfo->readlen=0;
            (this->*hostinfo->Write)(hostinfo,(char *)buff+size-leftlen,leftlen);
        } else {
            hostinfo->readlen=0;
        }
    }
}

ssize_t Guest_spdy::ChunkLWrite(Hostinfo* hostinfo, const void* buff, size_t size) {
    if (char* headerend = strnstr((const char*)buff, CRLF,size)) {
        headerend += strlen(CRLF);
        size=(char *)buff+size-headerend;
        sscanf((const char*)buff,"%x",&hostinfo->expectlen);
        if(hostinfo->expectlen==0) {
            ssize_t ret=Write("",0,hostinfo->id,FLAG_FIN);
            hostinfo->Write=&Guest_spdy::HeaderWrite;
        } else {
            hostinfo->Write=&Guest_spdy::ChunkBWrite;
            if(size) {
                ChunkBWrite(hostinfo,headerend,size);
            }
        }
    }
}


ssize_t Guest_spdy::ChunkBWrite(Hostinfo* hostinfo, const void* buff, size_t size)
{
    size_t len=Min(hostinfo->expectlen,size);
    len=Write(buff,len,hostinfo->id,0);
    hostinfo->expectlen-=len;
    if(hostinfo->expectlen == 0) {
        hostinfo->Write=&Guest_spdy::ChunkLWrite;
        if(size != len) {
            ChunkLWrite(hostinfo,(char *)buff+len+2,size-len-2);
        }
    }
}



ssize_t Guest_spdy::FixLenWrite(Hostinfo* hostinfo, const void* buff, size_t size) {
    hostinfo->expectlen-=size;
    if(hostinfo->expectlen) {
        return Write(buff,size,hostinfo->id,0);
    } else {
        ssize_t ret=Write(buff,size,hostinfo->id,FLAG_FIN);
        hostinfo->Write=&Guest_spdy::HeaderWrite;
        return ret;
    }
}


void Guest_spdy::ErrProc(uint32_t errcode) {
    LOGE("Get a Err:%u\n",errcode);
}


void Guest_spdy::defaultHE(uint32_t events) {
    struct epoll_event event;
    event.data.ptr = this;

    if (events & EPOLLIN ) {
        (this->*Proc)();
    }
    if (events & EPOLLOUT) {
        if(writelen) {
            int ret = Peer::Write();
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

void Guest_spdy::CFrameProc(syn_frame* sframe) {
    NTOHL(sframe->id);
    HttpReqHeader *req=new HttpReqHeader(sframe,&instream);
    req->port=80;
    
    LOG( "([%s]:%d): %s %s\n",
         sourceip, sourceport,
         req->method, req->url);

    if ( req->ismethod("GET") ||  req->ismethod("HEAD") ) {
        host2id[Host::gethost(req,this)]=sframe->id;
        handleEvent=(void (Con::*)(uint32_t))&Guest_spdy::defaultHE;
    } else if (req->ismethod("POST") ) {
        const char* lenpoint=req->getval("Content-Length");
        if (lenpoint == NULL) {
            LOGE( "([%s]:%d): unsported post version\n",sourceip, sourceport);
            clean(this);
            return;
        }

        sscanf(lenpoint, "%u", &expectlen);
        expectlen -= readlen;
        Host *host=Host::gethost(req,this);
        host2id[host]=sframe->id;
        handleEvent=(void (Con::*)(uint32_t))&Guest_spdy::postHE;
    } else if (req->ismethod("CONNECT")) {
        host2id[Host::gethost(req,this)]=sframe->id;
        handleEvent=(void (Con::*)(uint32_t))&Guest_spdy::defaultHE;
    } else {
        LOGE( "([%s]:%d): unsported method:%s\n",
              sourceip, sourceport,req->method);
        clean(this);
    }
    /*               HttpResHeader httpres("200 Fuck");
                   httpres.add("content-type","text/plain");
                   spdy_cframe_head *chead=(spdy_cframe_head *)(wbuff+write_len);
                   chead->magic=CTRL_MAGIC;
                   chead->type=htons(SYN_REPLY_TYPE);
                   chead->flag = 0;
                   write_len+=sizeof(*chead);

                   syn_reply_frame *srframe=(syn_reply_frame *)(wbuff+write_len);
                   srframe->id=htonl(sframe->id);
                   write_len += sizeof(*srframe);
                   buflen=bufleft();
                   buflen=spdy_deflate(&destream,headbuff,httpres.getstring(headbuff,SPDY),wbuff+write_len,buflen);
                   write_len+=buflen;
                   set24(chead->length,sizeof(syn_reply_frame)+buflen);

                   Write("welcome",7,sframe->id,FLAG_FIN);
                   handleEvent=(void (Con::*)(uint32_t))&Guest_spdy::defaultHE;
           */
}



void Guest_spdy::CFrameProc(rst_frame* rframe) {
    NTOHL(rframe->id);
    NTOHL(rframe->code);
    fprintf(stderr,"get reset frame %d:%d\n",rframe->id,rframe->code);
}


void Guest_spdy::CFrameProc(goaway_frame* gframe) {
    NTOHL(gframe->id);
    NTOHL(gframe->code);
    LOG("([%s]:%d): The peer goaway %u:%u\n",sourceip, sourceport,
        gframe->id,gframe->code);
    clean(this);
}




