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
        HttpResHeader http(hostinfo->buff);
        if(http.getval("Transfer-Encoding")!= nullptr){
            hostinfo->Write=&Guest_spdy::ChunkLWrite;
        }else if(http.getval("Content-Length")!=nullptr){
            sscanf(http.getval("Content-Length"),"%u",&hostinfo->expectlen);
            hostinfo->Write=&Guest_spdy::FixLenWrite;
        }else{
            
        }
        spdy_cframe_head *chead=(spdy_cframe_head *)(wbuff+writelen);
        chead->magic=CTRL_MAGIC;
        chead->type=htons(SYN_REPLY_TYPE);
        chead->flag = 0;
        writelen+=sizeof(*chead);

        syn_reply_frame *srframe=(syn_reply_frame *)(wbuff+writelen);
        srframe->id=htonl(hostinfo->id);
        writelen += sizeof(*srframe);

        uint32_t buflen=bufleft();
        char headbuff[8192];
        buflen=spdy_deflate(&destream,headbuff,http.getstring(headbuff,SPDY),wbuff+writelen,buflen);
        writelen+=buflen;
        set24(chead->length,sizeof(syn_reply_frame)+buflen);
        Peer::Write(nullptr,"",0);
        if(headerlen != hostinfo->readlen){
            size_t leftlen = hostinfo->readlen-headerlen;
            hostinfo->readlen=0;
            (this->*hostinfo->Write)(hostinfo,(char *)buff+size-leftlen,leftlen);
        }else{
            hostinfo->readlen=0;
        }
    }
}

ssize_t Guest_spdy::ChunkLWrite(Hostinfo* hostinfo, const void* buff, size_t size){
    if (char* headerend = strnstr((const char*)buff, CRLF,size)){
        headerend += strlen(CRLF);
        size=(char *)buff+size-headerend;
        sscanf((const char*)buff,"%x",&hostinfo->expectlen);
        if(hostinfo->expectlen==0){
            ssize_t ret=Write("",0,hostinfo->id,FLAG_FIN);
            hostinfo->Write=&Guest_spdy::HeaderWrite;
        }else{
            hostinfo->Write=&Guest_spdy::ChunkBWrite;
            if(size){
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
    if(hostinfo->expectlen == 0){
        hostinfo->Write=&Guest_spdy::ChunkLWrite;
        if(size != len){
            ChunkLWrite(hostinfo,(char *)buff+len+2,size-len-2);
        }
    }
}



ssize_t Guest_spdy::FixLenWrite(Hostinfo* hostinfo, const void* buff, size_t size){
    hostinfo->expectlen-=size;
    if(hostinfo->expectlen){
        return Write(buff,size,hostinfo->id,0);
    }else{
        ssize_t ret=Write(buff,size,hostinfo->id,FLAG_FIN);
        hostinfo->Write=&Guest_spdy::HeaderWrite;
        return ret;
    }
}


void Guest_spdy::defaultHE(uint32_t events) {
    if(events & EPOLLIN) {
        int len=sizeof(rbuff)-readlen;
        if(len == 0) {
            LOGE( "([%s]:%d): The header is too long\n",sourceip, sourceport);
            epoll_ctl(efd, EPOLL_CTL_DEL, fd, NULL);
            return;
        }
        int ret=Read(rbuff+readlen, len);
        if(ret<=0 ) {
            if(showerrinfo(ret,"spdy read error")) {
                clean(this);
            }
            return;
        }

        readlen+=ret;
    }
    if(readlen >= sizeof(spdy_head)) {
        spdy_head head;
        memcpy(&head,rbuff,sizeof(head));
        memmove(rbuff,rbuff+sizeof(head),readlen-sizeof(head));
        readlen-=sizeof(head);
        if(head.c==1) {
            spdy_cframe_head *chead=(spdy_cframe_head *)&head;
            NTOHS(chead->type);
            expectlen=get24(chead->length);
            switch(chead->type) {
            case SYN_TYPE:
                handleEvent=(void (Con::*)(uint32_t))&Guest_spdy::synHE;
                break;
            case SYN_REPLY_TYPE:
                handleEvent=(void (Con::*)(uint32_t))&Guest_spdy::synreplyHE;
                break;
            case RST_TYPE:
                handleEvent=(void (Con::*)(uint32_t))&Guest_spdy::rstHE;
                break;
            case GOAWAY_TYPE:
                handleEvent=(void (Con::*)(uint32_t))&Guest_spdy::goawayHE;
                break;
            default:
                printf("get a spdy ctrl frame:%d\n",chead->type);
                handleEvent=(void (Con::*)(uint32_t))&Guest_spdy::ctrlframedefultHE;
                break;
            }
            if(readlen) {
                (this ->*handleEvent) (events&(~EPOLLIN));
            }
        } else {
            spdy_dframe_head *dhead=(spdy_dframe_head *)&head;
            NTOHL(dhead->id);
            char *buff=new char[get24(dhead->length)];
            Read(buff,get24(dhead->length));
            spdy_cframe_head rsthead;
            memset(&rsthead,0,sizeof(rsthead));
            rsthead.magic=CTRL_MAGIC;
            rsthead.type=htons(3);

            Peer::Write(this,&rsthead,sizeof(rsthead));

            rst_frame rstframe;
            memset(&rstframe,0,sizeof(rstframe));
            rstframe.code=htonl(INVALID_STREAM);
            rstframe.id=htonl(dhead->id);
            Peer::Write(this,&rstframe,sizeof(rstframe));

        }
    }
    Guest::defaultHE(events&(~EPOLLIN));
}

void Guest_spdy::synHE(uint32_t events) {
    if(events & EPOLLIN) {
        int len=sizeof(rbuff)-readlen;
        if(len == 0) {
            LOGE( "([%s]:%d): The header is too long\n",sourceip, sourceport);
            epoll_ctl(efd, EPOLL_CTL_DEL, fd, NULL);
            return;
        }
        int ret=Read(rbuff+readlen, len);
        if(ret<=0 ) {
            if(showerrinfo(ret,"spdy syn read error")) {
                clean(this);
            }
            return;
        }

        readlen+=ret;
    }
    if(readlen >= expectlen) {
        syn_frame *sframe=(syn_frame*)rbuff;
        NTOHL(sframe->id);
        uchar headbuff[8192];
        size_t buflen=sizeof(headbuff);
        spdy_inflate(&instream,rbuff+sizeof(syn_frame),expectlen-sizeof(syn_frame),headbuff,buflen);

        readlen-=expectlen;
        memmove(rbuff,rbuff+expectlen,readlen);

        HttpReqHeader *Req=new HttpReqHeader(headbuff);
        Req->port=80;
        LOG( "([%s]:%d): %s %s\n",
             sourceip, sourceport,
             Req->method, Req->url);
/*
        if ( Req->ismethod("GET") ||  Req->ismethod("HEAD") ) {
            host2id[Host::gethost(Req,this)]=sframe->id;
            handleEvent=(void (Con::*)(uint32_t))&Guest_spdy::defaultHE;
        } else if (Req->ismethod("POST") ) {
            const char* lenpoint=Req->getval("Content-Length");
            if (lenpoint == NULL) {
                LOGE( "([%s]:%d): unsported post version\n",sourceip, sourceport);
                clean(this);
                return;
            }

            sscanf(lenpoint, "%u", &expectlen);
            expectlen -= readlen;
            Host *host=Host::gethost(Req,this);
            host2id[host]=sframe->id;
            handleEvent=(void (Con::*)(uint32_t))&Guest_spdy::postHE;
        } else if (Req->ismethod("CONNECT")) {
            host2id[Host::gethost(Req,this)]=sframe->id;
            handleEvent=(void (Con::*)(uint32_t))&Guest_spdy::defaultHE;
        } else {
            LOGE( "([%s]:%d): unsported method:%s\n",
                  sourceip, sourceport,Req->method);
            clean(this);
        }
                HttpResHeader httpres("200 Fuck");
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
    Guest::defaultHE(events&(~EPOLLIN));
}

void Guest_spdy::synreplyHE(uint32_t events) {
    if(events & EPOLLIN) {
        int len=sizeof(rbuff)-readlen;
        if(len == 0) {
            LOGE( "([%s]:%d): The header is too long\n",sourceip, sourceport);
            epoll_ctl(efd, EPOLL_CTL_DEL, fd, NULL);
            return;
        }
        int ret=Read(rbuff+readlen, len);
        if(ret<=0 ) {
            if(showerrinfo(ret,"spdy syn reply read error")) {
                clean(this);
            }
            return;
        }

        readlen+=ret;
    }
    if(readlen >= expectlen) {
        syn_reply_frame *rframe=(syn_reply_frame *)rbuff;
        NTOHL(rframe->id);
        char headbuff[8192];
        size_t buflen=sizeof(headbuff);
        spdy_inflate(&instream,rbuff+sizeof(syn_reply_frame),expectlen-sizeof(syn_reply_frame),headbuff,buflen);

        memmove(rbuff,rbuff+expectlen,readlen-expectlen);
        readlen-=expectlen;
        expectlen=0;

        while(1);
    }
    Guest::defaultHE(events&(~EPOLLIN));
}


void Guest_spdy::rstHE(uint32_t events) {
    if(events & EPOLLIN) {
        int len=sizeof(rbuff)-readlen;
        if(len == 0) {
            LOGE( "([%s]:%d): The header is too long\n",sourceip, sourceport);
            epoll_ctl(efd, EPOLL_CTL_DEL, fd, NULL);
            return;
        }
        int ret=Read(rbuff+readlen, len);
        if(ret<=0 ) {
            if(showerrinfo(ret,"spdy syn read error")) {
                clean(this);
            }
            return;
        }
        readlen+=ret;
    }
    if(readlen >= expectlen) {
        readlen-=expectlen;
        rst_frame *rframe=(rst_frame*)rbuff;
        NTOHL(rframe->id);
        NTOHL(rframe->code);
        fprintf(stderr,"get reset frame %d:%d\n",rframe->id,rframe->code);
        handleEvent=(void (Con::*)(uint32_t))&Guest_spdy::defaultHE;

    }
    Guest::defaultHE(events&(~EPOLLIN));
}

void Guest_spdy::goawayHE(uint32_t events) {
    if(events & EPOLLIN) {
        int len=sizeof(rbuff)-readlen;
        if(len == 0) {
            LOGE( "([%s]:%d): The header is too long\n",sourceip, sourceport);
            epoll_ctl(efd, EPOLL_CTL_DEL, fd, NULL);
            return;
        }
        int ret=Read(rbuff+readlen, len);
        if(ret<=0 ) {
            if(showerrinfo(ret,"spdy syn read error")) {
                clean(this);
            }
            return;
        }

        readlen+=ret;
    }

    if(readlen >= expectlen) {
        goaway_frame *gframe=(goaway_frame *)rbuff;
        NTOHL(gframe->id);
        NTOHL(gframe->code);
        LOG("([%s]:%d): The peer goaway %u:%u\n",sourceip, sourceport,
            gframe->id,gframe->code);
        clean(this);
    }
}


void Guest_spdy::ctrlframedefultHE(uint32_t events) {
    if(events & EPOLLIN) {
        int len=sizeof(rbuff)-readlen;
        if(len == 0) {
            LOGE( "([%s]:%d): The header is too long\n",sourceip, sourceport);
            epoll_ctl(efd, EPOLL_CTL_DEL, fd, NULL);
            return;
        }
        int ret=Read(rbuff+readlen, len);
        if(ret<=0 ) {
            if(showerrinfo(ret,"spdy syn read error")) {
                clean(this);
            }
            return;
        }

        readlen+=ret;
    }

    if(readlen >= expectlen) {
        memmove(rbuff,rbuff+expectlen,expectlen);
        readlen-=expectlen;
        expectlen=0;
        handleEvent=(void (Con::*)(uint32_t))&Guest_spdy::defaultHE;
        if(readlen) {
            (this ->*handleEvent) (events&(~EPOLLIN));
        }
    }
}


