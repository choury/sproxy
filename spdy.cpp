#include "spdy.h"
#include "sys/epoll.h"
#include "parse.h"
#include "spdy_type.h"
#include "spdy_zlib.h"

Spdy::Spdy(Guest_s* copy):Guest_s(copy){
    handleEvent=(void (Con::*)(uint32_t))&Spdy::defaultHE;
    spdy_deflate_init(&destream);
    spdy_inflate_init(&instream);
}

Spdy::~Spdy(){
    spdy_deflate_end(&destream);
    spdy_inflate_end(&instream);
}


void Spdy::defaultHE(uint32_t events) {
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
            NTOHS(chead->type);
            expectlen=get24(chead->length);
            switch(chead->type) {
            case 1:
                handleEvent=(void (Con::*)(uint32_t))&Spdy::synHE;
                break;
            case 2:
                handleEvent=(void (Con::*)(uint32_t))&Spdy::synreplyHE;
                break;
            case 3:
                handleEvent=(void (Con::*)(uint32_t))&Spdy::rstHE;
                break;
            default:
                printf("get a spdy ctrl frame:%d\n",chead->type);
                handleEvent=(void (Con::*)(uint32_t))&Spdy::ctrlframedefultHE;
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
            rsthead.magic=CTRL_MAGIC;
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

void Spdy::synHE(uint32_t events) {
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
        size_t buflen=sizeof(headbuff);
        spdy_inflate(&instream,rbuff+sizeof(syn_frame),expectlen-sizeof(syn_frame),headbuff,buflen);
        
        read_len-=expectlen;
        memmove(rbuff,rbuff+expectlen,read_len);
        
        
        HttpReqHeader httpreq(headbuff,SPDY);
        HttpResHeader httpres(H302);
        httpres.add("location","http://www.baidu.com");
        httpres.add("content-length","0");
        spdy_cframe_head *chead=(spdy_cframe_head *)(wbuff+write_len);
        chead->magic=CTRL_MAGIC;
        chead->type=htons(SYN_REPLY_TYPE);
        chead->flag = FLAG_FIN;
        write_len+=sizeof(*chead);
        
        syn_reply_frame *srframe=(syn_reply_frame *)(wbuff+write_len);
        srframe->id=htonl(sframe->id);
        write_len += sizeof(*srframe);
        buflen=bufleft();
        buflen=spdy_deflate(&destream,headbuff,httpres.getstring(headbuff,SPDY),wbuff+write_len,buflen);
        write_len+=buflen;
        set24(chead->length,sizeof(syn_reply_frame)+buflen);
        
        Peer::Write("",0);
        handleEvent=(void (Con::*)(uint32_t))&Spdy::defaultHE;
        
    }
    Guest::defaultHE(events&(~EPOLLIN));
}

void Spdy::synreplyHE(uint32_t events) {
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
        syn_reply_frame *rframe=(syn_reply_frame *)rbuff;
        NTOHL(rframe->id);
        char headbuff[8192];
        size_t buflen=sizeof(headbuff);
        spdy_inflate(&instream,rbuff+sizeof(syn_reply_frame),expectlen-sizeof(syn_reply_frame),headbuff,buflen);
        
        memmove(rbuff,rbuff+expectlen,read_len-expectlen);
        read_len-=expectlen;
        expectlen=0;
        
        while(1);
    }
    Guest::defaultHE(events&(~EPOLLIN));
}


void Spdy::rstHE(uint32_t events){
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
        read_len-=expectlen;
        rst_frame *rframe=(rst_frame*)rbuff;
        NTOHL(rframe->id);
        NTOHL(rframe->code);
        fprintf(stderr,"get reset frame %d:%d\n",rframe->id,rframe->code);
        handleEvent=(void (Con::*)(uint32_t))&Spdy::defaultHE;
        
    }
    Guest::defaultHE(events&(~EPOLLIN));
}

void Spdy::ctrlframedefultHE(uint32_t events) {
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
        handleEvent=(void (Con::*)(uint32_t))&Spdy::defaultHE;
        if(read_len) {
            (this ->*handleEvent) (events&(~EPOLLIN));
        }
    }
}


