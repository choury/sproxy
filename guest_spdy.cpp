#include "guest_spdy.h"
#include "parse.h"
#include "spdy_type.h"
#include "spdy_zlib.h"

Guest_spdy::Guest_spdy(Guest_s* copy):Guest_s(copy){
    handleEvent=(void (Con::*)(uint32_t))&Guest_spdy::defaultHE;
    spdy_deflate_init(&destream);
    spdy_inflate_init(&instream);
}

Guest_spdy::~Guest_spdy(){
    spdy_deflate_end(&destream);
    spdy_inflate_end(&instream);
}



int Guest_spdy::Write(const void* buf, size_t len,uint32_t id,uint8_t flag){
    spdy_dframe_head dhead;
    dhead.id=htonl(id);
    dhead.flag=flag;
    set24(dhead.length,len);
    Guest::Write(this,&dhead,sizeof(dhead));
    return Guest::Write(this,buf,len);
}


void Guest_spdy::defaultHE(uint32_t events) {
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
                clean(this);
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
        int len=sizeof(rbuff)-read_len;
        if(len == 0) {
            LOGE( "([%s]:%d): The header is too long\n",sourceip, sourceport);
            epoll_ctl(efd, EPOLL_CTL_DEL, fd, NULL);
            return;
        }
        int ret=Read(rbuff+read_len, len);
        if(ret<=0 ) {
            if(showerrinfo(ret,"spdy syn read error")) {
                clean(this);
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
        
        
        HttpReqHeader httpreq(headbuff);
        HttpResHeader httpres(H200);
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
        
    }
    Guest::defaultHE(events&(~EPOLLIN));
}

void Guest_spdy::synreplyHE(uint32_t events) {
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
                clean(this);
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


void Guest_spdy::rstHE(uint32_t events){
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
                clean(this);
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
        handleEvent=(void (Con::*)(uint32_t))&Guest_spdy::defaultHE;
        
    }
    Guest::defaultHE(events&(~EPOLLIN));
}

void Guest_spdy::goawayHE(uint32_t events){
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
                clean(this);
            }
            return;
        }

        read_len+=ret;
    }

    if(read_len >= expectlen) {
        goaway_frame *gframe=(goaway_frame *)rbuff;
        NTOHL(gframe->id);
        NTOHL(gframe->code);
        LOG("([%s]:%d): The peer goaway %u:%u\n",sourceip, sourceport,
            gframe->id,gframe->code);
        delete this;
    }
}


void Guest_spdy::ctrlframedefultHE(uint32_t events) {
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
                clean(this);
            }
            return;
        }

        read_len+=ret;
    }

    if(read_len >= expectlen) {
        memmove(rbuff,rbuff+expectlen,expectlen);
        read_len-=expectlen;
        expectlen=0;
        handleEvent=(void (Con::*)(uint32_t))&Guest_spdy::defaultHE;
        if(read_len) {
            (this ->*handleEvent) (events&(~EPOLLIN));
        }
    }
}


