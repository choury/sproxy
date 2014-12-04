#include <stddef.h>
#include <string.h>
#include "spdy.h"


Spdy::Spdy() {
    spdy_deflate_init(&destream);
    spdy_inflate_init(&instream);
}

Spdy::~Spdy() {
    spdy_deflate_end(&destream);
    spdy_inflate_end(&instream);
}



void Spdy::CFrameProc(syn_frame*) {
    LOGE("Get a syn frame\n");
}

void Spdy::CFrameProc(syn_reply_frame*) {
    LOGE("Get a syn reply frame\n");
}

void Spdy::CFrameProc(rst_frame*) {
    LOGE("Get a rst frame\n");
}


void Spdy::CFrameProc(goaway_frame*) {
    LOGE("Get a goaway frame\n");
}

ssize_t Spdy::DFrameProc(uint32_t,size_t size) {
    LOGE("Get a dataframe\n");
    if(size == 0){
        return 0;
    }
    ssize_t readlen = Read(spdy_buff,size>sizeof(spdy_buff)?sizeof(spdy_buff):size);
    if(readlen <= 0){
        ErrProc(readlen);
    }
    return readlen;
}


void Spdy::HeaderProc() {
    ssize_t readlen=Read(spdy_buff+spdy_getlen,sizeof(spdy_head));
    if(readlen<=0) {
        ErrProc(readlen);
        return;
    }else{
        spdy_getlen+=readlen;
    }
    if(spdy_getlen == sizeof(spdy_head)) {
        spdy_head *shead=(spdy_head *)spdy_buff;
        spdy_expectlen=get24(shead->length);
        if(shead->c==1) {
            spdy_cframe_head *chead=(spdy_cframe_head *)shead;
            NTOHS(chead->type);
            switch(chead->type) {
            case SYN_TYPE:
                Proc=&Spdy::SynProc;
                break;
            case SYN_REPLY_TYPE:
                Proc=&Spdy::SynreplyProc;
                break;
            case RST_TYPE:
                Proc=&Spdy::RstProc;
                break;
            case GOAWAY_TYPE:
                Proc=&Spdy::GoawayProc;
                break;
            default:
                printf("get a spdy ctrl frame:%d\n",chead->type);
                Proc=&Spdy::DefaultProc;
                break;
            }
        } else {
            spdy_dframe_head *dhead=(spdy_dframe_head *)shead;
            stream_id=ntohl(dhead->id);
            if(spdy_expectlen) {
                Proc=&Spdy::DataProc;
            } else if(dhead->flag & FLAG_FIN) {
                DataProc();
            }
        }
    }
}


void Spdy::SynProc() {
    if(spdy_expectlen+spdy_getlen >= sizeof(spdy_buff)) {
        ErrProc(FRAME_TOO_LARGE);
        Proc=&Spdy::DefaultProc;
        return;
    }
    ssize_t readlen=Read(spdy_buff+spdy_getlen,spdy_expectlen);
    if(readlen <= 0) {
        ErrProc(readlen);
        return;
    } else {
        spdy_expectlen -= readlen;
    }
    if(spdy_expectlen == 0) {
        CFrameProc((syn_frame *)spdy_buff);
        Proc = &Spdy::HeaderProc;
        spdy_getlen=0;
    }
}

void Spdy::SynreplyProc() {
    if(spdy_expectlen+spdy_getlen >= sizeof(spdy_buff)) {
        ErrProc(FRAME_TOO_LARGE);
        Proc=&Spdy::DefaultProc;
        return;
    }
    ssize_t readlen=Read(spdy_buff+spdy_getlen,spdy_expectlen);
    if(readlen <= 0) {
        ErrProc(readlen);
        return;
    } else {
        spdy_expectlen -= readlen;
    }
    if(spdy_expectlen == 0) {
        uchar spdy_flag = ((spdy_head *)spdy_buff)->flag;
        CFrameProc((syn_reply_frame *)spdy_buff);
        Proc = &Spdy::HeaderProc;
        spdy_getlen=0;

        if(spdy_flag & FLAG_FIN) {
            DFrameProc(((syn_reply_frame *)spdy_buff)->id,0);
        }
    }
}


void Spdy::RstProc() {
    if(spdy_expectlen+spdy_getlen >= sizeof(spdy_buff)) {
        ErrProc(FRAME_TOO_LARGE);
        Proc=&Spdy::DefaultProc;
        return;
    }
    ssize_t readlen=Read(spdy_buff+spdy_getlen,spdy_expectlen);
    if(readlen <= 0) {
        ErrProc(readlen);
        return;
    } else {
        spdy_expectlen -= readlen;
    }
    if(spdy_expectlen == 0) {
        CFrameProc((rst_frame *)spdy_buff);
        Proc = &Spdy::HeaderProc;
        spdy_getlen=0;
    }
}



void Spdy::GoawayProc() {
    if(spdy_expectlen+spdy_getlen >= sizeof(spdy_buff)) {
        ErrProc(FRAME_TOO_LARGE);
        Proc=&Spdy::DefaultProc;
        return;
    }
    ssize_t readlen=Read(spdy_buff+spdy_getlen,spdy_expectlen);
    if(readlen <= 0) {
        ErrProc(readlen);
        return;
    } else {
        spdy_expectlen -= readlen;
    }
    if(spdy_expectlen == 0) {
        CFrameProc((goaway_frame *)spdy_buff);
        Proc = &Spdy::HeaderProc;
        spdy_getlen=0;
    }
}


void Spdy::DataProc() {
    uchar spdy_flag = ((spdy_head *)spdy_buff)->flag;
    ssize_t readlen=DFrameProc(stream_id,spdy_expectlen);
    if(spdy_expectlen && (spdy_flag & FLAG_FIN)) {
        DFrameProc(stream_id,0);
    }
    if(readlen<0){
        Proc=&Spdy::DefaultProc;
        return;
    }
    if(readlen>0){
        spdy_expectlen-=readlen;
    }
    if(spdy_expectlen==0) {
        Proc=&Spdy::HeaderProc;
        spdy_getlen=0;
    }
}



void Spdy::DefaultProc() {
    size_t len=spdy_expectlen > sizeof(spdy_buff)?sizeof(spdy_buff):spdy_expectlen;
    ssize_t readlen=Read(spdy_buff,len);
    if(readlen <= 0) {
        ErrProc(readlen);
        return;
    } else {
        spdy_expectlen -= readlen;
    }

    if(spdy_expectlen == 0) {
        Proc=&Spdy::HeaderProc;
        spdy_getlen=0;
    }
}

