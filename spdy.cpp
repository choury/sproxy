#include <stddef.h>
#include <string.h>
#include "spdy.h"


Spdy::Spdy(){
    spdy_deflate_init(&destream);
    spdy_inflate_init(&instream);
}

Spdy::~Spdy(){
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

void Spdy::DFrameProc(void*,size_t,uint32_t) {
    LOGE("Get a dataframe\n");
}

ssize_t Spdy::Spdy_read(void *buff,size_t buflen,size_t expectlen){
    if(spdy_getlen + expectlen > sizeof(spdy_buff)){
        return -1;
    }
    if(expectlen > buflen){
        expectlen   -= buflen;
        memcpy(spdy_buff+spdy_getlen,buff,buflen);
        spdy_getlen += buflen;
        return buflen;
    }else{
        buflen      -= expectlen;
        memcpy(spdy_buff+spdy_getlen,buff,expectlen);
        spdy_getlen += expectlen;
        memmove(buff,(char *)buff+expectlen,buflen);
        return expectlen;;
    }
}

void Spdy::HeaderProc(void *buff,size_t buflen,void (Spdy::*ErrProc)(uint32_t)) {
    ssize_t readlen=Spdy_read(buff,buflen,sizeof(spdy_head));
    buflen -= readlen;
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
            if(buflen) {
                (this ->*Proc) (buff,buflen,ErrProc);
            }
        } else {
            spdy_dframe_head *dhead=(spdy_dframe_head *)shead;
            stream_id=ntohl(dhead->id);
            if(spdy_expectlen){
                Proc=&Spdy::DataProc;
            }else if(dhead->flag & FLAG_FIN){
                DataProc(buff,0,ErrProc);
            }
            if(buflen) {
                DataProc(buff,buflen,ErrProc);
            }
        }
    }
}


void Spdy::SynProc(void *buff,size_t buflen,void (Spdy::*ErrProc)(uint32_t)){
    ssize_t readlen=Spdy_read(buff,buflen,spdy_expectlen);
    if(readlen < 0){
        (this->*ErrProc)(FRAME_TOO_LARGE);
        Proc=&Spdy::DefaultProc;
        spdy_expectlen -= buflen;
        return;
    }else{
        spdy_expectlen -= readlen;
        buflen         -= readlen;
    }
    if(spdy_expectlen == 0) {
        CFrameProc((syn_frame *)spdy_buff);
        Proc = &Spdy::HeaderProc;
        spdy_getlen=0;
        if(buflen){
            (this ->*Proc) (buff,buflen,ErrProc);
        }
    }
}

void Spdy::SynreplyProc(void *buff,size_t buflen,void (Spdy::*ErrProc)(uint32_t)){
    ssize_t readlen=Spdy_read(buff,buflen,spdy_expectlen);
    if(readlen < 0){
        (this->*ErrProc)(FRAME_TOO_LARGE);
        Proc=&Spdy::DefaultProc;
        spdy_expectlen -= buflen;
        return;
    }else{
        spdy_expectlen -= readlen;
        buflen         -= readlen;
    }
    if(spdy_expectlen == 0) {
        uchar spdy_flag = ((spdy_head *)spdy_buff)->flag;
        CFrameProc((syn_reply_frame *)spdy_buff);
        Proc = &Spdy::HeaderProc;
        spdy_getlen=0;
        if(spdy_flag & FLAG_FIN){
            DFrameProc(buff,((syn_reply_frame *)spdy_buff)->id,0);
        }
        if(buflen){
            (this ->*Proc) (buff,buflen,ErrProc);
        }
    }
}


void Spdy::RstProc(void *buff,size_t buflen,void (Spdy::*ErrProc)(uint32_t)){
    ssize_t readlen=Spdy_read(buff,buflen,spdy_expectlen);
    if(readlen < 0){
        (this->*ErrProc)(FRAME_TOO_LARGE);
        Proc=&Spdy::DefaultProc;
        spdy_expectlen -= buflen;
        return;
    }else{
        spdy_expectlen -= readlen;
        buflen         -= readlen;
    }
    if(spdy_expectlen == 0) {
        CFrameProc((rst_frame *)spdy_buff);
        Proc = &Spdy::HeaderProc;
        spdy_getlen=0;
        if(buflen){
            (this ->*Proc) (buff,buflen,ErrProc);
        }
    }
}



void Spdy::GoawayProc(void *buff,size_t buflen,void (Spdy::*ErrProc)(uint32_t)){
    ssize_t readlen=Spdy_read(buff,buflen,spdy_expectlen);
    if(readlen < 0){
        (this->*ErrProc)(FRAME_TOO_LARGE);
        Proc=&Spdy::DefaultProc;
        spdy_expectlen -= buflen;
        return;
    }else{
        spdy_expectlen -= readlen;
        buflen         -= readlen;
    }
    if(spdy_expectlen == 0) {
        CFrameProc((goaway_frame *)spdy_buff);
        Proc = &Spdy::HeaderProc;
        spdy_getlen=0;
        if(buflen){
            (this ->*Proc) (buff,buflen,ErrProc);
        }
    }
}


void Spdy::DataProc(void *buff,size_t buflen,void (Spdy::*ErrProc)(uint32_t)){
    if(spdy_expectlen > buflen){
        spdy_expectlen -= buflen;
        DFrameProc(buff,stream_id,buflen);
    }else{
        buflen -= spdy_expectlen;
        uchar spdy_flag = ((spdy_head *)spdy_buff)->flag;
        if(spdy_expectlen || spdy_flag & FLAG_FIN){
            DFrameProc(buff,spdy_expectlen,stream_id);
            memmove(buff,(char *)buff+spdy_expectlen,buflen);
        }
        if(spdy_expectlen && (spdy_flag & FLAG_FIN)){
            DFrameProc(buff,stream_id,0);
        }
        Proc=&Spdy::HeaderProc;
        spdy_getlen=0;
        if(buflen){
            HeaderProc(buff,buflen,ErrProc);
        }
    }
}



void Spdy::DefaultProc(void *buff,size_t buflen,void (Spdy::*ErrProc)(uint32_t)){
    if(spdy_expectlen > buflen) {
        spdy_expectlen-=buflen;
    }else{
        buflen-=spdy_expectlen;
        memmove(buff,(char *)buff+spdy_expectlen,buflen);
        Proc=&Spdy::HeaderProc;
        spdy_getlen=0;
        if(buflen){
            HeaderProc(buff,buflen,ErrProc);
        }
    }
}

