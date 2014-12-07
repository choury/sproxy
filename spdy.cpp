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
    LOG("Get a syn frame\n");
}

void Spdy::CFrameProc(syn_reply_frame*) {
    LOG("Get a syn reply frame\n");
}

void Spdy::CFrameProc(rst_frame*) {
    LOG("Get a rst frame\n");
}


void Spdy::CFrameProc(goaway_frame*) {
    LOG("Get a goaway frame\n");
}

ssize_t Spdy::DFrameProc(uint32_t id,size_t size) {
    LOG("Get a dataframe\n");
    if(size == 0){
        return 0;
    }
    ssize_t readlen = Read(spdy_buff,size>sizeof(spdy_buff)?sizeof(spdy_buff):size);
    if(readlen <= 0){
        ErrProc(readlen,id);
    }
    return readlen;
}


void Spdy::HeaderProc() {
    ssize_t readlen=Read(spdy_buff+spdy_getlen,sizeof(spdy_head));
    if(readlen<=0) {
        ErrProc(readlen,stream_id);
        return;
    }else{
        spdy_getlen+=readlen;
    }
    if(spdy_getlen == sizeof(spdy_head)) {
        spdy_head *shead=(spdy_head *)spdy_buff;
        spdy_expectlen=get24(shead->length);
        if(shead->c==1) {
            spdy_cframe_head *chead=(spdy_cframe_head *)shead;
            if(chead->magic != CTRL_MAGIC){
                ErrProc(PROTOCOL_ERROR,stream_id);
                return;
            }
            NTOHS(chead->type);
            switch(chead->type) {
            case SYN_TYPE:
                Spdy_Proc=&Spdy::SynProc;
                break;
            case SYN_REPLY_TYPE:
                Spdy_Proc=&Spdy::SynreplyProc;
                break;
            case RST_TYPE:
                Spdy_Proc=&Spdy::RstProc;
                break;
            case GOAWAY_TYPE:
                Spdy_Proc=&Spdy::GoawayProc;
                break;
            default:
                printf("get a spdy ctrl frame:%d\n",chead->type);
                Spdy_Proc=&Spdy::DefaultProc;
                break;
            }
        } else {
            spdy_dframe_head *dhead=(spdy_dframe_head *)shead;
            stream_id=ntohl(dhead->id);
            Spdy_Proc=&Spdy::DataProc;
        }
    }
    (this->*Spdy_Proc)();
}


void Spdy::SynProc() {
    size_t len=Min(sizeof(spdy_buff)-spdy_getlen,spdy_expectlen);
    if(len==0){
        syn_frame *sframe=(syn_frame*)spdy_buff;
        stream_id=ntohl(sframe->id);
        ErrProc(FRAME_TOO_LARGE,stream_id);
        Spdy_Proc=&Spdy::DefaultProc;
    }else{
        ssize_t readlen=Read(spdy_buff+spdy_getlen,len);
        if(readlen <= 0) {
            ErrProc(readlen,stream_id);
            return;
        } else {
            spdy_expectlen -= readlen;
            spdy_getlen    += readlen;
        }
        if(spdy_expectlen == 0) {
            syn_frame *sframe=(syn_frame*)spdy_buff;
            stream_id=ntohl(sframe->id);
            CFrameProc(sframe);
            Spdy_Proc = &Spdy::HeaderProc;
            spdy_getlen=0;
        }
    }
    (this->*Spdy_Proc)();
}

void Spdy::SynreplyProc() {
    size_t len=Min(sizeof(spdy_buff)-spdy_getlen,spdy_expectlen);
    if(len==0){
        syn_reply_frame *srframe=(syn_reply_frame *)spdy_buff;
        stream_id=ntohl(srframe->id);
        ErrProc(FRAME_TOO_LARGE,stream_id);
        Spdy_Proc=&Spdy::DefaultProc;
        return;
    }else{
        ssize_t readlen=Read(spdy_buff+spdy_getlen,len);
        if(readlen <= 0) {
            ErrProc(readlen,stream_id);
            return;
        } else {
            spdy_expectlen -= readlen;
            spdy_getlen    += readlen;
        }
        if(spdy_expectlen == 0) {
            syn_reply_frame *srframe=(syn_reply_frame *)spdy_buff;
            uchar spdy_flag = srframe->head.flag;
            stream_id=htonl(srframe->id);
            CFrameProc(srframe);
            Spdy_Proc = &Spdy::HeaderProc;
            spdy_getlen=0;

            if(spdy_flag & FLAG_FIN) {
                DFrameProc(stream_id,0);
            }
        }
    }
    (this->*Spdy_Proc)();
}


void Spdy::RstProc() {
    ssize_t readlen=Read(spdy_buff+spdy_getlen,spdy_expectlen);
    if(readlen <= 0) {
        ErrProc(readlen,stream_id);
        return;
    } else {
        spdy_expectlen -= readlen;
        spdy_getlen    += readlen;
    }
    if(spdy_expectlen == 0) {
        CFrameProc((rst_frame *)spdy_buff);
        Spdy_Proc = &Spdy::HeaderProc;
        spdy_getlen=0;
    }
    (this->*Spdy_Proc)();
}



void Spdy::GoawayProc() {
    ssize_t readlen=Read(spdy_buff+spdy_getlen,spdy_expectlen);
    if(readlen <= 0) {
        ErrProc(readlen,stream_id);
        return;
    } else {
        spdy_expectlen -= readlen;
        spdy_getlen    += readlen;
    }
    if(spdy_expectlen == 0) {
        CFrameProc((goaway_frame *)spdy_buff);
        Spdy_Proc = &Spdy::HeaderProc;
        spdy_getlen=0;
    }
    (this->*Spdy_Proc)();
}


void Spdy::DataProc() {
    uchar spdy_flag = ((spdy_head *)spdy_buff)->flag;
    if(spdy_expectlen){
        ssize_t readlen=DFrameProc(stream_id,spdy_expectlen);
        if(readlen<0){
            Spdy_Proc=&Spdy::DefaultProc;
            return;
        }
        if(readlen>0){
            spdy_expectlen-=readlen;
        }
    }else if(spdy_flag & FLAG_FIN) {
        DFrameProc(stream_id,0);
    }
    if(spdy_expectlen==0) {
        if(spdy_flag & FLAG_FIN) {
            DFrameProc(stream_id,0);
        }
        Spdy_Proc=&Spdy::HeaderProc;
        spdy_getlen=0;
    }
    (this->*Spdy_Proc)();
}



void Spdy::DefaultProc() {
    size_t len=Min(sizeof(spdy_buff),spdy_expectlen);
    ssize_t readlen=Read(spdy_buff,len);
    if(readlen <= 0) {
        ErrProc(readlen,stream_id);
        return;
    } else {
        spdy_expectlen -= readlen;
    }

    if(spdy_expectlen == 0) {
        Spdy_Proc=&Spdy::HeaderProc;
        spdy_getlen=0;
    }
    (this->*Spdy_Proc)();
}

