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

void Spdy::CFrameProc(ping_frame*) {
    LOG("Get a ping frame\n");
}


void Spdy::CFrameProc(rst_frame*) {
    LOG("Get a rst frame\n");
}


void Spdy::CFrameProc(goaway_frame*) {
    LOG("Get a goaway frame\n");
}

ssize_t Spdy::DFrameProc(void *buff,size_t size,uint32_t id) {
    LOG("Get a dataframe\n");
    return size;
}


void Spdy::HeaderProc() {
    if(spdy_getlen >= sizeof(spdy_head)) {
        spdy_head *shead=(spdy_head *)spdy_buff;
        spdy_flag = shead->flag;
        spdy_expectlen=get24(shead->length);
        if(shead->c==1) {
            spdy_expectlen += sizeof(spdy_head);
            spdy_cframe_head *chead=(spdy_cframe_head *)shead;
            if(chead->magic != CTRL_MAGIC) {
                ErrProc(PROTOCOL_ERROR,stream_id);
                return;
            }
            switch(ntohs(chead->type)) {
            case SYN_TYPE:
                Spdy_Proc=&Spdy::SynProc;
                break;
            case SYN_REPLY_TYPE:
                Spdy_Proc=&Spdy::SynreplyProc;
                break;
            case PING_TYPE:
                Spdy_Proc=&Spdy::PingProc;
                break;
            case RST_TYPE:
                Spdy_Proc=&Spdy::RstProc;
                break;
            case GOAWAY_TYPE:
                Spdy_Proc=&Spdy::GoawayProc;
                break;
            default:
                printf("get a spdy ctrl frame:%d\n",ntohs(chead->type));
                Spdy_Proc=&Spdy::DropProc;
                break;
            }
        } else {
            spdy_dframe_head *dhead=(spdy_dframe_head *)shead;
            stream_id=ntohl(dhead->id);
            Spdy_Proc=&Spdy::DataProc;

            if(sizeof(spdy_head) != spdy_getlen) {
                memmove(spdy_buff,spdy_buff+sizeof(spdy_head),spdy_getlen-sizeof(spdy_head));
            }
            spdy_getlen -= sizeof(spdy_head);
        }
    } else {
        ssize_t readlen=Read(spdy_buff+spdy_getlen,sizeof(spdy_buff)-spdy_getlen);
        if(readlen <= 0) {
            ErrProc(readlen,stream_id);
            return;
        } else {
            spdy_getlen += readlen;
        }
    }
    (this->*Spdy_Proc)();
}


void Spdy::SynProc() {
    if(spdy_getlen >= spdy_expectlen) {
        syn_frame *sframe=(syn_frame*)spdy_buff;
        stream_id=ntohl(sframe->id);
        CFrameProc(sframe);
        Spdy_Proc = &Spdy::HeaderProc;
        if(spdy_expectlen != spdy_getlen) {
            memmove(spdy_buff,spdy_buff+spdy_expectlen,spdy_getlen-spdy_expectlen);
        }
        spdy_getlen -= spdy_expectlen;
    } else {
        if(sizeof(spdy_buff) == spdy_getlen) {
            syn_frame *sframe=(syn_frame*)spdy_buff;
            stream_id=ntohl(sframe->id);
            ErrProc(FRAME_TOO_LARGE,stream_id);
            Spdy_Proc=&Spdy::DropProc;
        } else {
            ssize_t readlen=Read(spdy_buff+spdy_getlen,sizeof(spdy_buff)-spdy_getlen);
            if(readlen <= 0) {
                ErrProc(readlen,stream_id);
                return;
            } else {
                spdy_getlen += readlen;
            }
        }
    }
    (this->*Spdy_Proc)();
}

void Spdy::SynreplyProc() {
    if(spdy_getlen >= spdy_expectlen) {
        syn_reply_frame *sframe=(syn_reply_frame*)spdy_buff;
        stream_id=ntohl(sframe->id);
        CFrameProc(sframe);
        Spdy_Proc = &Spdy::HeaderProc;
        if(spdy_expectlen != spdy_getlen) {
            memmove(spdy_buff,spdy_buff+spdy_expectlen,spdy_getlen-spdy_expectlen);
        }
        spdy_getlen -= spdy_expectlen;
    } else {
        if(sizeof(spdy_buff) == spdy_getlen) {
            syn_reply_frame *srframe=(syn_reply_frame *)spdy_buff;
            stream_id=htonl(srframe->id);
            CFrameProc(srframe);
            Spdy_Proc = &Spdy::HeaderProc;
            spdy_getlen=0;

            if(spdy_flag & FLAG_FIN) {
                DFrameProc(spdy_buff,0,stream_id);
            }
        } else {
            ssize_t readlen=Read(spdy_buff+spdy_getlen,sizeof(spdy_buff)-spdy_getlen);
            if(readlen <= 0) {
                ErrProc(readlen,stream_id);
                return;
            } else {
                spdy_getlen += readlen;
            }
        }
    }
    (this->*Spdy_Proc)();
}


void Spdy::PingProc() {
    if(spdy_getlen >= spdy_expectlen) {
        ping_frame *pframe=(ping_frame*)spdy_buff;
        stream_id=ntohl(pframe->id);
        CFrameProc(pframe);
        Spdy_Proc = &Spdy::HeaderProc;
        if(spdy_expectlen != spdy_getlen) {
            memmove(spdy_buff,spdy_buff+spdy_expectlen,spdy_getlen-spdy_expectlen);
        }
        spdy_getlen -= spdy_expectlen;
    } else {
        ssize_t readlen=Read(spdy_buff+spdy_getlen,sizeof(spdy_buff)-spdy_getlen);
        if(readlen <= 0) {
            ErrProc(readlen,stream_id);
            return;
        } else {
            spdy_getlen += readlen;
        }
    }
    (this->*Spdy_Proc)();
}


void Spdy::RstProc() {
    if(spdy_getlen >= spdy_expectlen) {
        rst_frame *rframe=(rst_frame*)spdy_buff;
        stream_id=ntohl(rframe->id);
        CFrameProc(rframe);
        Spdy_Proc = &Spdy::HeaderProc;
        if(spdy_expectlen != spdy_getlen) {
            memmove(spdy_buff,spdy_buff+spdy_expectlen,spdy_getlen-spdy_expectlen);
        }
        spdy_getlen -= spdy_expectlen;
    } else {
        ssize_t readlen=Read(spdy_buff+spdy_getlen,sizeof(spdy_buff)-spdy_getlen);
        if(readlen <= 0) {
            ErrProc(readlen,stream_id);
            return;
        } else {
            spdy_getlen += readlen;
        }
    }
    (this->*Spdy_Proc)();
}



void Spdy::GoawayProc() {
    if(spdy_getlen >= spdy_expectlen) {
        CFrameProc((goaway_frame *)spdy_buff);
        Spdy_Proc = &Spdy::HeaderProc;
        if(spdy_expectlen != spdy_getlen) {
            memmove(spdy_buff,spdy_buff+spdy_expectlen,spdy_getlen-spdy_expectlen);
        }
        spdy_getlen -= spdy_expectlen;
    } else {
        ssize_t readlen=Read(spdy_buff+spdy_getlen,sizeof(spdy_buff)-spdy_getlen);
        if(readlen <= 0) {
            ErrProc(readlen,stream_id);
            return;
        } else {
            spdy_getlen += readlen;
        }
    }
    (this->*Spdy_Proc)();
}


void Spdy::DataProc() {
    ssize_t readlen=Read(spdy_buff+spdy_getlen,sizeof(spdy_buff)-spdy_getlen);
    if(readlen<=0) {
        ErrProc(readlen,stream_id);
        return;
    }
    spdy_getlen += readlen;
    if(spdy_expectlen) {
        ssize_t writelen=DFrameProc(spdy_buff,Min(spdy_getlen,spdy_expectlen),stream_id);
        if(writelen<0) {
            Spdy_Proc=&Spdy::DropProc;
        }
        if(writelen>0) {
            memmove(spdy_buff,spdy_buff+writelen,spdy_getlen-writelen);
            spdy_expectlen -= writelen;
            spdy_getlen    -= writelen;
        }
    } else if(spdy_flag & FLAG_FIN) {
        DFrameProc(spdy_buff,0,stream_id);
    }
    if(spdy_expectlen==0) {
        if(spdy_flag & FLAG_FIN) {
            DFrameProc(spdy_buff,0,stream_id);
        }
        Spdy_Proc=&Spdy::HeaderProc;
    }
    (this->*Spdy_Proc)();
}



void Spdy::DropProc() {
    if(spdy_getlen >= spdy_expectlen) {
        Spdy_Proc=&Spdy::HeaderProc;
        memmove(spdy_buff,spdy_buff+spdy_expectlen,spdy_getlen-spdy_expectlen);
        spdy_getlen = spdy_getlen-spdy_expectlen;
        spdy_expectlen = 0;
    }else{
        spdy_expectlen -= spdy_getlen;
        ssize_t readlen=Read(spdy_buff,sizeof(spdy_buff));
        if(readlen <= 0) {
            ErrProc(readlen,stream_id);
            return;
        }
        spdy_getlen -= readlen;
    }
    (this->*Spdy_Proc)();
}

