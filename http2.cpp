#include "http2.h"
#include "common.h"

#include <string.h>

Http2::Http2() {
}

void Http2::InitProc() {
    if(http2_getlen >= http2_expectlen) {
        if (memcmp(http2_buff, H2_PREFACE, http2_expectlen)) {
            ErrProc(-1);
            return;
        }
        memmove(http2_buff, http2_buff + http2_expectlen, http2_getlen - http2_expectlen);
        http2_getlen -= http2_expectlen;
        http2_expectlen = 0;
        Http2_Proc = &Http2::DefaultProc;
        Http2_header header;
        memset(&header, 0, sizeof(header));
        header.type = SETTINGS_TYPE;
        Write(&header, sizeof(header));
    } else {
        ssize_t readlen = Read(http2_buff + http2_getlen, sizeof(http2_buff) - http2_getlen);
        if (readlen <= 0) {
            ErrProc(readlen);
            return;
        }
        http2_getlen += readlen;
    }
    (this->*Http2_Proc)();
}



void Http2::DefaultProc() {
    Http2_header *header = (Http2_header *)http2_buff;
    if (http2_expectlen == 0 && http2_getlen >= sizeof(header)) {
        http2_expectlen = sizeof(Http2_header) + get24(header->length);
    }
    //TODO 待优化，改为循环
    if (http2_expectlen && http2_getlen >= http2_expectlen) {
        try {
        switch(header->type) {
            case DATA_TYPE:
                break;
            case HEADERS_TYPE:
                HeadersProc(header);
                break;
            case PRIORITY_TYPE:
                break;
            case SETTINGS_TYPE:
                SettingsProc(header);
                break;
            case PING_TYPE:
                PingProc(header);
                break;
            case RST_STREAM_TYPE:
                RstProc(header);
                break;
            case GOAWAY_TYPE:
                GoawayProc(header);
                break;
            default:
                LOGE("unkown http2 frame:%d\n", header->type);
            }
        }catch(...){
            ErrProc(0);
            return;
        }

        memmove(http2_buff, http2_buff + http2_expectlen, http2_getlen - http2_expectlen);
        http2_getlen -= http2_expectlen;
        http2_expectlen = 0;
    } else {
        ssize_t readlen = Read(http2_buff + http2_getlen, sizeof(http2_buff) - http2_getlen );
        if (readlen <= 0) {
            ErrProc(readlen);
            return;
        }

        http2_getlen += readlen;
    }
    (this->*Http2_Proc)();
}


void Http2::HeadersProc(Http2_header* header) {
    const char *pos = (const char *)(header+1);
    uint8_t padlen = 0;
    if(header->flags & PADDED_F) {
        padlen = *pos++;
    }
    uint32_t streamdep = 0;
    uint8_t weigth = 0;
    if(header->flags & PRIORITY_F) {
        streamdep = get32(pos);
        pos += sizeof(streamdep);
        weigth = *pos++;
    }
    HttpReqHeader req(index_table.hpack_decode(pos, get24(header->length) - padlen - (pos - (const char *)(header+1))));
    req.id = get32(header->id);
    ReqProc(req);
    (void)weigth;
    return;
}


void Http2::SettingsProc(Http2_header* header) {
    SettingFrame *sf = (SettingFrame *)(header + 1);
    if((header->flags & ACK_F) == 0) {
        while((char *)sf-(char *)(header+1) < get24(header->length)){
            switch(get16(sf->identifier)){
            case SETTINGS_HEADER_TABLE_SIZE:
                index_table.set_dynamic_table_size_limit(get32(sf->value));
                break;
            default:
                LOG("Get a unkown setting(%d): %d\n", get16(sf->identifier), get32(sf->value));
                break;
            }
            sf++;
        }
        set24(header->length, 0);
        header->flags |= ACK_F;
        Write(header,sizeof(*header));
    }
}

void Http2::PingProc(Http2_header* header) {
    if((header->flags & ACK_F) == 0) {
        header->flags |= ACK_F;
        Write(header, sizeof(*header) + get24(header->length));
    }
}


void Http2::ReqProc(HttpReqHeader& req) {
    LOG("Get a http request\n");
}

void Http2::ResProc(HttpResHeader& res) {
    LOG("Get a http response\n");
}

void Http2::RstProc(Http2_header* header) {
    LOG("Get a Reset frame\n");
}


void Http2::GoawayProc(Http2_header* header) {
    LOG("Get a Goaway frame\n");
}

