#include "http2.h"
#include "common.h"

#include <string.h>


void Http2Base::DefaultProc() {
    Http2_header *header = (Http2_header *)http2_buff;
    if (http2_expectlen == 0 && http2_getlen >= sizeof(header)) {
        http2_expectlen = sizeof(Http2_header) + get24(header->length);
    }
    //TODO 待优化，改为循环
    if (http2_expectlen && http2_getlen >= http2_expectlen) {
        try {
        switch(header->type) {
            case DATA_TYPE:
                DataProc2(header);
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


void Http2Base::SettingsProc(Http2_header* header) {
    SettingFrame *sf = (SettingFrame *)(header + 1);
    if((header->flags & ACK_F) == 0) {
        while((char *)sf-(char *)(header+1) < get24(header->length)){
            switch(get16(sf->identifier)){
            case SETTINGS_HEADER_TABLE_SIZE:
                response_table.set_dynamic_table_size_limit(get32(sf->value));
                break;
            default:
                LOG("Get a unkown setting(%d): %d\n", get16(sf->identifier), get32(sf->value));
                break;
            }
            sf++;
        }
        set24(header->length, 0);
        header->flags |= ACK_F;
        Write2(header,sizeof(*header));
    }
}

void Http2Base::PingProc(Http2_header* header) {
    if((header->flags & ACK_F) == 0) {
        header->flags |= ACK_F;
        Write2(header, sizeof(*header) + get24(header->length));
    }
}


void Http2Base::RstProc(Http2_header* header) {
    LOG("Get a reset frame [%d]: %d\n", get32(header->id), get32(header+1));
}


void Http2Base::GoawayProc(Http2_header* header) {
    LOG("Get a Goaway frame\n");
}


void Http2Base::Reset(uint32_t id, uint32_t code) {
    char rst_stream[sizeof(Http2_header)+sizeof(uint32_t)]={0};
    Http2_header *header = (Http2_header *)rst_stream;
    header->type = RST_STREAM_TYPE;
    set32(header->id, id);
    set24(header->length, sizeof(uint32_t));
    set32(header+1, code);
    Write2(rst_stream, sizeof(rst_stream));
}


Http2Res::Http2Res() {
    http2_expectlen = strlen(H2_PREFACE);
}


void Http2Res::InitProc() {
    if(http2_getlen >= http2_expectlen) {
        if (memcmp(http2_buff, H2_PREFACE, http2_expectlen)) {
            ErrProc(ERR_PROTOCOL_ERROR);
            return;
        }
        memmove(http2_buff, http2_buff + http2_expectlen, http2_getlen - http2_expectlen);
        http2_getlen -= http2_expectlen;
        http2_expectlen = 0;
        Http2_Proc = &Http2Res::DefaultProc;
        Http2_header header;
        memset(&header, 0, sizeof(header));
        header.type = SETTINGS_TYPE;
        Write2(&header, sizeof(header));
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



void Http2Res::HeadersProc(Http2_header* header) {
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
    HttpReqHeader req(response_table.hpack_decode(pos, get24(header->length) - padlen - (pos - (const char *)(header+1))));
    req.id = get32(header->id);
    req.flags = header->flags;
    ReqProc(req);
    (void)weigth;
    return;
}



void Http2Req::init() {
    Write2(H2_PREFACE, strlen(H2_PREFACE));
    Http2_header header;
    memset(&header, 0, sizeof(header));
    header.type = SETTINGS_TYPE;
    Write2(&header, sizeof(header));
}



void Http2Req::InitProc() {
    Http2_header *header = (Http2_header *)http2_buff;
    if (http2_expectlen == 0 && http2_getlen >= sizeof(header)) {
        http2_expectlen = sizeof(Http2_header) + get24(header->length);
    }
    if (http2_expectlen && http2_getlen >= http2_expectlen) {
        if(header->type == SETTINGS_TYPE && (header->flags & ACK_F) == 0){
            SettingsProc(header);
            Http2_Proc = &Http2Req::DefaultProc;
        }else {
            ErrProc(ERR_PROTOCOL_ERROR);
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


void Http2Req::HeadersProc(Http2_header* header) {
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
    HttpResHeader res(response_table.hpack_decode(pos, get24(header->length) - padlen - (pos - (const char *)(header+1))));
    res.id = get32(header->id);
    res.flags = header->flags;
    ResProc(res);
    (void)weigth;
    return;
}
