#include "http2.h"
#include "common.h"

#include <string.h>


void Http2Base::DefaultProc() {
    Http2_header *header = (Http2_header *)http2_buff;
    if(http2_getlen < sizeof(Http2_header)){
        ssize_t len = sizeof(Http2_header) - http2_getlen;
        len = Read(http2_buff + http2_getlen, len);
        if (len <= 0) {
            ErrProc(len);
            return;
        }
        http2_getlen += len;
    }else{
        ssize_t len = sizeof(Http2_header) + get24(header->length) - http2_getlen;
        if(len == 0){
            try {
                switch(header->type) {
                case DATA_TYPE:
                    DataProc(header);
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
                case GOAWAY_TYPE:
                    GoawayProc(header);
                    break;
                case RST_STREAM_TYPE:
                    RstProc(get32(header->id), get32(header+1));
                    break;
                case WINDOW_UPDATE_TYPE:
                    WindowUpdateProc(get32(header->id), get32(header+1));
                    break;
                default:
                    LOGE("unkown http2 frame:%d\n", header->type);
                }
            }catch(...){
                Reset(get32(header->id), ERR_INTERNAL_ERROR);
                http2_getlen = 0;
                return;
            }
            http2_getlen = 0;
        }else{
            len = Read(http2_buff + http2_getlen, len);
            if (len <= 0) {
                ErrProc(len);
                return;
            }
            http2_getlen += len;
        }
    }
    (this->*Http2_Proc)();
}

/* ping 帧永远插到最前面*/
void Http2Base::SendFrame(Http2_header *header) {
    std::list<Http2_frame>::iterator i;
    switch(header->type){
    case PING_TYPE:
        for(i = framequeue.begin(); i!= framequeue.end() && i->header->type == PING_TYPE; ++i);
        break;
    case DATA_TYPE:
        i = framequeue.end();
        break;
    default:
        auto j = framequeue.rbegin();
        uint32_t id = get32(header->id);
        for(; j!= framequeue.rend(); j++){
            if(j->header->type != DATA_TYPE)
                break;
            uint32_t jid = get32(j->header->id);
            if(jid == 0 || jid == id)
                break;
        }
        i = j.base();
        break;
    }
    if(!framequeue.empty() && i == framequeue.begin()) //jump the first frame to avoid ssl invalid write retry error
        ++i;
    Http2_frame frame={header, 0};
    framequeue.insert(i, frame);
}

void Http2Base::SendFrame(const Http2_header *header) {
    size_t len = sizeof(Http2_header) + get24(header->length);
    Http2_header *dup_header = (Http2_header *)malloc(len);
    memcpy(dup_header, header, len);
    return SendFrame(dup_header);
}


int Http2Base::Write_Proc(){
    while(!framequeue.empty()){
        Http2_frame *frame = &framequeue.front();
        size_t len = sizeof(Http2_header) + get24(frame->header->length);
        ssize_t ret = Write((char *)frame->header + frame->wlen, len - frame->wlen);

        if (ret <= 0) {
            return ret;
        }

        if ((size_t)ret + frame->wlen == len) {
            free(frame->header);
            framequeue.pop_front();
        } else {
            frame->wlen += ret;
            break;
        }
    }
    return 1;
}

void Http2Base::SettingsProc(Http2_header* header) {
    Setting_Frame *sf = (Setting_Frame *)(header + 1);
    if((header->flags & ACK_F) == 0) {
        while((char *)sf-(char *)(header+1) < get24(header->length)){
            switch(get16(sf->identifier)){
            case SETTINGS_HEADER_TABLE_SIZE:
                response_table.set_dynamic_table_size_limit(get32(sf->value));
                break;
            case SETTINGS_INITIAL_WINDOW_SIZE:
                AdjustInitalFrameWindowSize(get32(sf->value) - remoteframewindowsize);
                remoteframewindowsize = get32(sf->value);
                break;
            default:
                LOG("Get a unkown setting(%d): %d\n", get16(sf->identifier), get32(sf->value));
                break;
            }
            sf++;
        }
        set24(header->length, 0);
        header->flags |= ACK_F;
        SendFrame((const Http2_header*)header);
    }
}

void Http2Base::PingProc(Http2_header* header) {
    if((header->flags & ACK_F) == 0) {
        header->flags |= ACK_F;
        SendFrame((const Http2_header *)header);
    }
}

void Http2Base::GoawayProc(Http2_header* header) {
    LOG("Get a Goaway frame\n");
}

void Http2Base::RstProc(uint32_t id, uint32_t errcode) {
    LOG("Get a reset frame [%d]: %d\n", id, errcode);
}

uint32_t Http2Base::ExpandWindowSize(uint32_t id, uint32_t size) {
    Http2_header *header = (Http2_header *)malloc(sizeof(Http2_header)+sizeof(uint32_t));
    memset(header, 0, sizeof(Http2_header));
    set32(header->id, id);
    set24(header->length, sizeof(uint32_t));
    header->type = WINDOW_UPDATE_TYPE;
    set32(header+1, size);
    SendFrame(header);
    return size;
}

void Http2Base::Ping(const void *buff) {
    Http2_header *header = (Http2_header *)malloc(sizeof(Http2_header) + 8);
    memset(header, 0, sizeof(Http2_header));
    header->type = PING_TYPE;
    set24(header->length, 8);
    memcpy(header+1, buff, 8);
    SendFrame(header);
}


void Http2Base::Reset(uint32_t id, uint32_t code) {
    Http2_header *header = (Http2_header *)malloc(sizeof(Http2_header)+sizeof(uint32_t));
    memset(header, 0, sizeof(Http2_header));
    header->type = RST_STREAM_TYPE;
    set32(header->id, id);
    set24(header->length, sizeof(uint32_t));
    set32(header+1, code);
    SendFrame(header);
}

void Http2Base::SendInitSetting() {
    Http2_header *header = (Http2_header *)malloc(sizeof(Http2_header) + sizeof(Setting_Frame));
    memset(header, 0, sizeof(Http2_header));
    Setting_Frame *sf = (Setting_Frame *)(header+1);
    set16(sf->identifier, SETTINGS_INITIAL_WINDOW_SIZE);
    set32(sf->value, localframewindowsize);

    set24(header->length, sizeof(Setting_Frame));
    header->type = SETTINGS_TYPE;
    SendFrame(header);
}

Http2Base::~Http2Base()
{
    while(!framequeue.empty()){
        free(framequeue.front().header);
        framequeue.pop_front();
    }
}


void Http2Res::InitProc() {
    size_t prelen = strlen(H2_PREFACE);
    if(http2_getlen >= prelen) {
        if (memcmp(http2_buff, H2_PREFACE, strlen(H2_PREFACE))) {
            ErrProc(ERR_PROTOCOL_ERROR);
            return;
        }
        http2_getlen = 0;
        Http2_Proc = &Http2Res::DefaultProc;
        SendInitSetting();
    } else {
        ssize_t readlen = Read(http2_buff + http2_getlen, prelen - http2_getlen);
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
    HttpReqHeader req(response_table.hpack_decode(pos,
                                                  get24(header->length) - padlen - (pos - (const char *)(header+1))),
                      shared_from_this());
    req.http_id = get32(header->id);
    req.flags = header->flags;
    ReqProc(req);
    (void)weigth;
    (void)streamdep;
    return;
}


void Http2Req::init() {
    Write(H2_PREFACE, strlen(H2_PREFACE));
    SendInitSetting(); 
}



void Http2Req::InitProc() {
    Http2_header *header = (Http2_header *)http2_buff;
    if(http2_getlen < sizeof(Http2_header)){
        ssize_t len = sizeof(Http2_header) - http2_getlen;
        len = Read(http2_buff + http2_getlen, len);
        if (len <= 0) {
            ErrProc(len);
            return;
        }
        http2_getlen += len;
    }else{
        ssize_t len = sizeof(Http2_header) + get24(header->length) - http2_getlen;
        if(len == 0){
            if(header->type == SETTINGS_TYPE && (header->flags & ACK_F) == 0){
                SettingsProc(header);
                Http2_Proc = &Http2Req::DefaultProc;
            }else {
                ErrProc(ERR_PROTOCOL_ERROR);
                return;
            }
            http2_getlen = 0;
        }else{
            len = Read(http2_buff + http2_getlen, len);
            if (len <= 0) {
                ErrProc(len);
                return;
            }
            http2_getlen += len;
        }
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
    HttpResHeader res(response_table.hpack_decode(pos,
                                                  get24(header->length) - padlen - (pos - (const char *)(header+1))),
                      shared_from_this());
    res.http_id = get32(header->id);
    res.flags = header->flags;
    ResProc(res);
    (void)weigth;
    (void)streamdep;
    return;
}
