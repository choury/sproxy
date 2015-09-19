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

/* ping 帧永远插到最前面*/
Http2_header *Http2Base::SendFrame(const Http2_header *header, size_t addlen) {
    size_t len = sizeof(Http2_header) + addlen;
    Http2_header *frame = (Http2_header *)malloc(len);
    memcpy(frame, header, len);
    std::list<Http2_header *>::iterator i;
    switch(frame->type){
    case PING_TYPE:
        for(i = framequeue.begin(); i!= framequeue.end() && (*i)->type == PING_TYPE; i++);
        break;
    case DATA_TYPE:
        i = framequeue.end();
        break;
    default:
        auto j = framequeue.rbegin();
        uint32_t id = get32(header->id);
        for(auto j = framequeue.rbegin(); j!= framequeue.rend(); j++){
            if((*j)->type != DATA_TYPE)
                break;
            uint32_t jid = get32((*j)->id);
            if(jid == 0 || jid == id)
                break;
        }
        i = j.base();
        break;
    }
    if(frameleft && i == framequeue.begin())
        i++;
    framequeue.insert(i, frame);
    return frame;
}

//返回1 代表需要继续写，返回2 代表全部内容已发出，返回非正数代表可能出错
size_t Http2Base::Write_Proc(char *wbuff, size_t &writelen){
    if (dataleft && writelen){ //先将data帧的数据写完
        int len = Min(writelen, dataleft);
        int ret = Write(wbuff, len);
        if(ret>0){
            memmove(wbuff, wbuff + ret, writelen - ret);
            writelen -= ret;
            dataleft -= ret;
            if(ret != len){
                return 1;
            }
        }else { 
            return ret;
        }
    }
    if(dataleft == 0 && !framequeue.empty()){  //data帧已写完
        do{
            Http2_header *header = framequeue.front();
            size_t framewritelen;
            if(header->type){
                framewritelen = get24(header->length) + sizeof(Http2_header);
            }else{
                framewritelen = sizeof(Http2_header);
            }
            frameleft = frameleft?frameleft:framewritelen;
            int ret = Write((char *)header+framewritelen-frameleft, frameleft);
            if(ret>0){
                frameleft -= ret;
                if(frameleft == 0 ){
                    size_t len = get24(header->length);
                    framequeue.pop_front();
                    if(header->type == 0 && len){
                        dataleft = len;
                        free(header);
                        return 1;
                    }
                    free(header);
                }
            }else{
                return ret;
            }
        }while(!framequeue.empty());
    }
    return (dataleft == 0 && framequeue.empty()) ? 2 : 1;
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
                AdjustInitalFrameWindowSize(get32(sf->value) - initalframewindowsize);
                initalframewindowsize = get32(sf->value);
                break;
            default:
                LOG("Get a unkown setting(%d): %d\n", get16(sf->identifier), get32(sf->value));
                break;
            }
            sf++;
        }
        set24(header->length, 0);
        header->flags |= ACK_F;
        SendFrame(header, get24(header->length));
    }
}

void Http2Base::PingProc(Http2_header* header) {
    if((header->flags & ACK_F) == 0) {
        header->flags |= ACK_F;
        SendFrame(header, get24(header->length));
    }
}

void Http2Base::GoawayProc(Http2_header* header) {
    LOG("Get a Goaway frame\n");
}

void Http2Base::RstProc(uint32_t id, uint32_t errcode) {
    LOG("Get a reset frame [%d]: %d\n", id, errcode);
}

uint32_t Http2Base::ExpandWindowSize(uint32_t id, uint32_t size) {
    char buff[sizeof(Http2_header)+sizeof(uint32_t)] = {0};
    Http2_header *header = (Http2_header *)buff;
    set32(header->id, id);
    set24(header->length, sizeof(uint32_t));
    header->type = WINDOW_UPDATE_TYPE;
    set32(header+1, size);
    SendFrame(header, sizeof(uint32_t));
    return size;
}

void Http2Base::Ping(const void *buff) {
    char ping[sizeof(Http2_header) + 8] = {0};
    Http2_header *header = (Http2_header *)ping;
    header->type = PING_TYPE;
    set24(header->length, 8);
    memcpy(header+1, buff, 8);
    SendFrame(header, 8);
}


void Http2Base::Reset(uint32_t id, uint32_t code) {
    char rst_stream[sizeof(Http2_header)+sizeof(uint32_t)]={0};
    Http2_header *header = (Http2_header *)rst_stream;
    header->type = RST_STREAM_TYPE;
    set32(header->id, id);
    set24(header->length, sizeof(uint32_t));
    set32(header+1, code);
    SendFrame(header, get24(header->length));
}

void Http2Base::SendInitSetting() {
    char settingframe[sizeof(Http2_header) + sizeof(Setting_Frame)];
    Http2_header *header = (Http2_header *)settingframe;
    Setting_Frame *sf = (Setting_Frame *)(header+1);
    set16(sf->identifier, SETTINGS_INITIAL_WINDOW_SIZE);
    set32(sf->value, 512 * 1024);
    memset(header, 0, sizeof(Http2_header));
    set24(header->length, sizeof(Setting_Frame));
    header->type = SETTINGS_TYPE;
    SendFrame(header, get24(header->length));
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
        SendInitSetting();
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
    Write(H2_PREFACE, strlen(H2_PREFACE));
    SendInitSetting(); 
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
