#include "http2.h"
#include "misc/util.h"

void Http2Base::DefaultProc() {
    Http2_header *header = (Http2_header *)http2_buff;
begin:
    if(http2_getlen < sizeof(Http2_header)){
        ssize_t len = sizeof(Http2_header) - http2_getlen;
        len = Read(http2_buff + http2_getlen, len);
        if (len <= 0) {
            ErrProc(len);
            return;
        }
        http2_getlen += len;
    }else{
        uint32_t length = get24(header->length);
        ssize_t len = sizeof(Http2_header) + length - http2_getlen;
        if(length > FRAMEBODYLIMIT){
            LOGE("ERROR frame size: %d\n", length);
            ErrProc(ERR_FRAME_SIZE_ERROR);
            return;
        }
        if(len == 0){
            uint32_t id = HTTP2_ID(header->id);
            if(http2_flag & HTTP2_FLAG_GOAWAYED){
                LOG("get a frame [%d]:%d, size:%d after goaway, ignore it.\n", id, header->type, length);
                http2_getlen = 0;
                return;
            }
            LOGD(DHTTP2, "get a frame [%d]:%d, size:%d\n", id, header->type, length);
            try {
                uint32_t value;
                switch(header->type) {
                case DATA_TYPE:
                    if(id == 0 || (id > recvid && id >= sendid-1)){
                        LOGE("ERROR wrong data id: %d/%d/%d\n", id, recvid, sendid);
                        ErrProc(ERR_PROTOCOL_ERROR);
                        return;
                    }
                    DataProc(id, header+1, length);
                    if(header->flags & END_STREAM_F){
                        EndProc(id);
                    }
                    break;
                case HEADERS_TYPE:
                    HeadersProc(header);
                    if(header->flags & END_STREAM_F){
                        EndProc(id);
                    }
                    break;
                case PRIORITY_TYPE:
                    break;
                case SETTINGS_TYPE:
                    if(id != 0 || length%6 != 0){
                        LOGE("ERROR wrong setting frame : %d/%d\n", id, length);
                        ErrProc(ERR_PROTOCOL_ERROR);
                        return;
                    }
                    SettingsProc(header);
                    break;
                case PING_TYPE:
                    if(id != 0 || length != 8){
                        LOGE("ERROR wrong ping frame: %d/%d\n", id, length);
                        ErrProc(ERR_FRAME_SIZE_ERROR);
                        return;
                    }
                    PingProc(header);
                    break;
                case GOAWAY_TYPE:
                    GoawayProc(header);
                    break;
                case RST_STREAM_TYPE:
                    value = get32(header+1);
                    if(length != 4){
                        LOGE("ERROR rst frame: %d/%d\n", id, length);
                        ErrProc(ERR_FRAME_SIZE_ERROR);
                        return;
                    }
                    if(id == 0 || (id > recvid && id >= sendid-1)){
                        LOGE("ERROR rst frame: %d/%d/%d\n", id, sendid, recvid);
                        ErrProc(ERR_PROTOCOL_ERROR);
                        return;
                    }
                    RstProc(id, value);
                    break;
                case WINDOW_UPDATE_TYPE:
                    value = get32(header+1);
                    if(length != 4){
                        LOGE("ERROR window update frame: %d/%d\n", id, length);
                        ErrProc(ERR_FRAME_SIZE_ERROR);
                        return;
                    }
                    if(value == 0 || (id > recvid && id >= sendid-1)){
                        LOGE("ERROR window update frame: value=%d id=%d/%d/%d\n", value, id, sendid, recvid);
                        ErrProc(ERR_PROTOCOL_ERROR);
                        return;
                    }
                    WindowUpdateProc(id, value);
                    break;
                default:
                    LOGE("unkown http2 frame:%d\n", header->type);
                }
            }catch(...){
                Reset(id, ERR_INTERNAL_ERROR);
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
    goto begin;
}

/* ping 帧永远插到最前面*/
void Http2Base::PushFrame(Http2_header *header) {
    uint32_t id = HTTP2_ID(header->id);
    LOGD(DHTTP2, "push a frame [%d]:%d, size:%d\n", id, header->type, get24(header->length));
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
        for(; j!= framequeue.rend(); j++){
            if(j->header->type != DATA_TYPE)
                break;
            uint32_t jid = HTTP2_ID(j->header->id);
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
    framelen += sizeof(Http2_header) + get24(header->length);
}

void Http2Base::PushFrame(const Http2_header *header) {
    size_t len = sizeof(Http2_header) + get24(header->length);
    Http2_header *dup_header = (Http2_header *)p_memdup(header, len);
    return PushFrame(dup_header);
}

int Http2Base::SendFrame(){
    while(!framequeue.empty()){
        Http2_frame& frame = framequeue.front();
        size_t len = sizeof(Http2_header) + get24(frame.header->length);
        assert(get24(frame.header->length) <= FRAMEBODYLIMIT);
        ssize_t ret = Write((char *)frame.header + frame.wlen, len - frame.wlen);

        if (ret <= 0) {
            return ret;
        }

        framelen -= ret;
        if ((size_t)ret + frame.wlen == len) {
            p_free(frame.header);
            framequeue.pop_front();
        } else {
            frame.wlen += ret;
            break;
        }
    }
    return 1;
}

void Http2Base::SettingsProc(Http2_header* header) {
    Setting_Frame *sf = (Setting_Frame *)(header + 1);
    if((header->flags & ACK_F) == 0) {
        while((char *)sf-(char *)(header+1) < get24(header->length)){
            uint32_t value = get32(sf->value);
            switch(get16(sf->identifier)){
            case SETTINGS_HEADER_TABLE_SIZE:
                LOGD(DHTTP2, "set head table size:%d\n", value);
                request_table.set_dynamic_table_size_limit_max(value);
                break;
            case SETTINGS_INITIAL_WINDOW_SIZE:
                if(value >= (uint32_t)1<<31){
                    LOGE("ERROR window overflow\n");
                    ErrProc(ERR_FLOW_CONTROL_ERROR);
                    return;
                }
                AdjustInitalFrameWindowSize(value - remoteframewindowsize);
                remoteframewindowsize = value;
                LOGD(DHTTP2, "set inital frame window size:%d\n", remoteframewindowsize);
                break;
            default:
                LOG("Get a unkown setting(%d): %d\n", get16(sf->identifier), value);
                break;
            }
            sf++;
        }
        set24(header->length, 0);
        header->flags |= ACK_F;
        PushFrame((const Http2_header*)header);
    }else if(get24(header->length) != 0){
        LOGE("ERROR setting ack with content\n");
        ErrProc(ERR_FRAME_SIZE_ERROR);
        return;
    }
}

void Http2Base::PingProc(Http2_header* header) {
    if((header->flags & ACK_F) == 0) {
        header->flags |= ACK_F;
        PushFrame((const Http2_header *)header);
    }
}

void Http2Base::GoawayProc(Http2_header* header) {
    LOGD(DHTTP2, "Get a Goaway frame\n");
}

void Http2Base::RstProc(uint32_t id, uint32_t errcode) {
    LOGD(DHTTP2, "Get a reset frame [%d]: %d\n", id, errcode);
}

void Http2Base::EndProc(uint32_t id) {
    LOGD(DHTTP2, "Stream end: %d\n", id);
}

uint32_t Http2Base::ExpandWindowSize(uint32_t id, uint32_t size) {
    LOGD(DHTTP2, "will expand window size [%d]: %d\n", id, size);
    Http2_header *header = (Http2_header *)p_malloc(sizeof(Http2_header)+sizeof(uint32_t));
    memset(header, 0, sizeof(Http2_header));
    set32(header->id, id);
    set24(header->length, sizeof(uint32_t));
    header->type = WINDOW_UPDATE_TYPE;
    set32(header+1, size);
    PushFrame(header);
    return size;
}

void Http2Base::Ping(const void *buff) {
    Http2_header *header = (Http2_header *)p_malloc(sizeof(Http2_header) + 8);
    memset(header, 0, sizeof(Http2_header));
    header->type = PING_TYPE;
    set24(header->length, 8);
    memcpy(header+1, buff, 8);
    PushFrame(header);
}


void Http2Base::Reset(uint32_t id, uint32_t code) {
    Http2_header *header = (Http2_header *)p_malloc(sizeof(Http2_header)+sizeof(uint32_t));
    memset(header, 0, sizeof(Http2_header));
    header->type = RST_STREAM_TYPE;
    set32(header->id, id);
    set24(header->length, sizeof(uint32_t));
    set32(header+1, code);
    PushFrame(header);
}

void Http2Base::Goaway(uint32_t lastid, uint32_t code, char *message) {
    http2_flag |= HTTP2_FLAG_GOAWAYED;
    size_t len = sizeof(Goaway_Frame);
    if(message){
        len += strlen(message)+1;
    }
    Http2_header *header = (Http2_header *)p_malloc(sizeof(Http2_header)+len);
    memset(header, 0, sizeof(Http2_header));
    set24(header->length, len);
    header->type = GOAWAY_TYPE;
    Goaway_Frame *goaway = (Goaway_Frame*)(header+1);
    set32(goaway->last_stream_id, lastid);
    set32(goaway->errcode, code);
    if(message){
        strcpy((char *)goaway->data, message);
    }
    PushFrame(header);
}


void Http2Base::SendInitSetting() {
    Http2_header *header = (Http2_header *)p_malloc(sizeof(Http2_header) + 2*sizeof(Setting_Frame));
    memset(header, 0, sizeof(Http2_header));
    Setting_Frame *sf = (Setting_Frame *)(header+1);
    set16(sf->identifier, SETTINGS_HEADER_TABLE_SIZE );
    set32(sf->value, 65536);
    response_table.set_dynamic_table_size_limit_max(get32(sf->value));
    sf++;
    set16(sf->identifier, SETTINGS_INITIAL_WINDOW_SIZE);
    set32(sf->value, localframewindowsize);

    set24(header->length, 2*sizeof(Setting_Frame));
    header->type = SETTINGS_TYPE;
    PushFrame(header);
}

uint32_t Http2Base::GetSendId(){
    uint32_t id = sendid;
    sendid += 2;
    return id;
}

Http2Base::~Http2Base()
{
    while(!framequeue.empty()){
        p_free(framequeue.front().header);
        framequeue.pop_front();
    }
}


void Http2Responser::InitProc() {
    size_t prelen = strlen(H2_PREFACE);
    if(http2_getlen >= prelen) {
        if (memcmp(http2_buff, H2_PREFACE, strlen(H2_PREFACE))) {
            LOGE("ERROR get http2 perface: %*s\n", (int)prelen, http2_buff);
            ErrProc(ERR_PROTOCOL_ERROR);
            return;
        }
        http2_getlen = 0;
        SendInitSetting();
        http2_flag |= HTTP2_FLAG_INITED;
        Http2_Proc = &Http2Responser::DefaultProc;
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

void Http2Responser::HeadersProc(Http2_header* header) {
    uint32_t id = HTTP2_ID(header->id);
    if(id <= recvid || (id&1) == 0){
        LOGE("ERROR header id: %d/%d\n", id, recvid);
        ErrProc(ERR_STREAM_CLOSED);
        return;
    }
    recvid = id;
    const unsigned char *pos = (const unsigned char *)(header+1);
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
    try{
        HttpReqHeader* req = new HttpReqHeader(response_table.hpack_decode(pos,
                                                    get24(header->length) - padlen - (pos - (const unsigned char *)(header+1))),
                        this);
        req->index = reinterpret_cast<void*>(id);
        ReqProc(req);
    }catch(int error){
        ErrProc(error);
        return;
    }
    (void)weigth;
    (void)streamdep;
    return;
}


void Http2Requster::init() {
    int __attribute__((unused)) ret=Write(H2_PREFACE, strlen(H2_PREFACE));
    assert(ret == strlen(H2_PREFACE));
    SendInitSetting(); 
}



void Http2Requster::InitProc() {
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
                http2_flag |=  HTTP2_FLAG_INITED;
                Http2_Proc = &Http2Requster::DefaultProc;
            }else {
                LOGE("ERROR get wrong setting frame from server\n");
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


void Http2Requster::HeadersProc(Http2_header* header) {
    uint32_t id = HTTP2_ID(header->id);
    if(id >= sendid-1 || (id&1) == 0){
        LOGE("ERROR header id: %d/%d\n", id, sendid);
        ErrProc(ERR_STREAM_CLOSED);
        return;
    }
    const unsigned char *pos = (const unsigned char *)(header+1);
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
    try{
        HttpResHeader* res = new HttpResHeader(response_table.hpack_decode(pos,
                                                    get24(header->length) - padlen - (pos - (const unsigned char *)(header+1))));

        res->index = reinterpret_cast<void*>(id);
        ResProc(res);
    }catch(int error){
        ErrProc(error);
        return;
    }
    (void)weigth;
    (void)streamdep;
    return;
}
