#include "http2.h"
#include "misc/util.h"

//#include <cinttypes>
#include <assert.h>

size_t Http2Base::DefaultProc(const uchar* http2_buff, size_t len) {
    const Http2_header *header = (const Http2_header *)http2_buff;
    if(len < sizeof(Http2_header)){
        if(len)
            LOGD(DHTTP2, "get a incompleted head, size:%zu\n", len);
        return 0;
    }else{
        uint32_t length = get24(header->length);
        if(length > FRAMEBODYLIMIT){
            LOGE("ERROR frame size: %d\n", length);
            ErrProc(ERR_FRAME_SIZE_ERROR);
            return 0;
        }
        if(len < length + sizeof(Http2_header)){
            LOGD(DHTTP2, "get a incompleted packet, size:%zu/%zu\n", len, length + sizeof(Http2_header));
            return 0;
        }else{
            uint32_t id = HTTP2_ID(header->id);
            if(http2_flag & HTTP2_FLAG_GOAWAYED){
                LOG("get a frame [%d]:%d, size:%d after goaway, ignore it.\n", id, header->type, length);
                return length + sizeof(Http2_header);
            }
            LOGD(DHTTP2, "get a frame [%d]:%d, size:%d, flags:%d\n", id, header->type, length, header->flags);
            try {
                uint32_t value;
                switch(header->type) {
                case DATA_TYPE:
                    if(id == 0 || (id > recvid && id >= sendid-1)){
                        LOGE("ERROR wrong data id: %d/%d/%d\n", id, recvid, sendid);
                        ErrProc(ERR_PROTOCOL_ERROR);
                        return 0;
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
                    if(id != 0 && (http2_flag & HTTP2_SUPPORT_SHUTDOWN) == 0){
                        LOGE("ERROR wrong setting id: %d\n", id);
                        ErrProc(ERR_PROTOCOL_ERROR);
                        return 0;
                    }
                    if(length%6 != 0){
                        LOGE("ERROR wrong setting length: %d\n", length);
                        ErrProc(ERR_PROTOCOL_ERROR);
                        return 0;
                    }
                    SettingsProc(header);
                    break;
                case PING_TYPE:
                    if(id != 0 || length != 8){
                        LOGE("ERROR wrong ping frame: %d/%d\n", id, length);
                        ErrProc(ERR_FRAME_SIZE_ERROR);
                        return 0;
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
                        return 0;
                    }
                    if(id == 0 || (id > recvid && id >= sendid-1)){
                        LOGE("ERROR rst frame: %d/%d/%d\n", id, sendid, recvid);
                        ErrProc(ERR_PROTOCOL_ERROR);
                        return 0;
                    }
                    RstProc(id, value);
                    break;
                case WINDOW_UPDATE_TYPE:
                    value = get32(header+1);
                    if(length != 4){
                        LOGE("ERROR window update frame: %d/%d\n", id, length);
                        ErrProc(ERR_FRAME_SIZE_ERROR);
                        return 0;
                    }
                    if(value == 0 || (id > recvid && id >= sendid-1)){
                        LOGE("ERROR window update frame: value=%d id=%d/%d/%d\n", value, id, sendid, recvid);
                        ErrProc(ERR_PROTOCOL_ERROR);
                        return 0;
                    }
                    WindowUpdateProc(id, value);
                    break;
                default:
                    LOGE("unkown http2 frame:%d\n", header->type);
                }
            }catch(...){
                Reset(id, ERR_INTERNAL_ERROR);
                return 0;
            }
            return length + sizeof(Http2_header);
        }
    }
}

/* ping 帧永远插到最前面*/
void Http2Base::PushFrame(Http2_header *header){
    uint32_t id = HTTP2_ID(header->id);
    LOGD(DHTTP2, "push a frame [%d]:%d, size:%d, flags: %d\n", id, header->type, get24(header->length), header->flags);
    std::list<write_block>::insert_iterator i;
    if((http2_flag & HTTP2_FLAG_INITED) == 0){
        i = queue_end();
        goto ret;
    }
    switch(header->type){
    case PING_TYPE:
        for(i = queue_head(); i!= queue_end() ; i++){
            if(i->offset){
                continue;
            }
            const Http2_header* check = (const Http2_header*)i->buff;
            if(check->type != PING_TYPE){
                break;
            }
        }
        break;
    case HEADERS_TYPE:{
        auto j = queue_end();
        do{
            i = j--;
            if(j == queue_head() || j->offset){
                break;
            }

            const Http2_header* check = (const Http2_header*)j->buff;
            if(check->type != DATA_TYPE)
                break;
            uint32_t jid = HTTP2_ID(check->id);
            if(jid == 0 || jid == id)
                break;
        }while(true);
        break;
    }
    default:
        i = queue_end();
        break;
    }
ret:
    size_t length = sizeof(Http2_header) + get24(header->length);
    assert(i == queue_end() || i == queue_head() || i->offset == 0);
    queue_insert(i, write_block{header, length, 0});
}

void Http2Base::PushData(uint32_t id, const void* data, size_t size){
    size_t left = size;
    while(left > remoteframebodylimit){
        Http2_header* const header=(Http2_header *)p_move(p_malloc(remoteframebodylimit), -(char)sizeof(Http2_header));
        memset(header, 0, sizeof(Http2_header));
        set32(header->id, id);
        set24(header->length, remoteframebodylimit);
        memcpy(header+1, data, remoteframebodylimit);
        PushFrame(header);
        data = (char*)data + remoteframebodylimit;
        left -= remoteframebodylimit;
    }
    Http2_header* const header=(Http2_header *)p_move(p_malloc(left), -(char)sizeof(Http2_header));
    memset(header, 0, sizeof(Http2_header));
    set32(header->id, id);
    set24(header->length, left);
    if(size == 0) {
        header->flags = END_STREAM_F;
    }else{
        memcpy(header+1, data, left);
    }
    PushFrame(header);
}


#if 0

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

#endif

void Http2Base::SettingsProc(const Http2_header* header) {
    uint32_t id = HTTP2_ID(header->id);
    const Setting_Frame *sf = (const Setting_Frame *)(header + 1);
    if((header->flags & ACK_F) == 0) {
        while((char *)sf-(char *)(header+1) < get24(header->length)){
            uint32_t value = get32(sf->value);
            switch(get16(sf->identifier)){
            case SETTINGS_HEADER_TABLE_SIZE:
                LOGD(DHTTP2, "set head table size:%d\n", value);
                request_table.set_dynamic_table_size_limit_max(value);
                break;
            case SETTINGS_INITIAL_WINDOW_SIZE:
                if(value >= (uint32_t)1<<31u){
                    LOGE("ERROR window overflow\n");
                    ErrProc(ERR_FLOW_CONTROL_ERROR);
                    return;
                }
                AdjustInitalFrameWindowSize((ssize_t)value - (ssize_t)remoteframewindowsize);
                remoteframewindowsize = value;
                LOGD(DHTTP2, "set inital frame window size:%d\n", remoteframewindowsize);
                break;
            case SETTINGS_MAX_FRAME_SIZE:
                if(value > 0xffffff || value < FRAMEBODYLIMIT){
                    LOGE("ERROR frame size overflow\n");
                    ErrProc(ERR_FRAME_SIZE_ERROR);
                    return;
                }
                remoteframebodylimit = value;
                LOGD(DHTTP2, "set frame body size limit: %d\n", remoteframebodylimit);
                break;
            case SETTINGS_ENABLE_PUSH:
            case SETTINGS_MAX_CONCURRENT_STREAMS:
            case SETTINGS_MAX_HEADER_LIST_SIZE:
                LOG("Get a unimplemented setting(%d): %d\n", get16(sf->identifier), value);
                break;
            case SETTINGS_PEER_SHUTDOWN:
                if(id == 0) {
                    http2_flag |= HTTP2_SUPPORT_SHUTDOWN;
                    LOGD(DHTTP2, "set shutdown enabled\n");
                }else{
                    ShutdownProc(id);
                }
                break;
            default:
                LOG("Get a unknown setting(%d): %d\n", get16(sf->identifier), value);
                break;
            }
            sf++;
        }
        Http2_header *header_back = (Http2_header *)p_memdup(header, sizeof(Http2_header));
        set24(header_back->length, 0);
        header_back->flags |= ACK_F;
        PushFrame(header_back);
    }else if(get24(header->length) != 0){
        LOGE("ERROR setting ack with content\n");
        ErrProc(ERR_FRAME_SIZE_ERROR);
    }
}

void Http2Base::PingProc(const Http2_header* header) {
    if((header->flags & ACK_F) == 0) {
        Http2_header *header_back = (Http2_header *)p_memdup(header, sizeof(Http2_header) + get24(header->length));
        header_back->flags |= ACK_F;
        PushFrame(header_back);
    }
}

void Http2Base::GoawayProc(const Http2_header*) {
    LOGD(DHTTP2, "Get a Goaway frame\n");
}

void Http2Base::RstProc(__attribute__ ((unused)) uint32_t id, __attribute__ ((unused)) uint32_t errcode) {
    LOGD(DHTTP2, "Get a reset frame [%d]: %d\n", id, errcode);
}

void Http2Base::EndProc(__attribute__ ((unused)) uint32_t id) {
    LOGD(DHTTP2, "Stream end: %d\n", id);
}

void Http2Base::ShutdownProc(__attribute__ ((unused)) uint32_t id) {
    LOGD(DHTTP2, "Stream shutdown: %d\n", id);
}

uint32_t Http2Base::ExpandWindowSize(uint32_t id, uint32_t size) {
    LOGD(DHTTP2, "will expand window size [%d]: %d\n", id, size);
    Http2_header* const header = (Http2_header *)p_malloc(sizeof(Http2_header)+sizeof(uint32_t));
    memset(header, 0, sizeof(Http2_header));
    set32(header->id, id);
    set24(header->length, sizeof(uint32_t));
    header->type = WINDOW_UPDATE_TYPE;
    set32(header+1, size);
    PushFrame(header);
    return size;
}

void Http2Base::Ping(const void *buff) {
    Http2_header* const header = (Http2_header *)p_malloc(sizeof(Http2_header) + 8);
    memset(header, 0, sizeof(Http2_header));
    header->type = PING_TYPE;
    set24(header->length, 8);
    memcpy(header+1, buff, 8);
    PushFrame(header);
}


void Http2Base::Reset(uint32_t id, uint32_t code) {
    Http2_header* const header = (Http2_header *)p_malloc(sizeof(Http2_header)+sizeof(uint32_t));
    memset(header, 0, sizeof(Http2_header));
    header->type = RST_STREAM_TYPE;
    set32(header->id, id);
    set24(header->length, sizeof(uint32_t));
    set32(header+1, code);
    PushFrame(header);
}

void Http2Base::Shutdown(uint32_t id) {
    assert(http2_flag & HTTP2_SUPPORT_SHUTDOWN);
    Http2_header* const header = (Http2_header *)p_malloc(sizeof(Http2_header) + sizeof(Setting_Frame));
    memset(header, 0, sizeof(Http2_header));
    set32(header->id, id);
    set24(header->length, sizeof(Setting_Frame));
    header->type = SETTINGS_TYPE;

    Setting_Frame *sf = (Setting_Frame *)(header+1);
    set16(sf->identifier, SETTINGS_PEER_SHUTDOWN);
    set32(sf->value, 0);
    PushFrame(header);
}

void Http2Base::Goaway(uint32_t lastid, uint32_t code, char *message) {
    http2_flag |= HTTP2_FLAG_GOAWAYED;
    size_t len = sizeof(Goaway_Frame);
    if(message){
        len += strlen(message)+1;
    }
    Http2_header* const header = (Http2_header *)p_malloc(sizeof(Http2_header)+len);
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
    Http2_header* const header = (Http2_header *)p_malloc(sizeof(Http2_header) + 3*sizeof(Setting_Frame));
    memset(header, 0, sizeof(Http2_header));
    Setting_Frame *sf = (Setting_Frame *)(header+1);
    set16(sf->identifier, SETTINGS_HEADER_TABLE_SIZE );
    set32(sf->value, 65536);
    response_table.set_dynamic_table_size_limit_max(get32(sf->value));
    sf++;
    set16(sf->identifier, SETTINGS_INITIAL_WINDOW_SIZE);
    set32(sf->value, localframewindowsize);
    LOGD(DHTTP2, "send inital frame window size:%d\n", localframewindowsize);

    sf++;
    set16(sf->identifier, SETTINGS_PEER_SHUTDOWN);
    set32(sf->value, 0);

    set24(header->length, 3*sizeof(Setting_Frame));
    header->type = SETTINGS_TYPE;
    PushFrame(header);
}

uint32_t Http2Base::GetSendId(){
    uint32_t id = sendid;
    sendid += 2;
    return id;
}

Http2Base::~Http2Base() = default;

size_t Http2Responser::InitProc(const uchar* http2_buff, size_t len) {
    size_t prelen = strlen(H2_PREFACE);
    if(len < prelen) {
        return 0;
    }else{
        if (memcmp(http2_buff, H2_PREFACE, strlen(H2_PREFACE)) != 0) {
            LOGE("ERROR get http2 perface: %.*s\n", (int)len, http2_buff);
            ErrProc(ERR_PROTOCOL_ERROR);
            return 0;
        }
        SendInitSetting();
        http2_flag |= HTTP2_FLAG_INITED;
        Http2_Proc = &Http2Responser::DefaultProc;
        return prelen + DefaultProc(http2_buff+prelen, len-prelen);
    }
}

void Http2Responser::HeadersProc(const Http2_header* header) {
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
        HttpReqHeader* req =
                new HttpReqHeader(response_table.hpack_decode(pos,
                        get24(header->length) - padlen - (pos - (const unsigned char *)(header+1))));
        ReqProc(id, req);
    }catch(int error){
        ErrProc(error);
        return;
    }
    (void)weigth;
    (void)streamdep;
}


void Http2Requster::init() {
    queue_insert(queue_head(),
                 write_block{p_strdup(H2_PREFACE), sizeof(H2_PREFACE)-1, 0}
                );
    SendInitSetting(); 
}



size_t Http2Requster::InitProc(const uchar* http2_buff, size_t len) {
    const Http2_header *header = (const Http2_header *)http2_buff;
    if(len < sizeof(Http2_header)){
        return 0;
    }else{
        size_t length = sizeof(Http2_header) + get24(header->length);
        if(len < length){
            return 0;
        }else{
            if(header->type == SETTINGS_TYPE && (header->flags & ACK_F) == 0){
                SettingsProc(header);
                http2_flag |=  HTTP2_FLAG_INITED;
                Http2_Proc = &Http2Requster::DefaultProc;
                return length + DefaultProc(http2_buff+length, len-length);
            }else {
                LOGE("ERROR get wrong setting frame from server\n");
                ErrProc(ERR_PROTOCOL_ERROR);
                return 0;
            }
        }
    }
}


void Http2Requster::HeadersProc(const Http2_header* header) {
    uint32_t id = HTTP2_ID(header->id);
    if(id >= sendid-1 || (id&1u) == 0){
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
        ResProc(id, res);
    }catch(int error){
        ErrProc(error);
        return;
    }
    (void)weigth;
    (void)streamdep;
}
