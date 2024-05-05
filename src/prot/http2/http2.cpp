#include "http2.h"
#include "misc/util.h"

//#include <cinttypes>
#include <assert.h>

size_t Http2Base::DefaultProc(const uchar* http2_buff, size_t len) {
    const Http2_header *header = (const Http2_header *)http2_buff;
    if(len < sizeof(Http2_header)){
        if(len)LOGD(DHTTP2, "get a incompleted head, size:%zu\n", len);
        return 0;
    }
    uint32_t length = get24(header->length);
    uint32_t id = HTTP2_ID(header->id);
    LOGD(DHTTP2, "get a frame [%d]:%d, size:%d, flags:%d\n", id, header->type, length, header->flags);
    if(length > FRAMEBODYLIMIT){
        LOGE("ERROR frame size: %d\n", length);
        ErrProc(HTTP2_ERR_FRAME_SIZE_ERROR);
        return 0;
    }
    if(len < length + sizeof(Http2_header)){
        LOGD(DHTTP2, "get a incompleted packet, size:%zu/%zu\n", len, length + sizeof(Http2_header));
        return 0;
    }
    if(http2_flag & HTTP2_FLAG_GOAWAYED){
        LOG("get a frame [%d]:%d, size:%d after goaway, ignore it.\n", id, header->type, length);
        return length + sizeof(Http2_header);
    }
    switch(header->type) {
        uint32_t value;
    case HTTP2_STREAM_DATA: {
        if (id == 0 || (id > recvid && id >= sendid - 1)) {
            LOGE("ERROR wrong data id: %d/%d/%d\n", id, recvid, sendid);
            ErrProc(HTTP2_ERR_PROTOCOL_ERROR);
            return 0;
        }
        char* pos = (char*)(header + 1);
        uint8_t padlen = 0;
        if (header->flags & HTTP2_PADDED_F) {
            padlen = *pos++;
            length --;
        }
        if(padlen > length){
            LOGE("ERROR padlen exceed length: %d/%d\n", padlen, length);
            ErrProc(HTTP2_ERR_PROTOCOL_ERROR);
            return 0;
        }
        //这里我们假定对端一定能接受所有数据，因为我们的窗口大小是根据对端的cap进行设置的
        //所以DataProc这个函数不需要一个返回值，我们也不考虑对端主动shrunk自己的cap的情况
        DataProc(id, pos, length - padlen);
        if (header->flags & HTTP2_END_STREAM_F) {
            EndProc(id);
        }
        break;
    }
    case HTTP2_STREAM_HEADERS: {
        const char *pos = (const char *) (header + 1);
        uint8_t padlen = 0;
        if (header->flags & HTTP2_PADDED_F) {
            padlen = *pos++;
            length--;
        }
        uint32_t streamdep = 0;
        uint8_t weigth = 0;
        if (header->flags & HTTP2_PRIORITY_F) {
            streamdep = get32(pos);
            if(streamdep == id){
                LOGE("ERROR streamdep equal id: %d/%d\n", streamdep, id);
                ErrProc(HTTP2_ERR_PROTOCOL_ERROR);
                return 0;
            }
            pos += sizeof(streamdep);
            weigth = *pos++;
            length -= 5;
        }
        if(padlen > length){
            LOGE("ERROR padlen exceed length: %d/%d\n", padlen, length);
            ErrProc(HTTP2_ERR_PROTOCOL_ERROR);
            return 0;
        }
        if(header_buffer->id != 0){
            LOGE("ERROR get another header id: %d/%d\n", (int)header_buffer->id, id);
            ErrProc(HTTP2_ERR_COMPRESSION_ERROR);
            return 0;
        }
        header_buffer->id = id;
        header_buffer->truncate(length - padlen);
        memcpy(header_buffer->mutable_data(), pos, length - padlen);
        if (header->flags & HTTP2_END_STREAM_F) {
            http2_flag |= HTTP2_FLAG_END;
        }
        if(header->flags & HTTP2_END_HEADERS_F){
            HeadersProc();
            if(http2_flag & HTTP2_FLAG_END){
                EndProc(id);
                http2_flag &= ~HTTP2_FLAG_END;
            }
        }
        (void)weigth;
        break;
    }
    case HTTP2_STREAM_SETTINGS:
        if(id != 0){
            LOGE("ERROR wrong setting id: %d\n", id);
            ErrProc(HTTP2_ERR_PROTOCOL_ERROR);
            return 0;
        }
        if(length%6 != 0){
            LOGE("ERROR wrong setting length: %d\n", length);
            ErrProc(HTTP2_ERR_PROTOCOL_ERROR);
            return 0;
        }
        SettingsProc(header);
        break;
    case HTTP2_STREAM_PING:
        if(id != 0 || length != 8){
            LOGE("ERROR wrong ping frame: %d/%d\n", id, length);
            ErrProc(HTTP2_ERR_FRAME_SIZE_ERROR);
            return 0;
        }
        PingProc(header);
        break;
    case HTTP2_STREAM_GOAWAY:
        http2_flag |= HTTP2_FLAG_GOAWAYED;
        GoawayProc(header);
        break;
    case HTTP2_STREAM_RESET:
        if(length != 4){
            LOGE("ERROR rst frame: %d/%d\n", id, length);
            ErrProc(HTTP2_ERR_FRAME_SIZE_ERROR);
            return 0;
        }
        if(id == 0 || (id > recvid && id >= sendid-1)){
            LOGE("ERROR rst frame: %d/%d/%d\n", id, sendid, recvid);
            ErrProc(HTTP2_ERR_PROTOCOL_ERROR);
            return 0;
        }
        value = get32(header+1);
        RstProc(id, value);
        break;
    case HTTP2_STREAM_WINDOW_UPDATE:
        if(length != 4){
            LOGE("ERROR window update frame: %d/%d\n", id, length);
            ErrProc(HTTP2_ERR_FRAME_SIZE_ERROR);
            return 0;
        }
        value = get32(header+1);
        if(value == 0 || (id > recvid && id >= sendid-1)){
            LOGE("ERROR window update frame: value=%d id=%d/%d/%d\n", value, id, sendid, recvid);
            ErrProc(HTTP2_ERR_PROTOCOL_ERROR);
            return 0;
        }
        WindowUpdateProc(id, value);
        break;
    case HTTP2_STREAM_CONTINUATION: {
        if (header_buffer->id != id) {
            LOGE("ERROR get another header id: %d/%d\n", (int) header_buffer->id, id);
            ErrProc(HTTP2_ERR_COMPRESSION_ERROR);
            return 0;
        }
        size_t origin = header_buffer->truncate(header_buffer->len + length);
        memcpy((char*)header_buffer->mutable_data() + origin, header + 1, length);
        if (header->flags & HTTP2_END_HEADERS_F) {
            HeadersProc();
            if (http2_flag & HTTP2_FLAG_END) {
                EndProc(id);
                http2_flag &= ~HTTP2_FLAG_END;
            }
        }
        break;
    }
    case HTTP2_STREAM_PRIORITY: {
        if(length != 5){
            LOGE("ERROR priority frame: %d/%d\n", id, length);
            ErrProc(HTTP2_ERR_FRAME_SIZE_ERROR);
            return 0;
        }
        if (id == 0) {
            LOGE("ERROR priority frame with frame 0: %d/%d\n", id, length);
            ErrProc(HTTP2_ERR_PROTOCOL_ERROR);
            return 0;
        }
        if(header_buffer->id != 0){
            LOGE("ERROR priority frame between header, id: %d/%d\n", (int) header_buffer->id, id);
            ErrProc(HTTP2_ERR_COMPRESSION_ERROR);
            return 0;
        }
        uint32_t streamdep = get32(header + 1);
        if (streamdep == id) {
            LOGE("ERROR streamdep equal id: %d/%d\n", streamdep, id);
            ErrProc(HTTP2_ERR_PROTOCOL_ERROR);
            return 0;
        }
        break;
    }
    case HTTP2_STREAM_PUSH_PROMISE:
    case HTTP2_STREAM_ALTSVC:
        LOGE("unimplemented http2 frame:%d\n", header->type);
        break;
    default:
        LOGE("unknown http2 frame:%d\n", header->type);
        if(header_buffer->id != 0){
            LOGE("ERROR get unknown frame between header, id: %d/%d\n", (int)header_buffer->id, id);
            ErrProc(HTTP2_ERR_COMPRESSION_ERROR);
            return 0;
        }
    }
    if(http2_flag & HTTP2_FLAG_ERROR){
        return 0;
    }
    return get24(header->length) + sizeof(Http2_header);
}

#if 0
/* ping 帧永远插到最前面*/
void Http2Base::PushFrame(Buffer&& bb){
    const Http2_header* header = (const Http2_header*)bb.data();
    uint32_t id = HTTP2_ID(header->id);
    LOGD(DHTTP2, "push a frame [%d]:%d, size:%d, flags: %d\n", id, header->type, get24(header->length), header->flags);
    buff_iterator i;
    if((http2_flag & HTTP2_FLAG_INITED) == 0){
        i = queue_end();
        goto ret;
    }
    switch(header->type){
    case HTTP2_STREAM_PING:
        for(i = queue_head(); i!= queue_end() ; i++){
            const Http2_header* check = (const Http2_header*) i->data();
            if(get24(check->length) + sizeof(Http2_header) != i->len ){
                continue;
            }
            if(check->type != HTTP2_STREAM_PING){
                break;
            }
        }
        break;
    case HTTP2_STREAM_HEADERS:{
        auto j = queue_end();
        do{
            i = j--;
            if(j == queue_head()){
                break;
            }
            const Http2_header* check = (const Http2_header*) j->data();
            if(get24(check->length) + sizeof(Http2_header) != i->len ){
                break;
            }

            if(check->type != HTTP2_STREAM_DATA)
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
    queue_insert(i, std::move(bb));
}
#endif

void Http2Base::PushData(Buffer&& bb){
    while(bb.len > remoteframebodylimit){
        Buffer buff{bb.data(), remoteframebodylimit, bb.id};
        buff.reserve(-(char) sizeof(Http2_header));
        Http2_header* const header=(Http2_header *)buff.mutable_data();
        memset(header, 0, sizeof(Http2_header));
        set32(header->id, bb.id);
        set24(header->length, remoteframebodylimit);
        PushFrame(std::move(buff));
        bb.reserve(remoteframebodylimit);
    }

    size_t size = bb.len;
    bb.reserve(-(char) sizeof(Http2_header));
    Http2_header* const header=(Http2_header *)bb.mutable_data();
    memset(header, 0, sizeof(Http2_header));
    set32(header->id, bb.id);
    set24(header->length, size);
    if(size == 0) {
        header->flags = HTTP2_END_STREAM_F;
    }
    PushFrame(std::move(bb));
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
    const Setting_Frame *sf = (const Setting_Frame *)(header + 1);
    if((header->flags & HTTP2_ACK_F) == 0) {
        while((char *)sf-(char *)(header+1) < get24(header->length)){
            uint32_t value = get32(sf->value);
            switch(get16(sf->identifier)){
            case HTTP2_SETTING_HEADER_TABLE_SIZE:
                LOGD(DHTTP2, "set head table size:%d\n", value);
                hpack_encoder.set_dynamic_table_size_limit_max(value);
                break;
            case HTTP2_SETTING_INITIAL_WINDOW_SIZE:
                if(value >= (uint32_t)1<<31u){
                    LOGE("ERROR window overflow\n");
                    ErrProc(HTTP2_ERR_FLOW_CONTROL_ERROR);
                    return;
                }
                AdjustInitalFrameWindowSize((ssize_t)value - (ssize_t)remoteframewindowsize);
                remoteframewindowsize = value;
                LOGD(DHTTP2, "set inital frame window size:%d\n", remoteframewindowsize);
                break;
            case HTTP2_SETTING_MAX_FRAME_SIZE:
                if(value > 0xffffff || value < FRAMEBODYLIMIT){
                    LOGE("ERROR frame size overflow\n");
                    ErrProc(HTTP2_ERR_FRAME_SIZE_ERROR);
                    return;
                }
                remoteframebodylimit = value;
                LOGD(DHTTP2, "set frame body size limit: %d\n", remoteframebodylimit);
                break;
            case HTTP2_SETTING_ENABLE_PUSH:
                if(value != 0 && value != 1){
                    LOGE("ERROR enable push value:%d\n", value);
                    ErrProc(HTTP2_ERR_PROTOCOL_ERROR);
                    return;
                }
                if(value == 1){
                    http2_flag |= HTTP2_FLAG_ENABLE_PUSH;
                }
                break;
            case HTTP2_SETTING_MAX_CONCURRENT_STREAMS:
            case HTTP2_SETTING_MAX_HEADER_LIST_SIZE:
                LOG("Get a unimplemented setting(%d): %d\n", get16(sf->identifier), value);
                break;
            default:
                LOG("Get a unknown setting(%d): %d\n", get16(sf->identifier), value);
                break;
            }
            sf++;
        }
        Block buff(header, sizeof(Http2_header));
        Http2_header *header_back =  (Http2_header*) buff.data();
        set24(header_back->length, 0);
        header_back->flags |= HTTP2_ACK_F;
        PushFrame(Buffer{std::move(buff), sizeof(Http2_header)});
    }else if(get24(header->length) != 0){
        LOGE("ERROR setting ack with content\n");
        ErrProc(HTTP2_ERR_FRAME_SIZE_ERROR);
    }
}

void Http2Base::PingProc(const Http2_header* header) {
    if((header->flags & HTTP2_ACK_F) == 0) {
        size_t len = sizeof(Http2_header) + get24(header->length);
        Block buff(header, len);
        Http2_header *header_back =  (Http2_header*)buff.data();
        header_back->flags |= HTTP2_ACK_F;
        PushFrame(Buffer{std::move(buff), len});
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

uint32_t Http2Base::ExpandWindowSize(uint32_t id, uint32_t size) {
    LOGD(DHTTP2, "will expand window size [%d]: %d\n", id, size);
    Block buff(sizeof(Http2_header) + sizeof(uint32_t));
    Http2_header* const header = (Http2_header *) buff.data();
    memset(header, 0, sizeof(Http2_header));
    set32(header->id, id);
    set24(header->length, sizeof(uint32_t));
    header->type = HTTP2_STREAM_WINDOW_UPDATE;
    set32(header+1, size);
    PushFrame(Buffer{std::move(buff), sizeof(uint32_t) + sizeof(Http2_header)});
    return size;
}

void Http2Base::Ping(const void *data) {
    Block buff(sizeof(Http2_header) + 8);
    Http2_header* const header = (Http2_header *) buff.data();
    memset(header, 0, sizeof(Http2_header));
    header->type = HTTP2_STREAM_PING;
    set24(header->length, 8);
    memcpy(header+1, data, 8);
    PushFrame(Buffer{std::move(buff), 8 + sizeof(Http2_header)});
}


void Http2Base::Reset(uint32_t id, uint32_t code) {
    Block buff(sizeof(Http2_header) + sizeof(uint32_t));
    Http2_header* const header = (Http2_header *) buff.data();
    memset(header, 0, sizeof(Http2_header));
    header->type = HTTP2_STREAM_RESET;
    set32(header->id, id);
    set24(header->length, sizeof(uint32_t));
    set32(header+1, code);
    PushFrame(Buffer{std::move(buff), sizeof(uint32_t) + sizeof(Http2_header)});
}

void Http2Base::Goaway(uint32_t lastid, uint32_t code, char *message) {
    http2_flag |= HTTP2_FLAG_GOAWAYED;
    size_t len = sizeof(Goaway_Frame);
    if(message){
        len += strlen(message)+1;
    }
    Block buff(sizeof(Http2_header) + len);
    Http2_header* const header = (Http2_header *) buff.data();
    memset(header, 0, sizeof(Http2_header));
    set24(header->length, len);
    header->type = HTTP2_STREAM_GOAWAY;
    Goaway_Frame *goaway = (Goaway_Frame*)(header+1);
    set32(goaway->last_stream_id, lastid);
    set32(goaway->errcode, code);
    if(message){
        strcpy((char *)goaway->data, message);
    }
    PushFrame(Buffer{std::move(buff), len + sizeof(Http2_header)});
}


void Http2Base::SendInitSetting() {
    Block buff(sizeof(Http2_header) + 2 * sizeof(Setting_Frame));
    Http2_header* const header = (Http2_header *) buff.data();
    memset(header, 0, sizeof(Http2_header));
    set24(header->length, 2*sizeof(Setting_Frame));
    header->type = HTTP2_STREAM_SETTINGS;

    Setting_Frame *sf = (Setting_Frame *)(header+1);
    set16(sf->identifier, HTTP2_SETTING_HEADER_TABLE_SIZE);
    set32(sf->value, 65536);
    hpack_decoder.set_dynamic_table_size_limit_max(get32(sf->value));

    sf++;
    set16(sf->identifier, HTTP2_SETTING_INITIAL_WINDOW_SIZE);
    set32(sf->value, localframewindowsize);
    LOGD(DHTTP2, "send inital frame window size:%d\n", localframewindowsize);

    PushFrame(Buffer{std::move(buff), 2 * sizeof(Setting_Frame) + sizeof(Http2_header)});
}

uint32_t Http2Base::OpenStream(){
    uint32_t id = sendid;
    sendid += 2;
    return id;
}

size_t Http2Responser::InitProc(const uchar* http2_buff, size_t len) {
    size_t prelen = strlen(HTTP2_PREFACE);
    if(len < prelen) {
        return 0;
    }
    if (memcmp(http2_buff, HTTP2_PREFACE, strlen(HTTP2_PREFACE)) != 0) {
        LOGE("ERROR get http2 perface: %.*s\n", (int)len, http2_buff);
        ErrProc(HTTP2_ERR_PROTOCOL_ERROR);
        return 0;
    }
    SendInitSetting();
    http2_flag |= HTTP2_FLAG_INITED;
    Http2_Proc = &Http2Responser::DefaultProc;
    return prelen + DefaultProc(http2_buff+prelen, len-prelen);
}

void Http2Responser::HeadersProc() {
    uint32_t id = header_buffer->id;
    if(id <= recvid || (id&1) == 0){
        LOGE("ERROR header id: %d/%d\n", id, recvid);
        ErrProc(HTTP2_ERR_STREAM_CLOSED);
        return;
    }
    recvid = id;
    std::shared_ptr<HttpReqHeader> req = hpack_decoder.UnpackHttp2Req(header_buffer->data(), header_buffer->len);
    if(req == nullptr){
        ErrProc(HTTP2_ERR_COMPRESSION_ERROR);
        return;
    }
    ReqProc(id, req);
    header_buffer->truncate(0);
    header_buffer->id = 0;
}

void Http2Responser::AltSvc(uint32_t id, const char *origin, const char *value) {
    size_t originlen = strlen(origin);
    size_t valuelen = strlen(value);
    size_t len = 2 + originlen + valuelen;
    Block buff(sizeof(Http2_header) + len);
    Http2_header* const header = (Http2_header *) buff.data();
    memset(header, 0, sizeof(Http2_header));
    header->type = HTTP2_STREAM_ALTSVC;
    set32(header->id, id);
    set24(header->length, len);
    set16(header+1, originlen);
    char* pos = (char *)(header+1) + 2;
    memcpy(pos, origin, originlen);
    pos += originlen;
    memcpy(pos, value, valuelen);
    PushFrame(Buffer{std::move(buff), len + sizeof(Http2_header)});
}

void Http2Requster::init() {
    PushFrame(Buffer{HTTP2_PREFACE, sizeof(HTTP2_PREFACE) - 1});
    SendInitSetting(); 
}

size_t Http2Requster::InitProc(const uchar* http2_buff, size_t len) {
    const Http2_header *header = (const Http2_header *)http2_buff;
    if(len < sizeof(Http2_header)){
        return 0;
    }
    size_t length = sizeof(Http2_header) + get24(header->length);
    if(len < length){
        return 0;
    }
    if(header->type == HTTP2_STREAM_SETTINGS && (header->flags & HTTP2_ACK_F) == 0){
        SettingsProc(header);
        http2_flag |=  HTTP2_FLAG_INITED;
        Http2_Proc = &Http2Requster::DefaultProc;
        return length + DefaultProc(http2_buff+length, len-length);
    }else {
        LOGE("ERROR get wrong setting frame from server\n");
        ErrProc(HTTP2_ERR_PROTOCOL_ERROR);
        return 0;
    }
}


void Http2Requster::HeadersProc() {
    uint32_t id = header_buffer->id;
    if(id >= sendid-1 || (id&1u) == 0){
        LOGE("ERROR header id: %d/%d\n", id, sendid);
        ErrProc(HTTP2_ERR_STREAM_CLOSED);
        return;
    }
    recvid = id;
    std::shared_ptr<HttpResHeader> res = hpack_decoder.UnpackHttp2Res(header_buffer->data(), header_buffer->len);
    if(res == nullptr){
        ErrProc(HTTP2_ERR_COMPRESSION_ERROR);
        return;
    }
    ResProc(id, res);
    header_buffer->truncate(0);
    header_buffer->id = 0;
}
