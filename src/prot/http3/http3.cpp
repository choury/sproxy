//
// Created by 周威 on 2021/8/5.
//
#include "http3.h"
#include "prot/quic/quic_pack.h"

#include <inttypes.h>
#include <assert.h>

Http3Base::Http3Base(): qpack_encoder([this](Buffer&& bb){
    bb.id = qpackeid_local;
    return PushFrame(std::move(bb));
}), qpack_decoder([this](Buffer&& bb){
    bb.id = qpackdid_local;
    return PushFrame(std::move(bb));
}) {
}

size_t Http3Base::Http3_Proc(const void* buff, size_t len, uint64_t id) {
    const uchar* pos = (const uchar*)buff;
    if(ctrlid_remote && id == ctrlid_remote){
        uint64_t stream, length;
        if(pos + variable_decode_len(pos) >= (uchar*)buff + len){
            return 0;
        }
        pos += variable_decode(pos, &stream);
        if(pos + variable_decode_len(pos) >= (uchar*)buff + len){
            return 0;
        }
        pos += variable_decode(pos, &length);
        if(pos + length > (uchar*)buff + len){
            ErrProc(HTTP3_ERR_FRAME_ERROR);
            return 0;
        }
        switch(stream){
        case HTTP3_STREAM_SETTINGS:
            SettingsProc(pos, length);
            break;
        case HTTP3_STREAM_GOAWAY:{
            uint64_t lastid;
            variable_decode(pos, &lastid);
            GoawayProc(lastid);
            break;
        }
        case HTTP3_STREAM_DATA:
        case HTTP3_STREAM_HEADERS:
        case HTTP3_STREAM_PUSH_PROMISE:
            ErrProc(HTTP3_ERR_FRAME_UNEXPECTED);
            return 0;
        default:
            break;
        }
        pos += length;
    }else if(qpackeid_remote && id == qpackeid_remote){
        int ret = qpack_encoder.push_ins(buff, len);
        if(ret < 0){
            ErrProc(HTTP3_ERR_QPACK_ENCODER_STREAM_ERROR);
            return 0;
        }
        pos += ret;
    }else if(qpackdid_remote && id == qpackdid_remote){
        int ret = qpack_decoder.push_ins(buff, len);
        if(ret < 0){
            ErrProc(HTTP3_ERR_QPACK_DECODER_STREAM_ERROR);
            return 0;
        }
        pos += ret;
    }else if((id & 0x02) == 0){
        uint64_t stream, length;
        if(pos + variable_decode_len(pos) >= (uchar*)buff + len){
            return 0;
        }
        pos += variable_decode(pos, &stream);
        if(pos + variable_decode_len(pos) > (uchar*)buff + len){
            return 0;
        }
        pos += variable_decode(pos, &length);
        if(pos + length > (uchar*)buff + len){
            return 0;
        }
        switch(stream){
        case HTTP3_STREAM_HEADERS:
            HeadersProc(id, pos, length);
            break;
        case HTTP3_STREAM_DATA:
            DataProc(id, pos, length);
            break;
        case HTTP3_STREAM_CANCEL_PUSH:
        case HTTP3_STREAM_MAX_PUSH_ID:
        case HTTP3_STREAM_GOAWAY:
            ErrProc(HTTP3_ERR_FRAME_UNEXPECTED);
            return 0;
        default:
            break;
        }
        pos += length;
    }else{
        uint64_t type;
        if(pos + variable_decode_len(pos) > (uchar*)buff + len){
            return 0;
        }
        pos += variable_decode(pos, &type);
        switch(type){
        case HTTP3_STREAM_TYPE_CONTROL:
            ctrlid_remote = id;
            break;
        case HTTP3_STREAM_TYPE_QPACK_ENCODE:
            qpackeid_remote = id;
            break;
        case HTTP3_STREAM_TYPE_QPACK_DECODE:
            qpackdid_remote = id;
            break;
        default:
            if((type - 0x21) % 0x1f == 0){
                LOGD(DHTTP3, "reserved stream type: %" PRIu64 "\n", type);
                return len;
            }else{
                LOGD(DHTTP3, "doesn't support stream type: %" PRIu64 "\n", type);
                ErrProc(HTTP3_ERR_STREAM_CREATION_ERROR);
                return 0;
            }
        }
    }
    if(http3_flag & HTTP3_FLAG_ERROR){
        return 0;
    }
    return pos - (const uchar*)buff;
}

void Http3Base::Init() {
    ctrlid_local   = CreateUbiStream();
    qpackeid_local = CreateUbiStream();
    qpackdid_local = CreateUbiStream();

    size_t len = 2 + variable_encode_len(1 + variable_encode_len(BUF_LEN))
            + 1 + variable_encode_len(BUF_LEN);
    auto buff = std::make_shared<Block>(len);
    char* pos = (char*)buff->data();
    pos += variable_encode(pos, HTTP3_STREAM_TYPE_CONTROL);
    pos += variable_encode(pos, HTTP3_STREAM_SETTINGS);
    pos += variable_encode(pos, 1 + variable_encode_len(BUF_LEN));
    pos += variable_encode(pos, HTTP3_SETTING_MAX_FIELD_SECTION_SIZE);
    pos += variable_encode(pos, BUF_LEN);
    assert(pos - (char*)buff->data() == (int)len);
    PushFrame({buff, len, ctrlid_local});

    buff = std::make_shared<Block>(variable_encode_len(HTTP3_STREAM_TYPE_QPACK_ENCODE));
    pos = (char*)buff->data();
    pos += variable_encode(pos, HTTP3_STREAM_TYPE_QPACK_ENCODE);
    PushFrame({buff, size_t(pos - (char*)buff->data()), qpackeid_local});

    buff = std::make_shared<Block>(variable_encode_len(HTTP3_STREAM_TYPE_QPACK_ENCODE));
    pos = (char*)buff->data();
    pos += variable_encode(pos, HTTP3_STREAM_TYPE_QPACK_DECODE);
    PushFrame({buff, size_t(pos - (char*)buff->data()), qpackdid_local});
    http3_flag |= HTTP3_FLAG_INITED;
}


void Http3Base::SettingsProc(const uchar* header, size_t len) {
    const uchar* pos = header;
    while(pos - header < (int)len){
        uint64_t id, value;
        pos += variable_decode(pos, &id);
        pos += variable_decode(pos, &value);
        switch(id){
        case HTTP3_SETTING_MAX_FIELD_SECTION_SIZE:
            LOGD(DHTTP3, "Get max_filed_section_size: %" PRIu64"\n", value);
            break;
        case HTTP3_SETTING_QPACK_MAX_TABLE_CAPACITY:
            LOGD(DHTTP3, "Get qpack_max_table_capacity: %" PRIu64"\n", value);
            break;
        case HTTP3_SETTING_QPACK_BLOCKED_STREAMS:
            LOGD(DHTTP3, "Get qpack_blocked_streams: %" PRIu64"\n", value);
            break;
        default:
            if(((id-0x21)&0x1f) == 0){
                LOGD(DHTTP3, "Get reserved settings: %" PRIu64"\n", id);
            }else if(id < HTTP3_SETTING_MAX_FIELD_SECTION_SIZE){
                ErrProc(HTTP3_ERR_SETTINGS_ERROR);
                return;
            }else{
                LOGD(DHTTP3, "Get unknown settings: %" PRIu64"\n", id);
            }
            break;
        }
    }
}

void Http3Base::GoawayProc(__attribute__ ((unused)) uint64_t id) {
    LOGD(DHTTP3, "Get a Goaway frame: %" PRIu64"\n", id);
}

void Http3Base::Goaway(uint64_t lastid){
    if(ctrlid_local == 0){
        //this connection is not inited.
        return;
    }
    auto buff = std::make_shared<Block>(1 + 1 + 8); // enough for goway frame
    char* pos = (char*)buff->data();
    pos += variable_encode(pos, HTTP3_STREAM_GOAWAY);
    pos += variable_encode(pos, variable_encode_len(lastid));
    pos += variable_encode(pos , lastid);
    PushFrame({buff, size_t(pos - (char*)buff->data()), ctrlid_local});
}

void Http3Base::PushData(Buffer&& bb) {
    size_t size = bb.len;
    char* pos = (char*) bb.trunc(-(1 + (int) variable_encode_len(size)));
    pos += variable_encode(pos, HTTP3_STREAM_DATA);
    pos += variable_encode(pos, size);
    PushFrame(std::move(bb));
}

void Http3Requster::HeadersProc(uint64_t id, const uchar* header, size_t length) {
    std::shared_ptr<HttpResHeader> res = qpack_decoder.UnpackHttp3Res(header, length);
    if(res == nullptr){
        ErrProc(HTTP3_ERR_QPACK_DECOMPRESSION_FAILED);
        return;
    }
    ResProc(id, res);
}

Http3Requster::Http3Requster() {
}

void Http3Responser::HeadersProc(uint64_t id, const uchar *header, size_t length) {
    std::shared_ptr<HttpReqHeader> req = qpack_decoder.UnpackHttp3Req(header, length);
    if(req == nullptr) {
        ErrProc(HTTP3_ERR_QPACK_DECOMPRESSION_FAILED);
        return;
    }
    ReqProc(id, req);
}

Http3Responser::Http3Responser() {
}
