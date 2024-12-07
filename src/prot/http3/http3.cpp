//
// Created by 周威 on 2021/8/5.
//
#include "http3.h"
#include "prot/quic/quic_pack.h"

#include <inttypes.h>
#include <assert.h>

Http3Base::Http3Base(): qpack_encoder([this](Buffer&& bb){
    bb.id = qpackeid_local;
    return SendData(std::move(bb));
}), qpack_decoder([this](Buffer&& bb){
    bb.id = qpackdid_local;
    return SendData(std::move(bb));
}) {
}

size_t Http3Base::Http3_Proc(Buffer& bb) {
    size_t len = bb.len;
    if(ctrlid_remote && bb.id == ctrlid_remote){
        uint64_t stream, length;
        if(variable_decode_len(bb.data()) >= bb.len){
            return 0;
        }
        bb.reserve(variable_decode(bb.data(), &stream));
        if(variable_decode_len(bb.data()) >= bb.len){
            return 0;
        }
        bb.reserve(variable_decode(bb.data(), &length));
        if(length > bb.len){
            LOGE("http3 frame error: type 0x%x, length %d, buff len %d\n", (int)stream, (int)length, (int)bb.len);
            ErrProc(HTTP3_ERR_FRAME_ERROR);
            return 0;
        }
        switch(stream){
        case HTTP3_STREAM_SETTINGS:
            LOGD(DHTTP3, "Get a settings frame: length: %" PRIu64 "\n", length);
            SettingsProc((const uchar*)bb.data(), length);
            break;
        case HTTP3_STREAM_GOAWAY:{
            LOGD(DHTTP3, "Get a goaway frame: length: %" PRIu64 "\n", length);
            uint64_t lastid;
            variable_decode(bb.data(), &lastid);
            http3_flag |= HTTP3_FLAG_GOAWAYED;
            GoawayProc(lastid);
            break;
        }
        case HTTP3_STREAM_DATA:
        case HTTP3_STREAM_HEADERS:
        case HTTP3_STREAM_PUSH_PROMISE:
            LOGE("http3 unexpected frame for control: type 0x%" PRIx64 ", length:%zd\n", stream, (size_t)length);
            ErrProc(HTTP3_ERR_FRAME_UNEXPECTED);
            return 0;
        default:
            if((stream - 0x21) % 0x1f == 0){
                LOGD(DHTTP3, "reserved stream type: 0x%" PRIx64 ", length:%zd\n", stream, (size_t)length);
            }else{
                LOGD(DHTTP3, "doesn't support stream type: %" PRIx64 "\n", stream);
            }
            break;
        }
        bb.reserve(length);
    }else if(qpackeid_remote && bb.id == qpackeid_remote){
        int ret = Qpack_encoder::push_ins(bb.data(), bb.len);
        if(ret < 0){
            ErrProc(HTTP3_ERR_QPACK_ENCODER_STREAM_ERROR);
            return 0;
        }
        bb.reserve(ret);
    }else if(qpackdid_remote && bb.id == qpackdid_remote){
        int ret = Qpack_decoder::push_ins(bb.data(), bb.len);
        if(ret < 0){
            ErrProc(HTTP3_ERR_QPACK_DECODER_STREAM_ERROR);
            return 0;
        }
        bb.reserve(ret);
    }else if((bb.id & 0x02) == 0){
        uint64_t stream, length;
        if(variable_decode_len(bb.data()) >= bb.len){
            return 0;
        }
        bb.reserve(variable_decode(bb.data(), &stream));
        if(variable_decode_len(bb.data()) > bb.len){
            return 0;
        }
        bb.reserve(variable_decode(bb.data(), &length));
        if(length > bb.len){
            return 0;
        }
        switch(stream){
        case HTTP3_STREAM_HEADERS:
            LOGD(DHTTP3, "Get a header frame: %" PRIu64 ", length: %" PRIu64 "\n", bb.id, length);
            HeadersProc(bb.id, (const uchar*)bb.data(), length);
            break;
        case HTTP3_STREAM_DATA: {
            LOGD(DHTTP3, "Get a data frame: %" PRIu64 ", length: %" PRIu64 "\n", bb.id, length);
            if(bb.len == length) {
                if (!DataProc(bb)) {
                    return 0;
                }
            } else {
                Buffer cbb = bb;
                cbb.truncate(length);
                if (!DataProc(cbb)) {
                    return 0;
                }
                bb.reserve(length - cbb.len);
            }
            return len - bb.len;
        }
        case HTTP3_STREAM_CANCEL_PUSH:
        case HTTP3_STREAM_MAX_PUSH_ID:
        case HTTP3_STREAM_GOAWAY:
            LOGE("http3 unexpected frame for data: type 0x%x\n", (int)stream);
            ErrProc(HTTP3_ERR_FRAME_UNEXPECTED);
            return 0;
        default:
            if((stream - 0x21) % 0x1f == 0){
                LOGD(DHTTP3, "reserved stream type: 0x%" PRIx64 ", length:%zd\n", stream, (size_t)length);
            }else{
                LOGD(DHTTP3, "doesn't support stream type: %" PRIx64 "\n", stream);
            }
            break;
        }
        bb.reserve(length);
    } else {
        uint64_t type;
        if(variable_decode_len(bb.data()) > bb.len){
            return 0;
        }
        bb.reserve(variable_decode(bb.data(), &type));
        switch(type){
        case HTTP3_STREAM_TYPE_CONTROL:
            ctrlid_remote = bb.id;
            LOGD(DHTTP3, "Get control stream id: %" PRIu64 "\n", bb.id);
            break;
        case HTTP3_STREAM_TYPE_QPACK_ENCODE:
            qpackeid_remote = bb.id;
            LOGD(DHTTP3, "Get qpack encode stream id: %" PRIu64 "\n", bb.id);
            break;
        case HTTP3_STREAM_TYPE_QPACK_DECODE:
            qpackdid_remote = bb.id;
            LOGD(DHTTP3, "Get qpack decode stream id: %" PRIu64 "\n", bb.id);
            break;
        default:
            if((type - 0x21) % 0x1f == 0){
                LOGD(DHTTP3, "reserved stream type: %" PRIu64 "\n", type);
                bb.reserve(bb.len);
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
    return len - bb.len;
}

void Http3Base::Init() {
    ctrlid_local   = CreateUbiStream();
    qpackeid_local = CreateUbiStream();
    qpackdid_local = CreateUbiStream();

    Block buff(BUF_LEN);
    char* pos = (char*)buff.data();
    pos += variable_encode(pos, HTTP3_SETTING_QPACK_MAX_TABLE_CAPACITY);
    pos += variable_encode(pos, 0);
    pos += variable_encode(pos, HTTP3_SETTING_MAX_FIELD_SECTION_SIZE);
    pos += variable_encode(pos, BUF_LEN);
    pos += variable_encode(pos, HTTP3_SETTING_ENABLE_CONNECT_PROTOCOL);
    pos += variable_encode(pos, 1);
    size_t len = pos - (char*)buff.data();
    pos = (char*)buff.reserve(-3); // type + id + length
    pos += variable_encode(pos, HTTP3_STREAM_TYPE_CONTROL);
    pos += variable_encode(pos, HTTP3_STREAM_SETTINGS);
    pos += variable_encode(pos, len);
    SendData({std::move(buff), len+3, ctrlid_local});

    Block buff1(variable_encode_len(HTTP3_STREAM_TYPE_QPACK_ENCODE));
    pos = (char*)buff1.data();
    pos += variable_encode(pos, HTTP3_STREAM_TYPE_QPACK_ENCODE);
    len = pos - (char*)buff1.data();
    SendData({std::move(buff1), len, qpackeid_local});

    Block buff2(variable_encode_len(HTTP3_STREAM_TYPE_QPACK_DECODE));
    pos = (char*)buff2.data();
    pos += variable_encode(pos, HTTP3_STREAM_TYPE_QPACK_DECODE);
    len = pos - (char*)buff2.data();
    SendData({std::move(buff2), len, qpackdid_local});
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
        case HTTP3_SETTING_ENABLE_CONNECT_PROTOCOL:
            LOGD(DHTTP3, "Get enable_connect_protocol\n");
            http3_flag |= HTTP3_FLAG_ENABLE_PROTOCOL;
            break;
        default:
            if(((id - 0x21) % 0x1f) == 0){
                LOGD(DHTTP3, "Get reserved settings: 0x%" PRIx64"\n", id);
            }else if(id < HTTP3_SETTING_MAX_FIELD_SECTION_SIZE){
                ErrProc(HTTP3_ERR_SETTINGS_ERROR);
                return;
            }else{
                LOGD(DHTTP3, "Get unknown settings: 0x%" PRIx64 " = %" PRIu64"\n", id, value);
            }
            break;
        }
    }
}

void Http3Base::GoawayProc(__attribute__ ((unused)) uint64_t id) {
    LOGD(DHTTP3, "Get a Goaway frame: %" PRIu64"\n", id);
}

void Http3Base::Goaway(uint64_t lastid){
    http3_flag |= HTTP3_FLAG_GOAWAYED;
    if(ctrlid_local == 0){
        //this connection is not inited.
        return;
    }
    Block buff(1 + 1 + 8); // enough for goway frame
    char* pos = (char*)buff.data();
    pos += variable_encode(pos, HTTP3_STREAM_GOAWAY);
    pos += variable_encode(pos, variable_encode_len(lastid));
    pos += variable_encode(pos , lastid);
    size_t len  = pos - (char*)buff.data();
    SendData({std::move(buff), len, ctrlid_local});
}

void Http3Base::PushData(Buffer&& bb) {
    if(bb.refs() == 1 || bb.len == 0) {
        size_t size = bb.len;
        bb.reserve(-(1 + (int) variable_encode_len(size)));
        char *pos = (char *) bb.mutable_data();
        pos += variable_encode(pos, HTTP3_STREAM_DATA);
        pos += variable_encode(pos, size);
    } else {
        size_t size = 1 + variable_encode_len(bb.len);
        Block buff(size);
        char* pos = (char*)buff.data();
        pos += variable_encode(pos, HTTP3_STREAM_DATA);
        pos += variable_encode(pos, bb.len);
        SendData({std::move(buff), size, bb.id});
    }
    SendData(std::move(bb));
}

void Http3Requster::HeadersProc(uint64_t id, const uchar* header, size_t length) {
    std::shared_ptr<HttpResHeader> res = Qpack_decoder::UnpackHttp3Res(header, length);
    if(res == nullptr){
        ErrProc(HTTP3_ERR_QPACK_DECOMPRESSION_FAILED);
        return;
    }
    ResProc(id, res);
}

Http3Requster::Http3Requster() {
}

void Http3Responser::HeadersProc(uint64_t id, const uchar *header, size_t length) {
    std::shared_ptr<HttpReqHeader> req = Qpack_decoder::UnpackHttp3Req(header, length);
    if(req == nullptr) {
        ErrProc(HTTP3_ERR_QPACK_DECOMPRESSION_FAILED);
        return;
    }
    ReqProc(id, req);
}

Http3Responser::Http3Responser() {
}
