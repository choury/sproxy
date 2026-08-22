//
// Created by choury on 2021/8/5.
//
#include "http3.h"
#include "prot/quic/quic_pack.h"
#include "misc/buffer.h"

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
    auto consume_data = [this, &bb](uint64_t& remain) -> ssize_t {
        if(bb.len == 0 || remain == 0) {
            return 0;
        }
        if(remain < bb.len){
            // 传入截断的拷贝cbb，DataProc操作的是cbb而非bb，
            // 所以需要手动用返回值推进bb
            Buffer cbb = bb;
            cbb.truncate((size_t)remain);
            ssize_t ret = DataProc(cbb);
            if(ret < 0){
                return ret;
            }
            if((uint64_t)ret > remain){
                LOGE("http3 data consume overflow: %" PRIu64 " > %" PRIu64 "\n",
                     (uint64_t)ret, remain);
                ErrProc(HTTP3_ERR_FRAME_ERROR);
                return -1;
            }
            remain -= (uint64_t)ret;
            bb.reserve((int)ret);
            return ret;
        }
        // 直接传入bb，DataProc内部会推进bb，
        // 这里不再bb.reserve以避免重复推进
        ssize_t ret = DataProc(bb);
        if(ret < 0){
            return ret;
        }
        if((uint64_t)ret > remain){
            LOGE("http3 data consume overflow: %" PRIu64 " > %" PRIu64 "\n",
                 (uint64_t)ret, remain);
            ErrProc(HTTP3_ERR_FRAME_ERROR);
            return -1;
        }
        remain -= (uint64_t)ret;
        return ret;
    };

    if(ctrlid_remote && bb.id == ctrlid_remote){
        if(bb.len == 0){
            return 0;
        }
        QuicCursor fc(bb.data(), bb.len);
        auto stream = fc.variable_decode();
        if(!stream){
            return 0;
        }
        auto length = fc.variable_decode();
        if(!length || length.value() > fc.length()){
            return 0;
        }
        size_t header_len = bb.len - fc.length();
        bb.reserve((int)header_len);
        switch(stream.value()){
        case HTTP3_STREAM_SETTINGS:
            LOGD(DHTTP3, "Get a settings frame: length: %" PRIu64 "\n", length.value());
            SettingsProc((const uchar*)bb.data(), length.value());
            break;
        case HTTP3_STREAM_GOAWAY:{
            LOGD(DHTTP3, "Get a goaway frame: length: %" PRIu64 "\n", length.value());
            //last stream id是varint，必须限制在帧长内解析，空帧/截断帧直接报错
            QuicCursor c(bb.data(), length.value());
            auto lastid = c.variable_decode();
            if(!lastid){
                LOGE("http3 goaway frame without last stream id\n");
                ErrProc(HTTP3_ERR_FRAME_ERROR);
                return 0;
            }
            http3_flag |= HTTP3_FLAG_GOAWAYED;
            GoawayProc(lastid.value());
            break;
        }
        case HTTP3_STREAM_DATA:
        case HTTP3_STREAM_HEADERS:
        case HTTP3_STREAM_PUSH_PROMISE:
            LOGE("http3 unexpected frame for control: type 0x%" PRIx64 ", length:%zd\n", stream.value(), (size_t)length.value());
            ErrProc(HTTP3_ERR_FRAME_UNEXPECTED);
            return 0;
        default:
            if((stream.value() - 0x21) % 0x1f == 0){
                LOGD(DHTTP3, "reserved stream type: 0x%" PRIx64 ", length:%zd\n", stream.value(), (size_t)length.value());
            }else{
                LOGD(DHTTP3, "doesn't support stream type: %" PRIx64 "\n", stream.value());
            }
            break;
        }
        bb.reserve((int)length.value());
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
        auto it = data_remain.find(bb.id);
        if(it != data_remain.end() && it->second > 0){
            ssize_t ret = consume_data(it->second);
            if(ret <= 0){
                return 0;
            }
            if(it->second == 0){
                data_remain.erase(it);
            }
            if(http3_flag & HTTP3_FLAG_ERROR){
                return 0;
            }
            return len - bb.len;
        }

        if(bb.len == 0){
            return 0;
        }
        QuicCursor fc(bb.data(), bb.len);
        auto stream = fc.variable_decode();
        if(!stream){
            LOGD(DHTTP3, "not enough to get stream type: %zd\n", bb.len);
            return 0;
        }
        auto length = fc.variable_decode();
        if(!length){
            LOGD(DHTTP3, "not enough to get frame [%" PRIu64"] len: %zd\n", stream.value(), bb.len);
            return 0;
        }
        size_t header_len = bb.len - fc.length();
        if(stream.value() == HTTP3_STREAM_DATA){
            LOGD(DHTTP3, "Get a data frame: %" PRIu64 ", length: %" PRIu64 "\n", bb.id, length.value());
            bb.reserve((int)header_len);
            if(length.value() == 0){
                return len - bb.len;
            }
            data_remain[bb.id] = length.value();
            auto it2 = data_remain.find(bb.id);
            ssize_t ret = consume_data(it2->second);
            if(ret < 0){
                return len - bb.len;
            }
            if(it2->second == 0){
                data_remain.erase(it2);
            }
            if(http3_flag & HTTP3_FLAG_ERROR){
                return 0;
            }
            return len - bb.len;
        }
        if(length.value() > bb.len - header_len){
            return 0;
        }
        bb.reserve((int)header_len);
        switch(stream.value()){
        case HTTP3_STREAM_HEADERS:
            LOGD(DHTTP3, "Get a header frame: %" PRIu64 ", length: %" PRIu64 "\n", bb.id, length.value());
            HeadersProc(bb.id, (const uchar*)bb.data(), length.value());
            break;
        case HTTP3_STREAM_CANCEL_PUSH:
        case HTTP3_STREAM_MAX_PUSH_ID:
        case HTTP3_STREAM_GOAWAY:
            LOGE("http3 unexpected frame for data: type 0x%x\n", (int)stream.value());
            ErrProc(HTTP3_ERR_FRAME_UNEXPECTED);
            return 0;
        default:
            if((stream.value() - 0x21) % 0x1f == 0){
                LOGD(DHTTP3, "reserved stream type: 0x%" PRIx64 ", length:%zd\n", stream.value(), (size_t)length.value());
            }else{
                LOGD(DHTTP3, "doesn't support stream type: %" PRIx64 "\n", stream.value());
            }
            break;
        }
        bb.reserve((int)length.value());
    } else {
        if(bb.len == 0){
            return 0;
        }
        QuicCursor c(bb.data(), bb.len);
        auto type = c.variable_decode();
        if(!type){
            return 0;
        }
        bb.reserve((int)(bb.len - c.length()));
        switch(type.value()){
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
            if((type.value() - 0x21) % 0x1f == 0){
                LOGD(DHTTP3, "reserved stream type: %" PRIu64 "\n", type.value());
                bb.reserve(bb.len);
            }else{
                LOGD(DHTTP3, "doesn't support stream type: %" PRIu64 "\n", type.value());
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

void Http3Base::Datagram_Proc(Buffer&& bb) {
    if(!(http3_flag & HTTP3_FLAG_H3_DATAGRAM)) {
        LOGD(DHTTP3, "HTTP Datagram not enabled, dropping\n");
        return;
    }

    // Parse Quarter Stream ID
    QuicCursor c(bb.data(), bb.len);
    auto quarter_stream_id = c.variable_decode();
    if(!quarter_stream_id) {
        LOGE("Invalid HTTP Datagram: insufficient data for Quarter Stream ID\n");
        ErrProc(HTTP3_ERR_DATAGRAM_ERROR);
        return;
    }

    bb.reserve((int)(bb.len - c.length()));
    bb.id = quarter_stream_id.value() * 4;
    LOGD(DHTTP3, "Get a datagram frame: %" PRIu64 ", length: %zd\n", bb.id, bb.len);
    DatagramProc(std::move(bb));
}


void Http3Base::Init() {
    ctrlid_local   = CreateUbiStream();
    qpackeid_local = CreateUbiStream();
    qpackdid_local = CreateUbiStream();

    Block buff(BUF_LEN);
    QuicCursor c(buff.data(), BUF_LEN);
    c.variable_encode(HTTP3_SETTING_QPACK_MAX_TABLE_CAPACITY);
    c.variable_encode(0);
    c.variable_encode(HTTP3_SETTING_MAX_FIELD_SECTION_SIZE);
    c.variable_encode(BUF_LEN);
    c.variable_encode(HTTP3_SETTING_ENABLE_CONNECT_PROTOCOL);
    c.variable_encode(1);
    c.variable_encode(HTTP3_SETTING_H3_DATAGRAM);
    c.variable_encode(1);
    size_t len = BUF_LEN - c.length();
    char* pos = (char*)buff.reserve(-3); // type + id + length
    QuicCursor fc(pos, 3);
    fc.variable_encode(HTTP3_STREAM_TYPE_CONTROL);
    fc.variable_encode(HTTP3_STREAM_SETTINGS);
    fc.variable_encode(len);
    SendData({std::move(buff), len+3, ctrlid_local});

    Block buff1(variable_encode_len(HTTP3_STREAM_TYPE_QPACK_ENCODE));
    QuicCursor c1(buff1.data(), variable_encode_len(HTTP3_STREAM_TYPE_QPACK_ENCODE));
    c1.variable_encode(HTTP3_STREAM_TYPE_QPACK_ENCODE);
    SendData({std::move(buff1), variable_encode_len(HTTP3_STREAM_TYPE_QPACK_ENCODE) - c1.length(), qpackeid_local});

    Block buff2(variable_encode_len(HTTP3_STREAM_TYPE_QPACK_DECODE));
    QuicCursor c2(buff2.data(), variable_encode_len(HTTP3_STREAM_TYPE_QPACK_DECODE));
    c2.variable_encode(HTTP3_STREAM_TYPE_QPACK_DECODE);
    SendData({std::move(buff2), variable_encode_len(HTTP3_STREAM_TYPE_QPACK_DECODE) - c2.length(), qpackdid_local});
    http3_flag |= HTTP3_FLAG_INITED;
}


void Http3Base::SettingsProc(const uchar* header, size_t len) {
    QuicCursor c(header, len);
    while(c.length()){
        auto id = c.variable_decode();
        auto value = c.variable_decode();
        if(!id || !value){
            //SETTINGS内容里的varint越过帧尾属于畸形帧(RFC 9114 §7.2.4)
            LOGE("http3 settings varint truncated\n");
            ErrProc(HTTP3_ERR_FRAME_ERROR);
            return;
        }
        switch(id.value()){
        case HTTP3_SETTING_MAX_FIELD_SECTION_SIZE:
            LOGD(DHTTP3, "Get max_filed_section_size: %" PRIu64"\n", value.value());
            break;
        case HTTP3_SETTING_QPACK_MAX_TABLE_CAPACITY:
            LOGD(DHTTP3, "Get qpack_max_table_capacity: %" PRIu64"\n", value.value());
            break;
        case HTTP3_SETTING_QPACK_BLOCKED_STREAMS:
            LOGD(DHTTP3, "Get qpack_blocked_streams: %" PRIu64"\n", value.value());
            break;
        case HTTP3_SETTING_ENABLE_CONNECT_PROTOCOL:
            LOGD(DHTTP3, "Get enable_connect_protocol\n");
            if(value.value() == 1) {
                http3_flag |= HTTP3_FLAG_ENABLE_PROTOCOL;
            }
            break;
        case HTTP3_SETTING_H3_DATAGRAM:
            LOGD(DHTTP3, "Get h3_datagram: %" PRIu64"\n", value.value());
            if(value.value() == 1) {
                http3_flag |= HTTP3_FLAG_H3_DATAGRAM;
            }
            break;
        default:
            if(((id.value() - 0x21) % 0x1f) == 0){
                LOGD(DHTTP3, "Get reserved settings: 0x%" PRIu64"\n", id.value());
            }else if(id.value() < HTTP3_SETTING_MAX_FIELD_SECTION_SIZE){
                ErrProc(HTTP3_ERR_SETTINGS_ERROR);
                return;
            }else{
                LOGD(DHTTP3, "Get unknown settings: 0x%" PRIu64 " = %" PRIu64"\n", id.value(), value.value());
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
    QuicCursor c(buff.data(), 1 + 1 + 8);
    c.variable_encode(HTTP3_STREAM_GOAWAY);
    c.variable_encode(variable_encode_len(lastid));
    c.variable_encode(lastid);
    SendData({std::move(buff), (1 + 1 + 8) - c.length(), ctrlid_local});
}

void Http3Base::PushData(Buffer&& bb) {
    if(bb.refs() == 1 || bb.len == 0) {
        size_t size = bb.len;
        size_t pre = 1 + variable_encode_len(size);
        bb.reserve(-(int)pre);
        QuicCursor c(bb.mutable_data(), pre);
        c.variable_encode(HTTP3_STREAM_DATA);
        c.variable_encode(size);
    } else {
        size_t size = 1 + variable_encode_len(bb.len);
        Block buff(size);
        QuicCursor c(buff.data(), size);
        c.variable_encode(HTTP3_STREAM_DATA);
        c.variable_encode(bb.len);
        SendData({std::move(buff), size, bb.id});
    }
    SendData(std::move(bb));
}

void Http3Base::PushDatagram(Buffer&& bb) {
    if(!(http3_flag & HTTP3_FLAG_H3_DATAGRAM)) {
        LOGE("HTTP Datagram not enabled\n");
        return;
    }

    uint64_t quarter_stream_id = bb.id / 4;
    if(quarter_stream_id == UINT64_MAX) {
        LOGE("Failed to encode Quarter Stream ID for stream %" PRIu64 "\n", bb.id);
        return;
    }

    size_t quarter_len = variable_encode_len(quarter_stream_id);
    // Prepend Quarter Stream ID to payload
    bb.reserve(-(int)quarter_len);
    QuicCursor c(bb.mutable_data(), quarter_len);
    c.variable_encode(quarter_stream_id);
    SendDatagram(std::move(bb));
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
