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

//解析帧头的type/length两个varint，成功返回帧头字节数，数据不足返回0
static size_t ParseFrameHeader(const Buffer& bb, uint64_t& type, uint64_t& length) {
    QuicCursor fc(bb.data(), bb.len);
    auto t = fc.variable_decode();
    if(!t){
        return 0;
    }
    auto l = fc.variable_decode();
    if(!l){
        return 0;
    }
    type = t.value();
    length = l.value();
    return bb.len - fc.length();
}

//按流类别分派：控制流/qpack流/push流/双向请求流/其他单向流
size_t Http3Base::Http3_Proc(Buffer& bb) {
    size_t len = bb.len;
    if(ctrlid_remote && bb.id == ctrlid_remote){
        CtrlStreamProc(bb);
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
    }else if(push_streams.count(bb.id)){
        PushStreamProc(bb);
    }else if((bb.id & 0x02) == 0){
        RequestStreamProc(bb);
    }else{
        UniStreamProc(bb);
    }
    if(http3_flag & HTTP3_FLAG_ERROR){
        return 0;
    }
    return len - bb.len;
}

//对端控制流：SETTINGS/MAX_PUSH_ID/CANCEL_PUSH/GOAWAY帧 
size_t Http3Base::CtrlStreamProc(Buffer& bb) {
    size_t len = bb.len;
    if(bb.len == 0){
        return 0;
    }
    uint64_t type = 0, length = 0;
    size_t header_len = ParseFrameHeader(bb, type, length);
    if(header_len == 0 || length > bb.len - header_len){
        return 0;
    }
    bb.reserve((int)header_len);
    //控制流首帧必须是SETTINGS
    if(!ctrl_settings_recv && type != HTTP3_STREAM_SETTINGS){
        LOGE("http3 first frame on control stream is not settings: type 0x%" PRIx64 "\n", type);
        ErrProc(HTTP3_ERR_MISSING_SETTINGS);
        return 0;
    }
    switch(type){
    case HTTP3_STREAM_SETTINGS:
        if(ctrl_settings_recv){
            //控制流上只允许一个SETTINGS帧
            LOGE("http3 duplicate settings frame on control stream\n");
            ErrProc(HTTP3_ERR_FRAME_UNEXPECTED);
            return 0;
        }
        ctrl_settings_recv = true;
        LOGD(DHTTP3, "Get a settings frame: length: %" PRIu64 "\n", length);
        SettingsProc((const uchar*)bb.data(), length);
        break;
    case HTTP3_STREAM_MAX_PUSH_ID:{
        //客户端扩大push配额，只允许扩大不允许缩小
        LOGD(DHTTP3, "Get a max push id frame: length: %" PRIu64 "\n", length);
        QuicCursor c(bb.data(), length);
        auto maxid = c.variable_decode();
        if(!maxid || c.length()){
            LOGE("http3 max push id frame malformed\n");
            ErrProc(HTTP3_ERR_FRAME_ERROR);
            return 0;
        }
        int64_t value = (int64_t)maxid.value();
        if(value < max_push_id){
            LOGE("http3 max push id decreased: %" PRIu64 " < %" PRIi64 "\n", maxid.value(), max_push_id);
            ErrProc(HTTP3_ERR_ID_ERROR);
            return 0;
        }
        if(max_push_id != value){
            max_push_id = value;
            MaxPushIdProc(max_push_id);
        }
        break;
    }
    case HTTP3_STREAM_CANCEL_PUSH:{
        //未知或已兑现的Push ID容忍(可能乱序先于PUSH_PROMISE到达，或push已被本端处理)
        LOGD(DHTTP3, "Get a cancel push frame: length: %" PRIu64 "\n", length);
        QuicCursor c(bb.data(), length);
        auto pushid = c.variable_decode();
        if(!pushid || c.length()){
            LOGE("http3 cancel push frame malformed\n");
            ErrProc(HTTP3_ERR_FRAME_ERROR);
            return 0;
        }
        //push接收方按本端授权的sent_max_push_id校验；push发送方按本端已分配的next_push_id校验
        int64_t limit = sent_max_push_id >= 0 ? sent_max_push_id : (int64_t)next_push_id - 1;
        if((int64_t)pushid.value() > limit){
            LOGE("http3 cancel push exceeds cancellable push id: %" PRIu64 "/%" PRIi64 "\n",
                 pushid.value(), limit);
            ErrProc(HTTP3_ERR_ID_ERROR);
            return 0;
        }
        //push_streams以流id为键，按Push ID(值)定位对应的push stream并丢弃其响应
        for(auto& p : push_streams){
            if(p.second == pushid.value()){
                p.second = UINT64_MAX; //丢弃后续响应
                break;
            }
        }
        break;
    }
    case HTTP3_STREAM_GOAWAY:{
        LOGD(DHTTP3, "Get a goaway frame: length: %" PRIu64 "\n", length);
        //last stream id是varint，必须限制在帧长内解析，空帧/截断帧直接报错
        QuicCursor c(bb.data(), length);
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
        LOGE("http3 unexpected frame for control: type 0x%" PRIx64 ", length:%zd\n", type, (size_t)length);
        ErrProc(HTTP3_ERR_FRAME_UNEXPECTED);
        return 0;
    default:
        if((type - 0x21) % 0x1f == 0){
            LOGD(DHTTP3, "reserved stream type: 0x%" PRIx64 ", length:%zd\n", type, (size_t)length);
        }else{
            LOGD(DHTTP3, "doesn't support stream type: %" PRIx64 "\n", type);
        }
        break;
    }
    bb.reserve((int)length);
    return len - bb.len;
}

size_t Http3Base::PushStreamProc(Buffer& bb) {
    size_t len = bb.len;
    if(bb.len == 0){
        return 0;
    }
    uint64_t type = 0, length = 0;
    size_t header_len = ParseFrameHeader(bb, type, length);
    if(header_len == 0){
        return 0;
    }
    if(length > bb.len - header_len){
        //HEADERS帧必须收齐才能解码，先于流控窗口判断头部超限，避免慢速滴灌攒大块
        if(type == HTTP3_STREAM_HEADERS && length > HTTP_HEADER_LIMIT){
            LOGE("ERROR http3 header frame too large: %" PRIu64"/%d\n", length, HTTP_HEADER_LIMIT);
            ErrProc(HTTP3_ERR_FRAME_ERROR);
            return 0;
        }
        return 0;
    }
    bb.reserve((int)header_len);
    switch(type){
    case HTTP3_STREAM_HEADERS:{
        auto it = push_streams.find(bb.id);
        LOGD(DHTTP3, "Get a pushed header frame: %" PRIu64 ", length: %" PRIu64 "\n", bb.id, length);
        if(it->second == UINT64_MAX){
            //已交付过响应头，后续HEADERS按trailers丢弃
            break;
        }
        std::shared_ptr<HttpResHeader> res = Qpack_decoder::UnpackHttp3Res(bb.data(), length);
        if(res == nullptr) {
            ErrProc(HTTP3_ERR_QPACK_DECOMPRESSION_FAILED);
            return 0;
        }
        PushResProc(it->second, res);
        it->second = UINT64_MAX;
        break;
    }
    case HTTP3_STREAM_DATA:
        //TODO: 数据暂未上送处理
        LOGD(DHTTP3, "push stream data frame: %" PRIu64 ", length: %" PRIu64 "\n", bb.id, length);
        break;
    default:
        LOGE("http3 unexpected frame on push stream: type 0x%" PRIx64 "\n", type);
        ErrProc(HTTP3_ERR_FRAME_UNEXPECTED);
        return 0;
    }
    bb.reserve((int)length);
    return len - bb.len;
}

//双向请求流：请求/响应的DATA/HEADERS/PUSH_PROMISE帧
size_t Http3Base::RequestStreamProc(Buffer& bb) {
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
    uint64_t type = 0, length = 0;
    size_t header_len = ParseFrameHeader(bb, type, length);
    if(header_len == 0){
        LOGD(DHTTP3, "not enough to get frame header: %zd\n", bb.len);
        return 0;
    }
    if(type == HTTP3_STREAM_DATA){
        LOGD(DHTTP3, "Get a data frame: %" PRIu64 ", length: %" PRIu64 "\n", bb.id, length);
        bb.reserve((int)header_len);
        if(length == 0){
            return len - bb.len;
        }
        data_remain[bb.id] = length;
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
    if(length > bb.len - header_len){
        //HEADERS/PUSH_PROMISE帧必须收齐才能解码，先于流控窗口判断头部超限，避免慢速滴灌攒大块
        if((type == HTTP3_STREAM_HEADERS || type == HTTP3_STREAM_PUSH_PROMISE)
           && length > HTTP_HEADER_LIMIT){
            LOGE("ERROR http3 header frame too large: %" PRIu64"/%d\n", length, HTTP_HEADER_LIMIT);
            ErrProc(HTTP3_ERR_FRAME_ERROR);
            return 0;
        }
        return 0;
    }
    bb.reserve((int)header_len);
    switch(type){
    case HTTP3_STREAM_HEADERS:
        LOGD(DHTTP3, "Get a header frame: %" PRIu64 ", length: %" PRIu64 "\n", bb.id, length);
        HeadersProc(bb.id, (const uchar*)bb.data(), length);
        break;
    case HTTP3_STREAM_PUSH_PROMISE: {
        LOGD(DHTTP3, "Get a push promise frame: %" PRIu64 ", length: %" PRIu64 "\n", bb.id, length);
        QuicCursor c(bb.data(), length);
        auto pushid = c.variable_decode();
        if(!pushid || c.empty()){
            LOGE("http3 push promise frame without field section\n");
            ErrProc(HTTP3_ERR_FRAME_ERROR);
            return 0;
        }
        //Push ID超过本端发出的MAX_PUSH_ID授权必须报错；
        if((int64_t)pushid.value() > sent_max_push_id){
            LOGE("http3 push promise exceeds max push id: %" PRIu64 "\n", pushid.value());
            ErrProc(HTTP3_ERR_ID_ERROR);
            return 0;
        }
        std::shared_ptr<HttpReqHeader> req = Qpack_decoder::UnpackHttp3Req(c.data(), c.length());
        if(req == nullptr) {
            ErrProc(HTTP3_ERR_QPACK_DECOMPRESSION_FAILED);
            return 0;
        }
        PushProc(pushid.value(), req);
        break;
    }
    case HTTP3_STREAM_CANCEL_PUSH:
    case HTTP3_STREAM_MAX_PUSH_ID:
    case HTTP3_STREAM_GOAWAY:
        LOGE("http3 unexpected frame for data: type 0x%x\n", (int)type);
        ErrProc(HTTP3_ERR_FRAME_UNEXPECTED);
        return 0;
    default:
        if((type - 0x21) % 0x1f == 0){
            LOGD(DHTTP3, "reserved stream type: 0x%" PRIx64 ", length:%zd\n", type, (size_t)length);
        }else{
            LOGD(DHTTP3, "doesn't support stream type: %" PRIx64 "\n", type);
        }
        break;
    }
    bb.reserve((int)length);
    return len - bb.len;
}

//未登记的单向流：解析流类型并登记
size_t Http3Base::UniStreamProc(Buffer& bb) {
    QuicCursor c(bb.data(), bb.len);
    auto type = c.variable_decode();
    if(!type){
        return 0;
    }
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
    case HTTP3_STREAM_TYPE_PUSH:{
        auto pushid = c.variable_decode();
        if(!pushid){
            LOGD(DHTTP3, "not enough to get push id: %zd\n", bb.len);
            return 0;
        }
        LOGD(DHTTP3, "Get push stream id: %" PRIu64 ", push id: %" PRIu64 "\n", bb.id, pushid.value());
        if((int64_t)pushid.value() > sent_max_push_id){
            LOGE("http3 push stream exceeds max push id: %" PRIu64 "/%" PRIu64 "\n",
                 pushid.value(), sent_max_push_id);
            if((bb.id & 0x03) == 0x02){
                // server角色收到push stream必须报H3_STREAM_CREATION_ERROR
                ErrProc(HTTP3_ERR_STREAM_CREATION_ERROR);
            }else {
                ErrProc(HTTP3_ERR_ID_ERROR);
            }
            return 0;
        }
        push_streams.emplace(bb.id, pushid.value());
        break;
    }
    default:
        if((type.value() - 0x21) % 0x1f == 0){
            LOGD(DHTTP3, "reserved stream type: %" PRIu64 "\n", type.value());
            c.advance((int)c.length());
        }else{
            LOGD(DHTTP3, "doesn't support stream type: %" PRIu64 "\n", type.value());
            ErrProc(HTTP3_ERR_STREAM_CREATION_ERROR);
            return 0;
        }
    }
    size_t len = bb.len - c.length();
    bb.reserve((int)len);
    return len;
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

//在控制流上发送MAX_PUSH_ID，授权对端push到maxid
void Http3Requster::SendMaxPushId(uint64_t maxid) {
    assert((int64_t)maxid >= sent_max_push_id && maxid < INT64_MAX);
    sent_max_push_id = (int64_t)maxid;
    Block buff(1 + 1 + 8); // enough for max push id frame
    QuicCursor c(buff.data(), 1 + 1 + 8);
    c.variable_encode(HTTP3_STREAM_MAX_PUSH_ID);
    c.variable_encode(variable_encode_len(maxid));
    c.variable_encode(maxid);
    SendData({std::move(buff), (1 + 1 + 8) - c.length(), ctrlid_local});
}

void Http3Responser::HeadersProc(uint64_t id, const uchar *header, size_t length) {
    std::shared_ptr<HttpReqHeader> req = Qpack_decoder::UnpackHttp3Req(header, length);
    if(req == nullptr) {
        ErrProc(HTTP3_ERR_QPACK_DECOMPRESSION_FAILED);
        return;
    }
    ReqProc(id, req);
}

//在流id上发送PUSH_PROMISE，Push ID取本端下一个未用值并返回，失败返回UINT64_MAX；
//调用方须确保已收到对端MAX_PUSH_ID授权且未用尽(next_push_id <= max_push_id)，且id为已创建的流
uint64_t Http3Responser::PushPromise(uint64_t id, std::shared_ptr<HttpReqHeader> req) {
    assert((int64_t)next_push_id <= max_push_id);
    Block buff(BUF_LEN);
    size_t len = Qpack_encoder::PackHttp3Req(req, buff.data(), BUF_LEN);
    if(len == 0){
        LOGE("http3 request header too long: %s\n", req->geturl().c_str());
        ErrProc(HTTP3_ERR_INTERNAL_ERROR);
        return UINT64_MAX;
    }
    uint64_t pushid = next_push_id++;
    //载荷 = Push ID + Encoded Field Section (RFC 9114 §7.2.5)
    size_t framelen = variable_encode_len(pushid) + len;
    size_t pre = variable_encode_len(HTTP3_STREAM_PUSH_PROMISE)
                 + variable_encode_len(framelen) + variable_encode_len(pushid);
    char* p = (char*)buff.reserve(-(int)pre);
    QuicCursor fc(p, pre);
    fc.variable_encode(HTTP3_STREAM_PUSH_PROMISE);
    fc.variable_encode(framelen);
    fc.variable_encode(pushid);
    SendData({std::move(buff), pre + len, id});
    return pushid;
}
