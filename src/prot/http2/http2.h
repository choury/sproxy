#ifndef HTTP2_H__
#define HTTP2_H__

#include "hpack.h"

#include <stdio.h>
#include <stdint.h>
#include <string.h>

class Buffer;

#define HTTP2_PREFACE "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

struct Http2_header {
    uint8_t length[3];
#define HTTP2_STREAM_DATA           0u
#define HTTP2_STREAM_HEADERS        1u
#define HTTP2_STREAM_PRIORITY       2u
#define HTTP2_STREAM_RESET          3u
#define HTTP2_STREAM_SETTINGS       4u
#define HTTP2_STREAM_PUSH_PROMISE   5u
#define HTTP2_STREAM_PING           6u
#define HTTP2_STREAM_GOAWAY         7u
#define HTTP2_STREAM_WINDOW_UPDATE  8u
#define HTTP2_STREAM_CONTINUATION   9u
#define HTTP2_STREAM_ALTSVC         10u
    uint8_t type;
#define HTTP2_ACK_F               1u
#define HTTP2_END_STREAM_F        1u
#define HTTP2_END_HEADERS_F       4u
#define HTTP2_PADDED_F            8u
#define HTTP2_PRIORITY_F          0x20u
    uint8_t flags;
    uint8_t id[4];
}__attribute__((packed));

#define HTTP2_ID(x) (get32(x) & 0x7fffffff)

struct Setting_Frame{
#define HTTP2_SETTING_HEADER_TABLE_SIZE      1
#define HTTP2_SETTING_ENABLE_PUSH            2
#define HTTP2_SETTING_MAX_CONCURRENT_STREAMS 3
#define HTTP2_SETTING_INITIAL_WINDOW_SIZE    4
#define HTTP2_SETTING_MAX_FRAME_SIZE         5
#define HTTP2_SETTING_MAX_HEADER_LIST_SIZE   6
#define HTTP2_SETTING_ENABLE_CONNECT_PROTOCOL 8  //rfc8441
    uint8_t identifier[2];
    uint8_t value[4];
}__attribute__((packed));

struct Goaway_Frame{
    uint8_t last_stream_id[4];
    uint8_t errcode[4];
    uint8_t data[0];
}__attribute__((packed));

#define HTTP2_ERR_NO_ERROR            0u
#define HTTP2_ERR_PROTOCOL_ERROR      1u
#define HTTP2_ERR_INTERNAL_ERROR      2u
#define HTTP2_ERR_FLOW_CONTROL_ERROR  3u
#define HTTP2_ERR_SETTINGS_TIMEOUT    4u
#define HTTP2_ERR_STREAM_CLOSED       5u
#define HTTP2_ERR_FRAME_SIZE_ERROR    6u
#define HTTP2_ERR_REFUSED_STREAM      7u
#define HTTP2_ERR_CANCEL              8u
#define HTTP2_ERR_COMPRESSION_ERROR   9u
#define HTTP2_ERR_CONNECT_ERROR       10u
#define HTTP2_ERR_ENHANCE_YOUR_CALM   11u
#define HTTP2_ERR_INADEQUATE_SECURITY 12u
#define HTTP2_ERR_HTTP_1_1_REQUIRED   13u


#define FRAMEBODYLIMIT BUF_LEN
#define localframewindowsize  FRAMEBODYLIMIT

struct Http2_frame{
    Http2_header *header;
    size_t wlen;
};


class Http2Base{
protected:
    uint32_t remoteframewindowsize = 65535; //由对端初始化的初始frame的窗口大小
    uint32_t remoteframebodylimit = FRAMEBODYLIMIT;

    int32_t remotewinsize = 65535; // 对端提供的窗口大小，发送时减小，收到对端update时增加
    int32_t localwinsize = 65535; // 发送给对端的窗口大小，接受时减小，给对端发送update时增加
#define HTTP2_FLAG_INITED      (1u << 0u)
#define HTTP2_FLAG_GOAWAYED    (1u << 1u)
#define HTTP2_FLAG_END         (1u << 2u)
#define HTTP2_FLAG_ERROR       (1u << 3u)
#define HTTP2_FLAG_ENABLE_PUSH (1u << 4u)
#define HTTP2_FLAG_ENABLE_PROTOCOL (1u << 5u)
    uint32_t http2_flag = 0;
    uint32_t recvid = 0;
    uint32_t sendid = 1;
    Hpack_encoder hpack_encoder;
    Hpack_decoder hpack_decoder;
    std::unique_ptr<Buffer> header_buffer;
    virtual size_t InitProc(Buffer& bb) = 0;
    size_t DefaultProc(Buffer& bb);

    // 处理header的所有信息都保存在header_buffer中
    virtual void HeadersProc() = 0;
    virtual void SettingsProc(const Http2_header *header);
    virtual void PingProc(const Http2_header *header);
    virtual void GoawayProc(const Http2_header *header);
    virtual void DataProc(Buffer&& bb) = 0;
    virtual void RstProc(uint32_t id, uint32_t errcode);
    virtual void EndProc(uint32_t id);
    virtual void ErrProc(int errcode) = 0;

    void Ping(const void *buff);
    void Reset(uint32_t id, uint32_t code);
    void Goaway(uint32_t lastid, uint32_t code, char* message = nullptr);
    void SendInitSetting(bool enable_push);
    virtual void SendData(Buffer&& bb) = 0;
    virtual void PushData(Buffer&& bb);

    virtual uint32_t ExpandWindowSize(uint32_t id, uint32_t size);
    virtual void WindowUpdateProc(uint32_t id, uint32_t size) = 0;
    virtual void AdjustInitalFrameWindowSize(ssize_t diff) = 0;
    size_t (Http2Base::*Http2_Proc)(Buffer& bb)=&Http2Base::InitProc;
public:
    ~Http2Base() = default;
};

class Http2Responser:public Http2Base{
protected:
    virtual size_t InitProc(Buffer& bb)override;
    virtual void HeadersProc()override;
    virtual void ReqProc(uint32_t id, std::shared_ptr<HttpReqHeader> req) = 0;
    virtual void AltSvc(uint32_t id, const char* origin, const char* value);
public:
    uint32_t OpenStream();
};


class Http2Requster:public Http2Base{
protected:
    void init(bool enable_push);
    virtual size_t InitProc(Buffer& bb)override;
    virtual void HeadersProc()override;
    virtual void ResProc(uint32_t id, std::shared_ptr<HttpResHeader> res) = 0;
    virtual void PushProc(uint32_t, std::shared_ptr<HttpReqHeader>) {}
public:
    uint32_t OpenStream();
};



#endif
