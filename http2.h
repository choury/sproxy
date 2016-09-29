#ifndef HTTP2_H__
#define HTTP2_H__

#include "parse.h"
#include "hpack.h"
#include "object.h"

#include <list>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#define H2_PREFACE "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"



struct Http2_header {
    uint8_t length[3];
#define DATA_TYPE           0
#define HEADERS_TYPE        1
#define PRIORITY_TYPE       2
#define RST_STREAM_TYPE     3
#define SETTINGS_TYPE       4
#define PUSH_PROMISE_TYPE   5
#define PING_TYPE           6
#define GOAWAY_TYPE         7
#define WINDOW_UPDATE_TYPE  8
#define CONTINUATION        9
    uint8_t type;
#define ACK_F               1
#define END_STREAM_F        1
#define END_SEGMENT_F       2
#define END_HEADERS_F       4
#define PADDED_F            8
#define PRIORITY_F          0x20
    uint8_t flags;
    uint8_t id[4];
}__attribute__((packed));


struct Setting_Frame{
#define SETTINGS_HEADER_TABLE_SIZE      1
#define SETTINGS_ENABLE_PUSH            2
#define SETTINGS_MAX_CONCURRENT_STREAMS 3
#define SETTINGS_INITIAL_WINDOW_SIZE    4
#define SETTINGS_MAX_FRAME_SIZE         5
#define SETTINGS_MAX_HEADER_LIST_SIZE   6
    uint8_t identifier[2];
    uint8_t value[4];
}__attribute__((packed));


#define ERR_NO_ERROR            0
#define ERR_PROTOCOL_ERROR      1
#define ERR_INTERNAL_ERROR      2
#define ERR_FLOW_CONTROL_ERROR  3
#define ERR_SETTINGS_TIMEOUT    4
#define ERR_STREAM_CLOSED       5
#define ERR_FRAME_SIZE_ERROR    6
#define ERR_REFUSED_STREAM      7
#define ERR_CANCEL              8
#define ERR_COMPRESSION_ERROR   9
#define ERR_CONNECT_ERROR       10
#define ERR_ENHANCE_YOUR_CALM   11
#define ERR_INADEQUATE_SECURITY 12
#define ERR_HTTP_1_1_REQUIRED   13


#define FRAMEBODYLIMIT 16384
#define FRAMELENLIMIT FRAMEBODYLIMIT+sizeof(Http2_header) 
#define localframewindowsize  (1024*1024)

struct Http2_frame{
    Http2_header *header;
    size_t wlen;
};

class Http2Base: virtual public Object{
protected:
    char http2_buff[FRAMELENLIMIT];
    uint32_t http2_getlen = 0;
    uint32_t remoteframewindowsize = 65535; //由对端初始化的初始frame的窗口大小
    bool inited = false;
    Index_table request_table;
    Index_table response_table;
    std::list<Http2_frame> framequeue;
    void DefaultProc();
    void Ping( const void *buff );
    void Reset(uint32_t id, uint32_t code);
    void SendInitSetting();
    virtual void InitProc() = 0;
    virtual void HeadersProc(Http2_header *header) = 0;
    virtual ssize_t Read(void* buff, size_t len) = 0;
    virtual ssize_t Write(const void *buff, size_t size) = 0;
    virtual void SendFrame(const Http2_header* header);
    virtual void SendFrame(Http2_header* header);

    virtual void SettingsProc(Http2_header *header);
    virtual void PingProc(Http2_header *header);
    virtual void GoawayProc(Http2_header *header);
    virtual void RstProc(uint32_t id, uint32_t errcode);
    virtual uint32_t ExpandWindowSize(uint32_t id, uint32_t size);
    virtual void WindowUpdateProc(uint32_t id, uint32_t size)=0;
    virtual void DataProc(const Http2_header *header)=0;
    virtual void ErrProc(int errcode) = 0;
    virtual void AdjustInitalFrameWindowSize(ssize_t diff) = 0;
    void (Http2Base::*Http2_Proc)()=&Http2Base::InitProc;
    int Write_Proc();
public:
    ~Http2Base();
};

class Http2Res:public Http2Base {
    using Http2Base::http2_buff;
    using Http2Base::http2_getlen;
protected:
    virtual void InitProc()override;
    virtual void HeadersProc(Http2_header *header)override;
    virtual void ReqProc(HttpReqHeader &req) = 0;
};


class Http2Req:public Http2Base {
    using Http2Base::http2_buff;
    using Http2Base::http2_getlen;
protected:
    virtual void InitProc()override;
    virtual void HeadersProc(Http2_header *header)override;
    virtual void ResProc(HttpResHeader &res) = 0;
public:
    void init();
};


#endif
