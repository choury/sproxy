#ifndef HTTP2_H__
#define HTTP2_H__

#include "parse.h"
#include "hpack.h"

#include <stdio.h>
#include <stdint.h>
#include <string.h>

#define H2_PREFACE "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

#define get16(a)  (((uchar*)(a))[0]<<8 | ((uchar*)(a))[1])
#define set16(a, x) do {\
                        ((uchar*)(a))[0] = (x)>>8;\
                        ((uchar*)(a))[1] = (x);\
                    }while(0);

#define get24(a) (((uchar*)(a))[0]<<16 | ((uchar*)(a))[1]<<8 | ((uchar*)(a))[2])
#define set24(a, x) do {\
                        ((uchar*)(a))[0] = (x)>>16;\
                        ((uchar*)(a))[1] = (x)>>8;\
                        ((uchar*)(a))[2] = (x);\
                    }while(0);
#define get32(a) (((uchar*)(a))[0]<<24 | ((uchar*)(a))[1]<<16 | ((uchar*)(a))[2]<<8 | ((uchar*)(a))[3])
#define set32(a, x) do {\
                        ((uchar*)(a))[0] = (x)>>24;\
                        ((uchar*)(a))[1] = (x)>>16;\
                        ((uchar*)(a))[2] = (x)>>8;\
                        ((uchar*)(a))[3] = (x);\
                    }while(0);

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
#define WINDOW_UPDATE       8
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


struct SettingFrame{
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

class Http2Base{
protected:
    char http2_buff[FRAMELENLIMIT];
    size_t http2_getlen = 0;
    size_t http2_expectlen = 0;
    Index_table request_table;
    Index_table response_table;
    void DefaultProc();
    void Reset(uint32_t id, uint32_t code);
    virtual void InitProc()=0;
    virtual void HeadersProc(Http2_header *header) = 0;
    virtual ssize_t Read(void* buff, size_t len) = 0;
    virtual ssize_t Write2(const void* buff, size_t len) = 0;
    virtual void SettingsProc(Http2_header *header);
    virtual void PingProc(Http2_header *header);
    virtual void ErrProc(int errcode) = 0;
    virtual void RstProc(Http2_header *header);
    virtual void GoawayProc(Http2_header *header);
    virtual void DataProc2(Http2_header *header)=0;
    void (Http2Base::*Http2_Proc)()=&Http2Base::InitProc;
};

class Http2Res:public Http2Base {
protected:
    virtual void InitProc()override;
    virtual void HeadersProc(Http2_header *header)override;
    virtual void ReqProc(HttpReqHeader &req) = 0;
public:
    Http2Res();
};


class Http2Req:public Http2Base {
protected:
    virtual void InitProc()override;
    virtual void HeadersProc(Http2_header *header)override;
    virtual void ResProc(HttpResHeader &res) = 0;
public:
    void init();
};

struct Http2Info{
    void *ptr;
    uint32_t id;
    uint32_t flags;
};

class Http2{
    std::map<void *, Http2Info*> ptr2info;
    std::map<uint32_t, Http2Info *> id2info;
public:
};

#endif