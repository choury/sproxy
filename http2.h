#ifndef HTTP2_H__
#define HTTP2_H__

#include "parse.h"
#include "hpack.h"

#include <stdio.h>
#include <stdint.h>
#include <string.h>

#define H2_PREFACE "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
#define FRAMELENLIMIT 16393

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

class Http2{
    char http2_buff[FRAMELENLIMIT];
    size_t http2_getlen = 0;
    size_t http2_expectlen = strlen(H2_PREFACE);
    void InitProc();
    void DefaultProc();
    void HeadersProc(Http2_header *header);
    void SettingsProc(Http2_header *header);
    void PingProc(Http2_header *header);
protected:
    Index_table index_table;
    virtual ssize_t Read(void* buff, size_t len) = 0;
    virtual ssize_t Write(const void* buff, size_t len) = 0;
    virtual void ErrProc(int errcode) = 0;
    virtual void ReqProc(HttpReqHeader &req);
    virtual void ResProc(HttpResHeader &res);
    virtual void RstProc(Http2_header *header);
    virtual void GoawayProc(Http2_header *header);
    virtual ssize_t DataProc2(Http2_header *header)=0;
public:
    void (Http2::*Http2_Proc)()=&Http2::InitProc;
    Http2();
};


#endif