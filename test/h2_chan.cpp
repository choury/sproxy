//h2层channel实现，设计说明见h2_chan.h
#include "h2_chan.h"
#include "common/common.h"
#include "prot/http/http_code.h"

#include <stdio.h>
#include <string.h>
#include <algorithm>

//本层编入工程的hpack.cpp/http_code.cpp，单测二进制不链整个sproxy，
//桩掉hpack.o引用的全局符号(与src/prot/http2/hpack_test同款做法)
void slog(int, const char*, ...) {}
struct debug_flags_map debug[128] = {};
static HeaderMap g_hpack_headers;
std::shared_ptr<HttpReqHeader> HttpReqHeader::create(HeaderMap&& headers) {
    g_hpack_headers = std::move(headers);
    return nullptr;
}
//Apple clang在-O0下引用HttpReqHeader的typeinfo，桩出全部非inline虚函数，
//使vtable/typeinfo随关键函数在本测试TU内发射；测试本身不调用它们
bool HttpReqHeader::no_body() const { return true; }
bool HttpReqHeader::no_end() const { return false; }
std::multimap<std::string, std::string> HttpReqHeader::Normalize() const { return {}; }
size_t HttpReqHeader::mem_usage() { return 0; }
HttpHeader::HttpHeader() {}
size_t HttpHeader::mem_usage() { return 0; }
std::multimap<std::string, std::string> HttpResHeader::Normalize() const { return {}; }
bool HttpResHeader::no_body() const { return false; }
bool HttpResHeader::no_end() const { return false; }
HttpResHeader::HttpResHeader(HeaderMap&& headers) {
    g_hpack_headers = std::move(headers);
}

//暴露Hpack受保护的encode/decode(HPACK编解码复用工程实现)：
//CONNECT头只需:method/:authority两个静态名字索引，无需构造HttpReqHeader
namespace {
struct HpackEnc: Hpack_encoder {
    using Hpack_encoder::Hpack_encoder;
    bool pack(HttpCursor& cursor, const char* name, const char* value) {
        return encode(cursor, name, value);
    }
};
struct HpackDec: Hpack_decoder {
    using Hpack_decoder::Hpack_decoder;
    HeaderMap unpack(const HttpCursor& cursor) {
        return decode(cursor);
    }
};
} //namespace

bool H2Channel::send_frame(uint8_t type, uint8_t flags, uint32_t fsid,
                           const void* payload, size_t len) {
    if(len > 16384) {
        return false;
    }
    unsigned char head[sizeof(Http2_header)] = {};
    set24(head, len);
    head[3] = type;
    head[4] = flags;
    set32(head + 5, fsid);
    if(base->write(head, sizeof(head)) != 0) {
        return false;
    }
    return len == 0 || base->write(payload, len) == 0;
}

bool H2Channel::read_frame(uint8_t& type, uint8_t& flags, uint32_t& fsid,
                           std::string& payload, int timeout_ms) {
    while(rbuf.size() < sizeof(Http2_header)) {
        char buf[16384];
        int n = base->read(buf, sizeof(buf), timeout_ms);
        if(n <= 0) {
            return false;
        }
        rbuf.append(buf, (size_t)n);
    }
    size_t len = (size_t)get24(&rbuf[0]);
    if(rbuf.size() < sizeof(Http2_header) + len) {
        char buf[16384];
        size_t want = sizeof(Http2_header) + len - rbuf.size();
        int n = base->read(buf, std::min(want, sizeof(buf)), timeout_ms);
        if(n <= 0) {
            return false;
        }
        rbuf.append(buf, (size_t)n);
        return read_frame(type, flags, fsid, payload, timeout_ms);
    }
    type = (uint8_t)rbuf[3];
    flags = (uint8_t)rbuf[4];
    fsid = HTTP2_ID(&rbuf[5]);
    payload.assign(rbuf, sizeof(Http2_header), len);
    rbuf.erase(0, sizeof(Http2_header) + len);
    return true;
}

//读一帧并处理：应答SETTINGS/PING，汇集流1的DATA
int H2Channel::pump(int timeout_ms) {
    for(;;) {
        uint8_t type, flags;
        uint32_t fsid;
        std::string payload;
        if(!read_frame(type, flags, fsid, payload, timeout_ms)) {
            fprintf(stderr, "[h2] read failed\n");
            return -1;
        }
        switch(type) {
        case HTTP2_STREAM_SETTINGS:
            if(!(flags & HTTP2_ACK_F)) {
                send_frame(HTTP2_STREAM_SETTINGS, HTTP2_ACK_F, 0, nullptr, 0);
            }
            continue;
        case HTTP2_STREAM_PING:
            if(!(flags & HTTP2_ACK_F)) {
                send_frame(HTTP2_STREAM_PING, HTTP2_ACK_F, 0, payload.data(), payload.size());
            }
            continue;
        case HTTP2_STREAM_WINDOW_UPDATE:
            continue; //测试流量不超初始窗口，见h2_chan.h
        case HTTP2_STREAM_DATA:
            if(fsid != sid) {
                continue;
            }
            if(flags & HTTP2_PADDED_F) {
                size_t padlen = (unsigned char)payload.back();
                if(payload.size() < 1 || padlen + 1 > payload.size()) {
                    fprintf(stderr, "[h2] read failed\n");
                    return -1;
                }
                payload = payload.substr(1, payload.size() - 1 - padlen);
            }
            datbuf.append(payload);
            if(flags & HTTP2_END_STREAM_F) {
                fin = true;
                printf("\n[h2] fin\n");
            }
            return 0;
        case HTTP2_STREAM_HEADERS:
            if(fsid != sid) {
                continue;
            }
            if(!(flags & HTTP2_END_STREAM_F)) {
                continue; //流中途的头块，与隧道数据无关
            }
            //trailer：标志流结束，内容不解析
            fin = true;
            printf("[h2] fin\n");
            return 0;
        case HTTP2_STREAM_RESET:
            if(fsid != sid) {
                continue;
            }
            rst = true;
            printf("[h2] rst\n");
            return 0;
        case HTTP2_STREAM_GOAWAY:
            goaway = true;
            printf("[h2] goaway\n");
            return 0;
        default:
            continue;
        }
    }
}

H2Channel::H2Channel(std::unique_ptr<Channel> b, const std::string& authority)
        : base(std::move(b)) {
    //preface + 空SETTINGS
    if(base->write(HTTP2_PREFACE, strlen(HTTP2_PREFACE)) != 0 ||
       !send_frame(HTTP2_STREAM_SETTINGS, 0, 0, nullptr, 0))
    {
        fprintf(stderr, "h2 connect failed: send preface failed\n");
        close();
        return;
    }
    //流1 CONNECT HEADERS(:method/:authority，HPACK静态名字索引+字面量值)
    char block[512];
    HttpCursor cursor(block, sizeof(block));
    {
        HpackEnc enc;
        if(!enc.pack(cursor, ":method", "CONNECT") ||
           !enc.pack(cursor, ":authority", authority.c_str()))
        {
            fprintf(stderr, "h2 connect failed: encode headers failed\n");
            close();
            return;
        }
    }
    size_t blen = sizeof(block) - cursor.length();
    if(!send_frame(HTTP2_STREAM_HEADERS, HTTP2_END_HEADERS_F, sid, block, blen)) {
        fprintf(stderr, "h2 connect failed: send headers failed\n");
        close();
        return;
    }
    //等待响应HEADERS(顺带应答对端SETTINGS/PING)
    for(;;) {
        uint8_t type, flags;
        uint32_t fsid;
        std::string payload;
        if(!read_frame(type, flags, fsid, payload, 5000)) {
            fprintf(stderr, "h2 connect failed: read timeout or error\n");
            break;
        }
        if(type == HTTP2_STREAM_SETTINGS && !(flags & HTTP2_ACK_F)) {
            send_frame(HTTP2_STREAM_SETTINGS, HTTP2_ACK_F, 0, nullptr, 0);
            continue;
        }
        if(type == HTTP2_STREAM_PING && !(flags & HTTP2_ACK_F)) {
            send_frame(HTTP2_STREAM_PING, HTTP2_ACK_F, 0, payload.data(), payload.size());
            continue;
        }
        if(type == HTTP2_STREAM_GOAWAY) {
            printf("[h2] goaway\n");
            fprintf(stderr, "h2 connect failed: goaway before response\n");
            break;
        }
        if(type == HTTP2_STREAM_RESET && fsid == sid) {
            printf("[h2] rst\n");
            fprintf(stderr, "h2 connect failed: stream reset\n");
            break;
        }
        if(type != HTTP2_STREAM_HEADERS || fsid != sid) {
            continue;
        }
        //响应头：剥PADDED/PRIORITY，拼CONTINUATION，解出:status
        if(flags & HTTP2_PADDED_F) {
            size_t padlen = payload.empty() ? 0 : (unsigned char)payload.back();
            if(payload.size() >= 1 && padlen + 1 <= payload.size()) {
                payload = payload.substr(1, payload.size() - 1 - padlen);
            }
        }
        if(flags & HTTP2_PRIORITY_F) {
            if(payload.size() >= 5) {
                payload.erase(0, 5);
            }
        }
        //响应头可能跨CONTINUATION续帧，逐帧续接到payload尾部
        while(!(flags & HTTP2_END_HEADERS_F)) {
            std::string cont;
            if(!read_frame(type, flags, fsid, cont, 5000) ||
               type != HTTP2_STREAM_CONTINUATION || fsid != sid)
            {
                fprintf(stderr, "h2 connect failed: read continuation failed\n");
                payload.clear();
                break;
            }
            payload += cont;
        }
        std::string status = "-";
        if(!payload.empty()) {
            HpackDec dec;
            HeaderMap headers = dec.unpack(HttpCursor(payload.data(), payload.size()));
            auto it = headers.find(":status");
            if(it != headers.end()) {
                status = it->second;
            }
        }
        printf("[h2] status %s\n", status.c_str());
        if(flags & HTTP2_END_STREAM_F) {
            fin = true;
            printf("[h2] fin\n");
        }
        if(status.size() == 3 && status[0] == '2') {
            ok = true;
            return;
        }
        fprintf(stderr, "h2 connect failed: status %s\n", status.c_str());
        break;
    }
    close();
}

int H2Channel::read(void* buf, size_t n, int timeout_ms) {
    if(!datbuf.empty()) {
        size_t c = std::min(n, datbuf.size());
        memcpy(buf, datbuf.data(), c);
        datbuf.erase(0, c);
        return (int)c;
    }
    if(rst) {
        return -2;
    }
    if(fin || goaway) {
        return 0;
    }
    if(pump(timeout_ms) != 0) {
        return -2;
    }
    if(datbuf.empty()) {
        return 0; //fin/rst/goaway事件，无数据
    }
    size_t c = std::min(n, datbuf.size());
    memcpy(buf, datbuf.data(), c);
    datbuf.erase(0, c);
    return (int)c;
}

int H2Channel::write(const void* p, size_t n) {
    if(fin || half_closed || rst) {
        return -1;
    }
    const char* pc = (const char*)p;
    while(n > 0) {
        size_t c = std::min(n, (size_t)16384);
        if(!send_frame(HTTP2_STREAM_DATA, 0, sid, pc, c)) {
            return -1;
        }
        pc += c;
        n -= c;
    }
    return 0;
}

void H2Channel::shutdown_wr() {
    //只关本端写半关；对端是否END_STREAM由read路径上的fin标志体现
    if(!half_closed && !rst) {
        send_frame(HTTP2_STREAM_DATA, HTTP2_END_STREAM_F, sid, nullptr, 0);
        half_closed = true;
    }
}

void H2Channel::close() {
    if(base) {
        base->close();
        base.reset();
    }
    rbuf.clear();
    datbuf.clear();
}
