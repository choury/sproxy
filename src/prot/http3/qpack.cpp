#include "qpach.h"

#include <string.h>

static const char* static_table[][2] = {
    {":authority", 0},
    {":path", "/"},
    {"age", "0"},
    {"content-disposition", 0},
    {"content-length", "0"},
    {"cookie", 0},
    {"date", 0},
    {"etag", 0},
    {"if-modified-since", 0},
    {"if-none-match", 0},
    {"last-modified", 0},
    {"link", 0},
    {"location", 0},
    {"referer", 0},
    {"set-cookie", 0},
    {":method", "CONNECT"},
    {":method", "DELETE"},
    {":method", "GET"},
    {":method", "HEAD"},
    {":method", "OPTIONS"},
    {":method", "POST"},
    {":method", "PUT"},
    {":scheme", "http"},
    {":scheme", "https"},
    {":status", "103"},
    {":status", "200"},
    {":status", "304"},
    {":status", "404"},
    {":status", "503"},
    {"accept", "*/*"},
    {"accept", "application/dns-message"},
    {"accept-encoding", "gzip, deflate, br"},
    {"accept-ranges", "bytes"},
    {"access-control-allow-headers", "cache-control"},
    {"access-control-allow-headers", "content-type"},
    {"access-control-allow-origin", "*"},
    {"cache-control", "max-age=0"},
    {"cache-control", "max-age=2592000"},
    {"cache-control", "max-age=604800"},
    {"cache-control", "no-cache"},
    {"cache-control", "no-store"},
    {"cache-control", "public, max-age=31536000"},
    {"content-encoding", "br"},
    {"content-encoding", "gzip"},
    {"content-type", "application/dns-message"},
    {"content-type", "application/javascript"},
    {"content-type", "application/json"},
    {"content-type", "application/x-www-form-urlencoded"},
    {"content-type", "image/gif"},
    {"content-type", "image/jpeg"},
    {"content-type", "image/png"},
    {"content-type", "text/css"},
    {"content-type", "text/html; charset=utf-8"},
    {"content-type", "text/plain"},
    {"content-type", "text/plain;charset=utf-8"},
    {"range", "bytes=0-"},
    {"strict-transport-security", "max-age=31536000"},
    {"strict-transport-security", "max-age=31536000; includesubdomains"},
    {"strict-transport-security", "max-age=31536000; includesubdomains; preload"},
    {"vary", "accept-encoding"},
    {"vary", "origin"},
    {"x-content-type-options", "nosniff"},
    {"x-xss-protection", "1; mode=block"},
    {":status", "100"},
    {":status", "204"},
    {":status", "206"},
    {":status", "302"},
    {":status", "400"},
    {":status", "403"},
    {":status", "421"},
    {":status", "425"},
    {":status", "500"},
    {"accept-language", 0},
    {"access-control-allow-credentials", "FALSE"},
    {"access-control-allow-credentials", "TRUE"},
    {"access-control-allow-headers", "*"},
    {"access-control-allow-methods", "get"},
    {"access-control-allow-methods", "get, post, options"},
    {"access-control-allow-methods", "options"},
    {"access-control-expose-headers", "content-length"},
    {"access-control-request-headers", "content-type"},
    {"access-control-request-method", "get"},
    {"access-control-request-method", "post"},
    {"alt-svc", "clear"},
    {"authorization", 0},
    {"content-security-policy", "script-src 'none'; object-src 'none'; base-uri 'none'"},
    {"early-data", "1"},
    {"expect-ct", 0},
    {"forwarded", 0},
    {"if-range", 0},
    {"origin", 0},
    {"purpose", "prefetch"},
    {"server", 0},
    {"timing-allow-origin", "*"},
    {"upgrade-insecure-requests", "1"},
    {"user-agent", 0},
    {"x-forwarded-for", 0},
    {"x-frame-options", "deny"},
    {"x-frame-options", "sameorigin"},
};

static const size_t static_table_count = sizeof(static_table)/(sizeof(static_table[1])) - 1;
static std::map<std::string, int> static_map;

static void init_static_map(){
    for(size_t i=1;i<static_table_count;++i){
        if(static_table[i][1])
            static_map[std::string(static_table[i][0])+char(0)+static_table[i][1]] = i;
        else
            static_map[std::string(static_table[i][0])+char(0)] = i;
    }
}

static bool qpack_inited = false;


Qpack::Qpack(std::function<void(Buffer&&)> sender, size_t dynamic_table_size_limit_max):
    dynamic_table_size_limit_max(dynamic_table_size_limit_max), sender(std::move(sender))
{
    if(unlikely(!qpack_inited)){
        init_static_map();
        qpack_inited = true;
    }
}

static size_t literal_decode_wrapper(const unsigned char* s, size_t len, int prefix, std::string& name){
    uint64_t value;
    if(integer_decode(s, len, prefix, &value) == 0){
        return 0;
    }
    name.resize(value * 2);
    int ret = literal_decode(s, len, prefix, &name[0]);
    if(ret <= 0){
        return ret;
    }
    name = name.c_str();
    return ret;
}


int Qpack::push_ins(const void *ins, size_t len) {
    const uchar* pos = (const uchar*)ins;
    while(pos < (uchar*)ins + len){
        if(pos[0] & 0x80){
            bool T = pos[0]&0x40;
            std::string name, value;
            uint64_t index;
            size_t l = integer_decode(pos, (uchar*)ins+len-pos, 6, &index);
            if(l == 0){
                return 0;
            }
            pos += l;
            if(T){
                name = static_table[index][0];
            }else{
            }
            l = literal_decode_wrapper(pos, (uchar*)ins+len-pos, 7, name);
            if(l <= 0){
                return (int)l;
            }
            pos += l;
            LOGD(DHPACK, "add %s:%s\n", name.c_str(), value.c_str());
        }else if(pos[0]&0x40){
            std::string name, value;
            size_t l = literal_decode_wrapper(pos, (uchar*)ins+len-pos, 5, name);
            if(l <= 0){
                return (int)l;
            }
            pos += l;
            l = literal_decode_wrapper(pos, (uchar*)ins+len-pos, 7, value);
            if(l <= 0){
                return (int)l;
            }
            pos += l;
            LOGD(DHPACK, "add %s:%s\n", name.c_str(), value.c_str());
        }else if(pos[0]&0x20){
            uint64_t cap;
            size_t l = integer_decode(pos, (uchar*)ins+len-pos, 5, &cap);
            if(l == 0){
                return 0;
            }
            pos += l;
            LOGD(DHPACK, "set cap: %d\n", (int)cap);
        }else{
            uint64_t index;
            size_t l = integer_decode(pos, (uchar*)ins+len-pos, 5, &index);
            if(l == 0){
                return 0;
            }
            pos += l;
            LOGD(DHPACK, "dup index: %d\n", (int)index);
        }
    }
    abort();
}

size_t Qpack_encoder::encode(unsigned char *buf, const std::string& name, const std::string& value) {
    auto pos = buf;
    *pos = 0x20; //  literal field line with literal name with N and H cleared
    pos += integer_encode(name.size(), 3, pos);
    memcpy(pos, name.data(), name.size());
    pos += name.size();
    *pos = 0x00; //clear Huffman flag
    pos += integer_encode(value.size(), 7, pos);
    memcpy(pos, value.data(), value.size());
    pos += value.size();
    return pos - buf;
}

size_t Qpack_encoder::PackHttp3Req(std::shared_ptr<const HttpReqHeader> req, void *data, size_t len) {
    uchar* p = (uchar*)data;
    p += integer_encode(0, 8, p);
    p += integer_encode(0, 7, p);
    for(const auto& i : req->Normalize()){
        p += encode(p, i.first, i.second);
    }
    return p - (uchar*)data;
}

size_t Qpack_encoder::PackHttp3Res(std::shared_ptr<const HttpResHeader> res, void *data, size_t len) {
    uchar* p = (uchar*)data;
    p += integer_encode(0, 8, p);
    *p = 0x00; // clear S bit
    p += integer_encode(0, 7, p);
    for(const auto& i : res->Normalize()){
        p += encode(p, i.first, i.second);
    }
    return p - (uchar*)data;
}


std::multimap<std::string, std::string> Qpack_decoder::decode(const unsigned char *data, size_t len) {
    std::multimap<std::string, std::string> headers;
    const uchar* pos = (uchar*)data;
    uint64_t reqid;
    size_t l = integer_decode(pos, (uchar*)data+len-pos, 8, &reqid);
    if(l == 0){
        return headers;
    }
    pos += l;
    uint64_t delta;
    l = integer_decode(pos, (uchar*)data+len-pos, 7, &delta);
    if(l == 0){
        return headers;
    }
    pos += l;
    while(pos < (uchar*)data + len){
        std::string name, value;
        if(pos[0] & 0x80){
            bool T = pos[0] & 0x40;
            uint64_t index;
            l = integer_decode(pos, (uchar*)data+len-pos, 6, &index);
            if(l == 0){
                return headers;
            }
            pos += l;
            if(T){
                name = static_table[index][0];
                value = static_table[index][1];
            }else{
                abort();
            }
            goto append;
        }else if(pos[0] & 0x40){
            bool N = pos[0] & 0x20;
            bool T = pos[0] & 0x10;
            uint64_t index;
            l = integer_decode(pos, (uchar*)data+len-pos, 4, &index);
            if(l == 0){
                return headers;
            }
            pos += l;
            if(T){
                name = static_table[index][0];
            }else{
                abort();
            }
            l = literal_decode_wrapper(pos, (uchar*)data+len-pos, 7, value);
            if(l <= 0){
                return headers;
            }
            pos += l;
            goto append;
        }else if(pos[0] & 0x20){
            bool N = pos[0]&0x10;
            l = literal_decode_wrapper(pos, (uchar*)data+len-pos, 3, name);
            if(l <= 0){
                return headers;
            }
            pos += l;
            l = literal_decode_wrapper(pos, (uchar*)data+len-pos, 7, value);
            if(l <= 0){
                return headers;
            }
            pos += l;
            goto append;
        }else if(pos[0] & 0x10){
            abort();
            goto append;
        }else{
            bool N = pos[0]&0x80;
            uint64_t index;
            l = integer_decode(pos, (uchar*)data+len-pos, 3, &index);
            if(l == 0){
                return headers;
            }
            pos += l;
            l = literal_decode_wrapper(pos, (uchar*)data+len-pos, 7, value);
            if(l <= 0){
                return headers;
            }
            pos += l;
            goto append;
        }
append:
        headers.emplace(name, value);
    }
    return headers;
}

std::shared_ptr<HttpResHeader> Qpack_decoder::UnpackHttp3Res(const void *data, size_t len) {
    std::multimap<std::string, std::string> headers = decode((const uchar*)data, len);
    if(headers.empty()) {
        return nullptr;
    }
    return std::make_shared<HttpResHeader>(std::move(headers));
}

std::shared_ptr<HttpReqHeader> Qpack_decoder::UnpackHttp3Req(const void *data, size_t len) {
    std::multimap<std::string, std::string> headers = decode((const uchar*)data, len);
    if(headers.empty()) {
        return nullptr;
    }
    return std::make_shared<HttpReqHeader>(std::move(headers));
}
