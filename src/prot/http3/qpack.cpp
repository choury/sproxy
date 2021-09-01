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


Qpack::Qpack(std::function<void(void *, size_t)> sender, size_t dynamic_table_size_limit_max):
    dynamic_table_size_limit_max(dynamic_table_size_limit_max), sender(std::move(sender))
{
    if(unlikely(!qpack_inited)){
        init_static_map();
        qpack_inited = true;
    }
}

static size_t literal_decode_wrapper(const unsigned char* s, int prefix, std::string& name, bool& failed){
    uint64_t len;
    integer_decode(s, prefix, &len);
    name.resize(len * 2);
    int ret = literal_decode(s, prefix, &name[0]);
    if(ret < 0){
        failed = true;
        return 0;
    }
    name.resize(ret);
    return ret;
}


int Qpack::push_ins(const void *ins, size_t len) {
    const uchar* pos = (const uchar*)ins;
    while(pos < (uchar*)ins + len){
        if(pos[0] & 0x80){
            bool T = pos[0]&0x40;
            std::string name, value;
            uint64_t index;
            pos += integer_decode(pos, 6, &index);
            if(T){
                name = static_table[index][0];
            }else{
            }
            bool failed = false;
            if(pos += literal_decode_wrapper(pos, 7, value, failed), failed){
                return -1;
            }
            LOGD(DHPACK, "add %s:%s\n", name.c_str(), value.c_str());
        }else if(pos[0]&0x40){
            bool failed = false;
            std::string name, value;
            if(pos += literal_decode_wrapper(pos, 5, name, failed), failed){
                return -1;
            }
            if(pos += literal_decode_wrapper(pos, 7, value, failed), failed){
                return -1;
            }
            LOGD(DHPACK, "add %s:%s\n", name.c_str(), value.c_str());
        }else if(pos[0]&0x20){
            uint64_t cap;
            pos += integer_decode(pos, 5, &cap);
            LOGD(DHPACK, "set cap: %d\n", (int)cap);
        }else{
            uint64_t index;
            pos += integer_decode(pos, 5, &index);
            LOGD(DHPACK, "dup index: %d\n", (int)index);
        }
    }
    abort();
}

size_t Qpack_encoder::encode(unsigned char *buf, const char *name, const char *value) {
    return 0;
}

size_t Qpack_encoder::PackHttp3Req(const HttpReqHeader *req, void *data, size_t len) {
    uchar* p = (uchar*)data;
    p += integer_encode(0, 8, p);
    p += integer_encode(0, 7, p);
    for(const auto& i : req->Normalize()){
        p[0] = 0x20;
        p += integer_encode(i.first.size(), 3, p);
        memcpy(p, i.first.data(), i.first.size());
        p += i.first.size();
        p += integer_encode(i.second.size(), 7, p);
        memcpy(p, i.second.data(), i.second.size());
        p += i.second.size();
    }
    return p - (uchar*)data;
}


std::multimap<std::string, std::string> Qpack_decoder::decode(const unsigned char *s, size_t len) {
    std::multimap<std::string, std::string> headers;
    return headers;
}

HttpResHeader *Qpack_decoder::UnpackHttp3Res(const void *data, size_t len) {
    uchar* pos = (uchar*)data;
    uint64_t reqid;
    pos += integer_decode(pos, 8, &reqid);
    uint64_t delta;
    pos += integer_decode(pos, 7, &delta);
    std::multimap<std::string, std::string> headers;
    while(pos < (uchar*)data + len){
        std::string name, value;
        if(pos[0] & 0x80){
            bool T = pos[0] & 0x40;
            uint64_t index;
            pos += integer_decode(pos, 6, &index);
            if(T){
                name = static_table[index][0];
                value = static_table[index][1];
            }else{
                abort();
            }
        }else if(pos[0] & 0x40){
            bool N = pos[0] & 0x20;
            bool T = pos[0] & 0x10;
            uint64_t index;
            pos += integer_decode(pos, 4, &index);
            if(T){
                name = static_table[index][0];
            }else{
                abort();
            }
            bool failed = false;
            if(pos += literal_decode_wrapper(pos, 7, value, failed), failed){
                return nullptr;
            }
        }else if(pos[0] & 0x20){
            bool N = pos[0]&0x10;
            bool failed = false;
            if(pos += literal_decode_wrapper(pos, 3, name, failed), failed){
                return nullptr;
            }
            if(pos += literal_decode_wrapper(pos, 7, value, failed), failed){
                return nullptr;
            }
        }else if(pos[0] & 0x10){
            abort();
        }else{
            bool N = pos[0]&0x80;
            uint64_t index;
            pos += integer_decode(pos, 3, &index);
            bool failed = false;
            if(pos += literal_decode_wrapper(pos, 7, value, failed), failed){
                return nullptr;
            }
        }
        headers.emplace(name, value);
    }
    return new HttpResHeader(std::move(headers));
}