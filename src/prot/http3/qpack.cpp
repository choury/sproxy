#include "qpach.h"

#include <string.h>

static const char* static_table[][2] = {
    {":authority", nullptr},
    {":path", "/"},
    {"age", "0"},
    {"content-disposition", nullptr},
    {"content-length", "0"},
    {"cookie", nullptr},
    {"date", nullptr},
    {"etag", nullptr},
    {"if-modified-since", nullptr},
    {"if-none-match", nullptr},
    {"last-modified", nullptr},
    {"link", nullptr},
    {"location", nullptr},
    {"referer", nullptr},
    {"set-cookie", nullptr},
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
    {"accept-language", nullptr},
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
    {"authorization", nullptr},
    {"content-security-policy", "script-src 'none'; object-src 'none'; base-uri 'none'"},
    {"early-data", "1"},
    {"expect-ct", nullptr},
    {"forwarded", nullptr},
    {"if-range", nullptr},
    {"origin", nullptr},
    {"purpose", "prefetch"},
    {"server", nullptr},
    {"timing-allow-origin", "*"},
    {"upgrade-insecure-requests", "1"},
    {"user-agent", nullptr},
    {"x-forwarded-for", nullptr},
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

uint32_t Qpack::getid(const std::string& name, const std::string& value) {
    std::string key = name+char(0)+value;
    uint32_t id = 0;
    if(static_map.count(key)) {
        id = static_map[key];
    } else {
        return UINT32_MAX;
    }
    LOGD(DHPACK, "get qpack %s:[%s] id: %d\n", name.c_str(), value.c_str(), id);
    return id;
}



Qpack::Qpack(std::function<void(Buffer&&)> sender, size_t dynamic_table_size_limit_max):
    dynamic_table_size_limit_max(dynamic_table_size_limit_max), sender(std::move(sender))
{
    if(unlikely(!qpack_inited)){
        init_static_map();
        qpack_inited = true;
    }
}

static int literal_decode_wrapper(const unsigned char* s, size_t len, int prefix, std::string& name){
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
            //将一个键值对加入动态表，key是索引，value是字面量
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
            //将一个键值对加入动态表，key和value都是是字面量
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
            //设置动态表大小
            uint64_t cap;
            size_t l = integer_decode(pos, (uchar*)ins+len-pos, 5, &cap);
            if(l == 0){
                return 0;
            }
            pos += l;
            LOGD(DHPACK, "set cap: %d\n", (int)cap);
            return pos - (const uchar*)ins;
        }else{
            //复制动态表中的索引处内容
            uint64_t index;
            size_t l = integer_decode(pos, (uchar*)ins+len-pos, 5, &index);
            if(l == 0){
                return 0;
            }
            pos += l;
            LOGD(DHPACK, "dup index: %d\n", (int)index);
        }
    }
    return -1;
}

size_t Qpack_encoder::encode(unsigned char *buf, const std::string& name, const std::string& value) {
    auto pos = buf;
    uint32_t id = getid(name, value);
    if(id != UINT32_MAX){
        *pos = 0xC0; //  indexed field line with static name with T set
        pos += integer_encode(id, 6, pos);
        return pos - buf;
    }
    id = getid(name);
    if(id != UINT32_MAX) {
        *pos = 0x50; //  indexed name with static name with T set and N cleared
        pos += integer_encode(id, 4, pos);
        *pos = 0x00; //clear Huffman flag
        pos += integer_encode(value.size(), 7, pos);
        memcpy(pos, value.data(), value.size());
        pos += value.size();
        return pos - buf;
    }
    *pos = 0x20; //  literal field line with literal name and value with N and H cleared
    pos += integer_encode(name.size(), 3, pos);
    memcpy(pos, name.data(), name.size());
    pos += name.size();
    *pos = 0x00; //clear Huffman flag
    pos += integer_encode(value.size(), 7, pos);
    memcpy(pos, value.data(), value.size());
    pos += value.size();
    return pos - buf;
}

size_t Qpack_encoder::PackHttp3Req(std::shared_ptr<const HttpReqHeader> req, void *data, __attribute__ ((unused)) size_t len) {
    uchar* p = (uchar*)data;
    p += integer_encode(0, 8, p);
    *p = 0x00; // clear S bit
    p += integer_encode(0, 7, p);
    for(const auto& i : req->Normalize()){
        p += encode(p, i.first, i.second);
    }
    return p - (uchar*)data;
}

size_t Qpack_encoder::PackHttp3Res(std::shared_ptr<const HttpResHeader> res, void *data, __attribute__ ((unused)) size_t len) {
    uchar* p = (uchar*)data;
    p += integer_encode(0, 8, p);
    *p = 0x00; // clear S bit
    p += integer_encode(0, 7, p);
    for(const auto& i : res->Normalize()){
        p += encode(p, i.first, i.second);
    }
    return p - (uchar*)data;
}


HeaderMap Qpack_decoder::decode(const unsigned char *data, size_t len) {
    HeaderMap headers;
    const uchar* pos = (uchar*)data;
    uint64_t ric;
    int l = integer_decode(pos, (uchar*)data+len-pos, 8, &ric);
    if(l == 0){
        return headers;
    }
    pos += l;
    uint64_t delta;
    // 最高位是delta的符号位，不过我们不支持动态表，所以没有读
    l = integer_decode(pos, (uchar*)data+len-pos, 7, &delta);
    if(l == 0){
        return headers;
    }
    pos += l;
    while(pos < (uchar*)data + len){
        std::string name, value;
        if(pos[0] & 0x80){  
            // 如果以1开头，表示这是一个索引
            // 第2位是T，表示这否是一个静态索引
            bool T = pos[0] & 0x40; 
            uint64_t index;
            l = integer_decode(pos, (uchar*)data+len-pos, 6, &index);
            if(l == 0){
                return decltype(headers){};
            }
            pos += l;
            if(T){
                if(index >= sizeof(static_table)/ sizeof(static_table[0])) {
                    return decltype(headers){};
                }
                name = static_table[index][0];
                value = static_table[index][1];
                LOGD(DHPACK, "get qpack %s:[%s] id: %d\n", name.c_str(), value.c_str(), (int)index);
            }else{ //当前不支持动态索引，因为我们将MAX_FIELD_SECTION_SIZE设置成了0
                return decltype(headers){};
            }
            goto append;
        }else if(pos[0] & 0x40){ 
            // 如果以01开头，表示key是索引，value是字面量
            // 第3位是N，表明该条目是否需要插入动态表
            // 第4位是T，表面该条目是否是静态索引
            //bool N = pos[0] & 0x20;
            bool T = pos[0] & 0x10;
            uint64_t index;
            l = integer_decode(pos, (uchar*)data+len-pos, 4, &index);
            if(l == 0){
                return decltype(headers){};
            }
            pos += l;
            if(T){
                if(index >= sizeof(static_table)/ sizeof(static_table[0])) {
                    return decltype(headers){};
                }
                name = static_table[index][0];
                LOGD(DHPACK, "get qpack key %s id: %d\n", name.c_str(), (int)index);
            }else{
                return decltype(headers){};
            }
            l = literal_decode_wrapper(pos, (uchar*)data+len-pos, 7, value);
            if(l <= 0){
                return decltype(headers){};
            }
            LOGD(DHPACK, "get qpack literal value %s\n", value.c_str());
            pos += l;
            goto append;
        }else if(pos[0] & 0x20){
            //如果以001开头，表示key和value都是字面量
            //第4位是N，表明该条目是否需要插入动态表
            //bool N = pos[0]&0x10;
            l = literal_decode_wrapper(pos, (uchar*)data+len-pos, 3, name);
            if(l <= 0){
                return decltype(headers){};
            }
            pos += l;
            l = literal_decode_wrapper(pos, (uchar*)data+len-pos, 7, value);
            if(l <= 0){
                return decltype(headers){};
            }
            LOGD(DHPACK, "get qpack literal %s:[%s]\n", name.c_str(), value.c_str());
            pos += l;
            goto append;
        }else if(pos[0] & 0x10){
            //如果以0001开头，表示是一个基于base位置的动态表索引，暂时不支持
            return decltype(headers){};
        }else{
            //如果以0000开头，表示key是基于base位置的动态表索引，value是字面量
            //第5位是N，表明该条目是否需要插入动态表
            //当前也不支持
            //bool N = pos[0]&0x80;
            uint64_t index;
            l = integer_decode(pos, (uchar*)data+len-pos, 3, &index);
            if(l == 0){
                return decltype(headers){};
            }
            pos += l;
            l = literal_decode_wrapper(pos, (uchar*)data+len-pos, 7, value);
            if(l <= 0){
                return decltype(headers){};
            }
            pos += l;
            return decltype(headers){};
        }
append:
        headers.emplace(name, value);
    }
    return headers;
}

std::shared_ptr<HttpResHeader> Qpack_decoder::UnpackHttp3Res(const void *data, size_t len) {
    auto headers = decode((const uchar*)data, len);
    if(headers.empty()) {
        return nullptr;
    }
    return std::make_shared<HttpResHeader>(std::move(headers));
}

std::shared_ptr<HttpReqHeader> Qpack_decoder::UnpackHttp3Req(const void *data, size_t len) {
    auto headers = decode((const uchar*)data, len);
    if(headers.empty()) {
        return nullptr;
    }
    return std::make_shared<HttpReqHeader>(std::move(headers));
}
