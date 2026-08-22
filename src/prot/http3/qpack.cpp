#include "qpach.h"
#include "prot/http/http_code.h"

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

static const size_t static_table_count = sizeof(static_table)/(sizeof(static_table[0]));
static std::map<std::string, int> static_map;

static void init_static_map(){
    for(size_t i=0;i<static_table_count;++i){
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

int Qpack::push_ins(const void *ins, size_t len) {
    HttpCursor cursor(ins, len);
    while(cursor.length()){
        uchar flag = cursor.data()[0];
        if(flag & 0x80){
            //将一个键值对加入动态表，key是索引，value是字面量
            auto index = cursor.integer_decode(6);
            if(!index){
                return 0;
            }
            std::string name;
            bool T = flag & 0x40;
            if(T){
                if(index >= static_table_count){
                    LOGE("qpack static table index out of range: %d\n", (int)index.value());
                    return -1;
                }
                name = static_table[index.value()][0];
            }
            auto value = cursor.literal_decode(7);
            if(!value){
                return 0;
            }
            LOGD(DHPACK, "add %s:%s\n", name.c_str(), value.value().c_str());
        }else if(flag & 0x40){
            //将一个键值对加入动态表，key和value都是字面量
            auto name = cursor.literal_decode(5);
            if(!name){
                return 0;
            }
            auto value = cursor.literal_decode(7);
            if(!value){
                return 0;
            }
            LOGD(DHPACK, "add %s:%s\n", name.value().c_str(), value.value().c_str());
        }else if(flag & 0x20){
            //设置动态表大小
            auto cap = cursor.integer_decode(5);
            if(!cap){
                return 0;
            }
            LOGD(DHPACK, "set cap: %d\n", (int)cap.value());
            return len - cursor.length();
        }else{
            //复制动态表中的索引处内容
            auto index = cursor.integer_decode(5);
            if(!index){
                return 0;
            }
            LOGD(DHPACK, "dup index: %d\n", (int)index.value());
        }
    }
    return -1;
}

//返回0表示空间不足，调用方需要断开连接；模式首字节后的字段由integer_encode/literal_encode整体自检空间
bool Qpack_encoder::encode(HttpCursor& cursor, const std::string& name, const std::string& value) {
    if(cursor.empty()){
        LOGE("qpack encode no space\n");
        return false;
    }
    uint32_t id = getid(name, value);
    if(id != UINT32_MAX){
        *cursor.mutable_data() = 0xC0; //  indexed field line with static name with T set
        if(!cursor.integer_encode(id, 6)){
            LOGE("qpack encode no space for index\n");
            return false;
        }
        return true;
    }
    id = getid(name);
    if(id != UINT32_MAX) {
        *cursor.mutable_data() = 0x50; //  indexed field line with static name with T set and N cleared
        if(!cursor.integer_encode(id, 4)){
            LOGE("qpack encode no space for index\n");
            return false;
        }
        //RFC 9204 §4.5.4: value为8-bit前缀字面量，Huffman位为最高位
        if(!cursor.literal_encode(value.data(), value.size(), 7)){
            LOGE("qpack literal no space: need %zd, left %zd\n", value.size(), cursor.length());
            return false;
        }
        return true;
    }
    *cursor.mutable_data() = 0x20; //  literal field line with literal name and value with N cleared
    //RFC 9204 §4.5.6: name为4-bit前缀字面量，Huffman位(0x08)紧邻3-bit长度前缀上方
    if(!cursor.literal_encode(name.data(), name.size(), 3)) {
        LOGE("qpack literal no space: need %zd, left %zd\n", name.size(), cursor.length());
        return false;
    }
    if(!cursor.literal_encode(value.data(), value.size(), 7)){
        LOGE("qpack literal no space: need %zd, left %zd\n", value.size(), cursor.length());
        return false;
    }
    return true;
}

size_t Qpack_encoder::PackHttp3Req(std::shared_ptr<const HttpReqHeader> req, void *data, size_t len) {
    //两个前缀域各占1字节
    if(len < 2){
        return 0;
    }
    HttpCursor cursor(data, len);
    cursor.integer_encode(0, 8);
    *cursor.mutable_data() = 0x00; // clear S bit
    cursor.integer_encode(0, 7);
    for(const auto& i : req->Normalize()){
        if(!encode(cursor, i.first, i.second)){
            return 0;
        }
    }
    return len - cursor.length();
}

size_t Qpack_encoder::PackHttp3Res(std::shared_ptr<const HttpResHeader> res, void *data, size_t len) {
    //两个前缀域各占1字节
    if(len < 2){
        return 0;
    }
    HttpCursor cursor(data, len);
    cursor.integer_encode(0, 8);
    *cursor.mutable_data() = 0x00; // clear S bit
    cursor.integer_encode(0, 7);
    for(const auto& i : res->Normalize()){
        if(!encode(cursor, i.first, i.second)){
            return 0;
        }
    }
    return len - cursor.length();
}


HeaderMap Qpack_decoder::decode(const HttpCursor& cursor) {
    HeaderMap headers;
    auto ric = cursor.integer_decode(8);
    if(!ric){
        return headers;
    }
    // 最高位是delta的符号位，不过我们不支持动态表，所以没有读
    auto delta = cursor.integer_decode(7);
    if(!delta){
        return headers;
    }
    while(cursor.length()){
        std::string name, value;
        uchar flag = cursor.data()[0];
        if(flag & 0x80){
            // 如果以1开头，表示这是一个索引
            // 第2位是T，表示这否是一个静态索引
            bool T = flag & 0x40;
            auto index = cursor.integer_decode(6);
            if(!index){
                return decltype(headers){};
            }
            if(T){
                if(index >= sizeof(static_table)/ sizeof(static_table[0])) {
                    return decltype(headers){};
                }
                name = static_table[index.value()][0];
                value = static_table[index.value()][1];
                LOGD(DHPACK, "get qpack %s:[%s] id: %d\n", name.c_str(), value.c_str(), (int)index.value());
            }else{ //当前不支持动态索引，因为我们将MAX_FIELD_SECTION_SIZE设置成了0
                return decltype(headers){};
            }
            goto append;
        }else if(flag & 0x40){
            // 如果以01开头，表示key是索引，value是字面量
            // 第3位是N，表明该条目是否需要插入动态表
            // 第4位是T，表面该条目是否是静态索引
            //bool N = pos[0] & 0x20;
            bool T = flag & 0x10;
            auto index = cursor.integer_decode(4);
            if(!index){
                return decltype(headers){};
            }
            if(T){
                if(index >= sizeof(static_table)/ sizeof(static_table[0])) {
                    return decltype(headers){};
                }
                name = static_table[index.value()][0];
                LOGD(DHPACK, "get qpack key %s id: %d\n", name.c_str(), (int)index.value());
            }else{
                return decltype(headers){};
            }
            auto result = cursor.literal_decode(7);
            if(!result){
                return decltype(headers){};
            }
            value = result.value();
            LOGD(DHPACK, "get qpack literal value %s\n", value.c_str());
            goto append;
        }else if(flag & 0x20){
            //如果以001开头，表示key和value都是字面量
            //第4位是N，表明该条目是否需要插入动态表
            //bool N = pos[0]&0x10;
            auto nameopt = cursor.literal_decode(3);
            if(!nameopt){
                return decltype(headers){};
            }
            auto valueopt = cursor.literal_decode(7);
            if(!valueopt){
                return decltype(headers){};
            }
            name = nameopt.value();
            value = valueopt.value();
            LOGD(DHPACK, "get qpack literal %s:[%s]\n", name.c_str(), value.c_str());
            goto append;
        }else if(flag & 0x10){
            //如果以0001开头，表示是一个基于base位置的动态表索引，暂时不支持
            return decltype(headers){};
        }else{
            //如果以0000开头，表示key是基于base位置的动态表索引，value是字面量
            //第5位是N，表明该条目是否需要插入动态表
            //当前也不支持
            //bool N = pos[0]&0x80;
            auto index = cursor.integer_decode(3);
            if(!index){
                return decltype(headers){};
            }
            auto valueopt = cursor.literal_decode(7);
            if(!valueopt){
                return decltype(headers){};
            }
            return decltype(headers){};
        }
append:
        headers.emplace(name, value);
    }
    return headers;
}

std::shared_ptr<HttpResHeader> Qpack_decoder::UnpackHttp3Res(const void *data, size_t len) {
    auto headers = decode(HttpCursor{data, len});
    if(headers.empty()) {
        return nullptr;
    }
    return std::make_shared<HttpResHeader>(std::move(headers));
}

std::shared_ptr<HttpReqHeader> Qpack_decoder::UnpackHttp3Req(const void *data, size_t len) {
    auto headers = decode(HttpCursor{data, len});
    if(headers.empty()) {
        return nullptr;
    }
    if(headers.count("transfer-encoding")) {
        //RFC 9114 禁止h3请求携带transfer-encoding，且转发h1时会造成走私
        LOGE("wrong frame http request, transfer-encoding in h3\n");
        return nullptr;
    }
    if(headers.count(":path")) {
        auto path = headers.find(":path")->second;
        if(path.empty() || path.length() > 8192){
            LOGE("path length is not allowed: %zd\n", (size_t)path.length());
            return nullptr;
        }
    }
    return HttpReqHeader::create(std::move(headers));
}
