#include "hpack.h"
#include "common/common.h"

#include <assert.h>

#define HTTP2_ERR_COMPRESSION_ERROR 9

static const char *static_table[][2]= {
    {nullptr, nullptr},
    {":authority", nullptr},
    {":method", "GET"},
    {":method", "POST"},
    {":path", "/"},
    {":path", "/index.html"},
    {":scheme", "http"},
    {":scheme", "https"},
    {":status", "200"},
    {":status", "204"},
    {":status", "206"},
    {":status", "304"},
    {":status", "400"},
    {":status", "404"},
    {":status", "500"},
    {"accept-charset", nullptr},
    {"accept-encoding", "gzip, deflate"},
    {"accept-language", nullptr},
    {"accept-ranges", nullptr},
    {"accept", nullptr},
    {"access-control-allow-origin", nullptr},
    {"age", nullptr},
    {"allow", nullptr},
    {"authorization", nullptr},
    {"cache-control", nullptr},
    {"content-disposition", nullptr},
    {"content-encoding", nullptr},
    {"content-language", nullptr},
    {"content-length", nullptr},
    {"content-location", nullptr},
    {"content-range", nullptr},
    {"content-type", nullptr},
    {"cookie", nullptr},
    {"date", nullptr},
    {"etag", nullptr},
    {"expect", nullptr},
    {"expires", nullptr},
    {"from", nullptr},
    {"host", nullptr},
    {"if-match", nullptr},
    {"if-modified-since", nullptr},
    {"if-none-match", nullptr},
    {"if-range", nullptr},
    {"if-unmodified-since", nullptr},
    {"last-modified", nullptr},
    {"link", nullptr},
    {"location", nullptr},
    {"max-forwards", nullptr},
    {"proxy-authenticate", nullptr},
    {"proxy-authorization", nullptr},
    {"range", nullptr},
    {"referer", nullptr},
    {"refresh", nullptr},
    {"retry-after", nullptr},
    {"server", nullptr},
    {"set-cookie", nullptr},
    {"strict-transport-security", nullptr},
    {"transfer-encoding", nullptr},
    {"user-agent", nullptr},
    {"vary", nullptr},
    {"via", nullptr},
    {"www-authenticate", nullptr},
};

static const size_t static_table_count = sizeof(static_table)/(sizeof(static_table[1])) - 1;
static std::map<std::string, size_t> static_map;

static void init_static_map(){
    for(size_t i=1;i<static_table_count;++i){
        if(static_table[i][1])
            static_map[std::string(static_table[i][0])+char(0)+static_table[i][1]] = i;
        else
            static_map[std::string(static_table[i][0])+char(0)] = i;
    }
}

static bool hpack_inited = false;

Hpack::Hpack(size_t dynamic_table_size_limit_max): dynamic_table_size_limit_max(dynamic_table_size_limit_max)
{
    LOGD(DHPACK, "init dynamic table size max [%zd]\n", dynamic_table_size_limit_max);
    if(unlikely(!hpack_inited)){
        init_static_map();
        hpack_inited = true;
    }
}


void Hpack::add_dynamic_table(const std::string &name, const std::string &value){
    size_t entry_size = name.size() + value.size() + 32;
    Hpack_index *index = new Hpack_index{name, value, dynamic_table.size() + evicted_count};
    dynamic_table.Add(index->id, name+char(0)+value, index);
    dynamic_table_size += entry_size;

    LOGD(DHPACK, "add hpack %s: %s [%zd/%zd]\n", name.c_str(), value.c_str(),
         dynamic_table_size, dynamic_table_size_limit);

    evict_dynamic_table();
}


uint32_t Hpack::getid(const std::string& name, const std::string& value) const{
    std::string key = name+char(0)+value;
    uint32_t id = 0;
    if(static_map.count(key))
        id = static_map[key];
    else if(dynamic_table.Has(key)){
        auto i = dynamic_table.GetOne(key);
        id = static_table_count + dynamic_table.size() + evicted_count - i->first.first;
    }
    if(id) {
        LOGD(DHPACK, "get hpack %s:[%s] id: %d\n", name.c_str(), value.c_str(), id);
    }
    return id;
}

const Hpack::Hpack_index *Hpack::getvalue(uint32_t id) const{
    static Hpack_index index;
    const Hpack_index * ret = nullptr;
    assert(id != 0);
    if(id <= static_table_count) {
        index.name = static_table[id][0];
        index.value = static_table[id][1]?static_table[id][1]:"";
        index.id = id;
        ret = &index;
    }else{
        size_t key = dynamic_table.size() - (id - static_table_count) + evicted_count;
        if(dynamic_table.Has(key))
            ret = dynamic_table.GetOne(key)->second;
    }
#ifndef NDEBUG
    if(ret){
        LOGD(DHPACK, "get hpack value [%d], %s: %s\n", id, ret->name.c_str(), ret->value.c_str());
    }else{
        LOGD(DHPACK, "get hpack not found value [%d]", id);
    }
#endif
    return ret;
}

void Hpack::set_dynamic_table_size_limit_max(size_t size){
    LOGD(DHPACK, "set dynamic table size max [%zd]\n", size);
    dynamic_table_size_limit_max = size;
    if(dynamic_table_size_limit > dynamic_table_size_limit_max){
        set_dynamic_table_size_limit(size);
    }
}

bool Hpack::set_dynamic_table_size_limit(size_t size){
    LOGD(DHPACK, "set dynamic table size [%zd]\n", size);
    if(size > dynamic_table_size_limit_max){
        LOGE("set a dynamic table size more than limit: %zd/%zd\n", size, dynamic_table_size_limit_max);
        return false;
    }
    dynamic_table_size_limit = size;
    evict_dynamic_table();
    return true;
}

void Hpack::evict_dynamic_table(){
    while(dynamic_table_size > dynamic_table_size_limit && dynamic_table.size()){
        Hpack_index *index = dynamic_table.GetOne(evicted_count)->second;
        dynamic_table.Delete(evicted_count);
        evicted_count++;
        dynamic_table_size -= index->name.size() + index->value.size() + 32;
        LOGD(DHPACK, "evict dynamic table [%zd], %s: %s\n", index->id, index->name.c_str(), index->value.c_str());
        delete index;
    }
}

Hpack::~Hpack()
{
    for(const auto& i : dynamic_table.data()){
        delete i.second;
    }
}

static int literal_decode_wrapper(const unsigned char* s, size_t len, std::string& name){
    uint64_t value;
    if(integer_decode(s, len, 7, &value) == 0){
        return 0;
    }
    name.resize(value * 2);
    int ret = literal_decode(s, len, 7, &name[0]);
    if(ret <= 0){
        return ret;
    }
    name = name.c_str();
    return ret;
}


static size_t literal_encode_wrapper(const std::string& name, unsigned char* result){
    return literal_encode(name.c_str(), 7, result);
}

HeaderMap Hpack_decoder::decode(const unsigned char* s, size_t len) {
    const uchar* pos = s;
    HeaderMap headers;
    bool noDynamic = false;
    while(pos <  s + len) {
        if(*pos & 0x80) {
            noDynamic = true;
            uint64_t index;
            int l = integer_decode(pos, len - (pos - s), 7, &index);
            if(l == 0){
                LOGE("incomplete integer found in hpack\n");
                return decltype(headers){};
            }
            pos += l;
            if(index == 0){
                LOGE("want to get value of index zero\n");
                return decltype(headers){};
            }
            const Hpack_index *value = getvalue(index);
            if(value == nullptr){
                LOGE("get null index from %d\n", (int)index);
                return decltype(headers){};
            }
            headers.insert(std::make_pair(value->name, value->value));
        }else if(*pos & 0x40) {
            noDynamic = true;
            uint64_t index;
            int l = integer_decode(pos, len - (pos - s), 6, &index);
            if(l == 0){
                LOGE("incomplete integer found in hpack\n");
                return decltype(headers){};
            }
            pos += l;
            std::string name, value;
            if(index == 0) {
                l = literal_decode_wrapper(pos, len - (pos - s), name);
                if(l <= 0){
                    LOGE("failed to decode literal in hpack\n");
                    return decltype(headers){};
                }
                pos += l;
            } else if (auto v = getvalue(index); v){
                name = v->name;
            } else {
                LOGE("get null index from %d\n", (int)index);
                return decltype(headers){};
            }
            l = literal_decode_wrapper(pos, len - (pos - s), value);
            if(l <= 0){
                LOGE("failed to decode literal in hpack\n");
                return decltype(headers){};
            }
            pos += l;
            headers.insert(std::make_pair(name, value));
            add_dynamic_table(name, value);
        }else if(*pos & 0x20) {
            if(noDynamic){
                LOGE("found update dynamic table limit after normal entry\n");
                return decltype(headers){};
            }
            uint64_t size;
            int l = integer_decode(pos, len - (pos - s), 5, &size);
            if(l == 0){
                LOGE("incomplete integer found in hpack\n");
                return decltype(headers){};
            }
            pos += l;
            if(!set_dynamic_table_size_limit(size)){
                return decltype(headers){};
            }
        }else {
            noDynamic = true;
            uint64_t index;
            int l = integer_decode(pos, len - (pos - s), 4, &index);
            if(l == 0){
                LOGE("incomplete integer found in hpack\n");
                return decltype(headers){};
            }
            pos += l;
            std::string name, value;
            if(index == 0) {
                l = literal_decode_wrapper(pos, len - (pos - s), name);
                if(l <= 0){
                    LOGE("failed to decode literal in hpack\n");
                    return decltype(headers){};
                }
                pos += l;
            } else if (auto v = getvalue(index); v){
                name = v->name;
            } else {
                LOGE("get null index from %d\n", (int)index);
                return decltype(headers){};
            }
            l = literal_decode_wrapper(pos, len - (pos - s), value);
            if(l <= 0){
                LOGE("failed to decode literal in hpack\n");
                return decltype(headers){};
            }
            pos += l;
            headers.insert(std::make_pair(name, value));
        }
        if(pos - s > (int)len){
            LOGE("may be overflow: %zu/%zu\n", pos - s, len);
            return decltype(headers){};
        }
    }
    //evict_dynamic_table();
    return headers;
}

std::shared_ptr<HttpReqHeader> Hpack_decoder::UnpackHttp2Req(const void *header, size_t len) {
    auto headers = decode((const unsigned char*)header, len);
    if(headers.empty()){
        return nullptr;
    }
    if(headers.count(":path")) {
        auto path = headers.find(":path")->second;
        if(path.empty() || path.length() > 8192){
            LOGE("path length is not allowed: %zd\n", (size_t)path.length());
            return nullptr;
        }
    }
    if(!headers.count(":method")){
        LOGE("wrong frame http request, no method\n");
        return nullptr;
    }
    for(auto &header : headers){
        if(header.first[0] == ':' && headers.count(header.first) > 1) {
            LOGE("wrong frame http request, duplicate pseudo-header\n");
            return nullptr;
        }
    }
    return std::make_shared<HttpReqHeader>(std::move(headers));
}

std::shared_ptr<HttpResHeader> Hpack_decoder::UnpackHttp2Res(const void *header, size_t len) {
    auto headers = decode((const unsigned char*)header, len);
    if(headers.empty()){
        return nullptr;
    }
    if(!headers.count(":status")){
        LOGE("wrong frame http response, no status\n");
        return nullptr;
    }
    for(auto &header : headers){
        if(header.first[0] == ':' && headers.count(header.first) > 1) {
            LOGE("wrong frame http request, duplicate pseudo-header\n");
            return nullptr;
        }
    }
    return std::make_shared<HttpResHeader>(std::move(headers));
}

size_t Hpack_encoder::encode(unsigned char* buf, const char* name, const char* value) {
    unsigned char *buf_begin = buf;
    uint32_t index = getid(name, value);
    if(index){
        *buf = 0x80;
        buf += integer_encode(index, 7, buf);
    }else if((index = getid(name))) {
        *buf = 0x40;
        buf += integer_encode(index, 6, buf);
        buf += literal_encode_wrapper(value, buf);
        add_dynamic_table(name, value);
    }else {
        *buf = 0x40;
        buf++;
        buf += literal_encode_wrapper(name, buf);
        buf += literal_encode_wrapper(value, buf);
        add_dynamic_table(name, value);
    }
    return buf - buf_begin;
}

size_t Hpack_encoder::PackHttp2Req(std::shared_ptr<const HttpReqHeader> req, void *data, size_t len) {
    uchar* p = (uchar*)data;
    for(const auto& i : req->Normalize()){
        p += encode(p, i.first.c_str(), i.second.c_str());
    }
    assert(p - (uchar*)data <= (int)len);
    (void)len;
    return p - (uchar*)data;
}

size_t Hpack_encoder::PackHttp2Res(std::shared_ptr<const HttpResHeader> res, void *data, size_t len) {
    uchar *p = (uchar *)data;
    for(const auto& i : res->Normalize()){
        p += encode(p, i.first.c_str(), i.second.c_str());
    }
    assert(p - (uchar*)data <= (int)len);
    (void)len;
    return p - (uchar*)data;
}
