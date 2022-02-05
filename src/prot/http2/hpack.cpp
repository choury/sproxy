#include "hpack.h"
#include "common/common.h"

#include <assert.h>

#define HTTP2_ERR_COMPRESSION_ERROR 9

static const char *static_table[][2]= {
    {0, 0},
    {":authority", 0},
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
    {"accept-charset", 0},
    {"accept-encoding", "gzip, deflate"},
    {"accept-language", 0},
    {"accept-ranges", 0},
    {"accept", 0},
    {"access-control-allow-origin", 0},
    {"age", 0},
    {"allow", 0},
    {"authorization", 0},
    {"cache-control", 0},
    {"content-disposition", 0},
    {"content-encoding", 0},
    {"content-language", 0},
    {"content-length", 0},
    {"content-location", 0},
    {"content-range", 0},
    {"content-type", 0},
    {"cookie", 0},
    {"date", 0},
    {"etag", 0},
    {"expect", 0},
    {"expires", 0},
    {"from", 0},
    {"host", 0},
    {"if-match", 0},
    {"if-modified-since", 0},
    {"if-none-match", 0},
    {"if-range", 0},
    {"if-unmodified-since", 0},
    {"last-modified", 0},
    {"link", 0},
    {"location", 0},
    {"max-forwards", 0},
    {"proxy-authenticate", 0},
    {"proxy-authorization", 0},
    {"range", 0},
    {"referer", 0},
    {"refresh", 0},
    {"retry-after", 0},
    {"server", 0},
    {"set-cookie", 0},
    {"strict-transport-security", 0},
    {"transfer-encoding", 0},
    {"user-agent", 0},
    {"vary", 0},
    {"via", 0},
    {"www-authenticate", 0},
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
    LOGD(DHPACK, "get hpack %s:[%s] id: %d\n", name.c_str(), value.c_str(), id);
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

static size_t literal_decode_wrapper(const unsigned char* s, size_t len, std::string& name){
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

std::multimap<std::string, std::string> Hpack_decoder::decode(const unsigned char* s, size_t len) {
    const uchar* pos = s;
    std::multimap<std::string, std::string> headers;
    bool noDynamic = false;
    while(pos <  s + len) {
        if(*pos & 0x80) {
            noDynamic = true;
            uint64_t index;
            size_t l = integer_decode(pos, len - (pos - s), 7, &index);
            if(l == 0){
                LOGE("incomplete integer found in hpack\n");
                return std::multimap<std::string, std::string>{};
            }
            pos += l;
            if(index == 0){
                LOGE("want to get value of index zero\n");
                return std::multimap<std::string, std::string>{};
            }
            const Hpack_index *value = getvalue(index);
            if(value == nullptr){
                LOGE("get null index from %d\n", (int)index);
                return std::multimap<std::string, std::string>{};
            }
            headers.insert(std::make_pair(value->name, value->value));
        }else if(*pos & 0x40) {
            noDynamic = true;
            uint64_t index;
            size_t l = integer_decode(pos, len - (pos - s), 6, &index);
            if(l == 0){
                LOGE("incomplete integer found in hpack\n");
                return std::multimap<std::string, std::string>{};
            }
            pos += l;
            std::string name, value;
            if(index) {
                name = getvalue(index)->name;
            } else {
                l = literal_decode_wrapper(pos, len - (pos - s), name);
                if(l <= 0){
                    LOGE("failed to decode literal in hpack\n");
                    return std::multimap<std::string, std::string>{};
                }
                pos += l;
            }
            l = literal_decode_wrapper(pos, len - (pos - s), value);
            if(l <= 0){
                LOGE("failed to decode literal in hpack\n");
                return std::multimap<std::string, std::string>{};
            }
            pos += l;
            headers.insert(std::make_pair(name, value));
            add_dynamic_table(name, value);
        }else if(*pos & 0x20) {
            if(noDynamic){
                LOGE("found update dynamic table limit after normal entry\n");
                return std::multimap<std::string, std::string>{};
            }
            uint64_t size;
            size_t l = integer_decode(pos, len - (pos - s), 5, &size);
            if(l == 0){
                LOGE("incomplete integer found in hpack\n");
                return std::multimap<std::string, std::string>{};
            }
            pos += l;
            if(!set_dynamic_table_size_limit(size)){
                return std::multimap<std::string, std::string>{};
            }
        }else {
            noDynamic = true;
            uint64_t index;
            size_t l = integer_decode(pos, len - (pos - s), 4, &index);
            if(l == 0){
                LOGE("incomplete integer found in hpack\n");
                return std::multimap<std::string, std::string>{};
            }
            pos += l;
            std::string name, value;
            if(index) {
                name = getvalue(index)->name;
            } else {
                l = literal_decode_wrapper(pos, len - (pos - s), name);
                if(l <= 0){
                    LOGE("failed to decode literal in hpack\n");
                    return std::multimap<std::string, std::string>{};
                }
                pos += l;
            }
            l = literal_decode_wrapper(pos, len - (pos - s), value);
            if(l <= 0){
                LOGE("failed to decode literal in hpack\n");
                return std::multimap<std::string, std::string>{};
            }
            pos += l;
            headers.insert(std::make_pair(name, value));
        }
        if(pos - s > (int)len){
            LOGE("may be overflow: %zu/%zu\n", pos - s, len);
            return std::multimap<std::string, std::string>{};
        }
    }
    //evict_dynamic_table();
    return headers;
}

HttpReqHeader *Hpack_decoder::UnpackHttp2Req(const void *header, size_t len) {
    auto headers = decode((const unsigned char*)header, len);
    if(headers.empty()){
        return nullptr;
    }
    if(!headers.count(":method")){
        LOGE("wrong frame http request, no method\n");
        return nullptr;
    }
    return new HttpReqHeader(std::move(headers));
}

HttpResHeader *Hpack_decoder::UnpackHttp2Res(const void *header, size_t len) {
    auto headers = decode((const unsigned char*)header, len);
    if(headers.empty()){
        return nullptr;
    }
    if(!headers.count(":status")){
        LOGE("wrong frame http response, no status\n");
        return nullptr;
    }
    return new HttpResHeader(std::move(headers));
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

size_t Hpack_encoder::PackHttp2Req(const HttpReqHeader *req, void *data, size_t len) {
    uchar* p = (uchar*)data;
    for(const auto& i : req->Normalize()){
        p += encode(p, i.first.c_str(), i.second.c_str());
    }
    assert(p - (uchar*)data <= (int)len);
    return p - (uchar*)data;
}

size_t Hpack_encoder::PackHttp2Res(const HttpResHeader *res, void *data, size_t len) {
    uchar *p = (uchar *)data;
    for(const auto& i : res->Normalize()){
        p += encode(p, i.first.c_str(), i.second.c_str());
    }
    assert(p - (uchar*)data <= (int)len);
    return p - (uchar*)data;
}
