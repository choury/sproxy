#include "hpack.h"
#include "prot/http/http_code.h"
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

HeaderMap Hpack_decoder::decode(const HttpCursor& cursor) {
    HeaderMap headers;
    bool noDynamic = false;
    while(cursor.length()) {
        uchar flag = cursor.data()[0];
        if(flag & 0x80) {
            noDynamic = true;
            auto index = cursor.integer_decode(7);
            if(!index){
                LOGE("incomplete integer found in hpack\n");
                return decltype(headers){};
            }
            if(index.value() == 0){
                LOGE("want to get value of index zero\n");
                return decltype(headers){};
            }
            const Hpack_index *value = getvalue(index.value());
            if(value == nullptr){
                LOGE("get null index from %d\n", (int)index.value());
                return decltype(headers){};
            }
            headers.insert(std::make_pair(value->name, value->value));
        }else if(flag & 0x40) {
            noDynamic = true;
            auto index = cursor.integer_decode(6);
            if(!index){
                LOGE("incomplete integer found in hpack\n");
                return decltype(headers){};
            }
            std::string name, value;
            if(index.value() == 0) {
                auto result = cursor.literal_decode(7);
                if(!result){
                    LOGE("failed to decode literal in hpack\n");
                    return decltype(headers){};
                }
                name = result.value();
            } else if (auto v = getvalue(index.value()); v){
                name = v->name;
            } else {
                LOGE("get null index from %d\n", (int)index.value());
                return decltype(headers){};
            }
            auto result = cursor.literal_decode(7);
            if(!result ){
                LOGE("failed to decode literal in hpack\n");
                return decltype(headers){};
            }
            value = result.value();
            headers.insert(std::make_pair(name, value));
            add_dynamic_table(name, value);
        }else if(flag & 0x20) {
            if(noDynamic){
                LOGE("found update dynamic table limit after normal entry\n");
                return decltype(headers){};
            }
            auto size = cursor.integer_decode(5);
            if(!size){
                LOGE("incomplete integer found in hpack\n");
                return decltype(headers){};
            }
            if(!set_dynamic_table_size_limit(size.value())){
                return decltype(headers){};
            }
        }else {
            noDynamic = true;
            auto index = cursor.integer_decode(4);
            if(!index){
                LOGE("incomplete integer found in hpack\n");
                return decltype(headers){};
            }
            std::string name;
            if(index.value() == 0) {
                auto result = cursor.literal_decode(7);
                if(!result){
                    LOGE("failed to decode literal in hpack\n");
                    return decltype(headers){};
                }
                name = result.value();
            } else if (auto v = getvalue(index.value()); v){
                name = v->name;
            } else {
                LOGE("get null index from %d\n", (int)index.value());
                return decltype(headers){};
            }
            auto result = cursor.literal_decode(7);
            if(!result){
                LOGE("failed to decode literal in hpack\n");
                return decltype(headers){};
            }
            headers.insert(std::make_pair(name, result.value()));
        }
    }
    //evict_dynamic_table();
    return headers;
}

std::shared_ptr<HttpReqHeader> Hpack_decoder::UnpackHttp2Req(const void *header, size_t len) {
    auto headers = decode(HttpCursor{header, len});
    if(headers.empty()){
        return nullptr;
    }
    if(headers.count("transfer-encoding")) {
        //RFC 9113 禁止h2请求携带transfer-encoding，且转发h1时会造成走私
        LOGE("wrong frame http request, transfer-encoding in h2\n");
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
    return HttpReqHeader::create(std::move(headers));
}

std::shared_ptr<HttpResHeader> Hpack_decoder::UnpackHttp2Res(const void *header, size_t len) {
    auto headers = decode(HttpCursor{header, len});
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

//返回false表示空间不足，调用方需要断开连接；模式首字节与varint由integer_encode/literal_encode自检空间
bool Hpack_encoder::encode(HttpCursor& cursor, const char* name, const char* value) {
    if(cursor.length() < 1){
        LOGE("hpack encode no space\n");
        return false;
    }
    uint32_t index = getid(name, value);
    if(index){
        *cursor.mutable_data() = 0x80;
        if(!cursor.integer_encode(index, 7)){
            LOGE("hpack encode no space for index\n");
            return false;
        }
        return true;
    }else if((index = getid(name))) {
        *cursor.mutable_data() = 0x40;
        if(!cursor.integer_encode(index, 6)){
            LOGE("hpack encode no space for index\n");
            return false;
        }
        if(!cursor.literal_encode(value, 7)){
            LOGE("hpack encode no space for literal\n");
            return false;
        }
        add_dynamic_table(name, value);
    }else {
        *cursor.mutable_data() = 0x40;
        cursor.advance(1);
        if(!cursor.literal_encode(name, 7)){
            LOGE("hpack encode no space for literal\n");
            return false;
        }
        if(!cursor.literal_encode(value, 7)){
            LOGE("hpack encode no space for literal\n");
            return false;
        }
        add_dynamic_table(name, value);
    }
    return true;
}

size_t Hpack_encoder::PackHttp2Req(std::shared_ptr<const HttpReqHeader> req, void *data, size_t len) {
    HttpCursor cursor(data, len);
    for(const auto& i : req->Normalize()){
        if(!encode(cursor, i.first.c_str(), i.second.c_str())){
            return 0;
        }
    }
    return len - cursor.length();
}

size_t Hpack_encoder::PackHttp2Res(std::shared_ptr<const HttpResHeader> res, void *data, size_t len) {
    HttpCursor cursor(data, len);
    for(const auto& i : res->Normalize()){
        if(!encode(cursor, i.first.c_str(), i.second.c_str())){
            return 0;
        }
    }
    return len - cursor.length();
}
