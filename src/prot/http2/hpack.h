#ifndef HPACK_H__
#define HPACK_H__
#include "prot/http/http_header.h"
#include "misc/index.h"

#include <string>

class Hpack {
protected:
    struct Hpack_index {
        std::string name;
        std::string value;
        size_t id;
    };

    size_t dynamic_table_size_limit_max = 4096;
    size_t dynamic_table_size_limit = 4096;
    size_t dynamic_table_size = 0;
    size_t evicted_count = 1;
    Index2<size_t, std::string, Hpack_index*> dynamic_table;
    void evict_dynamic_table();
    void add_dynamic_table(const std::string &name, const std::string &value);
    [[nodiscard]] uint32_t getid(const std::string& name, const std::string& value = "") const;
    [[nodiscard]] const Hpack_index *getvalue(uint32_t id) const;
    bool set_dynamic_table_size_limit(size_t size);
public:
    explicit Hpack(size_t dynamic_table_size_limit_max);
    ~Hpack();
    void set_dynamic_table_size_limit_max(size_t size);
    [[nodiscard]] size_t get_dynamic_table_size() const{
        return dynamic_table_size;
    };
};

class HttpCursor;

class Hpack_decoder: public Hpack {
    HeaderMap decode(const HttpCursor& cursor);
public:
    explicit Hpack_decoder(size_t dynamic_table_size_limit_max = 4096): Hpack(dynamic_table_size_limit_max){}
    std::shared_ptr<HttpReqHeader> UnpackHttp2Req(const void* header, size_t len);
    std::shared_ptr<HttpResHeader> UnpackHttp2Res(const void* header, size_t len);
};

class Hpack_encoder: public Hpack {
    bool encode(HttpCursor& cursor, const char* name, const char* value);
public:
    explicit Hpack_encoder(size_t dynamic_table_size_limit_max = 4096): Hpack(dynamic_table_size_limit_max){}
    size_t PackHttp2Req(std::shared_ptr<const HttpReqHeader> req, void* data, size_t len);
    size_t PackHttp2Res(std::shared_ptr<const HttpResHeader> res, void* data, size_t len);
};



#endif
