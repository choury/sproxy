#ifndef HPACK_H__
#define HPACK_H__
#include <string>
#include <map>

struct Hpack_index {
    std::string name;
    std::string value;
    size_t id;
};

class Hpack_index_table {
    size_t dynamic_table_size_limit_max = 4096;
    size_t dynamic_table_size_limit = 4096;
    size_t dynamic_table_size = 0;
    size_t evicted_count = 1;
    std::map<size_t, Hpack_index *> dynamic_table;
    std::map<std::string, Hpack_index*> dynamic_map;
    void evict_dynamic_table();
    void add_dynamic_table(const std::string &name, const std::string &value);
    uint32_t getid(const std::string& name, const std::string& value);
    uint32_t getid(const std::string& name);
    const Hpack_index *getvalue(uint32_t id);
    void set_dynamic_table_size_limit(size_t size);
public:
    explicit Hpack_index_table(size_t dynamic_table_size_limit_max = 4096);
    ~Hpack_index_table();
    void set_dynamic_table_size_limit_max(size_t size);
    std::multimap<std::string, std::string> hpack_decode(const unsigned char *s, int len);
    int hpack_encode(unsigned char *buf, const char *name, const char *value);
    int hpack_encode(unsigned char *buf, std::map<std::string, std::string> headers);
};

#endif
