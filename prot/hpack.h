#ifndef HPACK_H__
#define HPACK_H__
#include "binmap.h"

struct Index{
    std::string name;
    std::string value;
    size_t id;
};

class Index_table{
    size_t dynamic_table_size_limit_max = 4096;
    size_t dynamic_table_size_limit = 4096;
    size_t dynamic_table_size = 0;
    size_t evicted_count = 1;
    std::map<size_t, Index *> dynamic_table;
    std::map<std::string, Index*> dynamic_map;
    void evict_dynamic_table();
    void add_dynamic_table(const std::string &name, const std::string &value);
    uint32_t getid(const std::string& name, const std::string& value);
    uint32_t getid(const std::string& name);
    const Index *getvalue(uint32_t id);
    void set_dynamic_table_size_limit(size_t size);
public:
    explicit Index_table(size_t dynamic_table_size_limit_max = 4096);
    ~Index_table();
    void set_dynamic_table_size_limit_max(size_t size);
    std::multimap<std::string, std::string> hpack_decode(const unsigned char *s, int len);
    int hpack_encode(unsigned char *buf, const char *name, const char *value);
//    int hpack_encode(char *buf, mulmap<std::string, std::string> headers);
    int hpack_encode(unsigned char *buf, std::map<std::string, std::string> headers);
};

#endif
