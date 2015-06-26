#ifndef HPACK_H__
#define HPACK_H__

#include <string>
#include <boost/bimap.hpp>
#include <boost/bimap/multiset_of.hpp>

struct Index{
    std::string name;
    std::string value;
    size_t id;
};

class Index_table{
    size_t dynamic_table_size_limit;
    size_t dynamic_table_size = 0;
    size_t evicted_count = 1;
    std::map<size_t, Index *> dynamic_table;
    boost::bimap<boost::bimaps::multiset_of<std::string>, Index*> dynamic_map;
    void evict_dynamic_table(size_t size);
    void add_dynamic_table(const std::string &name, const std::string &value);
    uint getid(const std::string& name, const std::string& value);
    uint getid(const std::string& name);
    const Index *getvalue(uint id);
public:
    Index_table(size_t dynamic_table_size_limit = 4096);
    ~Index_table();
    void set_dynamic_table_size_limit(size_t size);
    std::list<std::pair<std::string, std::string>> hpack_decode(const char *s, int len);
    int hpack_encode(char *buf, const std::list<std::pair<std::string, std::string>> headers);
    int hpack_encode(char *buf, const char *name, const char *value);
};

#endif