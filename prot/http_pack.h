#ifndef HTTP_PACK_H__
#define HTTP_PACK_H__

#include "common.h"
#include "resobject.h"
#include "misc/istring.h"

#include <map>
#include <set>
#include <queue>
#include <functional>

class Index_table;
struct Http2_header;
struct CGI_Header;
class Requester;



class HttpHeader{
protected:
    std::map<istring, std::string> headers;
public:
    std::set<std::string> cookies;
    void* index = 0;
#define HTTP_RESPONED    1
    uint8_t flags = 0;

    void add(const istring& header, const std::string& value);
    void add(const istring& header, uint64_t value);
    void append(const istring& header, const std::string& value);
    void del(const istring& header);
    const char* get(const char *header) const;

    virtual bool no_body() const = 0;
    virtual char *getstring(size_t &len) const = 0;
    virtual Http2_header *getframe(Index_table *index_table, uint32_t http_id) const = 0;
    virtual CGI_Header *getcgi(uint32_t cgi_id) const = 0;
    virtual ~HttpHeader(){}
};


struct Range{
    ssize_t begin;
    ssize_t end;
};

class HttpReqHeader: public HttpHeader{
    void getfile();
public:
    Requester* src;
    char method[20];
    char protocol[20];
    char path[URLLIMIT];
    char hostname[DOMAINLIMIT] = {0};
    uint16_t port = 0;
    std::string filename;
    std::vector<Range> ranges;
    bool should_proxy  = false;
    explicit HttpReqHeader(const char* header,  ResObject* src);
    explicit HttpReqHeader(std::multimap<istring, std::string>&& headers, ResObject* src);
    explicit HttpReqHeader(const CGI_Header *headers);
    bool ismethod(const char* method) const;
    
    virtual bool no_body() const override;
    virtual char *getstring(size_t &len) const override;
    virtual Http2_header *getframe(Index_table *index_table, uint32_t http_id) const override;
    virtual CGI_Header *getcgi(uint32_t cgi_id) const override;
    
    std::map<std::string, std::string> getcookies()const;
    const char* getparamstring()const;
    bool getrange();
    std::string geturl() const;
};

class HttpResHeader: public HttpHeader{
public:
    char status[100];
    explicit HttpResHeader(const char* header);
    explicit HttpResHeader(std::multimap<istring, std::string>&& headers);
    explicit HttpResHeader(const CGI_Header *headers);
    
    virtual bool no_body() const override;
    virtual char *getstring(size_t &len) const override;
    virtual Http2_header *getframe(Index_table *index_table, uint32_t http_id) const override;
    virtual CGI_Header *getcgi(uint32_t cgi_id) const override;
};


class HttpBody{
    size_t content_size = 0;
public:
    std::queue<write_block> data;
    explicit HttpBody();
    explicit HttpBody(const HttpBody &) = delete;
    explicit HttpBody(HttpBody&& copy);
    ~HttpBody();
    
    void push(const void *buff, size_t len);
    void push(void *buff, size_t len);
    void push(const write_block& wb);
    write_block pop();
    size_t& size();
};

class HttpReq{
    size_t header_sent = 0;
    size_t header_len = 0;
public:
    void *header_buff = nullptr;
    HttpReqHeader*  header;
    HttpBody       body;
    HttpReq(const HttpReq&) = delete;
    HttpReq(HttpReq&&);
    explicit HttpReq(HttpReqHeader* header):header(header){};
    ~HttpReq();
    ssize_t  Write_string(std::function<ssize_t(const void*, size_t)> write_func);
    size_t size();
};

// trim from start
static inline std::string& ltrim(std::string && s) {
    s.erase(0, s.find_first_not_of(" "));
    return s;
}




#endif
