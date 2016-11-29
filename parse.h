#ifndef PARSE_H__
#define PARSE_H__

#include "common.h"
#include "istring.h"

#include <map>
#include <set>
#include <queue>

class Index_table;
struct Http2_header;
struct CGI_Header;
class Object;
class Requester;

enum class Strategy{
    direct,
    proxy,
    local,
    block,
};

class HttpHeader{
protected:
    std::map<istring, std::string> headers;
public:
    std::set<std::string> cookies;
    uint32_t http_id = 0;  // 由http2协议使用
    uint8_t flags = 0;
    bool should_proxy  = false;

    void add(const istring& header, const std::string& value);
    void add(const istring& header, int value);
    void append(const istring& header, const std::string& value);
    void del(const istring& header);
    const char* get(const char *header) const;

    virtual bool no_body() const = 0;
    virtual char *getstring(size_t &len) const = 0;
    virtual Http2_header *getframe(Index_table *index_table) const = 0;
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
    char url[URLLIMIT];
    char protocol[DOMAINLIMIT];
    char hostname[DOMAINLIMIT];
    char path[URLLIMIT];
    char filename[URLLIMIT];
    uint16_t port;
    std::vector<Range> ranges;
    explicit HttpReqHeader(const char* header,  Object* src);
    explicit HttpReqHeader(std::multimap<istring, std::string>&& headers, Object* src);
    explicit HttpReqHeader(CGI_Header *headers);
    bool ismethod(const char* method) const;
    
    virtual bool no_body() const override;
    virtual char *getstring(size_t &len) const override;
    virtual Http2_header *getframe(Index_table *index_table) const override;
    virtual CGI_Header *getcgi(uint32_t cgi_id) const override;
    
    std::map<std::string, std::string> getcookies()const;
    const char* getparamstring()const;
    bool getrange();
};

class HttpResHeader: public HttpHeader{
public:
    char status[100];
    explicit HttpResHeader(const char* header);
    explicit HttpResHeader(std::multimap<istring, std::string>&& headers);
    explicit HttpResHeader(CGI_Header *headers);
    
    virtual bool no_body() const override;
    virtual char *getstring(size_t &len) const override;
    virtual Http2_header *getframe(Index_table *index_table) const override;
    virtual CGI_Header *getcgi(uint32_t cgi_id) const override;
};


class HttpBody{
    size_t content_size = 0;
    std::queue<std::pair<void *, size_t>> data;
public:
    explicit HttpBody();
    explicit HttpBody(const HttpBody &) = delete;
    explicit HttpBody(HttpBody&& copy);
    ~HttpBody();
    
    size_t push(const void *buff, size_t len);
    size_t push(void *buff, size_t len);
    std::pair<void*, size_t> pop();
    size_t size();
};

class HttpReq{
public:
    HttpReqHeader  header;
    HttpBody       body;
    HttpReq(HttpReqHeader& header):header(header){};
};

class HttpRes{
public:
    HttpResHeader  header;
    HttpBody       body;
    HttpRes(HttpResHeader& header):header(header){};
};

// trim from start
static inline std::string& ltrim(std::string && s) {
    s.erase(0, s.find_first_not_of(" "));
    return s;
}


#ifdef  __cplusplus
extern "C" {
#endif


void loadsites();
bool addstrategy(const char *host, const char *strategy);
bool delstrategy(const char *host);
Strategy getstrategy(const char *host);
const char* getstrategystring(const char *host);

void addauth(const char * ip);
bool checkauth(const char *ip);

#ifdef  __cplusplus
}
#endif

#endif
