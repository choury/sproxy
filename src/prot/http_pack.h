#ifndef HTTP_PACK_H__
#define HTTP_PACK_H__

#include "rwer.h"
#include "common.h"

#include <map>
#include <set>
#include <queue>
#include <string>
#include <functional>

class Hpack_index_table;
struct Http2_header;
struct CGI_Header;
class Requester;

class HttpHeader{
protected:
    std::map<std::string, std::string> headers;
public:
    uint64_t request_id = 0;
    std::set<std::string> cookies;

    void set(const std::string& header, const std::string& value);
    void set(const std::string& header, uint64_t value);
    void append(const std::string& header, const std::string& value);
    void del(const std::string& header);
    const char* get(const std::string& header) const;
    const std::map<std::string, std::string>& getall() const;

    virtual bool no_body() const = 0;
    virtual char *getstring(size_t &len) const = 0;
    virtual Http2_header *getframe(Hpack_index_table *index_table, uint32_t http_id) const = 0;
    virtual CGI_Header *getcgi(uint32_t cgi_id) const = 0;
    virtual ~HttpHeader(){}
};

struct Range{
    ssize_t begin;
    ssize_t end;
};

class HttpReqHeader: public HttpHeader{
    void postparse();
public:
    char method[20];
    struct Destination Dest;
    char path[URLLIMIT];
    std::string filename;
    std::vector<Range> ranges;
    bool should_proxy  = false;
    explicit HttpReqHeader(const char* header, size_t len);
    explicit HttpReqHeader(std::multimap<std::string, std::string>&& headers);
    explicit HttpReqHeader(const CGI_Header *headers);
    bool ismethod(const char* method) const;
    
    virtual bool no_body() const override;
    virtual bool http_method() const;
    virtual bool normal_method() const;
    virtual char *getstring(size_t &len) const override;
    virtual Http2_header *getframe(Hpack_index_table *index_table, uint32_t http_id) const override;
    virtual CGI_Header *getcgi(uint32_t cgi_id) const override;
    
    std::map<std::string, std::string> getcookies()const;
    std::map<std::string, std::string> getparamsmap()const;
    const char* getparamstring()const;
    bool getrange();
    std::string geturl() const;
};

class HttpResHeader: public HttpHeader{
public:
    char status[100];
    explicit HttpResHeader(const char* header, size_t len = 0);
    explicit HttpResHeader(std::multimap<std::string, std::string>&& headers);
    explicit HttpResHeader(const CGI_Header *headers);
    
    virtual bool no_body() const override;
    virtual char *getstring(size_t &len) const override;
    virtual Http2_header *getframe(Hpack_index_table *index_table, uint32_t http_id) const override;
    virtual CGI_Header *getcgi(uint32_t cgi_id) const override;
};

class Channel{
public:
    typedef enum{
        CHANNEL_SHUTDOWN,
        CHANNEL_ABORT,
        CHANNEL_CLOSED,
    }signal;
    typedef std::function<void(PRE_POINTER void* buf, size_t len)> recv_t;
    typedef std::function<void(const void* buf, size_t len)> recv_const_t;
    typedef std::function<int()> cap_t;
    typedef std::function<void(signal)> handler_t;
    typedef std::function<void()> more_data_t;
private:
    recv_t recv_cb;
    recv_const_t recv_const_cb;
    cap_t cap_cb;
    handler_t handler;
    more_data_t need_more;
    bool eatData(PRE_POINTER void *buf, size_t size);
    bool eatData(const void *buf, size_t size);
protected:
    const static int DATALEN = 16384;
    uchar* data = nullptr;
    size_t len = 0;
    bool eof = false;
    bool closed = false;
public:
    Channel(const Channel&) = delete;
    const Channel& operator=(const Channel&) = delete;
    ~Channel();
    explicit Channel(more_data_t need_more);
    int cap();
    void send(PRE_POINTER void* buf, size_t len);
    void send(const void* buf, size_t len);
    void trigger(signal s);
    void attach(recv_t recv_cb, cap_t cap_cb);
    void attach(recv_const_t recv_cb, cap_t cap_cb);
    void setHandler(handler_t handler);
    void detach();
    void more();
};

//These flags just defined for user, it will NOT be set by this class
#define HTTP_CLOSED_F       (1u<<1u)   //cls
#define HTTP_CHUNK_F        (1u<<2u)
#define HTTP_NOLENGTH_F     (1u<<3u)
#define HTTP_REQ_COMPLETED  (1u<<4u)   //qc
#define HTTP_REQ_EOF        (1u<<5u)   //qe
#define HTTP_RES_COMPLETED  (1u<<6u)   //sc
#define HTTP_RES_EOF        (1u<<7u)   //se

/* Requester alloc HttpReq and Responser alloc HttpRes,
 * but they are all freed by requester.
 * Peers send zero message(send0) for completed, and trigger shutdown for eof.
 * Requester may trigger closed event for qc|sc requests.
 * Peer should trigger closed (instead of shutdown) if received shutdown already.
 * Trigger closed will reset connection if no `send0` message sent.
 * Callback of body must callable if no closed message was sent or received.
*/
class HttpRes: public Channel{
public:
    HttpResHeader* header;
    HttpRes(const HttpRes &) = delete;
    HttpRes(HttpResHeader* header, more_data_t more);
    HttpRes(HttpResHeader* header);
    HttpRes(HttpResHeader* header, const char* body);
    ~HttpRes();
};

class HttpReq: public Channel{
public:
    typedef std::function<void(HttpRes*)> res_cb;
    HttpReqHeader* header;
    res_cb         response;
    HttpReq(const HttpReq&) = delete;
    HttpReq(HttpReqHeader* header, res_cb response, more_data_t more);
    ~HttpReq();
};

void HttpLog(const char* src, const HttpReq* req, const HttpRes* res);

#endif
