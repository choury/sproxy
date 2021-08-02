#ifndef HTTP_PACK_H__
#define HTTP_PACK_H__

#include "prot/rwer.h"
#include "common/common.h"

#include <map>
#include <set>
#include <queue>
#include <string>
#include <functional>

#define CRLF      "\r\n"


#define H200        "HTTP/1.1 200 OK" CRLF CRLF

#define H204        "HTTP/1.1 204 No Content" CRLF CRLF

#define H205        "HTTP/1.1 205 Reset Content" CRLF CRLF

#define H206        "HTTP/1.1 206 Partial Content" CRLF CRLF

#define H301        "HTTP/1.1 301 Moved Permanently" CRLF CRLF

#define H302        "HTTP/1.1 302 Found" CRLF CRLF

#define H303        "HTTP/1.1 303 See Other" CRLF CRLF

#define H304        "HTTP/1.1 304 Not Modified" CRLF CRLF

#define H400        "HTTP/1.1 400 Bad Request" CRLF CRLF

#define H401        "HTTP/1.1 401 Unauthorized" CRLF CRLF

#define H403        "HTTP/1.1 403 Forbidden" CRLF  CRLF

#define H404        "HTTP/1.1 404 Not Found" CRLF CRLF

#define H405        "HTTP/1.1 405 Method Not Allowed" CRLF CRLF

#define H407        "HTTP/1.1 407 Proxy Authentication Required" CRLF \
                    "Proxy-Authenticate: Basic realm=\"Secure Area\"" CRLF CRLF

#define H408        "HTTP/1.1 408 Request Timeout" CRLF CRLF

#define H416        "HTTP/1.1 416 Requested Range Not Satisfiable" CRLF CRLF

#define H429        "HTTP/1.1 429 Too Many Requests" CRLF CRLF

#define H500        "HTTP/1.1 500 Internal Server Error" CRLF CRLF

#define H502        "HTTP/1.1 502 Bad Gateway" CRLF CRLF

#define H503        "HTTP/1.1 503 Service Unavailable" CRLF CRLF

#define H504        "HTTP/1.1 504 Gateway Timeout" CRLF CRLF

#define H508        "HTTP/1.1 508 Loop Detected" CRLF CRLF


class Hpack_index_table;
struct Http2_header;
struct CGI_Header;
class Requester;

class HttpHeader{
protected:
    std::map<std::string, std::string> headers;
public:
    uint32_t request_id = 0;
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
    virtual CGI_Header *getcgi() const = 0;
    virtual ~HttpHeader() = default;
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
    virtual CGI_Header *getcgi() const override;
    
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
    virtual CGI_Header *getcgi() const override;
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
    size_t eatData(const void *buf, size_t size);
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
 * Peers send zero message(send0) for completed, and trigger `shutdown` for eof.
 * Requester may trigger `closed` for qc|sc requests.
 * Peer should trigger `closed` (instead of shutdown) if received `shutdown` already.
 * Trigger `closed` will reset connection if no `send0` message sent.
 * Callback of body must callable if no `closed` was sent or received.
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
