#ifndef HTTP_DEF_H__
#define HTTP_DEF_H__

#include "http_header.h"

#include <functional>
#include <memory>

class Channel{
public:
    typedef enum{
        CHANNEL_SHUTDOWN,
        CHANNEL_ABORT,
        CHANNEL_CLOSED,
    }signal;
    typedef std::function<void(PREPTR void* buf, size_t len)> recv_t;
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

/* Requester alloc HttpReq and Responser alloc HttpRes.
 * Peers send zero message(send0) for completed (same as req and res),
 * but trigger `shutdown` for eof (used for vpn). Distinct send0 from eof,
 * because some implement will close connection if eof received.
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
    typedef std::function<void(std::shared_ptr<HttpRes>)> res_cb;
    HttpReqHeader* header;
    res_cb         response;
    HttpReq(const HttpReq&) = delete;
    HttpReq(HttpReqHeader* header, res_cb response, more_data_t more);
    ~HttpReq();
};

void HttpLog(const char* src, std::shared_ptr<const HttpReq> req, std::shared_ptr<const HttpRes> res);

#endif
