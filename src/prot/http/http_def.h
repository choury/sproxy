#ifndef HTTP_DEF_H__
#define HTTP_DEF_H__

#include "http_header.h"
#include "misc/buffer.h"

#include <functional>
#include <memory>
#include <list>

struct ChannelMessage{
    typedef enum{
        CHANNEL_MSG_HEADER,
        CHANNEL_MSG_DATA,
        CHANNEL_MSG_SIGNAL,
    }Type;
    typedef enum{
        CHANNEL_ABORT,
    }Signal;
    Type type;
    std::shared_ptr<HttpHeader> header;
    Buffer data;
    Signal signal;
    ChannelMessage(Buffer&& data);
    ChannelMessage(std::shared_ptr<HttpHeader> header);
    ChannelMessage(Signal signal);
    ChannelMessage(ChannelMessage &&other);
};

class Channel{
public:
    typedef std::function<int()> cap_t;
    typedef std::function<void()> pull_t;

    //返回0表示不能再接收数据了
    //返回非0表示可以继续接收数据
    //这个函数不能返回错误，如果出错，请调用对应的错误处理回调，或者发送信号
    typedef std::function<int(ChannelMessage&)> handler_t;
private:
    cap_t cap_cb = []{return BUF_LEN;}; //这里需要buffer一些数据，不然vpn那边体验会很差，依赖重传
    handler_t handler;
    pull_t pull_cb;
    void poll();
protected:
    std::list<ChannelMessage> message_queue;
public:
    Channel(const Channel&) = delete;
    const Channel& operator=(const Channel&) = delete;
    virtual ~Channel();
    explicit Channel(pull_t pull_cb);
    int cap() { return cap_cb(); }
    virtual void send(ChannelMessage&& message);
    virtual void send(const void* data, size_t len);
    virtual void send(Buffer&& bb);
    virtual void send(std::nullptr_t _);
    virtual void send(std::shared_ptr<HttpHeader> header);
    virtual void send(ChannelMessage::Signal s);
    //处理消息的时候，禁止调用send发回CHANNEL_MSG_SIGNAL，这样会导致Channel本身被销毁
    void attach(handler_t handler, cap_t cap);
    void detach();
    void pull(){
        pull_cb ? pull_cb() : void();
    }
    virtual size_t mem_usage();
};

//These flags just defined for user, it will NOT be set by this class
#define HTTP_CLOSED_F       (1u<<1u)   //cls
#define HTTP_CHUNK_F        (1u<<2u)   //http1 only
#define HTTP_NOEND_F        (1u<<3u)   //http1 only
#define HTTP_REQ_COMPLETED  (1u<<4u)   //qc
#define HTTP_RES_COMPLETED  (1u<<5u)   //sc

/* 1. Requester alloc HttpReq and Responser alloc HttpRes.
 * 2. Peers send zero message(send0) for end flag of single req or res,
 *    it will be transfor to HTTP2_END_STREAM_F in http2 or STREAM_FIN_F in QUIC,
 * 3. Requester may trigger `closed(abort)` for qc|sc requests.
 * 5. Trigger `abort` will reset connection if no completed message sent.
 * 6. Callback of body must be callable if no `closed/abort` was sent or received.
*/

class HttpRes: public Channel{
public:
    HttpRes(const HttpRes &) = delete;
    HttpRes(std::shared_ptr<HttpResHeader> header, pull_t pull_cb);
    HttpRes(std::shared_ptr<HttpResHeader> header);
    HttpRes(std::shared_ptr<HttpResHeader> header, const char* body);
    ~HttpRes();
    virtual size_t mem_usage() override {
        return Channel::mem_usage() + sizeof(*this);
    }
};

class HttpReq: public Channel{
public:
    std::shared_ptr<HttpReqHeader> header;
    typedef std::function<void(std::shared_ptr<HttpRes>)> res_cb;
    res_cb         response;
    HttpReq(const HttpReq&) = delete;
    HttpReq(std::shared_ptr<HttpReqHeader> header, res_cb response, pull_t pull_cb);
    using Channel::send;
    virtual void send(ChannelMessage::Signal s) override;
    ~HttpReq();
    virtual size_t mem_usage() override {
        return Channel::mem_usage() + header->mem_usage();
    }
};

void HttpLog(const char* src, std::shared_ptr<const HttpReqHeader> req, std::shared_ptr<const HttpResHeader> res);

#endif
