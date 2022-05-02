#include "http_def.h"
#include "misc/util.h"

#include <assert.h>
#include <inttypes.h>

ChannelMessage::ChannelMessage(Signal signal):
    type(CHANNEL_MSG_SIGNAL), header(nullptr), data(nullptr), signal(signal){
}

ChannelMessage::ChannelMessage(Buffer&& data):
    type(CHANNEL_MSG_DATA), header(nullptr), data(std::move(data)), signal(CHANNEL_SHUTDOWN){
}

ChannelMessage::ChannelMessage(std::shared_ptr<HttpHeader> header):
    type(CHANNEL_MSG_HEADER), header(header), data(nullptr), signal(CHANNEL_SHUTDOWN){
}

ChannelMessage::ChannelMessage(ChannelMessage&& other):
    type(other.type), header(std::move(other.header)), data(std::move(other.data)), signal(other.signal) {
}


Channel::Channel(more_data_t need_more): need_more(std::move(need_more)){
}

Channel::~Channel() {
}

void Channel::eatMessage() {
    while(true){
        if(!handler || message_queue.empty()){
            return;
        }
        int ret = handler(message_queue.front());
        message_queue.pop();
        if(ret){
            continue;
        }
        return;
    }
}

void Channel::send(ChannelMessage&& message) {
    message_queue.emplace(std::move(message));
    return eatMessage();
}

void Channel::send(std::shared_ptr<HttpHeader> header) {
    send(ChannelMessage(header));
}


void Channel::send(Buffer&& bb) {
    send(ChannelMessage(std::move(bb)));
}

void Channel::send(std::nullptr_t) {
    send(ChannelMessage(Buffer{nullptr}));
}

void Channel::send(const void *data, size_t len) {
    send(ChannelMessage(Buffer{data, len}));
}

void Channel::send(ChannelMessage::Signal s) {
    send(ChannelMessage(s));
}


void Channel::attach(handler_t handler, cap_t cap) {
    this->handler = handler;
    cap_cb = cap;
    return eatMessage();
}

void Channel::detach() {
    this->handler = nullptr;
    this->cap_cb = []{return 0;};
}

HttpRes::HttpRes(std::shared_ptr<HttpResHeader> header, more_data_t more):
    Channel(std::move(more))
{
    send(header);
}

HttpRes::HttpRes(std::shared_ptr<HttpResHeader> header): HttpRes(header, []{}) {
}

HttpRes::HttpRes(std::shared_ptr<HttpResHeader> header, const char *body):
    Channel([]{})
{
    int len = strlen(body);
    header->set("Content-Length", len);
    send(header);
    if(len) {
        send(body, len);
    }
    send(nullptr);
    send(ChannelMessage::CHANNEL_CLOSED);
}

HttpRes::~HttpRes() {
}

HttpReq::HttpReq(std::shared_ptr<HttpReqHeader> header, HttpReq::res_cb response, more_data_t more):
    Channel(std::move(more)), header(header), response(std::move(response))
{
    send(header);
}

HttpReq::~HttpReq() {
}


void HttpLog(const char* src, std::shared_ptr<const HttpReqHeader> req, std::shared_ptr<const HttpResHeader> res){
    char status[100];
    sscanf(res->status, "%s", status);
    LOG("%s [%" PRIu32 "] %s %s [%s] %s %dms [%s]\n", src,
        req->request_id, req->method, req->geturl().c_str(),
        req->get("Strategy"), status, res->ctime - req->ctime,
        req->get("User-Agent"));
}

