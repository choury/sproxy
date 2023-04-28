#include "http_def.h"
#include "misc/util.h"

#include <assert.h>
#include <inttypes.h>

ChannelMessage::ChannelMessage(Signal signal):
    type(CHANNEL_MSG_SIGNAL), header(nullptr), data(nullptr), signal(signal){
}

ChannelMessage::ChannelMessage(Buffer&& data):
    type(CHANNEL_MSG_DATA), header(nullptr), data(std::move(data)), signal(CHANNEL_ABORT){
}

ChannelMessage::ChannelMessage(std::shared_ptr<HttpHeader> header):
    type(CHANNEL_MSG_HEADER), header(header), data(nullptr), signal(CHANNEL_ABORT){
}

ChannelMessage::ChannelMessage(ChannelMessage&& other):
    type(other.type), header(std::move(other.header)), data(std::move(other.data)), signal(other.signal) {
}


Channel::Channel(pull_t pull_cb): pull_cb(std::move(pull_cb)){
}

Channel::~Channel() {
}

void Channel::poll() {
    while(true){
        if(!handler || message_queue.empty()){
            return;
        }
        ChannelMessage msg(std::move(message_queue.front()));
        message_queue.pop_front();
        int ret = handler(msg);
        if(ret){
            continue;
        }
        return;
    }
}

void Channel::send(ChannelMessage&& message) {
    message_queue.emplace_back(std::move(message));
    return poll();
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
    send(ChannelMessage(Buffer{std::make_shared<Block>(data, len), len}));
}

void Channel::send(ChannelMessage::Signal s) {
    send(ChannelMessage(s));
}

void Channel::attach(handler_t handler, cap_t cap) {
    this->handler = handler;
    cap_cb = cap;
    return poll();
}

void Channel::detach() {
    this->handler = nullptr;
    this->cap_cb = []{return 0;};
}

size_t Channel::mem_usage() {
    size_t usage = message_queue.size() * sizeof(ChannelMessage);
    for(const auto& msg : message_queue){
        switch(msg.type) {
        case ChannelMessage::CHANNEL_MSG_HEADER:
            usage += msg.header->mem_usage();
            break;
        case ChannelMessage::CHANNEL_MSG_DATA:
            usage += msg.data.cap;
            break;
        default:
            break;
        }
    }
    return usage;
}

HttpRes::HttpRes(std::shared_ptr<HttpResHeader> header, pull_t pull_cb):
    Channel(std::move(pull_cb))
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
}

HttpRes::~HttpRes() {
}

HttpReq::HttpReq(std::shared_ptr<HttpReqHeader> header, HttpReq::res_cb response, pull_t pull_cb):
    Channel(std::move(pull_cb)), header(header), response(std::move(response))
{
    send(header);
}

HttpReq::~HttpReq() {
}

void HttpReq::send(ChannelMessage::Signal s) {
    if(s == ChannelMessage::CHANNEL_ABORT){
        response = [](std::shared_ptr<HttpRes>){};
    }
    Channel::send(s);
}

void HttpLog(const char* src, std::shared_ptr<const HttpReqHeader> req, std::shared_ptr<const HttpResHeader> res){
    char status[100];
    sscanf(res->status, "%s", status);
    LOG("%s [%" PRIu32 "] %s %s [%s] %s %dms [%s]\n", src,
        req->request_id, req->method, req->geturl().c_str(),
        req->get("Strategy"), status, res->ctime - req->ctime,
        req->get("User-Agent"));
}
