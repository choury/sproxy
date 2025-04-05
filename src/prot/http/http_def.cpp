#include "http_def.h"
#include "misc/config.h"

#include <assert.h>
#include <inttypes.h>

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
        int ret = handler(std::move(msg));
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
    send(ChannelMessage(std::move(header)));
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

void Channel::send(Signal s) {
    send(ChannelMessage(s));
}

void Channel::attach(handler_t handler, cap_t cap) {
    this->handler = std::move(handler);
    cap_cb = std::move(cap);
    return poll();
}

void Channel::detach() {
    //this->pull_cb = nullptr;
    this->handler = nullptr;
    this->cap_cb = []{return 0;};
}

size_t Channel::mem_usage() {
    size_t usage = message_queue.size() * sizeof(ChannelMessage);
    for(const auto& msg : message_queue){
        switch(msg.type) {
        case ChannelMessage::CHANNEL_MSG_HEADER:
            usage += std::get<std::shared_ptr<HttpHeader>>(msg.data)->mem_usage();
            break;
        case ChannelMessage::CHANNEL_MSG_DATA:
            usage += std::get<Buffer>(msg.data).cap;
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

HttpRes::HttpRes(std::shared_ptr<HttpResHeader> header): HttpRes(std::move(header), []{}) {
}

HttpRes::HttpRes(std::shared_ptr<HttpResHeader> header, const char *body):
    Channel([]{})
{
    int len = strlen(body);
    header->set("Content-Length", len);
    send(header);
    if(len) {
        send({body, (size_t)len, header->request_id});
    }
    send(Buffer{nullptr, header->request_id});
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

void HttpReq::send(Signal s) {
    if(s == CHANNEL_ABORT){
        response = [](const std::shared_ptr<HttpRes>&){};
    }
    Channel::send(s);
}

void HttpLog(const std::string& src, std::shared_ptr<const HttpReqHeader> req, std::shared_ptr<const HttpResHeader> res){
    char status[100];
    sscanf(res->status, "%s", status); //get the first word of status (status code)
    uint32_t res_time = std::get<1>(req->tracker.back()) - std::get<1>(req->tracker[0]);
    if(debug[DHTTP].enabled){
        LOG("%s [%" PRIu64 "] %s %s [%s]\n", src.c_str(),
            req->request_id, req->method, req->geturl().c_str(), req->Dest.protocol);
        for(const auto& header : req->getall()){
            LOG("%s: %s\n", header.first.c_str(), header.second.c_str());
        }
        LOG("\nResponse: %s %ums\n" , status, res_time);
        for(const auto& header : res->getall()){
            LOG("%s: %s\n", header.first.c_str(), header.second.c_str());
        }
    } else {
        LOG("%s [%" PRIu64 "] %s %s [%s] %s %ums [%s]\n", src.c_str(),
            req->request_id, req->method, req->geturl().c_str(),
            req->get(STRATEGY), status, res_time,
            req->get("User-Agent"));
    }
    if(opt.trace_time > 0 && res_time > (size_t)opt.trace_time) {
        uint32_t mtime = std::get<1>(req->tracker[0]);
        for(auto [tracker, time] : req->tracker) {
            LOG("%s: %ums\n", tracker.c_str(), time - mtime);
        }
    }
}
