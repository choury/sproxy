#ifndef MEMIO_H__
#define MEMIO_H__

#include "rwer.h"
#include <variant>

class MemRWer: public FullRWer{
protected:
    char peer[128];
    CBuffer rb;
    std::function<int(std::variant<std::reference_wrapper<Buffer>, Buffer, Signal>)> read_cb;
    std::function<ssize_t()> cap_cb;
    std::function<void(const sockaddr_storage&)> connectCB = [](const sockaddr_storage&){};
    void connected(const sockaddr_storage& addr);
    virtual void closeHE(RW_EVENT events) override;
    virtual ssize_t Write(std::set<uint64_t>& writed_list) override;
    virtual bool IsConnected() {
        return true;
    }
    virtual size_t rlength(uint64_t id) override;

    virtual void push_data(Buffer&& bb);
    virtual void push_signal(Signal s);
public:
    explicit MemRWer(const char* pname,
                     std::function<int(std::variant<std::reference_wrapper<Buffer>, Buffer, Signal>)> read_cb,
                     std::function<ssize_t()> cap_cb);
    ~MemRWer() override;

    virtual size_t bufsize() {
        return rb.cap();
    }
    virtual void push(std::variant<Buffer, Signal> data);
    virtual void detach();

    void SetConnectCB(std::function<void(const sockaddr_storage&)> connectCB);
    virtual void Close(std::function<void()> func) override;
    virtual ssize_t cap(uint64_t id) override;
    virtual void ConsumeRData(uint64_t) override;
    virtual const char* getPeer() override {
        return peer;
    }
    virtual void dump_status(Dumper dp, void* param) override {
        dp(param, "MemRWer <%d> (%s): rlen: %zu, wlen: %zu, stats: %d, flags: 0x%04x,  event: %s\n",
            getFd(), getPeer(), rlength(0), wlen,
            (int)getStats(), flags, events_string[(int)getEvents()]);
    }
    virtual size_t mem_usage() override{
        return sizeof(*this) + wlen;
    }
};

class PMemRWer: public MemRWer {
public:
    using MemRWer::MemRWer;

    virtual size_t bufsize() override{
        return BUF_LEN;
    }
    virtual void push_data(Buffer&& bb) override;
    virtual void ConsumeRData(uint64_t) override;
};

#endif
