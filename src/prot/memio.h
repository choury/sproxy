#ifndef MEMIO_H__
#define MEMIO_H__

#include "rwer.h"
#include <variant>

class MemRWer: public FullRWer{
protected:
    Destination src;
    CBuffer rb;
    std::function<int(std::variant<std::reference_wrapper<Buffer>, Buffer, Signal>)> write_cb;
    std::function<void(uint64_t)> read_cb;
    std::function<ssize_t()> cap_cb;
    std::function<void(const sockaddr_storage&)> connectCB = [](const sockaddr_storage&){};
    void connected(const sockaddr_storage& addr);
    virtual void closeHE(RW_EVENT events) override;
    virtual void ErrorHE(int ret, int code) override;
    virtual ssize_t Write(std::set<uint64_t>& writed_list) override;
    virtual bool IsConnected() {
        return true;
    }
    virtual size_t rlength(uint64_t id) override;

    virtual void push_data(Buffer&& bb);
    virtual void push_signal(Signal s);
public:
    //write_cb act like write, return bytes handled
    explicit MemRWer(const Destination& src,
                     std::function<int(std::variant<std::reference_wrapper<Buffer>, Buffer, Signal>)> write_cb,
                     std::function<void(uint64_t)> read_cb,
                     std::function<ssize_t()> cap_cb);
    ~MemRWer() override;

    virtual size_t bufsize() {
        return rb.cap();
    }
    virtual void push(std::variant<Buffer, Signal> data);
    virtual void detach();
    virtual void pull(uint64_t id) {
        //let owner call Send to fill the buffer
        LOGD(DRWER, "<MemRwer> pull %d\n", (int)id);
        writeCB(id);
        addEvents(RW_EVENT::WRITE);
    }
    virtual void Unblock(uint64_t id) override {
        read_cb(id);
        FullRWer::Unblock(id);
    }

    void SetConnectCB(std::function<void(const sockaddr_storage&)> connectCB);
    virtual ssize_t cap(uint64_t id) override;
    virtual void ConsumeRData(uint64_t) override;
    virtual Destination getSrc() const override {
        return src;
    }
    virtual void dump_status(Dumper dp, void* param) override;
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
