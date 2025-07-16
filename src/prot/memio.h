#ifndef MEMIO_H__
#define MEMIO_H__

#include "rwer.h"
#include <deque>

class HttpResHeader;
struct IMemRWerCallback: std::enable_shared_from_this<IMemRWerCallback> {
    //write_cb act like write, return bytes handled
    std::function<int(Buffer)> write_data;
    std::function<void(Signal)> write_signal;
    std::function<void(std::shared_ptr<HttpResHeader>)> write_header = [](std::shared_ptr<HttpResHeader>){};
    std::function<void(uint64_t)> read_cb;
    std::function<ssize_t()> cap_cb;

    template<typename F>
    std::shared_ptr<IMemRWerCallback> onData(F&& f) {
        write_data = std::forward<F>(f);
        return shared_from_this();
    }
    template<typename F>
    std::shared_ptr<IMemRWerCallback> onHeader(F&& f) {
        write_header = std::forward<F>(f);
        return shared_from_this();
    }

    template<typename F>
    std::shared_ptr<IMemRWerCallback> onSignal(F&& f) {
        write_signal = std::forward<F>(f);
        return shared_from_this();
    }

    template<typename F>
    std::shared_ptr<IMemRWerCallback> onWrite(F&& f) {
        read_cb = std::forward<F>(f);
        return shared_from_this();
    }
    template<typename F>
    std::shared_ptr<IMemRWerCallback> onCap(F&& f) {
        cap_cb = std::forward<F>(f);
        return shared_from_this();
    }

    static std::shared_ptr<IMemRWerCallback> create() {
        return std::make_shared<IMemRWerCallback>();
    }
};

class MemRWer: public FullRWer{
protected:
    Destination src;
    std::weak_ptr<IMemRWerCallback> _callback;
    CBuffer rb;
    //std::function<void(const sockaddr_storage&)> connectCB = [](const sockaddr_storage&){};
    void connected(const sockaddr_storage& addr);
    virtual void closeHE(RW_EVENT events) override;
    virtual ssize_t Write(std::set<uint64_t>& writed_list) override;
    virtual bool IsConnected() override {
        return true;
    }
    virtual size_t rlength(uint64_t id) override;

public:
    explicit MemRWer(const Destination& src, std::shared_ptr<IMemRWerCallback> cb);
    ~MemRWer() override;

    virtual size_t bufsize() {
        return rb.cap();
    }
    virtual void push_data(Buffer&& bb);
    virtual void push_signal(Signal s);
    //virtual void detach();
    virtual void pull(uint64_t id) {
        //let owner call Send to fill the buffer
        LOGD(DRWER, "<MemRWer> <%d> %s pull %d\n",
            getFd(), dumpDest(src).c_str(), (int)id);
        if (auto cb = callback.lock(); cb) {
            cb->writeCB(id);
        }
        addEvents(RW_EVENT::WRITE);
    }
    virtual void SendHeader(std::shared_ptr<HttpResHeader> header) {
        if(auto cb = _callback.lock(); cb) {
            cb->write_header(header);
        }
    }
    virtual void Unblock(uint64_t id) override {
        if(auto cb = _callback.lock(); cb) {
            cb->read_cb(id);
        }
        FullRWer::Unblock(id);
    }

    //void SetConnectCB(std::function<void(const sockaddr_storage&)> connectCB);
    virtual void SetCallback(std::shared_ptr<IRWerCallback> cb) override;
    virtual ssize_t cap(uint64_t id) override;
    virtual void ConsumeRData(uint64_t) override;
    virtual Destination getSrc() const override {
        return src;
    }
    virtual void dump_status(Dumper dp, void* param) override;
    virtual size_t mem_usage() override{
        return sizeof(*this) + wbuff.length();
    }
};

class PMemRWer: public MemRWer {
protected:
    std::deque<Buffer> rb;
public:
    using MemRWer::MemRWer;

    virtual size_t bufsize() override{
        return BUF_LEN * 2;
    }
    virtual void Send(Buffer&& bb) override;
    virtual void push_data(Buffer&& bb) override;
    virtual void ConsumeRData(uint64_t) override;
};

#endif
