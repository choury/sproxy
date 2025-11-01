#ifndef RWER_H__
#define RWER_H__

#include "prot/ep.h"
#include "misc/buffer.h"

#include <inttypes.h>
#include <sys/socket.h>

#include <list>
#include <functional>
#include <set>

enum class RWerStats{
    Idle = 0,
    Resolving,
    Connecting,
    Connected,
    ReadEOF,
    Error,
};

enum class SslStats{
    Idel = 0,
    SslAccepting,
    SslConnecting,
    Established,
    SslError,
    SslEOF,
};

struct IRWerCallback: public std::enable_shared_from_this<IRWerCallback> {
    //返回值是处理的数据长度，返回len表示数据处理完毕，返回0表示数据完全没有被消费
    //!!readCB不可重入，调用者需通过 RWER_READING来保证这一点
    std::function<size_t(Buffer&& bb)> readCB = [](Buffer&& bb) {
        if (bb.len) {
            LOGE("send data to stub readCB: %zd [%" PRIu64 "]\n", bb.len, bb.id);
        } else {
            LOGD(DRWER, "send eof to stub readCB: [%" PRIu64"]\n", bb.id);
        }
        return (size_t)0;
    };
    std::function<void(uint64_t id)> writeCB = [](uint64_t) {};
    std::function<void()> closeCB = []() {};
    //errorCB must be set, otherwise RWer will not work
    std::function<void(int ret, int code)> errorCB;

    virtual ~IRWerCallback() = default;

    template<typename F>
    std::shared_ptr<IRWerCallback> onRead(F&& func) {
        readCB = std::forward<F>(func);
        return shared_from_this();
    }
    template<typename F>
    std::shared_ptr<IRWerCallback> onWrite(F&& func) {
        writeCB = std::forward<F>(func);
        return shared_from_this();
    }
    template<typename F>
    std::shared_ptr<IRWerCallback> onError(F&& func) {
        errorCB = std::forward<F>(func);
        return shared_from_this();
    }
    template<typename F>
    std::shared_ptr<IRWerCallback> onClose(F&& func) {
        closeCB = std::forward<F>(func);
        return shared_from_this();
    }
    static std::shared_ptr<IRWerCallback> create() {
        return std::make_shared<IRWerCallback>();
    }
};

class RWer: public Ep, public std::enable_shared_from_this<RWer> {
protected:
#define RWER_READING    0x01  // handling the read buffer
#define RWER_SENDING    0x02  // handling the write buffer
#define RWER_CLOSING    0x04  // closing the connection
#define RWER_SHUTDOWN   0x10  // shutdown by me (sent fin to peer)
#define RWER_EOFDELIVED 0x20  // shutdown by peer (handled by me)
    uint32_t   flags = 0;
    RWerStats  stats = RWerStats::Idle;
    CBuffer    wbuff;
    std::weak_ptr<IRWerCallback> callback;

    virtual ssize_t Write(std::set<uint64_t>& writed_list);
    virtual void SendData();
    virtual void ReadData() = 0;
    virtual void defaultHE(RW_EVENT events);
    virtual void closeHE(RW_EVENT events);
    virtual void IdleHE(RW_EVENT events);
    virtual void ErrorHE(int ret, int code);

    //for read buffer
    virtual size_t rlength(uint64_t id) = 0;
    //ConsumeRData只会在Unblock中被调用，ReadData逻辑，需要各实现自行处理readCB回调
    virtual void ConsumeRData(uint64_t id) = 0;
public:
    //如果一个函数的参数是Buffer&& 那么调用者需要保证该buffer中使用的内存是一直有效的，并由被调用者负责释放
    //如果参数是const Buffer& 那么该内存只在本次调用中有效，如果需要后续使用，需要在函数内自行拷贝
    explicit RWer(int fd, std::shared_ptr<IRWerCallback> cb);
    explicit RWer(std::shared_ptr<IRWerCallback> cb);
    //virtual void SetErrorCB(std::function<void(int ret, int code)> func);
    //virtual void SetReadCB(std::function<size_t(Buffer&& bb)> func);
    //virtual void SetWriteCB(std::function<void(uint64_t id)> func);
    //virtual void ClearCB();
    //virtual void Close(std::function<void()> func);
    virtual void SetCallback(std::shared_ptr<IRWerCallback> cb);
    virtual void Unblock(uint64_t id);
    virtual void Close();
    virtual Destination getSrc() const {
        Destination addr{};
        strcpy(addr.hostname, "<null>");
        return addr;
    }
    virtual Destination getDst() const {
        Destination addr{};
        strcpy(addr.hostname, "<null>");
        return addr;
    }

    //for write buffer
    virtual ssize_t cap(uint64_t id);
    virtual bool drained();
    virtual void Send(Buffer&& bb);

    virtual bool isTls();
    virtual bool isEof();
    virtual bool IsConnected();
    virtual bool idle(uint64_t id);
    virtual void dump_status(Dumper dp, void* param) = 0;
    virtual size_t mem_usage() = 0;
};

class NullRWer: public RWer{
public:
    explicit NullRWer();
    virtual ssize_t Write(std::set<uint64_t>& writed_list) override;
    virtual void ReadData() override;
    virtual size_t rlength(uint64_t id) override;

    virtual void ConsumeRData(uint64_t) override;
    virtual void dump_status(Dumper dp, void* param) override {
        dp(param, "NullRWer <%d>\n", getFd());
    }
    virtual size_t mem_usage() override{
        return sizeof(*this);
    }
};

class FullRWer: public RWer{
protected:
#ifndef __linux__
    int pairfd = -1;
#endif
    virtual ssize_t Write(std::set<uint64_t>& writed_list) override;
    virtual void ReadData() override;
    virtual void closeHE(RW_EVENT events) override;
public:
    explicit FullRWer(std::shared_ptr<IRWerCallback> cb);
    ~FullRWer() override;

    virtual size_t rlength(uint64_t id) override;
    virtual ssize_t cap(uint64_t id) override;
    virtual void ConsumeRData(uint64_t) override;
    virtual Destination getSrc() const override {
        Destination addr{};
        strcpy(addr.hostname, "<full>");
        return addr;
    }
    virtual void dump_status(Dumper dp, void* param) override {
        dp(param, "FullRWer <%d>\n", getFd());
    }
    virtual size_t mem_usage() override{
        return sizeof(*this);
    }
};

#endif
