#ifndef RWER_H__
#define RWER_H__

#include "prot/ep.h"
#include "misc/job.h"
#include "misc/buffer.h"

#include <sys/socket.h>

#include <memory>
#include <list>
#include <functional>



using std::placeholders::_1;
using std::placeholders::_2;
using std::placeholders::_3;
using std::placeholders::_4;
using std::placeholders::_5;
using std::placeholders::_6;
using std::placeholders::_7;
using std::placeholders::_8;
using std::placeholders::_9;
using std::placeholders::_10;

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
    SslEOF,
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
    WBuffer    wbuff;
    //返回值是剩余未处理的数据长度，返回0表示数据处理完毕，返回len表示数据完全没有被消费
    std::function<size_t(const Buffer& bb)> readCB;
    std::function<void(uint64_t id)> writeCB;
    std::function<void(int ret, int code)> errorCB;
    std::function<void()> closeCB;

    virtual ssize_t Write(const Buffer& bb);
    virtual void SendData();
    virtual void ReadData() = 0;
    virtual void defaultHE(RW_EVENT events);
    virtual void closeHE(RW_EVENT events);
    virtual void IdleHE(RW_EVENT events);
    virtual void ErrorHE(int ret, int code);
    //ConsumeRData只会在Unblock中被调用，ReadData逻辑，需要各实现自行处理readCB回调
    virtual void ConsumeRData(uint64_t id) = 0;
    virtual bool IsEOF();
public:
    //如果一个函数的参数是Buffer&& 那么调用者需要保证该buffer中使用的内存是一直有效的，并由被调用者负责释放
    //如果参数是const Buffer& 那么该内存只在本次调用中有效，如果需要后续使用，需要在函数内自行拷贝
    explicit RWer(int fd, std::function<void(int ret, int code)> errorCB);
    explicit RWer(std::function<void(int ret, int code)> errorCB);
    virtual void SetErrorCB(std::function<void(int ret, int code)> func);
    virtual void SetReadCB(std::function<size_t(const Buffer& bb)> func);
    virtual void SetWriteCB(std::function<void(uint64_t id)> func);

    virtual void Close(std::function<void()> func);
    virtual void Unblock(uint64_t id);
    RWerStats getStats(){return stats;}
    virtual const char* getPeer() {return "raw-rwer";}

    //for read buffer
    virtual size_t rlength(uint64_t id) = 0;

    //for write buffer
    virtual ssize_t cap(uint64_t id);
    virtual void buffer_insert(Buffer&& bb);

    virtual bool idle(uint64_t id);
    virtual void dump_status(Dumper dp, void* param) = 0;
    virtual size_t mem_usage() = 0;
};

class NullRWer: public RWer{
public:
    explicit NullRWer();
    virtual ssize_t Write(const Buffer& bb) override;
    virtual void ReadData() override;
    virtual size_t rlength(uint64_t id) override;

    virtual void ConsumeRData(uint64_t) override;
    virtual const char* getPeer() override {return "null-rwer";}
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
    virtual ssize_t Write(const Buffer& bb) override;
    virtual void ReadData() override;
    virtual void closeHE(RW_EVENT events) override;
public:
    explicit FullRWer(std::function<void(int ret, int code)> errorCB);
    ~FullRWer() override;

    virtual size_t rlength(uint64_t id) override;
    virtual ssize_t cap(uint64_t id) override;
    virtual void ConsumeRData(uint64_t) override;
    virtual const char* getPeer() override {return "full-rwer";}
    virtual void dump_status(Dumper dp, void* param) override {
        dp(param, "FullRWer <%d>\n", getFd());
    }
    virtual size_t mem_usage() override{
        return sizeof(*this);
    }
};

#endif
