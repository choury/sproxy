#ifndef RWER_H__
#define RWER_H__

#include "prot/ep.h"
#include "misc/job.h"
#include "misc/util.h"

#include <sys/socket.h>

#include <memory>
#include <list>
#include <functional>


#ifndef insert_iterator
#ifdef HAVE_CONST_ITERATOR_BUG
#define insert_iterator iterator
#else
#define insert_iterator const_iterator
#endif
#endif

class buff_block{
    bool delegate = false;
public:
    const PREPTR void* const buff = nullptr;
    size_t len = 0;
    size_t offset = 0;
    uint64_t id = 0;
    buff_block(const buff_block&) = delete;
    explicit buff_block(void* const buff, size_t len, size_t offset = 0, uint64_t id = 0):
        delegate(true), buff(buff), len(len), offset(offset), id(id)
    {
    }
    explicit buff_block(const void* const buff, size_t len, size_t offset = 0, uint64_t id = 0):
            buff(buff), len(len), offset(offset), id(id)
    {
    }
    buff_block(buff_block&& wb) noexcept :
        delegate(wb.delegate), buff(wb.buff), len(wb.len), offset(wb.offset), id(wb.id){
        wb.delegate = false;
        wb.len = 0;
        wb.offset = 0;
        wb.id = 0;
    }
    ~buff_block(){
        if(delegate && buff){
            p_free((PREPTR void*)buff);
        }
    }
};

using buff_iterator = std::list<buff_block>::insert_iterator;
class WBuffer {
    std::list<buff_block> write_queue;
    size_t  len = 0;
public:
    ~WBuffer();
    size_t length();
    buff_iterator start();
    buff_iterator end();
    buff_iterator push(buff_iterator i, buff_block&& bb);
    ssize_t  Write(std::function<ssize_t(const void*, size_t, uint64_t)> write_func);
};


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
    SslAccepting,
    SslConnecting,
    Connected,
    ReadEOF,
    Error,
};

class RWer: public Ep, public job_handler, public std::enable_shared_from_this<RWer> {
protected:
#define RWER_READING  1u  // handling the read buffer
#define RWER_SENDING  2u  // handling the write buffer
#define RWER_CLOSING  4u
#define RWER_SHUTDOWN 8u
    uint32_t   flags = 0;
    RWerStats  stats = RWerStats::Idle;
    WBuffer    wbuff;
    //std::function<void(size_t len, uint64_t id)> readCB;
    std::function<void(buff_block&)> readCB;
    std::function<void(size_t len)> writeCB;
    std::function<void(const sockaddr_storage&)> connectCB;
    std::function<void(int ret, int code)> errorCB;
    std::function<void()> closeCB;

    virtual ssize_t Write(const void* buff, size_t len, uint64_t id) = 0;
    virtual void SendData();
    virtual void ReadData() = 0;
    virtual void defaultHE(RW_EVENT events);
    virtual void closeHE(RW_EVENT events);
    virtual void Connected(const sockaddr_storage&);
    virtual void ErrorHE(int ret, int code);
    virtual void ConsumeRData() = 0;
public:
    explicit RWer(int fd, std::function<void(int ret, int code)> errorCB);
    explicit RWer(std::function<void(int ret, int code)> errorCB,
                  std::function<void(const sockaddr_storage&)> connectCB);
    virtual void SetErrorCB(std::function<void(int ret, int code)> func);
    virtual void SetReadCB(std::function<void(buff_block&)> func);
    virtual void SetWriteCB(std::function<void(size_t len)> func);

    virtual bool supportReconnect();
    virtual void Reconnect();
    virtual void Close(std::function<void()> func);
    void EatReadData();
    virtual void Shutdown();
    RWerStats getStats(){return stats;}
    virtual const char* getPeer() {return "raw-rwer";}

    //for read buffer
    virtual size_t rlength() = 0;

    //for write buffer
    virtual size_t wlength();
    virtual ssize_t cap(uint64_t id);
    virtual buff_iterator buffer_head();
    virtual buff_iterator buffer_end();
    virtual buff_iterator buffer_insert(buff_iterator where, buff_block&& bb);
};

class NullRWer: public RWer{
public:
    explicit NullRWer();
    virtual ssize_t Write(const void *buff, size_t len, uint64_t) override;
    virtual void ReadData() override;
    virtual size_t rlength() override;
    virtual size_t wlength() override;

    virtual void ConsumeRData() override;
    virtual const char* getPeer() override {return "null-rwer";}
};

class FullRWer: public RWer{
protected:
#ifndef __linux__
    int pairfd = -1;
#endif
    virtual ssize_t Write(const void* buff, size_t len, uint64_t) override;
    virtual void ReadData() override;
    virtual void closeHE(RW_EVENT events) override;
public:
    explicit FullRWer(std::function<void(int ret, int code)> errorCB);
    ~FullRWer() override;

    virtual size_t rlength() override;
    virtual ssize_t cap(uint64_t id) override;
    virtual void ConsumeRData() override;
    virtual const char* getPeer() override {return "full-rwer";}
};

#endif
