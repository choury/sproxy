#ifndef SSL_IO_H_
#define SSL_IO_H_

#include "netio.h"
#include "memio.h"
#include "misc/net.h"
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>

class SslRWerBase {
protected:
    SslStats sslStats = SslStats::Idel;
    SSL *ssl = nullptr;
    BIO* in_bio = BIO_new(BIO_s_mem());
    BIO* out_bio = BIO_new(BIO_s_mem());
    std::string server;

    bool isConnected();
    bool isEof();
    int sink_in_bio(uint64_t id);
    void sink_out_bio(uint64_t id);
    void do_handshake();

    virtual void write(Buffer&& bb) = 0;
    virtual size_t bufsize() = 0;
    virtual void onRead(Buffer&& bb) = 0;
    virtual void onError(int type, int code) = 0;
    virtual void onConnected() = 0;
    virtual void handleData(const void* data, size_t len);
    virtual void sendData(Buffer&& bb);
public:
    explicit SslRWerBase(SSL_CTX* ctx);
    explicit SslRWerBase(const char* hostname);
    virtual ~SslRWerBase();

    void get_alpn(const unsigned char **s, unsigned int * len);
    int set_alpn(const unsigned char *s, unsigned int len);
    void set_hostname_callback(int (* cb)(SSL *, int *, void*), void* arg);
    void set_server_name(const std::string& arg);
    virtual void dump(Dumper dp, void* param);
    virtual size_t mem_usage() {
        BUF_MEM *in_mem, *out_mem;
        BIO_get_mem_ptr(in_bio, &in_mem);
        BIO_get_mem_ptr(out_bio, &out_mem);
        return sizeof(*this) + in_mem->max + out_mem->max;
    }
};

class SslRWer: public SslRWerBase, public StreamRWer{
protected:
    virtual size_t bufsize() override {
        return rb.cap();
    }
    virtual void write(Buffer&& bb) override;
    virtual void onRead(Buffer&& bb) override;
    virtual void onError(int type, int code) override;
    virtual void onConnected() override;

    virtual bool IsConnected() override {
        return isConnected();
    }
    virtual size_t rlength(uint64_t id) override {
        return SSL_pending(ssl) + BIO_ctrl_pending(in_bio) + StreamRWer::rlength(id);
    }
    virtual void waitconnectHE(RW_EVENT events) override;
    virtual void ConsumeRData(uint64_t id) override {
        while(sink_in_bio(id));
        StreamRWer::ConsumeRData(id);
    }
public:
    SslRWer(SSL_CTX* ctx, int fd, const sockaddr_storage* peer, std::shared_ptr<IRWerCallback> cb):
            SslRWerBase(ctx), StreamRWer(fd, peer, std::move(cb))
    {
        set_server_name(storage_ntoa(peer));
    }

    SslRWer(const char* hostname, uint16_t port, Protocol protocol, std::shared_ptr<IRWerCallback> cb);
    virtual void ReadData() override;
    virtual void Send(Buffer&& bb) override;

    virtual bool isTls() override {
        return true;
    }
    virtual bool isEof() override {
        return StreamRWer::isEof() || SslRWerBase::isEof();
    }
    virtual void dump_status(Dumper dp, void* param) override;
};

class SslMer: public SslRWerBase, public MemRWer {
protected:
    virtual size_t bufsize() override {
        return BUF_LEN * 2 - rlen;
    }
    virtual void write(Buffer&& bb) override;
    virtual void onRead(Buffer&& bb) override;
    virtual void onError(int type, int code) override;
    virtual void onConnected() override;

    virtual bool IsConnected() override {
        return isConnected();
    }
    virtual size_t rlength(uint64_t id) override {
        return SSL_pending(ssl) + BIO_ctrl_pending(in_bio) + MemRWer::rlength(id);
    }
    virtual void ConsumeRData(uint64_t id) override {
        while(sink_in_bio(id));
        MemRWer::ConsumeRData(id);
    }
public:
    SslMer(SSL_CTX* ctx, const Destination& src, std::shared_ptr<IMemRWerCallback> _cb):
      SslRWerBase(ctx), MemRWer(src, std::move(_cb))
    {
        set_server_name(src.hostname);
    }
    virtual void push_data(Buffer&& bb) override;
    void Send(Buffer&& bb) override;

    virtual bool isTls() override {
        return true;
    }

    virtual bool isEof() override {
        return MemRWer::isEof() || SslRWerBase::isEof();
    }
    virtual void dump_status(Dumper dp, void* param) override;
};


#endif
