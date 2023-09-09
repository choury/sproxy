#ifndef SSL_IO_H_
#define SSL_IO_H_

#include "netio.h"
#include "memio.h"
#include "tls.h"
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>
#include <type_traits>

template<class T>
class SslRWerBase: public T {
protected:
    SslStats sslStats = SslStats::Idel;
    SSL *ssl = nullptr;
    SSL_CTX* ctx = nullptr;
    BIO* in_bio = BIO_new(BIO_s_mem());
    BIO* out_bio = BIO_new(BIO_s_mem());
    std::string server;

    virtual int fill_in_bio(){
        return BIO_ctrl_pending(in_bio);
    };
    int sink_out_bio(uint64_t id);


    template <typename U>
    static auto test_addrs(U *u) -> decltype(u->addrs, std::true_type());

    template <typename U>
    static std::false_type test_addrs(...);

    virtual bool IsConnected() override;
    virtual bool IsEOF() override;
public:
    template <typename... Args>
    explicit SslRWerBase(SSL_CTX* ctx, Args&&... args): T(std::forward<Args>(args)...) {
        ssl = SSL_new(ctx);
        this->setEvents(RW_EVENT::READWRITE);
        this->sslStats = SslStats::SslAccepting;
        this->handleEvent = (void (Ep::*)(RW_EVENT))&SslRWerBase::shakehandHE;
        SSL_set_accept_state(ssl);

        BIO_set_mem_eof_return(in_bio, -1);
        BIO_set_mem_eof_return(out_bio, -1);
        SSL_set_bio(ssl, in_bio, out_bio);
    }
    template <typename... Args>
    explicit SslRWerBase(Args&&... args): T(std::forward<Args>(args)...) {}
    virtual ~SslRWerBase() override;

    virtual void ReadData() override;
    virtual void buffer_insert(Buffer&& bb) override;

    static const bool has_addrs = std::is_same<decltype(test_addrs<T>(0)), std::true_type>::value;
    template<typename U = T>
    typename std::enable_if<SslRWerBase<U>::has_addrs, void>::type call_connected() {
        T::connected(this->addrs.front());
    }

    template<typename U = T>
    typename std::enable_if<!SslRWerBase<U>::has_addrs, void>::type call_connected() {
        T::connected({});
    }

    virtual int do_handshake();
    virtual void shakehandHE(RW_EVENT events);
    void get_alpn(const unsigned char **s, unsigned int * len);
    int set_alpn(const unsigned char *s, unsigned int len);
    void set_hostname_callback(int (* cb)(SSL *, int *, void*), void* arg);
    void set_server_name(const std::string& arg);
    virtual void dump_status(Dumper dp, void* param) override;
    virtual size_t mem_usage() override {
        BUF_MEM *in_mem, *out_mem;
        BIO_get_mem_ptr(in_bio, &in_mem);
        BIO_get_mem_ptr(out_bio, &out_mem);
        return sizeof(*this) + (this->rb.cap() + this->rb.length()) + this->wbuff.length() + in_mem->max + out_mem->max;
    }
};

template<class T>
class SslRWer: public SslRWerBase<T> {
};

template<>
class SslRWer<StreamRWer>: public SslRWerBase<StreamRWer>{
    virtual int fill_in_bio() override;
public:
    SslRWer(SSL_CTX* ctx, int fd, const sockaddr_storage* peer, std::function<void(int ret, int code)> errorCB):
            SslRWerBase<StreamRWer>(ctx, fd, peer, std::move(errorCB))
    {}
    SslRWer(const char* hostname, uint16_t port, Protocol protocol, std::function<void(int ret, int code)> errorCB);
    virtual void waitconnectHE(RW_EVENT events) override;
};

template<>
class SslRWer<MemRWer>: public SslRWerBase<MemRWer> {
    virtual int fill_in_bio() override;
public:
    SslRWer(SSL_CTX* ctx, const char* pname, std::function<int(Buffer&&)> read_cb, std::function<ssize_t()> cap_cb):
            SslRWerBase<MemRWer>(ctx, pname, read_cb, cap_cb)
    {}
    virtual void push(const Buffer& bb) override;
};


#endif
