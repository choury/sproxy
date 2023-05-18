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
    SSL *ssl = nullptr;
    SSL_CTX* ctx = nullptr;
    BIO* in_bio = BIO_new(BIO_s_mem());
    BIO* out_bio = BIO_new(BIO_s_mem());

    virtual int fill_in_bio(){
        return BIO_ctrl_pending(in_bio);
    };
    int sink_out_bio(uint64_t id);


    template <typename U>
    static auto test_addrs(U *u) -> decltype(u->addrs, std::true_type());

    template <typename U>
    static std::false_type test_addrs(...);

public:
    template <typename... Args>
    explicit SslRWerBase(SSL_CTX* ctx, Args&&... args): T(std::forward<Args>(args)...) {
        ssl = SSL_new(ctx);
        this->setEvents(RW_EVENT::READWRITE);
        this->stats = RWerStats::SslAccepting;
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
    SslRWer(const char* hostname, uint16_t port, Protocol protocol, std::function<void(int ret, int code)> errorCB):
            SslRWerBase<StreamRWer>(hostname, port, protocol, std::move(errorCB))
    {
        assert(this->protocol == Protocol::TCP);
        ctx = SSL_CTX_new(SSLv23_client_method());
        if (ctx == nullptr) {
            LOGF("SSL_CTX_new: %s\n", ERR_error_string(ERR_get_error(), nullptr));
        }
        SSL_CTX_set_keylog_callback(ctx, keylog_write_line);
#if __ANDROID__
        if (SSL_CTX_load_verify_locations(ctx, (getExternalFilesDir() + CABUNDLE).c_str(), "/etc/security/cacerts/") != 1)
#else
        if (SSL_CTX_load_verify_locations(ctx, CABUNDLE, "/etc/ssl/certs/") != 1)
#endif
            LOGE("SSL_CTX_load_verify_locations: %s\n", ERR_error_string(ERR_get_error(), nullptr));

        if (SSL_CTX_set_default_verify_paths(ctx) != 1)
            LOGE("SSL_CTX_set_default_verify_paths: %s\n", ERR_error_string(ERR_get_error(), nullptr));

        ssl = SSL_new(ctx);
        if(ssl == nullptr){
            LOGF("SSL_new: %s\n", ERR_error_string(ERR_get_error(), nullptr));
        }
        SSL_set_options(ssl, SSL_OP_NO_SSLv2|SSL_OP_NO_SSLv3);  // 去除支持SSLv2 SSLv3
        SSL_set_read_ahead(ssl, 1);
        SSL_set_connect_state(ssl);
        SSL_set_tlsext_host_name(ssl, this->hostname);

        BIO_set_mem_eof_return(in_bio, -1);
        BIO_set_mem_eof_return(out_bio, -1);
        SSL_set_bio(ssl, in_bio, out_bio);
    }
    virtual void waitconnectHE(RW_EVENT events) override;
};

template<>
class SslRWer<MemRWer>: public SslRWerBase<MemRWer> {
public:
    SslRWer(SSL_CTX* ctx, const char* pname, std::function<int(Buffer&&)> cb):
            SslRWerBase<MemRWer>(ctx, pname, cb)
    {}
    virtual void push(Buffer&& bb) override;
};


#endif
