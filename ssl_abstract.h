#ifndef SSL_ABSTRACT_H_
#define SSL_ABSTRACT_H_

#include <openssl/ssl.h>
#include <assert.h>

class Ssl{
protected:
    SSL *ssl;
public:
    Ssl(SSL *ssl):ssl(ssl){
        assert(ssl);
    }
    virtual ~Ssl(){
        SSL_shutdown(ssl);
        SSL_free(ssl);
    }
    virtual ssize_t write(const void *buff, size_t size){
        return SSL_write(ssl, buff, size);
    }
    virtual ssize_t read(void *buff, size_t size){
        return SSL_read(ssl, buff, size);
    }
};

#endif
