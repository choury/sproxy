#ifndef SSL_ABSTRACT_H_
#define SSL_ABSTRACT_H_

#include <openssl/ssl.h>
#include <assert.h>
#include <errno.h>

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
        int ret = SSL_write(ssl, buff, size);
        if(ret < 0){
            int error = SSL_get_error(ssl, ret);
            switch (error) {
                case SSL_ERROR_WANT_READ:
                case SSL_ERROR_WANT_WRITE:
                    errno = EAGAIN;
                    break;
                case SSL_ERROR_ZERO_RETURN:
                    ret = 0;
                    errno = 0;
                case SSL_ERROR_SYSCALL:
                    break;
            }
        }
        return ret;
    }
    virtual ssize_t read(void *buff, size_t size){
        int ret = SSL_read(ssl, buff, size);
        if(ret < 0){
            int error = SSL_get_error(ssl, ret);
            switch (error) {
                case SSL_ERROR_WANT_READ:
                case SSL_ERROR_WANT_WRITE:
                    errno = EAGAIN;
                    break;
                case SSL_ERROR_ZERO_RETURN:
                    ret = 0;
                    errno = 0;
                case SSL_ERROR_SYSCALL:
                    break;
            }
        }
        return ret;
    }
    virtual SSL *GetSSL(){
        return ssl;
    }
};

#endif
