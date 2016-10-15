#ifndef SSL_ABSTRACT_H_
#define SSL_ABSTRACT_H_

#include <openssl/ssl.h>
#include <assert.h>
#include <errno.h>
#include <openssl/x509v3.h>

class Ssl{
protected:
    SSL *ssl;
    int get_error(int ret){
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
                default:
                    errno = EIO;
                    break;
            }
        }
        return ret;
    }
public:
    Ssl(SSL *ssl):ssl(ssl){
        assert(ssl);
    }
    virtual ~Ssl(){
        SSL_shutdown(ssl);
        SSL_free(ssl);
    }
    virtual ssize_t write(const void *buff, size_t size){
        return get_error(SSL_write(ssl, buff, size));

    }
    virtual ssize_t read(void *buff, size_t size){
        return get_error(SSL_read(ssl, buff, size));
    }
    int accept(){
        return get_error(SSL_accept(ssl));
    }
    int connect(){
        return get_error(SSL_connect(ssl));
    }
    void get_alpn(const unsigned char **s, unsigned int * len){
        SSL_get0_alpn_selected(ssl, s, len);
    }
    int set_alpn(const unsigned char *s, unsigned int len){
        return SSL_set_alpn_protos(ssl, s, len);
    }
    void verify_hostname(const char *hostname, int (*callback) (int ok, X509_STORE_CTX *ctx)){
        X509_VERIFY_PARAM *param = SSL_get0_param(ssl);

        /* Enable automatic hostname checks */
        X509_VERIFY_PARAM_set_hostflags(param, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
        X509_VERIFY_PARAM_set1_host(param, hostname, 0);

        /* Configure a non-zero callback if desired */
        SSL_set_verify(ssl, SSL_VERIFY_PEER, callback);
    }
    virtual bool is_dtls(){
        return false;
    }
};


#endif
