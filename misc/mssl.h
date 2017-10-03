#ifndef MSSL_H__
#define MSSL_H__

#include "vssl.h"
#include <unistd.h>


class Mssl: public Ssl{
    char bio_buff[BUF_LEN];
protected:
    BIO* in_bio = nullptr;
    BIO* out_bio = nullptr;
    const int fd;
public:
    Mssl(SSL* ssl, int fd):Ssl(ssl),fd(fd){
        in_bio = BIO_new(BIO_s_mem());
        BIO_set_mem_eof_return(in_bio, -1);
        out_bio = BIO_new(BIO_s_mem());
        BIO_set_mem_eof_return(out_bio, -1);
        SSL_set_bio(ssl, in_bio, out_bio);
        SSL_set_accept_state(ssl);
    }
    virtual ssize_t write(const void *buff, size_t size){
        int ret = SSL_write(ssl, buff, size);
        if(ret > 0 || BIO_ctrl_pending(out_bio) > 0){
            int len = BIO_read(out_bio, bio_buff, sizeof(bio_buff));
            len = ::write(fd, bio_buff, len);
            if(len < 0){
                return len;
            }else{
                return ret;
            }
        }else{
            return get_error(ret);
        }

    }
    virtual ssize_t read(void *buff, size_t size){
        int ret = ::read(fd, bio_buff, sizeof(bio_buff));
        if(ret > 0 ){
            BIO_write(in_bio, bio_buff, ret);
            return get_error(SSL_read(ssl, buff, size));
        }else if(BIO_ctrl_pending(in_bio) > 0){
            return get_error(SSL_read(ssl, buff, size));
        }else{
            return ret;
        }
    }
    virtual int accept(){
        int ret = ::read(fd, bio_buff, sizeof(bio_buff));
        if(ret > 0){
            BIO_write(in_bio, bio_buff, ret);
            ret = get_error(SSL_accept(ssl));
        }else{
            return ret;
        }
        if(BIO_ctrl_pending(out_bio) > 0){
            int ret = BIO_read(out_bio, bio_buff, sizeof(bio_buff));
            ::write(fd, bio_buff, ret);
        }
        return ret;
    }
    ~Mssl(){
    }
};

#endif
