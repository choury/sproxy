#ifndef __CONF_H__
#define __CONF_H__

#include <openssl/ssl.h>
#include <sys/epoll.h>

#include "net.h"

#define SPORT 443
#define CPORT 3333

#define SHOST "p.choury.com"


/* guest   ---   (client) --- host(proxy) 
 * guest_s ---   (server) --- host */


enum Status {accept_s,start_s, post_s , connect_s, close_s ,wait_s,proxy_s};

class Peer{
protected:
    int fd;
    int efd;
    enum Status status;
    char wbuff[1024 * 1024];
    int  write_len;
    bool fulled;
public:
    Peer();
    Peer(int fd,int efd);
    virtual void handleEvent(uint32_t events)=0;
    virtual void clean()=0;
    virtual int Read(char *buff,size_t size);
    virtual int Write(const char *buff,size_t size);
    virtual int Write();
    virtual size_t bufleft();
    virtual ~Peer();
};

class Guest;

class Host:public Peer{
    int port;
    char host[DOMAINLIMIT];
protected:
    Guest* guest;
public:
    Host(int efd,Guest *guest,int port,const char *host) throw(int);
    virtual void handleEvent(uint32_t events);
    virtual void clean();
    virtual void disconnect();
    virtual void bufcanwrite();
    static Host *gethost(Host *exist,const char *host,int port,int efd,Guest *guest)throw(int);
};

class Guest:public Peer{
protected:
    Host *host;
    char rbuff[4096];
    uint32_t  read_len;
    uint32_t expectlen;
public:
    Guest(int fd,int efd);
    virtual void handleEvent(uint32_t events);
    virtual void clean();
    virtual void cleanhost();
    virtual void connected();
    virtual bool candelete();
};


class Guest_s:public Guest {
    SSL *ssl;
public:
    Guest_s(int fd,int efd,SSL *ssl);
    virtual ~Guest_s();
    virtual void handleEvent(uint32_t events);
    virtual int Read(char *buff,size_t size);
    virtual int Write();
    virtual void connected();
};

class Proxy : public Host{
    SSL *ssl;
    SSL_CTX *ctx;
public:
    Proxy(int efd,Guest *guest) throw(int);
    virtual ~Proxy();
    virtual void handleEvent(uint32_t events);
    virtual int Read(char *buff,size_t size);
    virtual int Write();
    virtual void connected();
    static Host *getproxy(Host *exist,int efd,Guest *guest)throw(int);
};



#ifdef  __cplusplus
extern "C" {
#endif

char* strnstr(const char* s1, const char* s2, size_t len);

    
#ifdef  __cplusplus
}
#endif

#endif