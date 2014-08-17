#ifndef __CONF_H__
#define __CONF_H__

#include <openssl/ssl.h>
#include <sys/epoll.h>
#include <netinet/in.h>

#include "net.h"

#define SPORT 443
#define CPORT 3333

#define THREADS 3




/* guest   ---   (client) --- host(proxy) 
 * guest_s ---   (server) --- host */


enum Status {accept_s,start_s, post_s , connect_s, close_s ,wait_s,proxy_s};

class Peer{
protected:
    int  fd;
    int  efd;
    enum Status status=start_s;
    char wbuff[1024 * 1024];
    int  write_len=0;
    bool fulled=false;
public:
    Peer();  //do nothing
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
    char hostname[DOMAINLIMIT];
    int targetport;
protected:
    Guest* guest;
public:
    Host(int efd,Guest *guest,const char *hostname,int port);
    virtual void handleEvent(uint32_t events);
    virtual void clean();
    virtual void disattach();
    virtual void bufcanwrite();
    static Host *gethost(Host *exist,const char *host,int port,int efd,Guest *guest);
    
    friend void connectHost(Host * host);
};

class Guest:public Peer{
protected:
    char sourceip[INET6_ADDRSTRLEN];
    int  sourceport;
    char destip[INET6_ADDRSTRLEN];
    int  destport;
    
    Host *host=NULL;
    char rbuff[4096];
    uint32_t  read_len=0;
    uint32_t expectlen=0;
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
    SSL *ssl=NULL;
    SSL_CTX *ctx=NULL;
public:
    Proxy(int efd,Guest *guest);
    virtual ~Proxy();
    virtual void handleEvent(uint32_t events);
    virtual int Read(char *buff,size_t size);
    virtual int Write();
    virtual void connected();
    static Host *getproxy(Host *exist,int efd,Guest *guest);
};



#ifdef  __cplusplus
extern "C" {
#endif

char* strnstr(const char* s1, const char* s2, size_t len);

    
#ifdef  __cplusplus
}
#endif

#endif