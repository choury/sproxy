#ifndef __NET__H__
#define __NET__H__

#include <netdb.h>

#define HTTPSPORT 443
#define HTTPPORT  80
#define CRLF      "\r\n"


#define  connecttip   "HTTP/1.0 200 Connection established" CRLF CRLF



#ifdef  __cplusplus
extern "C" {
#endif

union sockaddr_un{
    struct sockaddr addr;
    struct sockaddr_in addr_in;
    struct sockaddr_in6 addr_in6;
};

int spliturl(const char* url, char* host, char* path , uint16_t* port);
//int ConnectTo(const char* host, int port);

int Connect(struct sockaddr*);
    
#ifdef  __cplusplus
}
#endif



#endif