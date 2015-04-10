#ifndef NET__H__
#define NET__H__

#include <netdb.h>

#define HTTPSPORT 443
#define HTTPPORT  80
#define CRLF      "\r\n"


#define  connecttip   "HTTP/1.0 200 Connection established" CRLF CRLF

#define H200    "HTTP/1.1 200 OK" CRLF CRLF

#define H206    "HTTP/1.1 206 Partial Content" CRLF CRLF

#define H416    "HTTP/1.1 416 Requested Range Not Satisfiable" CRLF\
                "Content-Length: 0" CRLF CRLF

#define H403    "HTTP/1.1 403 Forbidden" CRLF \
                "Content-Length: 0" CRLF CRLF

#define H404    "HTTP/1.1 404 Not Found" CRLF\
                "Content-Length: 0" CRLF CRLF

#define H500    "HTTP/1.1 500 Internal Server Error" CRLF\
                "Content-Length: 0" CRLF CRLF

#define CHUNCKEND "0" CRLF CRLF
#ifdef  __cplusplus
extern "C" {
#endif

union sockaddr_un{
    struct sockaddr addr;
    struct sockaddr_in addr_in;
    struct sockaddr_in6 addr_in6;
};

int spliturl(const char* url, char* host, char* path , uint16_t* port);

int Connect(struct sockaddr*);

#ifdef  __cplusplus
}
#endif

#endif
