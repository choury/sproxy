#ifndef NET__H__
#define NET__H__

#include <netdb.h>
#include <arpa/inet.h>

#define HTTPSPORT 443
#define HTTPPORT  80
#define CRLF      "\r\n"


#define H200        "HTTP/1.0 200 OK" CRLF CRLF

#define H204        "HTTP/1.0 204 No Content" CRLF CRLF

#define H205        "HTTP/1.0 205 Reset Content" CRLF \
                    "Content-Length:0" CRLF CRLF

#define H206        "HTTP/1.0 206 Partial Content" CRLF CRLF

#define H301        "HTTP/1.0 301 Moved Permanently" CRLF\
                    "Content-Length:0" CRLF CRLF

#define H302        "HTTP/1.0 302 Found" CRLF\
                    "Content-Length:0" CRLF CRLF

#define H303        "HTTP/1.0 303 See Other" CRLF\
                    "Content-Length:0" CRLF CRLF

#define H304        "HTTP/1.0 304 Not Modified" CRLF CRLF

#define H400        "HTTP/1.1 400 Bad Request" CRLF \
                    "Content-Length:0" CRLF CRLF

#define H401        "HTTP/1.1 401 Unauthorized" CRLF \
                    "Content-Length:0" CRLF CRLF

#define H403        "HTTP/1.1 403 Forbidden" CRLF \
                    "Content-Length: 0" CRLF CRLF

#define H404        "HTTP/1.1 404 Not Found" CRLF\
                    "Content-Length: 0" CRLF CRLF

#define H405        "HTTP/1.1 405 Method Not Allowed" CRLF\
                    "Content-Length:0" CRLF CRLF

#define H407        "HTTP/1.1 407 Proxy Authentication Required" CRLF \
                    "Proxy-Authenticate: Basic realm=\"Secure Area\"" CRLF \
                    "Content-Length: 0" CRLF CRLF

#define H408        "HTTP/1.1 408 Request Timeout" CRLF\
                    "Content-Length:0" CRLF CRLF

#define H416        "HTTP/1.1 416 Requested Range Not Satisfiable" CRLF\
                    "Content-Length: 0" CRLF CRLF

#define H500        "HTTP/1.1 500 Internal Server Error" CRLF\
                    "Content-Length: 0" CRLF CRLF

#define H503        "HTTP/1.1 503 Service Unavailable" CRLF\
                    "Content-Length: 0" CRLF CRLF

#define H504        "HTTP/1.1 504 Gateway Timeout" CRLF\
                    "Content-Length: 0" CRLF CRLF

#define H508        "HTTP/1.1 508 Loop Detected" CRLF\
                    "Content-Length: 0" CRLF CRLF

#ifdef  __cplusplus
extern "C" {
#endif
    
extern const char *DEFAULT_CIPHER_LIST;

union sockaddr_un;

int Checksocket(int fd, const char* msg);
void SetTcpOptions(int fd);
int Listen(int type, short int port);
int Connect(const union sockaddr_un*, int type);
int Bind(int type, short port, const union sockaddr_un* addr);
int IcmpSocket(const union sockaddr_un* addr);
const char *getaddrstring(const union sockaddr_un *addr);
const char *getaddrportstring(const union sockaddr_un *addr);
union sockaddr_un* getlocalip ();


#ifdef  __cplusplus
}
#endif

#endif
