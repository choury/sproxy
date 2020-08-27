#ifndef NET__H__
#define NET__H__

#include <netdb.h>
#include <arpa/inet.h>
#include <stdbool.h>

#define HTTPSPORT 443u
#define HTTPPORT  80u
#define CRLF      "\r\n"


#define H200        "HTTP/1.1 200 OK" CRLF CRLF

#define H204        "HTTP/1.1 204 No Content" CRLF CRLF

#define H205        "HTTP/1.1 205 Reset Content" CRLF CRLF

#define H206        "HTTP/1.1 206 Partial Content" CRLF CRLF

#define H301        "HTTP/1.1 301 Moved Permanently" CRLF CRLF

#define H302        "HTTP/1.1 302 Found" CRLF CRLF

#define H303        "HTTP/1.1 303 See Other" CRLF CRLF

#define H304        "HTTP/1.1 304 Not Modified" CRLF CRLF

#define H400        "HTTP/1.1 400 Bad Request" CRLF CRLF

#define H401        "HTTP/1.1 401 Unauthorized" CRLF CRLF

#define H403        "HTTP/1.1 403 Forbidden" CRLF  CRLF

#define H404        "HTTP/1.1 404 Not Found" CRLF CRLF

#define H405        "HTTP/1.1 405 Method Not Allowed" CRLF CRLF

#define H407        "HTTP/1.1 407 Proxy Authentication Required" CRLF \
                    "Proxy-Authenticate: Basic realm=\"Secure Area\"" CRLF CRLF

#define H408        "HTTP/1.1 408 Request Timeout" CRLF CRLF

#define H416        "HTTP/1.1 416 Requested Range Not Satisfiable" CRLF CRLF

#define H429        "HTTP/1.1 429 Too Many Requests" CRLF CRLF

#define H500        "HTTP/1.1 500 Internal Server Error" CRLF CRLF

#define H502        "HTTP/1.1 502 Bad Gateway" CRLF CRLF

#define H503        "HTTP/1.1 503 Service Unavailable" CRLF CRLF

#define H504        "HTTP/1.1 504 Gateway Timeout" CRLF CRLF

#define H508        "HTTP/1.1 508 Loop Detected" CRLF CRLF

#ifdef  __cplusplus
extern "C" {
#endif
    
extern const char *DEFAULT_CIPHER_LIST;

union sockaddr_un;

int Checksocket(int fd, const char* msg);
void SetTcpOptions(int fd, const union sockaddr_un* addr);
int Listen(int type, short int port);
int Connect(const union sockaddr_un*, int type);
int Bind(int type, short port, const union sockaddr_un* addr);
int IcmpSocket(const union sockaddr_un* addr);
const char *getaddrstring(const union sockaddr_un *addr);
const char *getaddrportstring(const union sockaddr_un *addr);
int getsocketaddr(const char* ip, uint16_t port, union sockaddr_un *addr);
union sockaddr_un* getlocalip ();
bool hasIpv6Address();


#ifdef  __cplusplus
}
#endif

#endif
