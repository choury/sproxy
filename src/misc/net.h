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

int Checksocket(int fd, const char* msg);
void SetSocketUnblock(int fd);
void SetTcpOptions(int fd, const struct sockaddr_storage* addr);
void SetUdpOptions(int fd, const struct sockaddr_storage* addr);
void SetIcmpOptions(int fd, const struct sockaddr_storage* addr);
void SetUnixOptions(int fd, const struct sockaddr_storage* addr);

int ListenNet(int type, short int port);
int ListenUnix(const char* path);

int Connect(const struct sockaddr_storage*, int type);
int IcmpSocket(const struct sockaddr_storage* addr);
const char *getaddrstring(const struct sockaddr_storage* addr);
const char *storage_ntoa(const struct sockaddr_storage* addr);
int storage_aton(const char* ipstr, uint16_t port, struct sockaddr_storage* addr);
struct sockaddr_storage* getlocalip ();
bool hasIpv6Address();


#ifdef  __cplusplus
}
#endif

#endif
