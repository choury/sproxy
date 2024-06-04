#ifndef NET__H__
#define NET__H__

#include <netdb.h>
#include <arpa/inet.h>
#include <stdbool.h>

#ifdef  __cplusplus
extern "C" {
#endif

int Checksocket(int fd, const char* msg);
void SetSocketUnblock(int fd);
void SetTcpOptions(int fd, const struct sockaddr_storage* addr);
void SetUdpOptions(int fd, const struct sockaddr_storage* addr);
void SetIcmpOptions(int fd, const struct sockaddr_storage* addr);
void SetUnixOptions(int fd, const struct sockaddr_storage* addr);
void SetRecvPKInfo(int fd, const struct sockaddr_storage* addr);
size_t GetCapSize(int fd);
size_t GetBuffSize(int fd);

int ListenTcp(const char* ipstr, short int port);
int ListenUdp(const struct sockaddr_storage* addr);
int ListenUnix(const char* path);

int Connect(const struct sockaddr_storage*, int type);
int IcmpSocket(const struct sockaddr_storage* addr, int raw);
const char *getaddrstring(const struct sockaddr_storage* addr);
const char *storage_ntoa(const struct sockaddr_storage* addr);
int storage_aton(const char* ipstr, uint16_t port, struct sockaddr_storage* addr);
struct sockaddr_storage* getlocalip ();
bool hasIpv6Address();
bool isLocalIp(const struct sockaddr_storage* addr);


#ifdef  __cplusplus
}
#endif

#endif
