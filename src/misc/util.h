#ifndef UTIL_H__
#define UTIL_H__

#include "common/common.h"

#include <stddef.h>
#include <string.h>
#include <sys/types.h>

#define NAT64PREFIX "\0\x64\xff\x9b\0\0\0\0\0\0\0\0"
#define IPV4MAPIPV6 "\0\0\0\0\0\0\0\0\0\0\xff\xff"


#ifdef  __cplusplus
extern "C" {
#endif

#ifndef __APPLE__
const char* strnstr(const char* s1, const char* s2, size_t len);
#endif
#if ! defined(_GNU_SOURCE) || defined(__APPLE__)
char* strchrnul(const char *s, int c);
#endif
char* strlchrnul (const char* s, int c);


int URLEncode(char *des,const char* src, size_t len);
int URLDecode(char *des,const char* src, size_t len);
void Base64Encode(const char* s, size_t len, char* dst);

void dump_trace(int ignore);

void* memdup(const void* ptr, size_t size);
char* avsprintf(size_t* size, const char* fmt, va_list ap);
const char* findprogram(ino_t inode);
struct in6_addr mapIpv4(struct in_addr addr, const char* prefix);
struct in_addr getMapped(struct in6_addr addr, const char* prefix);

const char* protstr(Protocol p);

int spliturl(const char* url, struct Destination* server, char* path);
int dumpDestToBuffer(const struct Destination* server, char* buff, size_t buflen);
const char* dumpDest(const struct Destination* server);
const char* dumpAuthority(const struct Destination* Server);
void storage2Dest(const struct sockaddr_storage* addr, socklen_t len, struct Destination* dest);
void change_process_name(const char *name);
#ifdef  __cplusplus
}
#endif

#endif
