#ifndef UTIL_H__
#define UTIL_H__

#include "common/common.h"

#include <stddef.h>
#include <string.h>
#include <sys/types.h>
#include <sys/time.h>

#define NAT64PREFIX "\0\x64\xff\x9b\0\0\0\0\0\0\0\0"
#define IPV4MAPIPV6 "\0\0\0\0\0\0\0\0\0\0\xff\xff"


#ifdef  __cplusplus
extern "C" {
#endif

#ifndef __APPLE__
const char* strnstr(const char* s1, const char* s2, size_t len);
#endif
#if ! defined(_GNU_SOURCE) || defined(__APPLE__) || defined(__ANDROID__)
char* strchrnul(const char *s, int c);
#endif
int startwith(const char *s1, const char *s2);
int endwith(const char *s1, const char *s2);

int URLEncode(char *des,const char* src, size_t len);
int URLDecode(char *des,const char* src, size_t len);
void Base64Encode(const char* s, size_t len, char* dst);

uint64_t getutime();
uint32_t getmtime();

void dump_stat();
void dump_trace(int ignore);

PRE_POINTER void* memdup(const void* ptr, size_t size);

PRE_POINTER void* p_malloc(size_t size);
PRE_POINTER void* p_memdup(const void *ptr, size_t size);

inline PRE_POINTER void* p_strdup(const char* str){
    return p_memdup(str, strlen(str)+1);
}

void p_free(PRE_POINTER void* ptr);
PRE_POINTER void* p_move(PRE_POINTER void* ptr, signed char len);
char* avsprintf(size_t* size, const char* fmt, va_list ap);
const char* findprogram(ino_t inode);
struct in6_addr mapIpv4(struct in_addr addr, const char* prefix);
struct in_addr getMapped(struct in6_addr addr, const char* prefix);

const char* protstr(Protocol p);

int spliturl(const char* url, struct Destination* server, char* path);
int dumpDestToBuffer(const struct Destination* server, char* buff, size_t buflen);
const char* dumpDest(const struct Destination* server);
void change_process_name(const char *name);
#ifdef  __cplusplus
}
#endif

#endif
