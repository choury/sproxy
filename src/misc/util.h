#ifndef UTIL_H__
#define UTIL_H__

#include "common.h"

#include <stddef.h>
#include <string.h>
#include <sys/types.h>
#include <sys/time.h>

#ifdef  __cplusplus
extern "C" {
#endif

#ifndef __APPLE__
const char* strnstr(const char* s1, const char* s2, size_t len);
#endif
int startwith(const char *s1, const char *s2);
int endwith(const char *s1, const char *s2);
int spliturl(const char* url, char *protocol, char* host, char* path , uint16_t* port);

int URLEncode(char *des,const char* src, size_t len);
int URLDecode(char *des,const char* src, size_t len);
void Base64Encode(const char* s, size_t len, char* dst);

uint64_t getutime();
uint32_t getmtime();

void dump_stat();
void dump_trace(int ignore);

void* memdup(const void* ptr, size_t size);

void* p_malloc(size_t size);
void* p_memdup(const void *ptr, size_t size);

inline void* p_strdup(const char* str){
    return p_memdup(str, strlen(str)+1);
}

void p_free(void* ptr);
void* p_move(void* ptr, signed char len);
char* p_avsprintf(size_t* size, const char* fmt, va_list ap);
const char* findprogram(ino_t inode);
const char* getDeviceInfo();
struct in6_addr mapIpv4(struct in_addr addr);
struct in_addr getMapped(struct in6_addr addr);

const char* protstr(Protocol p);
#ifdef  __cplusplus
}
#endif

#endif
