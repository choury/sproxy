#ifndef __COMMON_H__
#define __COMMON_H__

#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <syslog.h>
#include <arpa/inet.h>
#include <sys/epoll.h>

extern uint16_t SPORT;
#define CPORT 3333


extern char SHOST[];

#define Min(x, y) ((uint64_t)(x) < (uint64_t)(y)?(x):(y))

#define DOMAINLIMIT   256
#define HEADLENLIMIT  8192
#define URLLIMIT      4096

#ifdef _ANDROID_

#include <jni.h>
#include <android/log.h>
#define  LOG_TAG    "sproxy_client"   // 定义logcat中tag标签
#define  LOG(...)  __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define  LOGE(...)   __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#define  LOGOUT(...) LOGE(__VA_ARGS__)

#else
#define  LOG(...)  syslog(LOG_INFO, __VA_ARGS__)
#define  LOGE(...)   syslog(LOG_ERR, __VA_ARGS__)
#define  LOGOUT(...) fprintf(stderr, __VA_ARGS__)
#endif

#ifdef  __cplusplus
extern "C" {
#endif

#define HTONL(x) (x = htonl(x))
#define HTONS(x) (x = htons(x))


#define NTOHL(x) (x = ntohl(x))
#define NTOHS(x) (x = ntohs(x))

typedef unsigned char uchar;
char* strnstr(const char* s1, const char* s2, size_t len);
void dump_trace();

#ifdef  __cplusplus
}
#endif

#endif
