#ifndef __CONF_H__
#define __CONF_H__

#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <arpa/inet.h>


extern uint16_t SPORT;
#define CPORT 3333


extern char SHOST[];

#define Min(x,y) ((x)<(y)?(x):(y))

#define HEALLENLIMIT   8192

#ifdef _ANDROID_

#include <jni.h>
#include <android/log.h>
#define  LOG_TAG    "sproxy_client"   //定义logcat中tag标签
#define  LOG(...)  __android_log_print(ANDROID_LOG_INFO,LOG_TAG,__VA_ARGS__)
#define  LOGE(...)   __android_log_print(ANDROID_LOG_ERROR,LOG_TAG,__VA_ARGS__)
#else

#define  LOG(...)  fprintf(stdout,__VA_ARGS__)
#define  LOGE(...)   fprintf(stderr,__VA_ARGS__)
#endif


#ifdef  __cplusplus
extern "C" {
#endif

#define HTONL(x) (x=htonl(x))
#define HTONS(x) (x=htons(x))


#define NTOHL(x) (x=ntohl(x))
#define NTOHS(x) (x=ntohs(x))

char* strnstr(const char* s1, const char* s2, size_t len);

    
#ifdef  __cplusplus
}
#endif

#endif