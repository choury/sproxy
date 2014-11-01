#ifndef __CONF_H__
#define __CONF_H__

extern uint16_t SPORT;
#define CPORT 3333


extern char SHOST[];

#include <stdio.h>

#define Min(x,y) ((x)<(y)?(x):(y))

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

char* strnstr(const char* s1, const char* s2, size_t len);

    
#ifdef  __cplusplus
}
#endif

#endif