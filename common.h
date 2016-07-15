#ifndef COMMON_H__
#define COMMON_H__

#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <syslog.h>
#include <arpa/inet.h>
#include <sys/epoll.h>

extern uint16_t SPORT;
extern char SHOST[];

extern char *auth_string;
extern int daemon_mode;

#define Min(x, y) ((int64_t)(x) < (int64_t)(y)?(x):(y))

#define DOMAINLIMIT   256
#define HEADLENLIMIT  8192
#define URLLIMIT      4096

#define BUF_LEN       16384


#ifdef __ANDROID__

#include <jni.h>
#include <android/log.h>
#define  LOG_TAG    "sproxy_client"   // 定义logcat中tag标签
#define  LOG(...)  __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define  LOGE(...)   __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#define  LOGOUT(...) LOGE(__VA_ARGS__)

#else
#define  LOGOUT(...) fprintf(stderr, __VA_ARGS__)
#define  LOG(...)    do{ \
                        if(daemon_mode) \
                            syslog(LOG_INFO, __VA_ARGS__); \
                        else \
                            fprintf(stdout, __VA_ARGS__); \
                     }while(0)
#define  LOGE(...)   do{\
                        char tmp[1024]; \
                        sprintf(tmp, __VA_ARGS__); \
                        if(daemon_mode) \
                            syslog(LOG_ERR, "%s[%d]: %s", __PRETTY_FUNCTION__, __LINE__, tmp);\
                        else \
                            fprintf(stderr, "%s[%d]: %s", __PRETTY_FUNCTION__, __LINE__, tmp);\
                     }while(0)
#endif


#ifdef  __cplusplus
extern "C" {
#endif

#ifndef __ANDROID__
#define HTONL(x) (x = htonl(x))
#define HTONS(x) (x = htons(x))


#define NTOHL(x) (x = ntohl(x))
#define NTOHS(x) (x = ntohs(x))
#else
#define SCNx64   "llx"
#define SCNu64   "llu"
#endif

#define get16(a)  (((uchar*)(a))[0]<<8 | ((uchar*)(a))[1])
#define set16(a, x) \
do {\
    ((uchar*)(a))[0] = ((x)>>8) & 0xff;\
    ((uchar*)(a))[1] = (x) & 0xff;\
}while(0);

#define get24(a) (((uchar*)(a))[0]<<16 | ((uchar*)(a))[1]<<8 | ((uchar*)(a))[2])
#define set24(a, x) \
do {\
    ((uchar*)(a))[0] = ((x)>>16) & 0xff;\
    ((uchar*)(a))[1] = ((x)>>8) & 0xff;\
    ((uchar*)(a))[2] = (x) & 0xff;\
}while(0);

#define get32(a) (((uchar*)(a))[0]<<24 | ((uchar*)(a))[1]<<16 | ((uchar*)(a))[2]<<8 | ((uchar*)(a))[3])
#define set32(a, x) \
do {\
    ((uchar*)(a))[0] = ((x)>>24) & 0xff;\
    ((uchar*)(a))[1] = ((x)>>16) & 0xff;\
    ((uchar*)(a))[2] = ((x)>>8) & 0xff;\
    ((uchar*)(a))[3] = (x) & 0xff;\
}while(0);

#define get64(a) \
    ((uint64_t)((uchar*)(a))[0]<<56 |\
     (uint64_t)((uchar*)(a))[1]<<48 |\
     (uint64_t)((uchar*)(a))[2]<<40 |\
     (uint64_t)((uchar*)(a))[3]<<32 |\
     (uint64_t)((uchar*)(a))[4]<<24 |\
     (uint64_t)((uchar*)(a))[5]<<16 |\
     (uint64_t)((uchar*)(a))[6]<<8 |\
     (uint64_t)((uchar*)(a))[7])

#define set64(a, x) \
do {\
    ((uchar*)(a))[0] = ((uint64_t)(x)>>56) & 0xff;\
    ((uchar*)(a))[1] = ((uint64_t)(x)>>48) & 0xff;\
    ((uchar*)(a))[2] = ((uint64_t)(x)>>40) & 0xff;\
    ((uchar*)(a))[3] = ((uint64_t)(x)>>32) & 0xff;\
    ((uchar*)(a))[4] = ((uint64_t)(x)>>24) & 0xff;\
    ((uchar*)(a))[5] = ((uint64_t)(x)>>16) & 0xff;\
    ((uchar*)(a))[6] = ((uint64_t)(x)>>8) & 0xff;\
    ((uchar*)(a))[7] = ((uint64_t)x) & 0xff;\
}while(0);

#define likely(x)   __builtin_expect(!!(x), 1)  
#define unlikely(x) __builtin_expect(!!(x), 0)

#define NOERROR             0
#define CONNECT_ERR         31
#define SSL_SHAKEHAND_ERR   32
#define HEAD_TOO_LONG_ERR   33
#define HTTP_PROTOCOL_ERR   34
#define READ_ERR            34
#define WRITE_ERR           36
#define INTERNAL_ERR        37
#define PEER_LOST_ERR       38
#define IP_BLOCK_ERR        39

typedef unsigned char uchar;
char* strnstr(const char* s1, const char* s2, size_t len);
int endwith(const char *s1, const char *s2);
int URLEncode(char *des,const char* src, size_t len);
int URLDecode(char *des,const char* src, size_t len);
void Base64Encode(const char *src, size_t len, char *dst);
void hosttick();
void dnstick();
void proxy2tick();
void flushproxy2();
uint64_t getutime();
void sighandle(int signum);
void dump_trace();
int showstatus(const char *command);

#ifdef  __cplusplus
}
#endif

#endif
