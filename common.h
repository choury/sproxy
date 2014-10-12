#ifndef __CONF_H__
#define __CONF_H__

extern uint16_t SPORT;
#define CPORT 3333


extern char SHOST[];

#include <stdio.h>

#define Min(x,y) ((x)<(y)?(x):(y))
#define  LOG(...)  fprintf(stdout,__VA_ARGS__)
#define  LOGE(...)   fprintf(stderr,__VA_ARGS__)





#ifdef  __cplusplus
extern "C" {
#endif

char* strnstr(const char* s1, const char* s2, size_t len);

    
#ifdef  __cplusplus
}
#endif

#endif