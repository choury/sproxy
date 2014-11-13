#ifndef __SPDY_ZLIB_H__
#define __SPDY_ZLIB_H__


#ifdef __cplusplus
extern "C"{
#endif


ssize_t spdy_deflate(void *buffin,size_t inlen,void *buffout,size_t outlen);
ssize_t spdy_inflate(void *buffin,size_t inlen,void *buffout,size_t outlen);

#ifdef __cplusplus
}
#endif


#endif