#ifndef __SPDY_ZLIB_H__
#define __SPDY_ZLIB_H__

#include <zlib.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C"{
#endif


int spdy_deflate_init(z_stream *stream);
int spdy_inflate_init(z_stream *stream);
int spdy_deflate_end(z_stream *stream);
int spdy_inflate_end(z_stream *stream);
ssize_t spdy_deflate(z_stream *c_stream,const void *buffin,size_t inlen,void *buffout,size_t outlen);
ssize_t spdy_inflate(z_stream *d_stream,const void *buffin,size_t inlen,void *buffout,size_t outlen);

#ifdef __cplusplus
}
#endif


#endif