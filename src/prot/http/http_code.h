#ifndef HTTP_CODE_H__
#define HTTP_CODE_H__

#include <stdint.h>
#include <stddef.h>

#ifdef  __cplusplus
extern "C" {
#endif

size_t hfm_encode(const char *s, size_t len, unsigned char *result);
int hfm_decode(const unsigned char *s, size_t len, char* result);

size_t integer_encode(uint64_t value, int prefix, unsigned char *buff);
int integer_decode(const unsigned char *s, int prefix, uint64_t *value);

size_t literal_encode(const char* s, int prefix, unsigned char *result);
int literal_decode(const unsigned char *s, int prefix, char* result);

#ifdef  __cplusplus
}
#endif

#endif