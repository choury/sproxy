#ifndef QUIC_TLS_H__
#define QUIC_TLS_H__

#include <stdint.h>


int variable_encode(uint64_t value, unsigned char* data);
int variable_decode(unsigned char* data, uint64_t* value);

int HKDF_Extract(const char* cid, size_t clen, char* prk);
int HKDF_Expand_Label(const char* prk, const char* info, const char *msg, char* okm, size_t len);


int gcm_encrypt(unsigned char *plaintext, int plaintext_len,
                unsigned char *aad, int aad_len,
                unsigned char *key,
                unsigned char *iv, int iv_len,
                unsigned char *ciphertext);

int aes_encode(const unsigned char* key,
               const unsigned char* data, int data_len,
               unsigned char* out);

#endif
