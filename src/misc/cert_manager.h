#ifndef CERT_MANAGER_H__
#define CERT_MANAGER_H__

#include <openssl/err.h>
#include <openssl/conf.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/x509v3.h>

#ifdef  __cplusplus
extern "C" {
#endif

struct cert_pair;
int load_cert_key(const char *ca_crt_path, const char *ca_key_path, struct cert_pair* cert);
int generate_signed_key_pair(const char* domain, EVP_PKEY **key, X509 **crt);
void release_key_pair();

#ifdef __cplusplus
}
#endif

#endif
