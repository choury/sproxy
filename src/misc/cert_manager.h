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

int load_ca(const char *ca_crt_path, const char *ca_key_path);
int generate_signed_key_pair(const char* domain, EVP_PKEY **key, X509 **crt);

#ifdef __cplusplus
}
#endif

#endif
