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
int load_ca_cert(const char *crt_path, const char *key_path);
int load_cert_key(const char *crt_path, const char *key_path);
int load_certs_dir(const char *dir_path);
const struct cert_pair* lookup_cert(const char *domain);
const struct cert_pair* generate_cert(const char *domain);
int has_ca_cert(void);
EVP_PKEY* get_default_key(void);
void release_key_pair();

#ifdef __cplusplus
}
#endif

#endif
