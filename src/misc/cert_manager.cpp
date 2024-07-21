#include "cert_manager.h"
#include "common/common.h"
#include "misc/config.h"
#include "defer.h"
#include "net.h"

#include <string>
#include <map>
#include <assert.h>


static std::map<std::string, cert_pair> certs;

int load_cert_key(const char *crt_path, const char *key_path, struct cert_pair* cert) {
    BIO* cbio = BIO_new(BIO_s_file());
    defer(BIO_free_all, cbio);
    if (!BIO_read_filename(cbio, crt_path)) return -1;
    X509* crt = PEM_read_bio_X509(cbio, nullptr, nullptr, nullptr);
    if(crt == nullptr) {
        LOGE("Error reading cert file: %s\n", ERR_error_string(ERR_get_error(), nullptr));
        return -1;
    }

    /* Load CA private key. */
    BIO* kbio = BIO_new(BIO_s_file());
    defer(BIO_free_all, kbio);
    if (!BIO_read_filename(kbio, key_path)) return -1;
    EVP_PKEY* key = PEM_read_bio_PrivateKey(kbio, nullptr, nullptr, nullptr);
    if(key == nullptr){
        LOGE("Error reading private key: %s\n", ERR_error_string(ERR_get_error(), nullptr));
        X509_free(crt);
        return -1;
    }
    LOG("loaded cert from %s and %s\n", crt_path, key_path);
    if(cert->crt) {
        X509_free(cert->crt);
    }
    if(cert->key) {
        EVP_PKEY_free(cert->key);
    }
    cert->crt = crt;
    cert->key = key;
    return 0;
}

static EVP_PKEY* generate_key() {
    BIGNUM *e = BN_new();
    if(e == nullptr) {
        return nullptr;
    }
    defer(BN_free, e);
    BN_set_word(e, RSA_F4);

    RSA* rsa = RSA_new();
    if (rsa == nullptr) {
        return nullptr;
    }
    if (!RSA_generate_key_ex(rsa, 2048, e, nullptr)) {
        RSA_free(rsa);
        return nullptr;
    }

    EVP_PKEY* key = EVP_PKEY_new();
    if(key == nullptr) {
        RSA_free(rsa);
        return nullptr;
    }
    if (!EVP_PKEY_assign_RSA(key, rsa)) {
        EVP_PKEY_free(key);
        RSA_free(rsa);
        return nullptr;
    }
    return key;
}

static X509_REQ* generate_csr(EVP_PKEY *key, const char* domain) {
    X509_REQ* req = X509_REQ_new();
    if (!req) return nullptr;
    X509_REQ_set_pubkey(req, key);

    /* Set the DN of the request. */
    X509_NAME *name = X509_REQ_get_subject_name(req);
    /*
    X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (const unsigned char*)REQ_DN_C, -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "ST", MBSTRING_ASC, (const unsigned char*)REQ_DN_ST, -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "L", MBSTRING_ASC, (const unsigned char*)REQ_DN_L, -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (const unsigned char*)REQ_DN_O, -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "OU", MBSTRING_ASC, (const unsigned char*)REQ_DN_OU, -1, -1, 0);
    */
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (const unsigned char*)domain, -1, -1, 0);

    /* Self-sign the request to prove that we posses the key. */
    if (!X509_REQ_sign(req, key, EVP_sha256())) {
        X509_REQ_free(req);
        return nullptr;
    };
    return req;
}

int generate_signed_key_pair(const char* domain, EVP_PKEY **key, X509 **crt) {
    if(certs.count(domain)) {
        *key = certs[domain].key;
        *crt = certs[domain].crt;
        return 0;
    }
    /* Generate the private key and corresponding CSR. */
    if((*key = generate_key()) == nullptr){
        LOGE("Failed to generate key!\n");
        return -1;
    }
    X509_REQ *req = generate_csr(*key, domain);
    if (!req) {
        EVP_PKEY_free(*key);
        LOGE("Failed to generate CSR!\n");
        return -1;
    }

    /* Sign with the CA. */
    if((*crt = X509_new()) == nullptr) goto err;

    ASN1_INTEGER_set(X509_get_serialNumber(*crt), (random()<<31)|random());
    X509_set_version(*crt, 2); /* Set version to X509v3 */
    /* Set issuer to CA's subject. */
    X509_set_issuer_name(*crt, X509_get_subject_name(opt.ca.crt));

    /* Set validity of certificate to 2 month. */
    X509_gmtime_adj(X509_get_notBefore(*crt), (long)-24*3600);
    X509_gmtime_adj(X509_get_notAfter(*crt), (long)2*30*24*3600);
    {
        X509V3_CTX ctx;
        X509V3_set_ctx_nodb(&ctx);
        X509V3_set_ctx(&ctx, opt.ca.crt, *crt, req, nullptr, 0);

        // Create and add the Basic Constraints extension
        X509_EXTENSION* bc_ext = X509V3_EXT_conf_nid(nullptr, &ctx, NID_basic_constraints, "critical,CA:FALSE");
        defer(X509_EXTENSION_free, bc_ext);
        if (!X509_add_ext(*crt, bc_ext, -1)) {
            goto err;
        }

        // Create and add the Key Usage extension
        X509_EXTENSION* ku_ext = X509V3_EXT_conf_nid(nullptr, &ctx, NID_key_usage, "critical,digitalSignature,keyEncipherment");
        defer(X509_EXTENSION_free, ku_ext);
        if (!X509_add_ext(*crt, ku_ext, -1)) {
            goto err;
        }

        // Create and add the Extended Key Usage extension
        X509_EXTENSION* eku_ext = X509V3_EXT_conf_nid(nullptr, &ctx, NID_ext_key_usage, "serverAuth");
        defer(X509_EXTENSION_free, eku_ext);
        if (!X509_add_ext(*crt, eku_ext, -1)) {
            goto err;
        }

        // Create and add the Subject Key Identifier extension
        X509_EXTENSION* ski_ext = X509V3_EXT_conf_nid(nullptr, &ctx, NID_subject_key_identifier, "hash");
        defer(X509_EXTENSION_free, ski_ext);
        if (!X509_add_ext(*crt, ski_ext, -1)) {
            goto err;
        }

        // Create and add the Authority Key Identifier extension
        X509_EXTENSION* aki_ext = X509V3_EXT_conf_nid(nullptr, &ctx, NID_authority_key_identifier, "keyid:always");
        defer(X509_EXTENSION_free, aki_ext);
        if (!X509_add_ext(*crt, aki_ext, -1)) {
            goto err;
        }

        std::string san;
        struct sockaddr_storage _ignore;
        if(storage_aton(domain, 0, &_ignore) == 1) {
            san += "IP:";
        }else{
            san += "DNS:";
        }
        san += domain;
        X509_EXTENSION* an_ext = X509V3_EXT_conf_nid(nullptr, &ctx, NID_subject_alt_name, san.c_str());
        if (!an_ext) {
            goto err;
        }
        defer(X509_EXTENSION_free, an_ext);
        if (!X509_add_ext(*crt, an_ext, -1)) {
            goto err;
        }
    }
    /* Get the request's subject and just use it (we don't bother checking it since we generated
     * it ourself). Also take the request's public key. */
    X509_set_subject_name(*crt, X509_REQ_get_subject_name(req));
    {
        EVP_PKEY *req_pubkey = X509_REQ_get_pubkey(req);
        X509_set_pubkey(*crt, req_pubkey);
        EVP_PKEY_free(req_pubkey);
    }

    /* Now perform the actual signing with the CA. */
    if (X509_sign(*crt, opt.ca.key, EVP_sha256()) == 0) goto err;
    X509_REQ_free(req);
    certs.emplace(domain, cert_pair{*crt, *key});
    return 0;
err:
    EVP_PKEY_free(*key);
    X509_REQ_free(req);
    X509_free(*crt);
    return -1;
}


void release_key_pair() {
    for(const auto& [_, cert]: certs) {
        X509_free(cert.crt);
        EVP_PKEY_free(cert.key);
    }
    certs.clear();
}
