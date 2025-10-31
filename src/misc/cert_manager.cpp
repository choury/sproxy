#include "cert_manager.h"
#include "common/common.h"
#include "misc/config.h"
#include "defer.h"
#include "net.h"

#include <string>
#include <map>
#include <assert.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/core_names.h>
#include <openssl/params.h>
#endif


static std::map<std::string, cert_pair> certs;

int load_cert_key(const char *crt_path, const char *key_path, struct cert_pair* cert) {
    BIO* cbio = BIO_new(BIO_s_file());
    defer(BIO_free_all, cbio);
    if (!BIO_read_filename(cbio, crt_path)) return -1;
    STACK_OF(X509_INFO)* infos = PEM_X509_INFO_read_bio(cbio, NULL, NULL, NULL);
    if(infos == nullptr) {
        LOGE("Error reading cert file %s: %s\n", crt_path, ERR_error_string(ERR_get_error(), nullptr));
        return -1;
    }
    defer([infos]() { sk_X509_INFO_pop_free(infos, X509_INFO_free); });

    STACK_OF(X509)* chain = sk_X509_new_null();
    if(chain == nullptr) {
        LOGE("Failed to allocate certificate chain stack\n");
        return -1;
    }
    auto info_count = sk_X509_INFO_num(infos);
    for(decltype(info_count) idx = 0; idx < info_count; ++idx) {
        X509_INFO* info = sk_X509_INFO_value(infos, static_cast<int>(idx));
        if(info->x509 == nullptr) {
            continue;
        }
        sk_X509_push(chain, X509_dup(info->x509));
    }
    if(sk_X509_num(chain) == 0) {
        LOGE("No valid certificate found in %s\n", crt_path);
        sk_X509_pop_free(chain, X509_free);
        return -1;
    }

    /* Load CA private key. */
    BIO* kbio = BIO_new(BIO_s_file());
    defer(BIO_free_all, kbio);
    if (!BIO_read_filename(kbio, key_path)) {
        sk_X509_pop_free(chain, X509_free);
        return -1;
    }
    EVP_PKEY* key = PEM_read_bio_PrivateKey(kbio, nullptr, nullptr, nullptr);
    if(key == nullptr){
        LOGE("Error reading private key: %s\n", ERR_error_string(ERR_get_error(), nullptr));
        sk_X509_pop_free(chain, X509_free);
        return -1;
    }
    LOG("loaded cert from %s and %s\n", crt_path, key_path);
    if(cert->chain) {
        sk_X509_pop_free(cert->chain, X509_free);
    }
    if(cert->key) {
        EVP_PKEY_free(cert->key);
    }
    cert->chain = chain;
    cert->key = key;
    LOG("certificate %s loaded with %zu certificates\n", crt_path, static_cast<size_t>(sk_X509_num(chain)));
    return 0;
}

static EVP_PKEY* generate_key() {
#if OPENSSL_VERSION_NUMBER >= 0x30000000L && !defined(OPENSSL_IS_BORINGSSL)
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_name(nullptr, "RSA", nullptr);
    if(ctx == nullptr) {
        return nullptr;
    }
    defer(EVP_PKEY_CTX_free, ctx);

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        return nullptr;
    }

    unsigned int bits = 2048;
    unsigned int exponent = RSA_F4;
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_uint(OSSL_PKEY_PARAM_RSA_BITS, &bits),
        OSSL_PARAM_construct_uint(OSSL_PKEY_PARAM_RSA_E, &exponent),
        OSSL_PARAM_construct_end()
    };

    if (EVP_PKEY_CTX_set_params(ctx, params) <= 0) {
        return nullptr;
    }

    EVP_PKEY* key = nullptr;
    if (EVP_PKEY_generate(ctx, &key) <= 0) {
        return nullptr;
    }

    return key;
#else
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    if(ctx == nullptr) {
        return nullptr;
    }
    defer(EVP_PKEY_CTX_free, ctx);

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        return nullptr;
    }
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0) {
        return nullptr;
    }

    BIGNUM *e = BN_new();
    if(e == nullptr) {
        return nullptr;
    }
    defer(BN_free, e);
    if (!BN_set_word(e, RSA_F4)) {
        return nullptr;
    }

    if (EVP_PKEY_CTX_set_rsa_keygen_pubexp(ctx, e) <= 0) {
        return nullptr;
    }

    EVP_PKEY* key = nullptr;
    if (EVP_PKEY_keygen(ctx, &key) <= 0) {
        return nullptr;
    }

    return key;
#endif
}

static std::string truncateDomain(const std::string &domain) {
    if (domain.length() <= 64)
        return domain;

    size_t pos         = domain.length();
    std::string result = "";

    while (pos != std::string::npos) {
        pos = domain.find_last_of('.', pos - 1);
        if (pos == std::string::npos)
            break;

        std::string substr = domain.substr(pos);
        if (substr.length() + result.length() > 64) {
            break;
        }
        result = substr + result;
    }
    return result.substr(1);
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
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (const unsigned char*)truncateDomain(domain).c_str(), -1, -1, 0);

    /* Self-sign the request to prove that we posses the key. */
    if (!X509_REQ_sign(req, key, EVP_sha256())) {
        X509_REQ_free(req);
        return nullptr;
    };
    return req;
}

int generate_signed_key_pair(const char* domain, EVP_PKEY **key, X509 **crt) {
    auto it = certs.find(domain);
    if(it != certs.end()) {
        *key = it->second.key;
        *crt = cert_pair_leaf(&it->second);
        return 0;
    }
    *crt = nullptr;
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
    X509* ca_cert = cert_pair_leaf(&opt.ca);
    STACK_OF(X509)* chain = nullptr;
    X509* leaf = X509_new();
    if(leaf == nullptr) goto err;
    if(ca_cert == nullptr) {
        LOGE("CA certificate is not available for MITM signing\n");
        goto err;
    }

    ASN1_INTEGER_set(X509_get_serialNumber(leaf), (random()<<31)|random());
    X509_set_version(leaf, 2); /* Set version to X509v3 */
    /* Set issuer to CA's subject. */
    X509_set_issuer_name(leaf, X509_get_subject_name(ca_cert));

    /* Set validity of certificate to 2 month. */
    X509_gmtime_adj(X509_get_notBefore(leaf), (long)-24*3600);
    X509_gmtime_adj(X509_get_notAfter(leaf), (long)2*30*24*3600);
    {
        X509V3_CTX ctx;
        X509V3_set_ctx_nodb(&ctx);
        X509V3_set_ctx(&ctx, ca_cert, leaf, req, nullptr, 0);

        // Create and add the Basic Constraints extension
        X509_EXTENSION* bc_ext = X509V3_EXT_nconf_nid(nullptr, &ctx, NID_basic_constraints, "critical,CA:FALSE");
        defer(X509_EXTENSION_free, bc_ext);
        if (!X509_add_ext(leaf, bc_ext, -1)) {
            goto err;
        }

        // Create and add the Key Usage extension
        X509_EXTENSION* ku_ext = X509V3_EXT_nconf_nid(nullptr, &ctx, NID_key_usage, "critical,digitalSignature,keyEncipherment");
        defer(X509_EXTENSION_free, ku_ext);
        if (!X509_add_ext(leaf, ku_ext, -1)) {
            goto err;
        }

        // Create and add the Extended Key Usage extension
        X509_EXTENSION* eku_ext = X509V3_EXT_nconf_nid(nullptr, &ctx, NID_ext_key_usage, "serverAuth");
        defer(X509_EXTENSION_free, eku_ext);
        if (!X509_add_ext(leaf, eku_ext, -1)) {
            goto err;
        }

        // Create and add the Subject Key Identifier extension
        X509_EXTENSION* ski_ext = X509V3_EXT_nconf_nid(nullptr, &ctx, NID_subject_key_identifier, "hash");
        defer(X509_EXTENSION_free, ski_ext);
        if (!X509_add_ext(leaf, ski_ext, -1)) {
            goto err;
        }

        // Create and add the Authority Key Identifier extension
        X509_EXTENSION* aki_ext = X509V3_EXT_nconf_nid(nullptr, &ctx, NID_authority_key_identifier, "keyid:always");
        defer(X509_EXTENSION_free, aki_ext);
        if (!X509_add_ext(leaf, aki_ext, -1)) {
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
        X509_EXTENSION* an_ext = X509V3_EXT_nconf_nid(nullptr, &ctx, NID_subject_alt_name, san.c_str());
        if (!an_ext) {
            goto err;
        }
        defer(X509_EXTENSION_free, an_ext);
        if (!X509_add_ext(leaf, an_ext, -1)) {
            goto err;
        }
    }
    /* Get the request's subject and just use it (we don't bother checking it since we generated
     * it ourself). Also take the request's public key. */
    X509_set_subject_name(leaf, X509_REQ_get_subject_name(req));
    {
        EVP_PKEY *req_pubkey = X509_REQ_get_pubkey(req);
        X509_set_pubkey(leaf, req_pubkey);
        EVP_PKEY_free(req_pubkey);
    }

    /* Now perform the actual signing with the CA. */
    if (X509_sign(leaf, opt.ca.key, EVP_sha256()) == 0) goto err;
    X509_REQ_free(req);
    req = nullptr;

    chain = sk_X509_new_null();
    if(chain == nullptr) goto err;
    if(!sk_X509_push(chain, leaf)) {
        sk_X509_free(chain);
        chain = nullptr;
        goto err;
    }
    leaf = nullptr;
    if(!sk_X509_push(chain, X509_dup(ca_cert))) {
        goto err;
    }

    certs.emplace(domain, cert_pair{chain, *key});
    *crt = cert_pair_leaf(&certs[domain]);
    return 0;
err:
    EVP_PKEY_free(*key);
    *key = nullptr;
    if(chain) {
        sk_X509_pop_free(chain, X509_free);
        chain = nullptr;
    }
    if(leaf) {
        X509_free(leaf);
        leaf = nullptr;
    }
    if(req) {
        X509_REQ_free(req);
    }
    *crt = nullptr;
    return -1;
}


void release_key_pair() {
    for(const auto& [_, cert]: certs) {
        if(cert.chain) {
            sk_X509_pop_free(cert.chain, X509_free);
        }
        if(cert.key) {
            EVP_PKEY_free(cert.key);
        }
    }
    certs.clear();
}

int reload_cert_key(const char* cert_file, const char* key_file, struct cert_pair* cert) {
    if(!cert_file || !key_file || !cert) {
        return -1;
    }

    // 创建临时的cert_pair来测试加载新证书
    struct cert_pair new_cert = {nullptr, nullptr};
    int ret = load_cert_key(cert_file, key_file, &new_cert);
    if(ret == 0) {
        // 成功加载新证书，替换旧证书
        if(cert->chain) {
            sk_X509_pop_free(cert->chain, X509_free);
        }
        if(cert->key) {
            EVP_PKEY_free(cert->key);
        }

        cert->chain = new_cert.chain;
        cert->key = new_cert.key;
    } else {
        // 加载失败，清理临时证书（如果有的话）
        if(new_cert.chain) {
            sk_X509_pop_free(new_cert.chain, X509_free);
        }
        if(new_cert.key) {
            EVP_PKEY_free(new_cert.key);
        }
        LOGE("Failed to reload certificate pair from %s and %s, keeping existing certificate\n", cert_file, key_file);
    }

    return ret;
}
