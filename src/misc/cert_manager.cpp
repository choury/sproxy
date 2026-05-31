#include "cert_manager.h"
#include "common/common.h"
#include "misc/config.h"
#include "defer.h"
#include "net.h"

#include <string>
#include <map>
#include <vector>
#include <algorithm>
#include <memory>
#include <assert.h>
#include <dirent.h>
#include <strings.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/core_names.h>
#include <openssl/params.h>
#endif


static void cert_pair_free(cert_pair* p) {
    if(!p) {
        return;
    }
    if(p->chain) sk_X509_pop_free(p->chain, X509_free);
    if(p->key) EVP_PKEY_free(p->key);
    delete p;
}

using cert_pair_ptr = std::shared_ptr<cert_pair>;

static cert_pair_ptr make_cert_pair(STACK_OF(X509)* chain, EVP_PKEY* key) {
    return cert_pair_ptr(new cert_pair{chain, key}, cert_pair_free);
}

static cert_pair_ptr ca_cert;
static std::map<std::string, cert_pair_ptr> certs;

static std::vector<std::string> extract_domains(X509* leaf) {
    std::vector<std::string> domains;
    // Extract SAN DNS names
    STACK_OF(GENERAL_NAME)* san = (STACK_OF(GENERAL_NAME)*)X509_get_ext_d2i(
        leaf, NID_subject_alt_name, nullptr, nullptr);
    if(san) {
        size_t count = sk_GENERAL_NAME_num(san);
        for(size_t i = 0; i < count; ++i) {
            GENERAL_NAME* name = sk_GENERAL_NAME_value(san, static_cast<int>(i));
            if(name->type == GEN_DNS) {
                std::string dns((const char*)ASN1_STRING_get0_data(name->d.dNSName),
                                ASN1_STRING_length(name->d.dNSName));
                domains.push_back(std::move(dns));
            } else if(name->type == GEN_IPADD) {
                const unsigned char* addr = ASN1_STRING_get0_data(name->d.iPAddress);
                int addrlen = ASN1_STRING_length(name->d.iPAddress);
                char buf[INET6_ADDRSTRLEN];
                if(addrlen == 4 && inet_ntop(AF_INET, addr, buf, sizeof(buf))) {
                    domains.emplace_back(buf);
                } else if(addrlen == 16 && inet_ntop(AF_INET6, addr, buf, sizeof(buf))) {
                    domains.emplace_back(buf);
                }
            }
        }
        sk_GENERAL_NAME_pop_free(san, GENERAL_NAME_free);
    }
    // Fallback to CN
    if(domains.empty()) {
        X509_NAME* subject = X509_get_subject_name(leaf);
        int idx = X509_NAME_get_index_by_NID(subject, NID_commonName, -1);
        if(idx >= 0) {
            X509_NAME_ENTRY* entry = X509_NAME_get_entry(subject, idx);
            ASN1_STRING* asn1_str = X509_NAME_ENTRY_get_data(entry);
            std::string cn((const char*)ASN1_STRING_get0_data(asn1_str),
                           ASN1_STRING_length(asn1_str));
            domains.push_back(std::move(cn));
        }
    }
    return domains;
}

int load_cert_key(const char *crt_path, const char *key_path) {
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

    auto pair = make_cert_pair(chain, key);
    X509* leaf = cert_pair_leaf(pair.get());
    auto domains = extract_domains(leaf);
    if(domains.empty()) {
        LOGE("No domain found in certificate: %s\n", crt_path);
        return -1;
    }
    for(const auto& domain : domains) {
        certs[domain] = pair;
    }
    LOG("certificate %s loaded with %zu certificates, %zu domain(s)\n",
        crt_path, static_cast<size_t>(sk_X509_num(chain)), domains.size());
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
    if (!BN_set_word(e, RSA_F4)) {
        BN_free(e);
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

static int generate_signed_key_pair(const char* domain, STACK_OF(X509)** chain, EVP_PKEY **key) {
    *chain = nullptr;
    *key = nullptr;
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
    X509* ca_leaf = cert_pair_leaf(ca_cert.get());
    X509* leaf = nullptr;
    *chain = sk_X509_new_null();
    if(*chain == nullptr) goto err;
    leaf = X509_new();
    if(leaf == nullptr) goto err;
    if(ca_leaf == nullptr) {
        LOGE("CA certificate is not available for MITM signing\n");
        goto err;
    }

    ASN1_INTEGER_set(X509_get_serialNumber(leaf), (random()<<31)|random());
    X509_set_version(leaf, 2); /* Set version to X509v3 */
    /* Set issuer to CA's subject. */
    X509_set_issuer_name(leaf, X509_get_subject_name(ca_leaf));

    /* Set validity of certificate to 2 month. */
    X509_gmtime_adj(X509_get_notBefore(leaf), (long)-24*3600);
    X509_gmtime_adj(X509_get_notAfter(leaf), (long)2*30*24*3600);
    {
        X509V3_CTX ctx;
        X509V3_set_ctx_nodb(&ctx);
        X509V3_set_ctx(&ctx, ca_leaf, leaf, req, nullptr, 0);

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
    if (X509_sign(leaf, ca_cert->key, EVP_sha256()) == 0) goto err;
    X509_REQ_free(req);
    req = nullptr;

    if(!sk_X509_push(*chain, leaf)) {
        sk_X509_pop_free(*chain, X509_free);
        *chain = nullptr;
        goto err;
    }
    leaf = nullptr;
    if(!sk_X509_push(*chain, X509_dup(ca_leaf))) {
        goto err;
    }

    return 0;
err:
    EVP_PKEY_free(*key);
    *key = nullptr;
    if(*chain) {
        sk_X509_pop_free(*chain, X509_free);
        *chain = nullptr;
    }
    if(leaf) {
        X509_free(leaf);
    }
    if(req) {
        X509_REQ_free(req);
    }
    return -1;
}


void release_key_pair() {
    certs.clear();
    ca_cert.reset();
}

static int load_combined_pem(const char* filepath, cert_pair* pair) {
    BIO* bio = BIO_new(BIO_s_file());
    if(!bio) return -1;
    defer(BIO_free_all, bio);
    if(!BIO_read_filename(bio, filepath)) return -1;

    STACK_OF(X509_INFO)* infos = PEM_X509_INFO_read_bio(bio, nullptr, nullptr, nullptr);
    if(!infos) {
        LOGE("Error reading PEM file %s: %s\n", filepath, ERR_error_string(ERR_get_error(), nullptr));
        return -1;
    }
    defer([infos]() { sk_X509_INFO_pop_free(infos, X509_INFO_free); });

    STACK_OF(X509)* chain = sk_X509_new_null();
    if(!chain) return -1;

    auto info_count = sk_X509_INFO_num(infos);
    for(decltype(info_count) idx = 0; idx < info_count; ++idx) {
        X509_INFO* info = sk_X509_INFO_value(infos, static_cast<int>(idx));
        if(info->x509) {
            sk_X509_push(chain, X509_dup(info->x509));
        }
    }

    // Reset BIO and read private key via public API (take the last one)
    BIO_reset(bio);
    BIO_read_filename(bio, filepath);
    EVP_PKEY* key = nullptr;
    for(;;) {
        EVP_PKEY* tmp = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
        if(!tmp) break;
        if(key) EVP_PKEY_free(key);
        key = tmp;
    }

    if(sk_X509_num(chain) == 0) {
        LOGE("No certificate found in %s\n", filepath);
        sk_X509_pop_free(chain, X509_free);
        if(key) EVP_PKEY_free(key);
        return -1;
    }
    if(!key) {
        LOGE("No private key found in %s\n", filepath);
        sk_X509_pop_free(chain, X509_free);
        return -1;
    }

    pair->chain = chain;
    pair->key = key;
    return 0;
}

int load_certs_dir(const char* dir_path) {
    DIR* dir = opendir(dir_path);
    if(!dir) {
        LOGE("Failed to open certs directory %s: %s\n", dir_path, strerror(errno));
        return -1;
    }

    size_t count = 0;
    struct dirent* entry;
    while((entry = readdir(dir)) != nullptr) {
        const char* name = entry->d_name;
        size_t len = strlen(name);
        if(len < 5 || strcasecmp(name + len - 4, ".pem") != 0) {
            continue;
        }

        std::string filepath = std::string(dir_path) + "/" + name;
        cert_pair raw = {nullptr, nullptr};
        if(load_combined_pem(filepath.c_str(), &raw) != 0) {
            LOGE("Failed to load PEM file: %s\n", filepath.c_str());
            continue;
        }

        X509* leaf = cert_pair_leaf(&raw);
        if(!leaf) {
            sk_X509_pop_free(raw.chain, X509_free);
            if(raw.key) EVP_PKEY_free(raw.key);
            continue;
        }

        auto domains = extract_domains(leaf);
        if(domains.empty()) {
            LOGE("No domain found in certificate: %s\n", filepath.c_str());
            sk_X509_pop_free(raw.chain, X509_free);
            if(raw.key) EVP_PKEY_free(raw.key);
            continue;
        }

        auto pair = make_cert_pair(raw.chain, raw.key);
        for(const auto& domain : domains) {
            certs[domain] = pair;
            LOG("preloaded cert for domain: %s (from %s)\n", domain.c_str(), name);
        }
        count++;
    }
    closedir(dir);
    LOG("Loaded %zu certificate file(s) from %s\n", count, dir_path);
    return 0;
}

const cert_pair* lookup_cert(const char* domain) {
    if(!domain) return nullptr;
    std::string dname(domain);

    // Exact match
    auto it = certs.find(dname);
    if(it != certs.end()) {
        return it->second.get();
    }

    // Wildcard match: www.example.com -> *.example.com
    size_t dot = dname.find('.');
    if(dot != std::string::npos) {
        std::string wildcard = "*" + dname.substr(dot);
        it = certs.find(wildcard);
        if(it != certs.end()) {
            return it->second.get();
        }
    }

    return nullptr;
}

const cert_pair* generate_cert(const char* domain) {
    if(!domain) return nullptr;
    auto pair_ = lookup_cert(domain);
    if(pair_) {
        return pair_;
    }

    STACK_OF(X509)* chain = nullptr;
    EVP_PKEY* key = nullptr;
    if(generate_signed_key_pair(domain, &chain, &key) != 0) {
        return nullptr;
    }

    auto pair = make_cert_pair(chain, key);
    certs[domain] = pair;
    return pair.get();
}

int load_ca_cert(const char *crt_path, const char *key_path) {
    // Load certificate chain
    BIO* cbio = BIO_new(BIO_s_file());
    if(!cbio) return -1;
    defer(BIO_free_all, cbio);
    if(!BIO_read_filename(cbio, crt_path)) return -1;
    STACK_OF(X509_INFO)* infos = PEM_X509_INFO_read_bio(cbio, NULL, NULL, NULL);
    if(!infos) {
        LOGE("Error reading cert file %s: %s\n", crt_path, ERR_error_string(ERR_get_error(), nullptr));
        return -1;
    }
    defer([infos]() { sk_X509_INFO_pop_free(infos, X509_INFO_free); });
    STACK_OF(X509)* chain = sk_X509_new_null();
    if(!chain) return -1;
    auto info_count = sk_X509_INFO_num(infos);
    for(decltype(info_count) idx = 0; idx < info_count; ++idx) {
        X509_INFO* info = sk_X509_INFO_value(infos, static_cast<int>(idx));
        if(info->x509) sk_X509_push(chain, X509_dup(info->x509));
    }
    if(sk_X509_num(chain) == 0) {
        LOGE("No valid certificate found in %s\n", crt_path);
        sk_X509_pop_free(chain, X509_free);
        return -1;
    }
    // Load private key
    BIO* kbio = BIO_new(BIO_s_file());
    if(!kbio) {
        sk_X509_pop_free(chain, X509_free);
        return -1;
    }
    defer(BIO_free_all, kbio);
    if(!BIO_read_filename(kbio, key_path)) {
        sk_X509_pop_free(chain, X509_free);
        return -1;
    }
    EVP_PKEY* key = PEM_read_bio_PrivateKey(kbio, nullptr, nullptr, nullptr);
    if(!key) {
        LOGE("Error reading private key: %s\n", ERR_error_string(ERR_get_error(), nullptr));
        sk_X509_pop_free(chain, X509_free);
        return -1;
    }
    ca_cert = make_cert_pair(chain, key);
    LOG("CA certificate loaded from %s\n", crt_path);
    return 0;
}

int has_ca_cert(void) {
    return ca_cert && cert_pair_leaf(ca_cert.get()) && ca_cert->key;
}

EVP_PKEY* get_default_key(void) {
    if(ca_cert && ca_cert->key) {
        return ca_cert->key;
    }
    for(const auto& [_, pair] : certs) {
        X509* leaf = cert_pair_leaf(pair.get());
        if(leaf && X509_check_issued(leaf, leaf) != X509_V_OK && pair->key) {
            return pair->key;
        }
    }
    return nullptr;
}
