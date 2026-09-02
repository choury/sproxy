//ech测试：HTTPS RR ech参数解析、loopback双端ECH握手、以及给test.sh用的
//-g 生成服务端ech密钥文件 / -c 作为ech客户端真实连接 两个子命令
#include "dns.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <string>
#include <vector>

//密钥生成、BIO泵等副作用都写在检查表达式里，assert在NDEBUG构建下会被编译掉，
//必须用常开的CHECK，否则Release构建的测试是空跑
#define CHECK(cond) do { \
    if(!(cond)) { \
        fprintf(stderr, "%s:%d: check failed: %s\n", __FILE__, __LINE__, #cond); \
        exit(1); \
    } \
} while(0)

//dns.cpp里的日志宏需要，链接桩实现
extern "C" void slog(int, const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
}

struct debug_flags_map debug[]{
    {}, //DNONE
    {"event"}, {"dns"}, {"ssl"}, {"http2"}, {"job"}, {"vpn"}, {"hpack"},
    {"http"}, {"file"}, {"net"}, {"quic"}, {"http3"}, {"rwer"}, {"socks"},
};

//桩实现，仅为满足dns.cpp的链接
extern "C" int storage_aton(const char* ipstr, uint16_t, struct sockaddr_storage* addr) {
    struct in_addr ip;
    if(inet_pton(AF_INET, ipstr, &ip) != 1) {
        return 0;
    }
    memset(addr, 0, sizeof(*addr));
    ((struct sockaddr_in*)addr)->sin_family = AF_INET;
    ((struct sockaddr_in*)addr)->sin_addr = ip;
    return 1;
}

#ifdef HAVE_ECH
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hpke.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <unistd.h>
#endif

static void put16(std::string& s, uint16_t v) {
    s.push_back((char)(v >> 8));
    s.push_back((char)(v & 0xff));
}

static void put32(std::string& s, uint32_t v) {
    s.push_back((char)(v >> 24));
    s.push_back((char)(v >> 16));
    s.push_back((char)(v >> 8));
    s.push_back((char)v);
}

static std::string qname(const char* name) {
    std::string out;
    if(name[0] == '\0' || (name[0] == '.' && name[1] == '\0')) {
        out.push_back('\0'); //根域名
        return out;
    }
    const char* p = name;
    while(*p) {
        const char* dot = strchr(p, '.');
        size_t l = dot ? (size_t)(dot - p) : strlen(p);
        out.push_back((char)l);
        out.append(p, l);
        p += l;
        if(dot == nullptr) {
            break;
        }
        p++;
    }
    out.push_back('\0');
    return out;
}

//RDATA: SvcPriority(2) + TargetName + SvcParam{key(2) len(2) value}
static std::string svcb_rdata(uint16_t priority, const char* target,
                              std::vector<std::pair<uint16_t, std::string>> params) {
    std::string rdata;
    put16(rdata, priority);
    rdata += qname(target);
    for(const auto& [key, value] : params) {
        put16(rdata, key);
        put16(rdata, (uint16_t)value.size());
        rdata += value;
    }
    return rdata;
}

//构造 question(example.com HTTPS) + N条HTTPS RR 的响应
static std::string build_response(const std::vector<std::string>& rdatas, uint16_t rcode = 0) {
    std::string pkt;
    put16(pkt, 0x1234);              //id
    put16(pkt, 0x8180 | rcode);      //qr|rd|ra
    put16(pkt, 1);                   //qdcount
    put16(pkt, (uint16_t)rdatas.size());
    put16(pkt, 0);                   //nscount
    put16(pkt, 0);                   //arcount
    pkt += qname("example.com");
    put16(pkt, ns_t_https);
    put16(pkt, 1);
    for(const auto& rdata : rdatas) {
        pkt += "\xc0\x0c";           //压缩指针指向question name(偏移12)
        put16(pkt, ns_t_https);
        put16(pkt, 1);
        put32(pkt, 300);
        put16(pkt, (uint16_t)rdata.size());
        pkt += rdata;
    }
    return pkt;
}

static std::string raw(const unsigned char* data, size_t len) {
    return std::string((const char*)data, len);
}

static void test_parse() {
    std::string ech;
    uint32_t ttl = 0;

    //ech参数value是一段完整的ECHConfigList(2字节总长+串接的ECHConfig)
    const unsigned char list1[] = {0x00, 0x04, 0xfe, 0x0d, 0x00, 0x01};
    const unsigned char list2[] = {0x00, 0x04, 0xfe, 0x0d, 0x00, 0x02};
    const unsigned char cfg1[] = {0xfe, 0x0d, 0x00, 0x01};
    const unsigned char cfg2[] = {0xfe, 0x0d, 0x00, 0x02};

    //1. ServiceMode + ech
    auto pkt = build_response({svcb_rdata(1, ".", {{5, raw(list1, sizeof(list1))}})});
    CHECK(parse_ech_configs(pkt.data(), pkt.size(), ech, &ttl) == 0);
    CHECK(ech == raw(list1, sizeof(list1)));
    CHECK(ttl == 300);

    //2. 两条记录的ech合并为一个列表(去掉各自的长度前缀重新包装)
    pkt = build_response({svcb_rdata(1, ".", {{5, raw(list1, sizeof(list1))}}),
                          svcb_rdata(2, ".", {{5, raw(list2, sizeof(list2))}})});
    CHECK(parse_ech_configs(pkt.data(), pkt.size(), ech, &ttl) == 0);
    CHECK(ech == raw((const unsigned char*)"\x00\x08", 2) + raw(cfg1, sizeof(cfg1)) + raw(cfg2, sizeof(cfg2)));

    //3. 只有alpn没有ech
    pkt = build_response({svcb_rdata(1, ".", {{1, std::string("\x02h2")}})});
    CHECK(parse_ech_configs(pkt.data(), pkt.size(), ech, &ttl) == 0);
    CHECK(ech.empty());

    //4. AliasMode(priority=0)没有SvcParam
    pkt = build_response({svcb_rdata(0, "alias.example.com", {})});
    CHECK(parse_ech_configs(pkt.data(), pkt.size(), ech, &ttl) == 0);
    CHECK(ech.empty());

    //5. NOERROR空应答
    pkt = build_response({});
    CHECK(parse_ech_configs(pkt.data(), pkt.size(), ech, &ttl) == 0);
    CHECK(ech.empty());

    //6. NXDOMAIN
    pkt = build_response({}, 3);
    CHECK(parse_ech_configs(pkt.data(), pkt.size(), ech, &ttl) == 0);
    CHECK(ech.empty());

    //7. 报文截断
    pkt = build_response({svcb_rdata(1, ".", {{5, raw(list1, sizeof(list1))}})});
    pkt.resize(pkt.size() - 5);
    CHECK(parse_ech_configs(pkt.data(), pkt.size(), ech, &ttl) == -1);

    //8. SvcParam声明长度越过rdlength：按无ech处理而非报文错误
    std::string bad = svcb_rdata(1, ".", {});
    put16(bad, 5);
    put16(bad, 100); //声明100字节但后面没有了
    pkt = build_response({bad});
    CHECK(parse_ech_configs(pkt.data(), pkt.size(), ech, &ttl) == 0);
    CHECK(ech.empty());

    printf("parse_ech_configs: all passed\n");
}

#ifdef HAVE_ECH

static const char b64_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static size_t b64_encode(const unsigned char* data, size_t len, char* dst) {
    size_t i = 0, j = 0;
    for(; i + 2 < len; i += 3) {
        dst[j++] = b64_chars[data[i] >> 2];
        dst[j++] = b64_chars[((data[i] << 4) & 0x30) | (data[i + 1] >> 4)];
        dst[j++] = b64_chars[((data[i + 1] << 2) & 0x3c) | (data[i + 2] >> 6)];
        dst[j++] = b64_chars[data[i + 2] & 0x3f];
    }
    if(len % 3 == 1) {
        dst[j++] = b64_chars[data[i] >> 2];
        dst[j++] = b64_chars[(data[i] << 4) & 0x30];
        dst[j++] = '=';
        dst[j++] = '=';
    }else if(len % 3 == 2) {
        dst[j++] = b64_chars[data[i] >> 2];
        dst[j++] = b64_chars[((data[i] << 4) & 0x30) | (data[i + 1] >> 4)];
        dst[j++] = b64_chars[((data[i + 1] << 2) & 0x3c)];
        dst[j++] = '=';
    }
    dst[j] = 0;
    return j;
}

static int b64_index(char c) {
    if(c >= 'A' && c <= 'Z') return c - 'A';
    if(c >= 'a' && c <= 'z') return c - 'a' + 26;
    if(c >= '0' && c <= '9') return c - '0' + 52;
    if(c == '+') return 62;
    if(c == '/') return 63;
    return -1;
}

static size_t b64_decode(const char* src, size_t len, unsigned char* dst) {
    size_t j = 0;
    int buf = 0, bits = 0;
    for(size_t i = 0; i < len; i++) {
        if(src[i] == '=' || src[i] == '\n' || src[i] == '\r') {
            continue;
        }
        int v = b64_index(src[i]);
        if(v < 0) {
            continue;
        }
        buf = (buf << 6) | v;
        bits += 6;
        if(bits >= 8) {
            bits -= 8;
            dst[j++] = (unsigned char)(buf >> bits);
        }
    }
    return j;
}

//生成ech密钥并按tls.c load_ech_keys的格式落盘，stdout打印可发布到DNS的base64
static int generate_key_file(const char* path, const char* public_name) {
    EVP_HPKE_KEY* hpke_key = EVP_HPKE_KEY_new();
    SSL_ECH_KEYS* keys = SSL_ECH_KEYS_new();
    if(hpke_key == nullptr || keys == nullptr) {
        EVP_HPKE_KEY_free(hpke_key);
        SSL_ECH_KEYS_free(keys);
        return 1;
    }
    uint8_t config_id = 0;
    RAND_bytes(&config_id, 1);
    uint8_t* marshaled = nullptr;
    size_t marshaled_len = 0;
    uint8_t* retry = nullptr;
    size_t retry_len = 0;
    int ret = 1;
    if(EVP_HPKE_KEY_generate(hpke_key, EVP_hpke_x25519_hkdf_sha256()) != 1 ||
       SSL_marshal_ech_config(&marshaled, &marshaled_len, config_id, hpke_key,
                              public_name, strlen(public_name)) != 1) {
        fprintf(stderr, "generate ech key failed\n");
        goto out;
    }
    if(SSL_ECH_KEYS_add(keys, 1, marshaled, marshaled_len, hpke_key) != 1) {
        fprintf(stderr, "add ech key failed\n");
        goto out;
    }
    {
        uint8_t private_key[EVP_HPKE_MAX_PRIVATE_KEY_LENGTH];
        size_t private_key_len = sizeof(private_key);
        if(EVP_HPKE_KEY_private_key(hpke_key, private_key, &private_key_len, private_key_len) != 1) {
            goto out;
        }
        //与tls.c write_ech_key_file保持一致：0600且不跟随已有符号链接
        int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
        if(fd < 0) {
            perror("open");
            goto out;
        }
        FILE* fp = fdopen(fd, "w");
        if(fp == nullptr) {
            close(fd);
            goto out;
        }
        char b64[1024];
        fprintf(fp, "public_name=%s\n", public_name);
        b64_encode(marshaled, marshaled_len, b64);
        fprintf(fp, "ech_config=%s\n", b64);
        b64_encode(private_key, private_key_len, b64);
        fprintf(fp, "private_key=%s\n", b64);
        fclose(fp);
        //DNS HTTPS RR ech参数的值 = retry configs序列化的base64
        if(SSL_ECH_KEYS_marshal_retry_configs(keys, &retry, &retry_len) != 1) {
            goto out;
        }
        b64_encode(retry, retry_len, b64);
        printf("%s\n", b64);
        ret = 0;
    }
out:
    OPENSSL_free(marshaled);
    OPENSSL_free(retry);
    EVP_HPKE_KEY_free(hpke_key);
    SSL_ECH_KEYS_free(keys);
    return ret;
}

static int connect_host(const char* host, uint16_t port) {
    char portstr[8];
    snprintf(portstr, sizeof(portstr), "%u", port);
    struct addrinfo hints{};
    hints.ai_socktype = SOCK_STREAM;
    struct addrinfo* result = nullptr;
    if(getaddrinfo(host, portstr, &hints, &result) != 0 || result == nullptr) {
        return -1;
    }
    int fd = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if(fd >= 0 && connect(fd, result->ai_addr, result->ai_addrlen) != 0) {
        close(fd);
        fd = -1;
    }
    freeaddrinfo(result);
    return fd;
}

//作为ech客户端连接host:port，校验ECH协商成功
static int ech_connect(const char* host, uint16_t port, const char* b64, const char* sni) {
    static unsigned char config[4096];
    size_t config_len = b64_decode(b64, strlen(b64), config);
    int fd = connect_host(host, port);
    if(fd < 0) {
        fprintf(stderr, "connect %s:%u failed\n", host, port);
        return 1;
    }
    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    SSL* ssl = SSL_new(ctx);
    SSL_set_min_proto_version(ssl, TLS1_3_VERSION);
    SSL_set_tlsext_host_name(ssl, sni);
    SSL_set1_ech_config_list(ssl, config, config_len);
    SSL_set_verify(ssl, SSL_VERIFY_NONE, nullptr);
    SSL_set_fd(ssl, fd);
    if(SSL_connect(ssl) != 1) {
        fprintf(stderr, "ssl connect failed: %s\n", ERR_error_string(ERR_get_error(), nullptr));
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        close(fd);
        return 1;
    }
    int accepted = SSL_ech_accepted(ssl);
    printf("ech %s, tls %s\n", accepted ? "accepted" : "NOT accepted",
           SSL_get_version(ssl));
    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    close(fd);
    return accepted ? 0 : 1;
}

//内存BIO驱动的双端握手，验证服务端ECH密钥可用
static int loopback_test() {
    EVP_HPKE_KEY* hpke_key = EVP_HPKE_KEY_new();
    CHECK(EVP_HPKE_KEY_generate(hpke_key, EVP_hpke_x25519_hkdf_sha256()) == 1);
    uint8_t* marshaled = nullptr;
    size_t marshaled_len = 0;
    CHECK(SSL_marshal_ech_config(&marshaled, &marshaled_len, 0x42, hpke_key,
                                  "localhost", strlen("localhost")) == 1);
    SSL_ECH_KEYS* keys = SSL_ECH_KEYS_new();
    CHECK(SSL_ECH_KEYS_add(keys, 1, marshaled, marshaled_len, hpke_key) == 1);
    OPENSSL_free(marshaled);
    uint8_t* retry = nullptr;
    size_t retry_len = 0;
    CHECK(SSL_ECH_KEYS_marshal_retry_configs(keys, &retry, &retry_len) == 1);

    //自签证书
    RSA* rsa = RSA_new();
    BIGNUM* e = BN_new();
    BN_set_word(e, RSA_F4);
    CHECK(RSA_generate_key_ex(rsa, 2048, e, nullptr) == 1);
    BN_free(e);
    EVP_PKEY* pkey = EVP_PKEY_new();
    CHECK(pkey != nullptr && EVP_PKEY_assign_RSA(pkey, rsa) == 1);
    X509* x = X509_new();
    CHECK(x != nullptr);
    X509_set_version(x, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(x), 1);
    X509_gmtime_adj(X509_getm_notBefore(x), 0);
    X509_gmtime_adj(X509_getm_notAfter(x), 3600);
    X509_NAME* name = X509_get_subject_name(x);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (const unsigned char*)"localhost", -1, -1, 0);
    X509_set_issuer_name(x, name);
    X509_set_pubkey(x, pkey);
    CHECK(X509_sign(x, pkey, EVP_sha256()) > 0);

    SSL_CTX* sctx = SSL_CTX_new(TLS_server_method());
    CHECK(sctx != nullptr);
    CHECK(SSL_CTX_use_certificate(sctx, x) == 1);
    CHECK(SSL_CTX_use_PrivateKey(sctx, pkey) == 1);
    CHECK(SSL_CTX_set1_ech_keys(sctx, keys) == 1);

    SSL_CTX* cctx = SSL_CTX_new(TLS_client_method());
    SSL* client = SSL_new(cctx);
    SSL* server = SSL_new(sctx);
    CHECK(SSL_set1_ech_config_list(client, retry, retry_len) == 1);
    SSL_set_tlsext_host_name(client, "localhost");
    SSL_set_min_proto_version(client, TLS1_3_VERSION);
    SSL_set_verify(client, SSL_VERIFY_NONE, nullptr);
    OPENSSL_free(retry);

    BIO* c_in = BIO_new(BIO_s_mem());
    BIO* c_out = BIO_new(BIO_s_mem());
    BIO* s_in = BIO_new(BIO_s_mem());
    BIO* s_out = BIO_new(BIO_s_mem());
    SSL_set_bio(client, c_in, c_out);
    SSL_set_bio(server, s_in, s_out);
    SSL_set_connect_state(client);
    SSL_set_accept_state(server);

    //双向泵握手数据
    for(int i = 0; i < 20 && !(SSL_is_init_finished(client) && SSL_is_init_finished(server)); i++) {
        if(!SSL_is_init_finished(client)) {
            SSL_do_handshake(client);
        }
        if(!SSL_is_init_finished(server)) {
            SSL_do_handshake(server);
        }
        char buf[4096];
        int len;
        while((len = (int)BIO_read(c_out, buf, sizeof(buf))) > 0) {
            CHECK(BIO_write(s_in, buf, len) == len);
        }
        while((len = (int)BIO_read(s_out, buf, sizeof(buf))) > 0) {
            CHECK(BIO_write(c_in, buf, len) == len);
        }
        if(!SSL_is_init_finished(server)) {
            SSL_do_handshake(server);
        }
        while((len = (int)BIO_read(s_out, buf, sizeof(buf))) > 0) {
            CHECK(BIO_write(c_in, buf, len) == len);
        }
    }
    CHECK(SSL_is_init_finished(client));
    CHECK(SSL_is_init_finished(server));
    int ret = 0;
    if(!SSL_ech_accepted(client) || !SSL_ech_accepted(server)) {
        fprintf(stderr, "loopback ech not accepted\n");
        ret = 1;
    }
    printf("loopback ech: %s\n", ret == 0 ? "accepted" : "failed");
    SSL_free(client);
    SSL_free(server);
    SSL_CTX_free(cctx);
    SSL_CTX_free(sctx);
    X509_free(x);
    EVP_PKEY_free(pkey);
    SSL_ECH_KEYS_free(keys);
    EVP_HPKE_KEY_free(hpke_key);
    return ret;
}
#endif

int main(int argc, char** argv) {
#ifdef HAVE_ECH
    if(argc == 4 && strcmp(argv[1], "-g") == 0) {
        return generate_key_file(argv[2], argv[3]);
    }
    if(argc >= 4 && strcmp(argv[1], "-c") == 0) {
        const char* sni = argc > 4 ? argv[4] : "localhost";
        char* colon = strrchr(argv[2], ':');
        if(colon == nullptr) {
            fprintf(stderr, "usage: %s -c host:port base64ech [sni]\n", argv[0]);
            return 1;
        }
        *colon = 0;
        return ech_connect(argv[2], (uint16_t)atoi(colon + 1), argv[3], sni);
    }
#else
    if(argc >= 2 && (strcmp(argv[1], "-g") == 0 || strcmp(argv[1], "-c") == 0)) {
        fprintf(stderr, "ech is not supported by this build\n");
        return 77; //SKIP
    }
#endif
    test_parse();
#ifdef HAVE_ECH
    return loopback_test();
#else
    printf("loopback ech: skipped (HAVE_ECH not defined)\n");
    return 0;
#endif
}
