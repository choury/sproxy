//ech单测：HTTPS RR ech参数解析、RR改写、内存BIO双端ECH握手。
#include "dns.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <string>
#include <vector>

//握手、密钥生成等副作用都写在检查表达式里，assert在NDEBUG构建下会被编译掉，
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

static void test_rewrite() {
    const unsigned char list1[] = {0x00, 0x04, 0xfe, 0x0d, 0x00, 0x01};
    const unsigned char list2[] = {0x00, 0x04, 0xfe, 0x0d, 0x00, 0x02};
    in_addr fake4;
    in6_addr fake6;
    CHECK(inet_pton(AF_INET, "198.18.0.5", &fake4) == 1);
    CHECK(inet_pton(AF_INET6, "64:ff9b::198.18.0.5", &fake6) == 1);
    in_addr real4s[2];
    in6_addr real6s[2];
    CHECK(inet_pton(AF_INET, "93.184.216.34", &real4s[0]) == 1);
    CHECK(inet_pton(AF_INET, "1.2.3.4", &real4s[1]) == 1);
    CHECK(inet_pton(AF_INET6, "2606:2800:220:1::1", &real6s[0]) == 1);
    CHECK(inet_pton(AF_INET6, "2606:2800:220:1::2", &real6s[1]) == 1);

    //改写后与"用期望参数重建的报文"逐字节对比
    auto check_rewrite = [](const std::string& in, const std::string& expect, unsigned flags,
                            const in_addr* v4, const in6_addr* v6) {
        std::string wr(in);
        size_t newlen = rewrite_https_rr((unsigned char*)wr.data(), wr.size(), flags, v4, v6);
        CHECK(newlen == expect.size());
        CHECK(wr.compare(0, newlen, expect) == 0);
    };

    //1. ech剥离：alpn+ech混排，只删ech，alpn原样，报文收缩
    check_rewrite(
        build_response({svcb_rdata(1, ".", {{1, std::string("\x02h2")}, {5, raw(list1, sizeof(list1))}})}),
        build_response({svcb_rdata(1, ".", {{1, std::string("\x02h2")}})}),
        HTTPS_RR_STRIP_ECH, nullptr, nullptr);

    //2. 多RR且ech跨记录分布：全部剥离，ancount不变，改写后可重新parse且无ech
    {
        std::string in = build_response({svcb_rdata(1, ".", {{5, raw(list1, sizeof(list1))}}),
                                         svcb_rdata(2, ".", {{5, raw(list2, sizeof(list2))}})});
        std::string wr(in);
        size_t newlen = rewrite_https_rr((unsigned char*)wr.data(), wr.size(), HTTPS_RR_STRIP_ECH, nullptr, nullptr);
        std::string expect = build_response({svcb_rdata(1, ".", {}), svcb_rdata(2, ".", {})});
        CHECK(newlen == expect.size());
        CHECK(wr.compare(0, newlen, expect) == 0);
        //ancount不变(2)
        CHECK(ntohs(((const uint16_t*)wr.data())[3]) == 2);
        std::string ech; uint32_t ttl;
        CHECK(parse_ech_configs(wr.data(), newlen, ech, &ttl) == 0 && ech.empty());
    }

    //3. FAKE_V4：双地址hint替换为单假地址
    check_rewrite(
        build_response({svcb_rdata(1, ".", {{4, raw((const unsigned char*)real4s, sizeof(real4s))}})}),
        build_response({svcb_rdata(1, ".", {{4, raw((const unsigned char*)&fake4, 4)}})}),
        HTTPS_RR_FAKE_V4HINT, &fake4, nullptr);

    //4. FAKE_V6：双地址hint替换为单假地址
    check_rewrite(
        build_response({svcb_rdata(1, ".", {{6, raw((const unsigned char*)real6s, sizeof(real6s))}})}),
        build_response({svcb_rdata(1, ".", {{6, raw((const unsigned char*)&fake6, 16)}})}),
        HTTPS_RR_FAKE_V6HINT, nullptr, &fake6);

    //5. DROP_V6：ipv6hint整段删除
    check_rewrite(
        build_response({svcb_rdata(1, ".", {{6, raw((const unsigned char*)real6s, sizeof(real6s))},
                                            {1, std::string("\x02h3")}})}),
        build_response({svcb_rdata(1, ".", {{1, std::string("\x02h3")}})}),
        HTTPS_RR_DROP_V6HINT, nullptr, nullptr);

    //6. 混合flags：ech剥离+hint替换+无关参数(mandatory key 0)原样
    check_rewrite(
        build_response({svcb_rdata(1, ".",
            {{0, std::string("\x00\x01")},
             {5, raw(list1, sizeof(list1))},
             {4, raw((const unsigned char*)real4s, sizeof(real4s))}})}),
        build_response({svcb_rdata(1, ".",
            {{0, std::string("\x00\x01")},
             {4, raw((const unsigned char*)&fake4, 4)}})}),
        HTTPS_RR_STRIP_ECH | HTTPS_RR_FAKE_V4HINT, &fake4, nullptr);

    //7. AliasMode(priority=0)与flags=0：均原样返回
    {
        std::string in = build_response({svcb_rdata(0, "alias.example.com", {})});
        std::string wr(in);
        CHECK(rewrite_https_rr((unsigned char*)wr.data(), wr.size(), HTTPS_RR_STRIP_ECH, nullptr, nullptr) == in.size());
        CHECK(wr == in);
        CHECK(rewrite_https_rr((unsigned char*)wr.data(), wr.size(), 0, &fake4, &fake6) == in.size());
    }

    //8. 畸形SvcParam声明长度越界(尾部残余)：不改写，原样返回
    {
        std::string bad = svcb_rdata(1, ".", {});
        put16(bad, 5);
        put16(bad, 100); //声明100字节但后面没有了
        std::string in = build_response({bad});
        std::string wr(in);
        CHECK(rewrite_https_rr((unsigned char*)wr.data(), wr.size(), HTTPS_RR_STRIP_ECH, nullptr, nullptr) == in.size());
        CHECK(wr == in);
    }

    //9. 空ipv4hint(无法容纳替换值)：参数被丢弃
    check_rewrite(
        build_response({svcb_rdata(1, ".", {{4, std::string()}, {1, std::string("\x02h2")}})}),
        build_response({svcb_rdata(1, ".", {{1, std::string("\x02h2")}})}),
        HTTPS_RR_FAKE_V4HINT, &fake4, nullptr);

    //10. get_dns_question
    {
        char domain[DOMAINLIMIT];
        uint16_t qtype = 0;
        auto pkt = build_response({svcb_rdata(1, ".", {{5, raw(list1, sizeof(list1))}})});
        CHECK(get_dns_question(pkt.data(), pkt.size(), domain, sizeof(domain), &qtype) == 0);
        CHECK(strcmp(domain, "example.com") == 0);
        CHECK(qtype == ns_t_https);
        //畸形报文
        CHECK(get_dns_question(pkt.data(), 4, domain, sizeof(domain), &qtype) == -1);
    }

    printf("rewrite_https_rr: all passed\n");
}

#ifdef HAVE_ECH

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

int main() {
    test_parse();
    test_rewrite();
#ifdef HAVE_ECH
    return loopback_test();
#else
    printf("loopback ech: skipped (HAVE_ECH not defined)\n");
    return 0;
#endif
}
