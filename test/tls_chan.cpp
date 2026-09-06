//TLS层channel实现，设计说明见tls_chan.h
#include "tls_chan.h"
#include "misc/util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <algorithm>

#include <openssl/err.h>
#include <openssl/x509.h>
#ifdef HAVE_ECH
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/hpke.h>
#include <openssl/rand.h>
#endif

//本文件编入工程的misc/util.c(base64编解码，ech密钥文件/DNS RR与
//ECHConfigList解析共用，与tls.c同源)，桩掉util.o引用而测试不用的符号
//(与h2_chan.cpp桩hpack.o同款做法)
extern "C" {
void addrstring(const struct sockaddr_storage*, char*, size_t) {}
void demangle_func(char*, int) {}
}

//打印协商结果与对端证书供脚本断言(ech为空/"grease"/base64)，返回ech是否按预期接受
static int report_tls_result(SSL* ssl, const std::string& ech) {
    bool ech_ok = true;
#ifdef HAVE_ECH
    if(ech == "grease") {
        printf("ech grease, tls %s\n", SSL_get_version(ssl));
    }else if(!ech.empty()) {
        ech_ok = SSL_ech_accepted(ssl) == 1;
        printf("ech %s, tls %s\n", ech_ok ? "accepted" : "NOT accepted", SSL_get_version(ssl));
    }else{
        printf("tls %s\n", SSL_get_version(ssl));
    }
#else
    (void)ech;
    printf("tls %s\n", SSL_get_version(ssl));
#endif
    const unsigned char* alpn = nullptr;
    unsigned int alpn_len = 0;
    SSL_get0_alpn_selected(ssl, &alpn, &alpn_len);
    if(alpn) {
        printf("alpn: %.*s\n", alpn_len, (const char*)alpn);
    }else{
        printf("alpn: none\n");
    }
    X509* cert = SSL_get_peer_certificate(ssl);
    if(cert) {
        char* subj = X509_NAME_oneline(X509_get_subject_name(cert), nullptr, 0);
        char* issuer = X509_NAME_oneline(X509_get_issuer_name(cert), nullptr, 0);
        printf("cert subject: %s, issuer: %s\n", subj ? subj : "?", issuer ? issuer : "?");
        OPENSSL_free(subj);
        OPENSSL_free(issuer);
        X509_free(cert);
    }
    return ech_ok ? 0 : -2;
}

//创建内嵌mem-BIO的客户端SSL并完成ech/sni/alpn配置，握手收发由调用方驱动
static SSL* tls_ssl_new(const std::string& sni, const std::string& ech,
                        const std::string& alpn, SSL_CTX** pctx) {
    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    SSL* ssl = SSL_new(ctx);
    //mem-BIO：不绑定socket，收发一律经下层channel
    SSL_set_bio(ssl, BIO_new(BIO_s_mem()), BIO_new(BIO_s_mem()));
    if(getenv("ECH_DUMP_CH")) {
        //调试：把发出的ClientHello dump到文件，供嗅探层分析
        SSL_CTX_set_msg_callback(ctx,
            [](int write_p, int, int, const void* buf, size_t len, SSL*, void*) {
                if(!write_p || len < 5) {
                    return;
                }
                const unsigned char* p = (const unsigned char*)buf;
                //完整record(5字节头+handshake)或裸handshake消息两种格式都收
                if((p[0] == 0x16 && p[5] == 1) || p[0] == 1) {
                    FILE* f = fopen("ch_dump.bin", "w");
                    if(f) {
                        fwrite(buf, len, 1, f);
                        fclose(f);
                    }
                }
            });
    }
    //ECH只在TLS1.3存在(RFC 9480)，指定ech时限定1.3，否则允许1.2起协商
    SSL_set_min_proto_version(ssl, ech.empty() ? TLS1_2_VERSION : TLS1_3_VERSION);
    SSL_set_tlsext_host_name(ssl, sni.c_str());
#ifdef HAVE_ECH
    if(ech == "grease") {
        SSL_set_enable_ech_grease(ssl, 1);
    }else if(!ech.empty()) {
        static unsigned char config[4096];
        size_t config_len = Base64Decode(ech.c_str(), ech.size(), (char*)config);
        SSL_set1_ech_config_list(ssl, config, config_len);
    }
#endif
    SSL_set_verify(ssl, SSL_VERIFY_NONE, nullptr);
    if(!alpn.empty()) {
        //"h2,http/1.1" -> wire格式(len+proto)序列
        unsigned char wire[256];
        size_t wlen = 0;
        for(size_t i = 0; i <= alpn.size() && wlen < sizeof(wire);) {
            size_t j = alpn.find(',', i);
            if(j == std::string::npos) {
                j = alpn.size();
            }
            size_t plen = std::min(j - i, (size_t)255);
            if(wlen + 1 + plen > sizeof(wire)) {
                break;
            }
            wire[wlen++] = (unsigned char)plen;
            memcpy(wire + wlen, alpn.data() + i, plen);
            wlen += plen;
            i = j + 1;
        }
        SSL_set_alpn_protos(ssl, wire, wlen); //返回0成功，1表示输入畸形，这里构造不会
    }
    *pctx = ctx;
    return ssl;
}

TlsChannel::TlsChannel(std::unique_ptr<Channel> b, const std::string& sni,
                       const std::string& ech0, const std::string& alpn)
        : base(std::move(b)) {
    std::string ech = ech0 == "-" ? "" : ech0;
#ifndef HAVE_ECH
    if(!ech.empty()) {
        fprintf(stderr, "ech is not supported by this build\n");
        close();
        return;
    }
#endif
    ssl = tls_ssl_new(sni, ech, alpn, &ssl_ctx);
    for(;;) {
        int r = SSL_connect(ssl);
        if(r == 1) {
            if(report_tls_result(ssl, ech) != 0) {
                break; //ech未按预期接受，按失败处理
            }
            ok = true;
            return;
        }
        int err = SSL_get_error(ssl, r);
        if(err == SSL_ERROR_WANT_WRITE) {
            if(pump_write() != 0) {
                break;
            }
            continue;
        }
        if(err != SSL_ERROR_WANT_READ) {
            fprintf(stderr, "ssl connect failed: %s\n",
                    ERR_error_string(ERR_get_error(), nullptr));
            break;
        }
        if(pump_write() != 0) {
            fprintf(stderr, "ssl connect failed: send handshake data failed\n");
            break;
        }
        char buf[16384];
        int n = base->read(buf, sizeof(buf), 5000);
        if(n == 0) {
            //下层隧道在对端握手期间EOF，此措辞同时覆盖旧脚本对两条消息的grep
            fprintf(stderr, "ssl connect failed: stream closed during handshake\n");
            break;
        }
        if(n < 0) {
            fprintf(stderr, "ssl connect failed: %s\n", n == -1 ? "timeout" : "read error");
            break;
        }
        BIO_write(SSL_get_rbio(ssl), buf, n);
    }
    close();
}

TlsChannel::~TlsChannel() {
    close();
}

int TlsChannel::pump_write() {
    BIO* wbio = SSL_get_wbio(ssl);
    char out[16384];
    for(;;) {
        int n = BIO_read(wbio, out, sizeof(out));
        if(n <= 0) {
            return 0;
        }
        if(base->write(out, (size_t)n) != 0) {
            return -1;
        }
    }
}

int TlsChannel::read(void* buf, size_t n, int timeout_ms) {
    if(ssl == nullptr) {
        return -2;
    }
    for(;;) {
        int r = SSL_read(ssl, buf, (int)n);
        if(r > 0) {
            return r;
        }
        int err = SSL_get_error(ssl, r);
        if(err == SSL_ERROR_ZERO_RETURN) {
            printf("[tls] eof\n");
            return 0; //收到close_notify
        }
        if(err == SSL_ERROR_WANT_READ) {
            //SSL内部缓冲区已空：去下层读新密文。SSL_read(buf,n)一次取不完时
            //剩余明文留在SSL内部，此循环天然覆盖旧的SSL_pending路径
            char tbuf[16384];
            int br = base->read(tbuf, sizeof(tbuf), timeout_ms);
            if(br > 0) {
                BIO_write(SSL_get_rbio(ssl), tbuf, br);
                continue;
            }
            if(br == 0) {
                //下层EOF：即使对端没发close_notify也按干净EOF上报
                printf("[tls] eof\n");
                return 0;
            }
            return br; //-1超时/-2错误
        }
        if(err == SSL_ERROR_WANT_WRITE) {
            if(pump_write() != 0) {
                return -2;
            }
            continue;
        }
        return -2;
    }
}

int TlsChannel::write(const void* p, size_t n) {
    if(ssl == nullptr) {
        return -1;
    }
    const char* pc = (const char*)p;
    while(n > 0) {
        int w = SSL_write(ssl, pc, (int)n);
        if(w > 0) {
            pc += w;
            n -= (size_t)w;
            continue;
        }
        if(SSL_get_error(ssl, w) == SSL_ERROR_WANT_WRITE && pump_write() == 0) {
            continue;
        }
        return -1;
    }
    //mem-BIO下SSL_write的密文落在wbio里，必须显式排到下层channel
    return pump_write() == 0 ? 0 : -1;
}

void TlsChannel::shutdown_wr() {
    if(ssl == nullptr) {
        return;
    }
    SSL_shutdown(ssl);
    pump_write(); //close_notify落在wbio里，必须显式排到下层
}

void TlsChannel::close() {
    if(ssl) {
        SSL_free(ssl);
        ssl = nullptr;
    }
    if(ssl_ctx) {
        SSL_CTX_free(ssl_ctx);
        ssl_ctx = nullptr;
    }
    if(base) {
        base->close();
        base.reset();
    }
}

#ifdef HAVE_ECH

//按tls.c load_ech_keys的格式落盘
int ech_gen(const std::string& path, const std::string& public_name) {
    EVP_HPKE_KEY* hpke_key = EVP_HPKE_KEY_new();
    SSL_ECH_KEYS* keys = SSL_ECH_KEYS_new();
    if(hpke_key == nullptr || keys == nullptr) {
        EVP_HPKE_KEY_free(hpke_key);
        SSL_ECH_KEYS_free(keys);
        return -2;
    }
    uint8_t config_id = 0;
    RAND_bytes(&config_id, 1);
    uint8_t* marshaled = nullptr;
    size_t marshaled_len = 0;
    uint8_t* retry = nullptr;
    size_t retry_len = 0;
    int ret = -2;
    if(EVP_HPKE_KEY_generate(hpke_key, EVP_hpke_x25519_hkdf_sha256()) != 1 ||
       SSL_marshal_ech_config(&marshaled, &marshaled_len, config_id, hpke_key,
                              public_name.c_str(), public_name.size()) != 1) {
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
        int fd = open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL, 0600);
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
        fprintf(fp, "public_name=%s\n", public_name.c_str());
        Base64Encode((const char*)marshaled, marshaled_len, b64);
        fprintf(fp, "ech_config=%s\n", b64);
        Base64Encode((const char*)private_key, private_key_len, b64);
        fprintf(fp, "private_key=%s\n", b64);
        fclose(fp);
        //DNS HTTPS RR ech参数的值 = retry configs序列化的base64
        if(SSL_ECH_KEYS_marshal_retry_configs(keys, &retry, &retry_len) != 1) {
            goto out;
        }
        Base64Encode((const char*)retry, retry_len, b64);
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

#else

int ech_gen(const std::string&, const std::string&) {
    fprintf(stderr, "ech is not supported by this build\n");
    return -2;
}

#endif
