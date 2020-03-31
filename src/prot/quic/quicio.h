//
// Created by 周威 on 2021/6/20.
//

#ifndef SPROXY_QUICIO_H
#define SPROXY_QUICIO_H

#include "prot/netio.h"
#include "quic_pack.h"
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <list>
#include <map>

enum class PacketResult{
    ok,
    skip,
    error,
};

struct quic_frame_pn{
    uint64_t pn;
    struct quic_frame* frame;
};

struct quic_packet{
    quic_pkt_header header;
    std::vector<quic_frame*> frames;
};

struct pn_namespace{
    uint64_t pn_current = 0;
    uint64_t pn_seen = 0;
    uint64_t pn_acked = 0;
    uint64_t seen_time = 0;
    std::list <quic_frame*>   pendq;
    std::list <quic_frame_pn> sendq;
};

struct QuicStreamStat{
    uint64_t offset = 0;
};

class QuicRWer: public SocketRWer {
protected:
    SSL_CTX* ctx = nullptr;
    SSL *ssl = nullptr;
    OSSL_ENCRYPTION_LEVEL level_max = ssl_encryption_initial;
    std::string scid;
    std::string dcid;
    struct {
        bool valid = false;
        struct quic_secret   write_secret;
        struct quic_secret   read_secret;
        size_t crypto_offset = 0;
        size_t crypto_want = 0;
        struct pn_namespace* pnNs;
    }sctx[4];
    std::list <quic_packet*> recvq;
    uint64_t stream_current = 0x04;
    std::map <uint64_t, QuicStreamStat> streammap;
    virtual void ReadData() override;
    virtual size_t rlength() override;
    virtual size_t rleft() override;
    virtual const char* rdata() override;
    virtual void consume(const char* data, size_t l) override;
    virtual ssize_t Write(const void* buff, size_t len) override;

    void generatecid();
    void dropkey(OSSL_ENCRYPTION_LEVEL level);
    PacketResult handlePacketBeforeHandshake(const quic_packet *packet);
    PacketResult handlePacket(const quic_packet* packet);

    int sendNsPacket(OSSL_ENCRYPTION_LEVEL level, pn_namespace* pnNs);
    void sendPacket();
    void PushFrame(pn_namespace* pnNs, quic_frame* frame);
    Job* packet_tx = nullptr;
public:
    explicit QuicRWer(const char* hostname, uint16_t port, Protocol protocol,
                     std::function<void(int ret, int code)> errorCB,
                     std::function<void(const sockaddr_storage&)> connectCB = nullptr);
    virtual ~QuicRWer() override;

    virtual void waitconnectHE(RW_EVENT events) override;


    static int set_encryption_secrets(SSL *ssl, OSSL_ENCRYPTION_LEVEL level,
                                      const uint8_t *read_secret,
                                      const uint8_t *write_secret, size_t secret_len);

    static int add_handshake_data(SSL *ssl, OSSL_ENCRYPTION_LEVEL level,
                                  const uint8_t *data, size_t len);

    static int flush_flight(SSL *ssl);

    static int send_alert(SSL *ssl, enum ssl_encryption_level_t level, uint8_t alert);

    void get_alpn(const unsigned char **s, unsigned int * len);
    int set_alpn(const unsigned char *s, unsigned int len);
};

#endif //SPROXY_QUICIO_H
