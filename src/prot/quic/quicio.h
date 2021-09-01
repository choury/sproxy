//
// Created by 周威 on 2021/6/20.
//

#ifndef SPROXY_QUICIO_H
#define SPROXY_QUICIO_H

#include "prot/netio.h"
#include "quic_pack.h"
#include "quic_pn.h"
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <list>
#include <map>

#define QUIC_CID_LEN     20

enum class PacketResult{
    ok,
    skip,
    error,
};

/*
       o
       | Create Stream (Sending)
       | Peer Creates Bidirectional Stream
       v
   +-------+
   | Ready | Send RESET_STREAM
   |       |-----------------------.
   +-------+                       |
       |                           |
       | Send STREAM /             |
       |      STREAM_DATA_BLOCKED  |
       v                           |
   +-------+                       |
   | Send  | Send RESET_STREAM     |
   |       |---------------------->|
   +-------+                       |
       |                           |
       | Send STREAM + FIN         |
       v                           v
   +-------+                   +-------+
   | Data  | Send RESET_STREAM | Reset |
   | Sent  |------------------>| Sent  |
   +-------+                   +-------+
       |                           |
       | Recv All ACKs             | Recv ACK
       v                           v
   +-------+                   +-------+
   | Data  |                   | Reset |
   | Recvd |                   | Recvd |
   +-------+                   +-------+
 */

/*
       o
       | Recv STREAM / STREAM_DATA_BLOCKED / RESET_STREAM
       | Create Bidirectional Stream (Sending)
       | Recv MAX_STREAM_DATA / STOP_SENDING (Bidirectional)
       | Create Higher-Numbered Stream
       v
   +-------+
   | Recv  | Recv RESET_STREAM
   |       |-----------------------.
   +-------+                       |
       |                           |
       | Recv STREAM + FIN         |
       v                           |
   +-------+                       |
   | Size  | Recv RESET_STREAM     |
   | Known |---------------------->|
   +-------+                       |
       |                           |
       | Recv All Data             |
       v                           v
   +-------+ Recv RESET_STREAM +-------+
   | Data  |--- (optional) --->| Reset |
   | Recvd |  Recv All Data    | Recvd |
   +-------+<-- (optional) ----+-------+
       |                           |
       | App Read All Data         | App Read Reset
       v                           v
   +-------+                   +-------+
   | Data  |                   | Reset |
   | Read  |                   | Read  |
   +-------+                   +-------+
 */


struct quic_packet{
    quic_pkt_header header;
    std::vector<quic_frame*> frames;
};

class QuicRWer: public SocketRWer {
protected:
    SSL_CTX* ctx = nullptr;
    SSL *ssl = nullptr;
    struct {
        bool valid = false;
        struct quic_secret   write_secret;
        struct quic_secret   read_secret;
        size_t crypto_offset = 0;
        size_t crypto_want = 0;
        pn_namespace* pnNs;
    }context[4];

    struct cid{
        std::string id;
        char token[16];
    };
    std::vector<cid> scids;
    size_t scid_id = 0;
    std::vector<cid> dcids;
    size_t dcid_id = 0;
    std::string initToken;
    std::list <quic_packet*> recvq;

    struct QuicStreamStatus{
#define STREAM_FLAG_FIN    0x01
#define STREAM_FLAG_EOF    0x02
#define STREAM_FLAG_RESET  0x04
        uint32_t flags = 0;
        size_t   offset = 0;
        size_t   finSize = 0;
        uint64_t my_max_data = 0;
        uint64_t his_max_data = 0;
        CBuffer  rb;
    };
    size_t   rblen = 0;
    uint64_t nextLocalUbiId;
    uint64_t nextRemoteUbiId;
    uint64_t nextLocalBiId;
    uint64_t nextRemoteBiId;
    std::map <uint64_t, QuicStreamStatus> streammap;
    using iterator = typename decltype(streammap)::iterator;
    iterator OpenStream(uint64_t id);
    bool IsLocal(uint64_t id);
    bool IsBidirect(uint64_t id);
    bool IsIdle(uint64_t id);
    uint64_t max_idle_timeout = 120000;

    uint64_t his_max_payload_size = 65527;
    uint64_t his_max_data = 0;
    uint64_t his_max_stream_data_bidi_local = 0;
    uint64_t his_max_stream_data_bidi_remote = 0;
    uint64_t his_max_stream_data_uni = 0;
    uint64_t his_max_streams_bidi = 0;
    uint64_t his_max_streams_uni = 0;
    uint64_t his_max_ack_delay = 25;

    uint64_t my_send_data = 0;
    uint64_t my_received_data = 0;
    uint64_t my_max_payload_size = 1280;
    uint64_t my_max_data = 1024 * 1024;
    uint64_t my_max_stream_data_bidi_local = BUF_LEN;
    uint64_t my_max_stream_data_bidi_remote = BUF_LEN;
    uint64_t my_max_stream_data_uni = BUF_LEN;
    uint64_t my_max_streams_bidi = 100;
    uint64_t my_max_streams_uni = 10;

    virtual void ReadData() override;
    virtual void ConsumeRData() override;
    virtual size_t rlength() override;
    virtual ssize_t Write(const void* buff, size_t len, uint64_t id) override;

    void generateCid();
    size_t generateParams(char data[QUIC_INITIAL_LIMIT]);
    void dropkey(OSSL_ENCRYPTION_LEVEL level);
    PacketResult handleCryptoPacket(const quic_crypto* crypto, OSSL_ENCRYPTION_LEVEL level);
    PacketResult handleStreamPacket(uint64_t type, const quic_stream* stream);
    PacketResult handlePacketBeforeHandshake(const quic_packet *packet);
    PacketResult handlePacket(const quic_packet* packet);
    void handleRetryPacket(const quic_pkt_header* header);

    int sendNsPacket(OSSL_ENCRYPTION_LEVEL level, pn_namespace* pnNs);
    void sendPacket();
    void PushFrame(pn_namespace* pnNs, quic_frame* frame);
    Job* packet_tx = nullptr;
    Job* keep_alive = nullptr;
    void keepAlive();
    Job* time_out = nullptr;
    void timedOut();
public:
    explicit QuicRWer(const char* hostname, uint16_t port, Protocol protocol,
                     std::function<void(int ret, int code)> errorCB,
                     std::function<void(const sockaddr_storage&)> connectCB = nullptr);
    virtual ~QuicRWer() override;
    void Reset(uint64_t id, uint32_t code);

    virtual void waitconnectHE(RW_EVENT events) override;


    static int set_encryption_secrets(SSL *ssl, OSSL_ENCRYPTION_LEVEL level,
                                      const uint8_t *read_secret,
                                      const uint8_t *write_secret, size_t secret_len);
    static int add_handshake_data(SSL *ssl, OSSL_ENCRYPTION_LEVEL level,
                                  const uint8_t *data, size_t len);
    static int flush_flight(SSL *ssl);
    static int send_alert(SSL *ssl, OSSL_ENCRYPTION_LEVEL level, uint8_t alert);

    void get_alpn(const unsigned char **s, unsigned int * len);
    int set_alpn(const unsigned char *s, unsigned int len);
    uint64_t CreateBiStream();
    uint64_t CreateUbiStream();
};

#endif //SPROXY_QUICIO_H
