//
// Created by 周威 on 2021/6/20.
//

#ifndef SPROXY_QUICIO_H
#define SPROXY_QUICIO_H

#include "prot/netio.h"
#include "quic_pack.h"
#include "quic_qos.h"
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <list>
#include <map>

#define QUIC_CIPHERS                                              \
   "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:"               \
   "TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_CCM_SHA256"

#define QUIC_GROUPS "P-256:X25519:P-384:P-521"

#define QUIC_CID_LEN     20

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

class QuicMgr;

class QuicRWer: public SocketRWer {
protected:
    SSL_CTX* ctx = nullptr;  // server will be null
    SSL *ssl = nullptr;
    QuicMgr* mgr = nullptr;

    QuicQos qos;
    struct quic_context{
        OSSL_ENCRYPTION_LEVEL  level;
        struct quic_secret     write_secret;
        struct quic_secret     read_secret;
        bool     hasKey = false;
        size_t   crypto_offset = 0;
        size_t   crypto_want = 0;
        //only crypto and stream frame will be buffered
        std::multimap<uint64_t, const quic_frame*> recvq;
    } contexts[4];
    struct cid{
        std::string id;
        char token[16];
    };
    std::vector<std::string> myids;
    size_t myid_idx = 0;
    std::vector<std::string> hisids;
    std::vector<std::string> histoken;
    size_t hisid_idx = 0;
    std::string initToken;
    std::string originDcid;
    struct QuicStreamStatus{
#define STREAM_FLAG_FIN_SENT    0x01   //已经发送了fin标记
#define STREAM_FLAG_FIN_RECVD   0x02   //收到对方发送的fin标记
#define STREAM_FLAG_FIN_DELIVED 0x04   //fin标记已经发送给应用层了
#define STREAM_FLAG_RESET_SENT    0x10
#define STREAM_FLAG_RESET_RECVD   0x20
#define STREAM_FLAG_RESET_DELIVED 0x40
        uint32_t flags = 0;
        size_t   offset = 0;
        size_t   finSize = 0;
        uint64_t my_max_data = 0;
        uint64_t his_max_data = 0;
        EBuffer  rb;
    };
    size_t   rblen = 0;
    uint64_t nextLocalUbiId;
    uint64_t nextRemoteUbiId;
    uint64_t nextLocalBiId;
    uint64_t nextRemoteBiId;
    std::map <uint64_t, QuicStreamStatus> streammap;
    std::list<quic_frame*> fullq;

    uint64_t max_idle_timeout = 120000;
    uint64_t his_max_payload_size = 65527;
    uint64_t his_max_data = 0;
    uint64_t his_max_stream_data_bidi_local = 0;
    uint64_t his_max_stream_data_bidi_remote = 0;
    uint64_t his_max_stream_data_uni = 0;
    uint64_t his_max_streams_bidi = 0;
    uint64_t his_max_streams_uni = 0;
    uint64_t his_max_ack_delay = 0;

    uint64_t my_sent_data = 0;
    uint64_t my_received_data = 0;
    uint64_t my_max_payload_size = max_datagram_size;
    uint64_t my_max_data = 1024 * 1024;
    uint64_t my_max_stream_data_bidi_local = BUF_LEN;
    uint64_t my_max_stream_data_bidi_remote = BUF_LEN;
    uint64_t my_max_stream_data_uni = BUF_LEN;
    uint64_t my_max_streams_bidi = 100;
    uint64_t my_max_streams_uni = 10;

    virtual void waitconnectHE(RW_EVENT events) override;
    virtual void closeHE(RW_EVENT events) override;

    virtual void ReadData() override;
    virtual void ConsumeRData() override;
    virtual size_t rlength() override;
    virtual ssize_t cap(uint64_t id) override;
    virtual ssize_t Write(const void* buff, size_t len, uint64_t id) override;

    void generateCid();
    size_t generateParams(char data[QUIC_INITIAL_LIMIT]);
    quic_context* getContext(uint8_t type);
    void dropkey(OSSL_ENCRYPTION_LEVEL level);

    enum class FrameResult{
        ok,
        skip,
        error,
    };
    FrameResult handleCryptoFrame(quic_context* context, const quic_crypto* crypto);
    FrameResult handleStreamFrame(uint64_t type, const quic_stream* stream);
    FrameResult handleResetFrame(const quic_reset *stream);
    FrameResult handleHandshakeFrames(quic_context* context, const quic_frame* frame);
    FrameResult handleFrames(quic_context* context, const quic_frame* frame);

    std::function<int(const quic_pkt_header* header, std::vector<const quic_frame*>& frames)> walkHandler;
    int handleHandshakePacket(const quic_pkt_header* header, std::vector<const quic_frame*>& frames);
    int handleRetryPacket(const quic_pkt_header* header);
    int handle1RttPacket(const quic_pkt_header* header, std::vector<const quic_frame*>& frames);
    int handlePacket(const quic_pkt_header* header, std::vector<const quic_frame*>& frames);
    bool checkStatelessReset(const void* may_be_token);

    using iterator = typename decltype(streammap)::iterator;
    iterator OpenStream(uint64_t id);
    void CleanStream(uint64_t id);
    bool IsLocal(uint64_t id);
    static bool IsBidirect(uint64_t id);

    size_t envelopLen(OSSL_ENCRYPTION_LEVEL level, uint64_t pn, uint64_t ack, size_t len);
    int send(OSSL_ENCRYPTION_LEVEL level, uint64_t pn, uint64_t ack, const void* body, size_t len);
    void resendFrames(pn_namespace* ns, quic_frame* frame);
    Job* keepAlive_timer = nullptr;
    void keepAlive_action();
    Job* disconnect_timer = nullptr;
    void disconnect_action();
    Job* close_timer = nullptr;

    std::function<void(uint64_t id, uint32_t error)> resetHandler = nullptr;
public:
    explicit QuicRWer(const char* hostname, uint16_t port, Protocol protocol,
                     std::function<void(int ret, int code)> errorCB,
                     std::function<void(const sockaddr_storage&)> connectCB = nullptr);
    explicit QuicRWer(int fd, const sockaddr_storage* peer, SSL_CTX* ctx, QuicMgr* mgr,
                     std::function<void(int ret, int code)> errorCB,
                     std::function<void(const sockaddr_storage&)> connectCB = nullptr);
    virtual ~QuicRWer() override;
    virtual buff_iterator buffer_insert(buff_iterator where, Buffer&& bb) override;

    //virtual void Shutdown() override;
    virtual void Close(std::function<void()> func) override;

    void setResetHandler(std::function<void(uint64_t id, uint32_t error)> func);
    void Reset(uint64_t id, uint32_t code);

    static int set_encryption_secrets(SSL *ssl, OSSL_ENCRYPTION_LEVEL level,
                                      const uint8_t *read_secret,
                                      const uint8_t *write_secret, size_t secret_len);
    static int add_handshake_data(SSL *ssl, OSSL_ENCRYPTION_LEVEL level,
                                  const uint8_t *data, size_t len);
    static int flush_flight(SSL *ssl);
    static int send_alert(SSL *ssl, OSSL_ENCRYPTION_LEVEL level, uint8_t alert);

    void walkPackets(const void* buff, size_t length);
    void reorderData();

    virtual bool idle(uint64_t id) override;
    void get_alpn(const unsigned char **s, unsigned int * len);
    int set_alpn(const unsigned char *s, unsigned int len);
    uint64_t CreateBiStream();
    uint64_t CreateUbiStream();
};

#endif //SPROXY_QUICIO_H
