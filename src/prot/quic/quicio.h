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

class Quic_server;

class Recvq{
public:
    std::list<const quic_frame*> data;
    ~Recvq();
    void insert(const quic_frame* frame);
};

class QuicBase {
protected:
    SslStats sslStats = SslStats::Idel;
    SSL_CTX* ctx = nullptr;  // server will be null
    SSL *ssl = nullptr;
    bool isClosing = false;

    QuicQos qos;
    struct quic_context{
        OSSL_ENCRYPTION_LEVEL  level;
        struct quic_secret     write_secret;
        struct quic_secret     read_secret;
        bool     hasKey = false;
        size_t   crypto_offset = 0;
        size_t   crypto_want = 0;
        //only crypto and stream frame will be buffered
        Recvq    recvq;
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
#define STREAM_FLAG_FIN_SENT    0x01   //已经发送了finsize(stream 或者 reset)
#define STREAM_FLAG_FIN_RECVD   0x02   //收到对方发送的fin标记
#define STREAM_FLAG_FIN_DELIVED 0x04   //fin标记已经发送给应用层了
#define STREAM_FLAG_STOP_SENT     0x10
#define STREAM_FLAG_RESET_RECVD   0x20  //打了这个标记意味者后续数据不会再上送到应用层
#define STREAM_FLAG_RESET_DELIVED 0x40
        uint32_t flags = 0;
        size_t   my_offset = 0;
        size_t   his_offset = 0;
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
    uint64_t my_sent_data_total = 0;
    uint64_t my_received_data = 0;
    uint64_t my_received_data_total = 0;
    uint64_t my_max_payload_size = max_datagram_size;
    uint64_t my_max_data = MAX_BUF_LEN;
    uint64_t my_max_stream_data_bidi_local = BUF_LEN;
    uint64_t my_max_stream_data_bidi_remote = BUF_LEN;
    uint64_t my_max_stream_data_uni = BUF_LEN;
    uint64_t my_max_streams_bidi = 100;
    uint64_t my_max_streams_uni = 10;

    void sinkData(uint64_t id, QuicStreamStatus& status);
    void sinkData(uint64_t id);
    void reorderData();
    void walkPacket(const void* buff, size_t length);

    void generateCid();
    size_t generateParams(char data[QUIC_INITIAL_LIMIT]);
    void getParams(const uint8_t* data, size_t len);
    quic_context* getContext(uint8_t type);
    void dropkey(OSSL_ENCRYPTION_LEVEL level);

    enum class FrameResult{
        ok,
        skip,
        error,
    };
    virtual FrameResult handleCryptoFrame(quic_context* context, const quic_crypto* crypto);
    virtual FrameResult handleStreamFrame(uint64_t type, const quic_stream* stream);
    virtual FrameResult handleResetFrame(const quic_reset *stream);
    virtual FrameResult handleHandshakeFrames(quic_context* context, const quic_frame* frame);
    virtual FrameResult handleFrames(quic_context* context, const quic_frame* frame);

    std::function<int(const quic_pkt_header* header, std::vector<const quic_frame*>& frames)> walkHandler;
    virtual int handleHandshakePacket(const quic_pkt_header* header, std::vector<const quic_frame*>& frames);
    virtual int handleRetryPacket(const quic_pkt_header* header);
    virtual int handle1RttPacket(const quic_pkt_header* header, std::vector<const quic_frame*>& frames);
    virtual int handlePacket(const quic_pkt_header* header, std::vector<const quic_frame*>& frames);
    bool checkStatelessReset(const void* may_be_token);

    using iterator = typename decltype(streammap)::iterator;
    iterator openStream(uint64_t id);
    void cleanStream(uint64_t id);
    bool isLocal(uint64_t id);
    static bool isBidirect(uint64_t id);

    size_t envelopLen(OSSL_ENCRYPTION_LEVEL level, uint64_t pn, uint64_t ack, size_t len);
    size_t envelop(OSSL_ENCRYPTION_LEVEL level, uint64_t pn, uint64_t ack, const char *in, size_t len, void *out);
    std::list<quic_packet_pn> send(OSSL_ENCRYPTION_LEVEL level,
                                   uint64_t pn, uint64_t ack,
                                   std::list<quic_frame*>& pend_frames, size_t window);
    void resendFrames(pn_namespace* ns, quic_frame* frame);


    Job keepAlive_timer = nullptr;
    void keepAlive_action();
    Job disconnect_timer = nullptr;
    void disconnect_action();
    Job close_timer = nullptr;

    virtual size_t getWritableSize() = 0;
    virtual ssize_t writem(const struct iovec *iov, int iovcnt) = 0;
    virtual void onError(int type, int code) = 0;
    virtual size_t onRead(const Buffer& bb) = 0;
    virtual void onWrite(uint64_t id) = 0;
    virtual void onReset(uint64_t id, uint32_t error) = 0;
    virtual void onConnected() = 0;
    virtual void onCidChange(const std::string& /*cid*/, bool /*retired*/) {}
public:
    explicit QuicBase(const char* hostname);
    explicit QuicBase(SSL_CTX* ctx);

    ~QuicBase();


    static int set_encryption_secrets(SSL *ssl, OSSL_ENCRYPTION_LEVEL level,
                                      const uint8_t *read_secret,
                                      const uint8_t *write_secret, size_t secret_len);
    static int add_handshake_data(SSL *ssl, OSSL_ENCRYPTION_LEVEL level,
                                  const uint8_t *data, size_t len);
    static int flush_flight(SSL *ssl);
    static int send_alert(SSL *ssl, OSSL_ENCRYPTION_LEVEL level, uint8_t alert);

    int doSslConnect(const char* hostname);
    void walkPackets(const iovec* iov, int iovcnt);
    void sendData(Buffer&& bb);
    void reset(uint64_t id, uint32_t code);
    void close();

    bool idle(uint64_t id);
    ssize_t window(uint64_t id);
    void getAlpn(const unsigned char **s, unsigned int * len);
    int setAlpn(const unsigned char *s, unsigned int len);
    uint64_t createBiStream();
    uint64_t createUbiStream();
};

class QuicRWer: public QuicBase, public SocketRWer {
protected:
    Quic_server* server = nullptr;
    size_t sndbuf = 0;

    virtual size_t getWritableSize()  override;
    virtual ssize_t writem(const struct iovec *iov, int iovcnt) override;
    virtual void onConnected() override;
    virtual void onError(int type, int code) override;
    virtual size_t onRead(const Buffer& bb) override;
    virtual void onWrite(uint64_t id) override;
    virtual void onReset(uint64_t id, uint32_t error) override;
    virtual void onCidChange(const std::string& cid, bool retired) override;
    virtual int handleRetryPacket(const quic_pkt_header* header) override;

    virtual void waitconnectHE(RW_EVENT events) override;
    virtual void closeHE(RW_EVENT events) override;
    virtual void ReadData() override;
    virtual void ConsumeRData(uint64_t id) override;
    virtual size_t rlength(uint64_t id) override;
    virtual bool IsConnected() override;

    std::function<void(uint64_t id, uint32_t error)> resetHandler = [](uint64_t, uint32_t){};
public:
    explicit QuicRWer(const char* hostname, uint16_t port, Protocol protocol,
             std::function<void(int, int)> errorCB);
    explicit QuicRWer(int fd, const sockaddr_storage *peer, SSL_CTX *ctx, Quic_server* server);
    void setResetHandler(std::function<void(uint64_t id, uint32_t error)> func);
    virtual void buffer_insert(Buffer&& bb) override;
    virtual void Close(std::function<void()> func) override;
    virtual bool idle(uint64_t id) override {
        return QuicBase::idle(id);
    }
    virtual ssize_t cap(uint64_t id) override {
        return window(id);
    }

    ~QuicRWer();

    virtual void dump_status(Dumper dp, void* param) override;
    virtual size_t mem_usage() override;
};

#endif //SPROXY_QUICIO_H
