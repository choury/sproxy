//
// Created by choury on 2021/8/22.
//

#ifndef SPROXY_QUIC_QOS_H
#define SPROXY_QUIC_QOS_H

#include "pn_namespace.h"
#include "misc/job.h"

#include <openssl/ssl.h>
#include <stdint.h>

const uint64_t max_datagram_size = 1500;
const uint64_t kInitialWindow = 14720;
const uint64_t kMinimumWindow = 2 * max_datagram_size;
const uint64_t kGranularity = 1000; // 1ms

#define QUIC_PACKET_NAMESPACE_INITIAL 0
#define QUIC_PACKET_NAMESPACE_HANDSHAKE 1
#define QUIC_PAKCET_NAMESPACE_APP 2

#ifdef USE_BORINGSSL
typedef  enum ssl_encryption_level_t OSSL_ENCRYPTION_LEVEL;
#endif

class QuicQos {
protected:
    size_t pto_count = 0;
    size_t bytes_in_flight = 0;
    uint64_t last_receipt_ack_time = 0;
    uint64_t his_max_ack_delay = 0;
    bool has_packet_been_congested = false;
    bool has_drain_all = false;

    //used for bbr
    size_t delivered_bytes = 0;
    size_t packets_sent = 0;
    uint64_t last_sent_time = 0;
    //end

    pn_namespace* pns[3];
    bool isServer = false;
    Job loss_timer = nullptr;
    void OnLossDetectionTimeout(pn_namespace* ns);
    Job packet_tx = nullptr;
    std::function<void(pn_namespace*, quic_frame*)> resendFrames;
    void maySend();

    bool PeerCompletedAddressValidation();
    void SetLossDetectionTimer();
    virtual void OnPacketsLost(pn_namespace* ns, const std::list<quic_packet_pn>& lost_packets) = 0;
    virtual void OnPacketsAcked(const std::list<quic_packet_meta>& acked_packets) = 0;
    virtual void OnCongestionEvent(uint64_t sent_time) = 0;
public:
    Rtt    rtt;
    /*
    typedef std::function<int(OSSL_ENCRYPTION_LEVEL level, uint64_t pn, uint64_t ack,
            const void* body, size_t len, const std::set<uint64_t>& streams)>  send_func;
            */
    typedef std::function<std::list<quic_packet_pn>(OSSL_ENCRYPTION_LEVEL level,
                                           uint64_t pn, uint64_t ack,
                                           std::list<quic_frame*>& pend_frames, size_t window)> send_func;
    QuicQos(bool isServer, const send_func& sent,
           std::function<void(pn_namespace*, quic_frame*)> resendFrames);
    virtual ~QuicQos();
    virtual void sendPacket(bool force = false);
    virtual void Migrated();
    [[nodiscard]] virtual ssize_t windowLeft() const = 0;
    [[nodiscard]] virtual ssize_t sendWindow() const {
        return windowLeft();
    };
    void KeyGot(OSSL_ENCRYPTION_LEVEL level);
    void KeyLost(OSSL_ENCRYPTION_LEVEL level);
    //set ack_delay_exponent for app level
    void SetAckDelayExponent(uint64_t exponent);
    //set max_ack_delay for app level
    void SetMaxAckDelay(uint64_t delay);
    uint64_t GetLargestPn(OSSL_ENCRYPTION_LEVEL level);
    pn_namespace* GetNamespace(OSSL_ENCRYPTION_LEVEL level);

    std::set<uint64_t> handleFrame(OSSL_ENCRYPTION_LEVEL level, uint64_t number, const quic_frame* frame);
    void HandleRetry();
    void PushFrame(OSSL_ENCRYPTION_LEVEL level, quic_frame* frame);;
    void PushFrame(pn_namespace* ns, quic_frame* frame);
    void FrontFrame(pn_namespace* ns, quic_frame* frame);
    void DrainAll();
    size_t PendingSize(OSSL_ENCRYPTION_LEVEL level);

    size_t mem_usage();
};

// Factory function to create appropriate congestion control algorithm
std::unique_ptr<QuicQos> createQos(
    bool isServer,
    const QuicQos::send_func& sent,
    std::function<void(pn_namespace*, quic_frame*)> resendFrames
);

#endif //SPROXY_QUIC_QOS_H
