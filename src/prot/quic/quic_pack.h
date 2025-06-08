#ifndef QUIC_PACK_H__
#define QUIC_PACK_H__

#include "common/common.h"
#include "misc/buffer.h"

#include <deque>
#include <string>
#include <set>

#include <stdint.h>
#include <stdlib.h>
#include <openssl/evp.h>

#define QUIC_VERSION_1 0x00000001
#define QUIC_VERSION_2 0x6b3343cf
#define QUIC_INITIAL_LIMIT 1200
#define QUIC_TOKEN_LEN   16
/*
Long Header Packet Types
Type	Name	Section
0x0	Initial	Section 17.2.2
0x1	0-RTT	Section 17.2.3
0x2	Handshake	Section 17.2.4
0x3	Retry	Section 17.2.5
 */


#define QUIC_PACKET_INITIAL   (0x0<<4)
#define QUIC_PACKET_0RTT      (0x1<<4)
#define QUIC_PACKET_HANDSHAKE (0x2<<4)
#define QUIC_PACKET_RETRY     (0x3<<4)

/*
All version 2 Long Header packet types are different. The Type field values are:
Initial: 0b01
0-RTT: 0b10
Handshake: 0b11
Retry: 0b00
 */
#define QUIC_PACKET_RETRYV2     (0x0<<4)
#define QUIC_PACKET_INITIALV2   (0x1<<4)
#define QUIC_PACKET_0RTTV2      (0x2<<4)
#define QUIC_PACKET_HANDSHAKEV2 (0x3<<4)


#define QUIC_PACKET_1RTT      (0x3f)  //pseudo-type code

/*
Initial QUIC Transport Error Codes Entries
0x00	NO_ERROR	No error	Section 20
0x01	INTERNAL_ERROR	Implementation error	Section 20
0x02	CONNECTION_REFUSED	Server refuses a connection	Section 20
0x03	FLOW_CONTROL_ERROR	Flow control error	Section 20
0x04	STREAM_LIMIT_ERROR	Too many streams opened	Section 20
0x05	STREAM_STATE_ERROR	Frame received in invalid stream state	Section 20
0x06	FINAL_SIZE_ERROR	Change to final size	Section 20
0x07	FRAME_ENCODING_ERROR	Frame encoding error	Section 20
0x08	TRANSPORT_PARAMETER_ERROR	Error in transport parameters	Section 20
0x09	CONNECTION_ID_LIMIT_ERROR	Too many connection IDs received	Section 20
0x0a	PROTOCOL_VIOLATION	Generic protocol violation	Section 20
0x0b	INVALID_TOKEN	Invalid Token received	Section 20
0x0c	APPLICATION_ERROR	Application error	Section 20
0x0d	CRYPTO_BUFFER_EXCEEDED	CRYPTO data buffer overflowed	Section 20
0x0e	KEY_UPDATE_ERROR	Invalid packet protection update	Section 20
0x0f	AEAD_LIMIT_REACHED	Excessive use of packet protection keys	Section 20
0x10	NO_VIABLE_PATH	No viable network path exists	Section 20
0x0100-0x01ff	CRYPTO_ERROR	TLS alert code	Section 20
 */

#define QUIC_NO_ERROR                  0x00
#define QUIC_INTERNAL_ERROR            0x01
#define QUIC_CONNECTION_REFUSED        0x02
#define QUIC_FLOW_CONTROL_ERROR        0x03
#define QUIC_STREAM_LIMIT_ERROR        0x04
#define QUIC_STREAM_STATE_ERROR        0x05
#define QUIC_FINAL_SIZE_ERROR          0x06
#define QUIC_FRAME_ENCODING_ERROR      0x07
#define QUIC_TRANSPORT_PARAMETER_ERROR 0x08
#define QUIC_CONNECTION_ID_LIMIT_ERROR 0x09
#define QUIC_PROTOCOL_VIOLATION        0x0A
#define QUIC_INVALID_TOKEN             0x0B
#define QUIC_APPLICATION_ERROR         0x0C
#define QUIC_CRYPTO_BUFFER_EXCEEDED    0x0D
#define QUIC_KEY_UPDATE_ERROR          0x0E
#define QUIC_AEAD_LIMIT_REACHED        0x0f
#define QUIC_NO_VIABLE_PATH            0x10
#define QUIC_CRYPTO_ERROR              0x0100
#define QUIC_CRYPTO_ERROR_END          0x01ff
#define QUIC_CONNECTION_CLOSED         0xffff

/*
Type Value	Frame Type Name         Definition  	Pkts	Spec
0x00	    PADDING	                Section 19.1	IH01	NP
0x01	    PING	                Section 19.2	IH01
0x02-0x03	ACK	                    Section 19.3	IH_1	NC
0x04	    RESET_STREAM	        Section 19.4	__01
0x05	    STOP_SENDING	        Section 19.5	__01
0x06	    CRYPTO	                Section 19.6	IH_1
0x07	    NEW_TOKEN	            Section 19.7	___1
0x08-0x0f	STREAM	                Section 19.8	__01	F
0x10	    MAX_DATA	            Section 19.9	__01
0x11	    MAX_STREAM_DATA	        Section 19.10	__01
0x12-0x13	MAX_STREAMS	            Section 19.11	__01
0x14	    DATA_BLOCKED	        Section 19.12	__01
0x15	    STREAM_DATA_BLOCKED	    Section 19.13	__01
0x16-0x17	STREAMS_BLOCKED	        Section 19.14	__01
0x18	    NEW_CONNECTION_ID	    Section 19.15	__01	P
0x19	    RETIRE_CONNECTION_ID	Section 19.16	__01
0x1a	    PATH_CHALLENGE	        Section 19.17	__01	P
0x1b	    PATH_RESPONSE	        Section 19.18	___1	P
0x1c-0x1d	CONNECTION_CLOSE	    Section 19.19	ih01	N
0x1e	    HANDSHAKE_DONE	        Section 19.20	___1
 */

#define QUIC_FRAME_PADDING              0x00
#define QUIC_FRAME_PING                 0x01
#define QUIC_FRAME_ACK                  0x02
#define QUIC_FRAME_ACK_ECN              0x03
#define QUIC_FRAME_RESET_STREAM         0x04
#define QUIC_FRAME_STOP_SENDING         0x05
#define QUIC_FRAME_CRYPTO               0x06
#define QUIC_FRAME_NEW_TOKEN            0x07
#define QUIC_FRAME_STREAM_START_ID      0x08
#define QUIC_FRAME_STREAM_END_ID        0x0f
#define QUIC_FRAME_STREAM_OFF_F         0x04
#define QUIC_FRAME_STREAM_LEN_F         0x02
#define QUIC_FRAME_STREAM_FIN_F         0x01
#define QUIC_FRAME_MAX_DATA             0x10
#define QUIC_FRAME_MAX_STREAM_DATA      0x11
#define QUIC_FRAME_MAX_STREAMS_BI       0x12
#define QUIC_FRAME_MAX_STREAMS_UBI      0x13
#define QUIC_FRAME_DATA_BLOCKED         0x14
#define QUIC_FRAME_STREAM_DATA_BLOCKED  0x15
#define QUIC_FRAME_STREAMS_BLOCKED_BI   0x16
#define QUIC_FRAME_STREAMS_BLOCKED_UBI  0x17
#define QUIC_FRAME_NEW_CONNECTION_ID    0x18
#define QUIC_FRAME_RETIRE_CONNECTION_ID 0x19
#define QUIC_FRAME_PATH_CHALLENGE       0x1a
#define QUIC_FRAME_PATH_RESPONSE        0x1b
#define QUIC_FRAME_CONNECTION_CLOSE     0x1c
#define QUIC_FRAME_CONNECTION_CLOSE_APP 0x1d
#define QUIC_FRAME_HANDSHAKE_DONE       0x1e

#define quic_original_destination_connection_id       0x00
#define quic_max_idle_timeout                         0x01
#define quic_stateless_reset_token                    0x02
#define quic_max_udp_payload_size                     0x03
#define quic_initial_max_data                         0x04
#define quic_initial_max_stream_data_bidi_local       0x05
#define quic_initial_max_stream_data_bidi_remote      0x06
#define quic_initial_max_stream_data_uni              0x07
#define quic_initial_max_streams_bidi                 0x08
#define quic_initial_max_streams_uni                  0x09
#define quic_ack_delay_exponent                       0x0a
#define quic_max_ack_delay                            0x0b
#define quic_disable_active_migration                 0x0c
#define quic_preferred_address                        0x0d
#define quic_active_connection_id_limit               0x0e
#define quic_initial_source_connection_id             0x0f
#define quic_retry_source_connection_id               0x10
#define quic_version_information                      0x11 //rfc9368
#define quic_max_datagram_frame_size                  0x20 //rfc9221
#define quic_grease_quic_bit                          0x2ab2 //rfc9287


size_t variable_encode(void* data_, uint64_t value);
size_t variable_encode_len(uint64_t value);
size_t variable_decode(const void* data, uint64_t* value);
size_t variable_decode_len(const void* data);

struct quic_secret{
    const EVP_MD* md;
#ifdef USE_BORINGSSL
    const EVP_AEAD   *cipher;
#else
    const EVP_CIPHER *cipher;
#endif
    const EVP_CIPHER *hcipher;
    char iv[12];
    char hp[32];
    char key[32];
};

int quic_generate_initial_key(int client, const char* id, uint8_t id_len, quic_secret* secret);
int quic_secret_set_key(quic_secret* secret, const char* key, uint32_t cipher);

struct quic_crypto{
    uint64_t offset;
    uint64_t length;
    Buffer* buffer;
};

struct quic_ack_range{
    uint64_t  gap = 0;
    uint64_t  length = 0;
};

struct quic_ack{
    uint64_t  acknowledged;
    uint64_t  delay;
    uint64_t  range_count;
    uint64_t  first_range;
    struct quic_ack_range* ranges;
    uint64_t ecn_ect0;
    uint64_t ecn_ect1;
    uint64_t ecn_ce;
};

struct quic_new_id{
    uint64_t seq;
    uint64_t retired;
    uint8_t length;
    char* id;
    char token[16];
};

struct quic_new_token{
    uint64_t length;
    char* token;
};

struct quic_close{
    uint64_t error;
    uint64_t frame_type;
    uint64_t reason_len;
    char*    reason;
};

struct quic_reset{
    uint64_t id;
    uint64_t error;
    uint64_t fsize;
};

struct quic_stop{
    uint64_t id;
    uint64_t error;
};

struct quic_max_stream_data {
    uint64_t id;
    uint64_t max;
};

struct quic_stream_data_blocked{
    uint64_t id;
    uint64_t size;
};

struct quic_stream{
    uint64_t id;
    uint64_t offset;
    uint64_t length;
    Buffer* buffer;
};

struct quic_frame{
    uint64_t type;
    union {
        struct quic_crypto    crypto;
        struct quic_ack       ack;
        struct quic_close     close;
        struct quic_new_id    new_id;
        struct quic_new_token new_token;
        struct quic_stream    stream;
        struct quic_reset     reset;
        struct quic_stop      stop;
        struct quic_max_stream_data max_stream_data;
        struct quic_stream_data_blocked  stream_data_blocked;
        char     path_data[64];
        uint64_t extra;
    };
};


struct quic_meta{
    uint8_t type = 0xff;   //for long packet or 0x3f for short packet
    uint8_t flags = 0;  //for short packet
    uint32_t version = 0;
    std::string dcid;
    std::string scid;
    std::string token;
};

struct quic_pkt_header: public quic_meta{
    uint64_t pn = 0;
    uint64_t pn_base = 0;
    size_t pn_length = 0;
};

/*
Ack-eliciting frames:
All frames other than ACK, PADDING, and CONNECTION_CLOSE are considered ack-eliciting.

Ack-eliciting packets:
Packets that contain ack-eliciting frames elicit an ACK from the receiver within the
maximum acknowledgment delay and are called ack-eliciting packets.

In-flight packets:
Packets are considered in flight when they are ack-eliciting or contain a PADDING frame,
and they have been sent but are not acknowledged, declared lost, or discarded along with old keys.
 */

struct quic_packet_meta{
    uint64_t pn;
    bool ack_eliciting;
    bool in_flight;
    size_t sent_bytes;
    uint64_t sent_time;
    bool app_limited; // used for bbr
    std::set<uint64_t> streamIds;
    quic_packet_meta(uint64_t pn, size_t len):
            pn(pn), ack_eliciting(false), in_flight(false), sent_bytes(len), sent_time(0),
            app_limited(false) {}
};

struct quic_packet_pn{
    quic_packet_meta meta;
    std::deque<quic_frame*> frames;
};


int unpack_meta(const void* data, size_t len, quic_meta* meta);
std::deque<const quic_frame*> decode_packet(const void* data, size_t len,
                                       quic_pkt_header* header, const quic_secret* secret);


size_t pack_frame_len(const quic_frame* frame);
void* pack_frame(void* buff, const quic_frame* frame);
size_t encode_packet(const void* data, size_t len,
                  const quic_pkt_header* header, const quic_secret* secret,
                  char* body);

std::string dumpHex(const void* data, size_t len);
bool is_ack_eliciting(const quic_frame* frame);
void dumpFrame(const char* prefix, char name, const quic_frame* frame);
size_t frame_size(const quic_frame* frame);
void frame_release(const quic_frame* frame);

std::string sign_cid(const std::string& id);

#endif
