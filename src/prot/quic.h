#ifndef QUIC_H__
#define QUIC_H__

#include <stdint.h>

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

struct quic_long_header{
    uint8_t flags;
    uint32_t version;
    unsigned char left[0];
}__attribute__((packed));

struct quic_short_header{
    uint8_t flags;
    unsigned char left[0];
}__attribute__((packed));

/*
Initial QUIC Transport Error Codes Entries
Value	Error	Description	Specification
0x0	NO_ERROR	No error	Section 20
0x1	INTERNAL_ERROR	Implementation error	Section 20
0x2	SERVER_BUSY	Server currently busy	Section 20
0x3	FLOW_CONTROL_ERROR	Flow control error	Section 20
0x4	STREAM_LIMIT_ERROR	Too many streams opened	Section 20
0x5	STREAM_STATE_ERROR	Frame received in invalid stream state	Section 20
0x6	FINAL_SIZE_ERROR	Change to final size	Section 20
0x7	FRAME_ENCODING_ERROR	Frame encoding error	Section 20
0x8	TRANSPORT_PARAMETER_ERROR	Error in transport parameters	Section 20
0xA	PROTOCOL_VIOLATION	Generic protocol violation	Section 20
0xC	INVALID_MIGRATION	Violated disabled migration	Section 20
 */

#define QUIC_NO_ERROR                  0x0
#define QUIC_INTERNAL_ERROR            0x1
#define QUIC_SERVER_BUSY               0x2
#define QUIC_FLOW_CONTROL_ERROR        0x3
#define QUIC_STREAM_LIMIT_ERROR        0x4
#define QUIC_STREAM_STATE_ERROR        0x5
#define QUIC_FINAL_SIZE_ERROR          0x6
#define QUIC_FRAME_ENCODING_ERROR      0x7
#define QUIC_TRANSPORT_PARAMETER_ERROR 0x8
#define QUIC_PROTOCOL_VIOLATION        0xA
#define QUIC_INVALID_MIGRATION         0xC


/*
Frame Types
Type Value	Frame Type Name	Definition
0x00	PADDING	Section 19.1
0x01	PING	Section 19.2
0x02 - 0x03	ACK	Section 19.3
0x04	RESET_STREAM	Section 19.4
0x05	STOP_SENDING	Section 19.5
0x06	CRYPTO	Section 19.6
0x07	NEW_TOKEN	Section 19.7
0x08 - 0x0f	STREAM	Section 19.8
0x10	MAX_DATA	Section 19.9
0x11	MAX_STREAM_DATA	Section 19.10
0x12 - 0x13	MAX_STREAMS	Section 19.11
0x14	DATA_BLOCKED	Section 19.12
0x15	STREAM_DATA_BLOCKED	Section 19.13
0x16 - 0x17	STREAMS_BLOCKED	Section 19.14
0x18	NEW_CONNECTION_ID	Section 19.15
0x19	RETIRE_CONNECTION_ID	Section 19.16
0x1a	PATH_CHALLENGE	Section 19.17
0x1b	PATH_RESPONSE	Section 19.18
0x1c - 0x1d	CONNECTION_CLOSE	Section 19.19
 */

#define QUIC_FRAME_PADDING              0x00
#define QUIC_FRAME_PING                 0x01
#define QUIC_FRAME_ACK                  0x02
#define QUIC_FRAME_ACK_ECN              0x03
#define QUIC_FRAME_RESET_STREAM         0x04
#define QUIC_FRAME_STOP_SENDING         0x05
#define QUIC_FRAME_CRYPTO               0x06
#define QUIC_FRAME_NEW_TOKEN            0x07
#define QUIC_FRAME_STREAM_START         0x08
#define QUIC_FRAME_STREAM_MASK          0x0f
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

#endif