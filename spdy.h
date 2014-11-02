#ifndef __SPDY_H__
#define __SPDY_H__

#include <stdint.h>

#include <endian.h>

#define SPDY_VERSION 3

#if (BYTE_ORDER == LITTLE_ENDIAN)
#define LITTLE_ENDIAN_BITFIELD
#else
#define BIG_ENDIAN_BITFIELD
#endif

/*
+----------------------------------+
|C| Version(15bits) | Type(16bits) |
+----------------------------------+
| Flags (8)  |  Length (24 bits)   |
+----------------------------------+
|               Data               |
+----------------------------------+
*/


typedef struct{
#if defined (LITTLE_ENDIAN_BITFIELD)
    uint16_t version:15;
    uint16_t c:1;
    uint16_t type;
    uint8_t flag;
    uint8_t length[3];
    #define get24(x) ((x)[0]<<16|(x)[1]<<8|(x)[2])
#elif defined (BIG_ENDIAN_BITFIELD)
    uint16_t c:1;
    uint16_t version:15;
    uint16_t type;
    uint8_t flag;
    uint8_t length[3];
    #define get24(x) (x)
#endif
    
}__attribute__ ((packed)) spdy_cframe_head;

/*
+----------------------------------+
|C|       Stream-ID (31bits)       |
+----------------------------------+
| Flags (8)  |  Length (24 bits)   |
+----------------------------------+
|               Data               |
+----------------------------------+
*/

typedef struct{

#if defined (LITTLE_ENDIAN_BITFIELD)
    uint32_t id:31;
    uint32_t c:1;
#elif defined (BIG_ENDIAN_BITFIELD)
    uint32_t c:1;
    uint32_t id:31;
#endif
    uint8_t flag;
    uint8_t length[3];
}__attribute__ ((packed)) spdy_dframe_head;


typedef struct{
#if defined (LITTLE_ENDIAN_BITFIELD)
    uint8_t :7;
    uint8_t c:1;
#elif defined (BIG_ENDIAN_BITFIELD)
    uint8_t c:1;
    uint8_t :7;
#endif
    uint8_t unused[7];
}__attribute__ ((packed)) spdy_head;

/*
+------------------------------------+
|1|    version    |         1        |
+------------------------------------+
|  Flags (8)  |  Length (24 bits)    |
+------------------------------------+
|X|           Stream-ID (31bits)     |
+------------------------------------+
|X| Associated-To-Stream-ID (31bits) |
+------------------------------------+
| Pri|Unused | Slot |                |
+-------------------+                |
| Number of Name/Value pairs (int32) |   <+
+------------------------------------+    |
|     Length of name (int32)         |    | This section is the "Name/Value
+------------------------------------+    | Header Block", and is compressed.
|           Name (string)            |    |
+------------------------------------+    |
|     Length of value  (int32)       |    |
+------------------------------------+    |
|          Value   (string)          |    |
+------------------------------------+    |
|           (repeats)                |   <+

*/

typedef struct{
#if defined (LITTLE_ENDIAN_BITFIELD)
    uint32_t id:31;
    uint32_t :1;
    uint32_t atid:31;
    uint32_t :1;
    uint8_t :5;
    uint8_t priority:3;
#elif defined (BIG_ENDIAN_BITFIELD)
    uint32_t :1;
    uint32_t id:31;
    uint32_t :1;
    uint32_t atid:31;
    uint8_t priority:3;
    uint8_t :5;
#endif
    uint8_t slot;
}__attribute__ ((packed)) syn_frame;


/*
+----------------------------------+
|1|   version    |         3       |
+----------------------------------+
| Flags (8)  |         8           |
+----------------------------------+
|X|          Stream-ID (31bits)    |
+----------------------------------+
|          Status code             |
+----------------------------------+
*/

typedef struct{
#if defined (LITTLE_ENDIAN_BITFIELD)
    uint32_t id:31;
    uint32_t :1;
#elif defined (BIG_ENDIAN_BITFIELD)
    uint32_t :1;
    uint32_t id:31;
#endif

#define PROTOCOL_ERROR          1 //This is a generic error, and should only be used if a more specific error is not available.
#define INVALID_STREAM          2 //This is returned when a frame is received for a stream which is not active.
#define REFUSED_STREAM          3 //Indicates that the stream was refused before any processing has been done on the stream.
#define UNSUPPORTED_VERSION     4 //Indicates that the recipient of a stream does not support the SPDY version requested.
#define CANCEL                  5 //Used by the creator of a stream to indicate that the stream is no longer needed.
#define INTERNAL_ERROR          6 //This is a generic error which can be used when the implementation has internally failed, not due to anything in the protocol.
#define FLOW_CONTROL_ERROR      7 //The endpoint detected that its peer violated the flow control protocol.
#define STREAM_IN_USE           8 //The endpoint received a SYN_REPLY for a stream already open.
#define STREAM_ALREADY_CLOSED   9 //The endpoint received a data or SYN_REPLY frame for a stream which is half closed.
#define FRAME_TOO_LARGE         11 //The endpoint received a frame which this implementation could not support. If FRAME_TOO_LARGE is sent for a SYN_STREAM, HEADERS, or SYN_REPLY frame without fully processing the compressed portion of those frames, then the compression state will be out-of-sync with the other endpoint. In this case, senders of FRAME_TOO_LARGE MUST close the session.
    uint32_t code;
}__attribute__ ((packed)) rst_frame;

#ifdef __cplusplus
extern "C"{
#endif


void spdy_deflate(void *buffin,size_t inlen,void *buffout,size_t outlen);
int spdy_inflate(void *buffin,size_t inlen,void *buffout,size_t outlen);

#ifdef __cplusplus
}
#endif

#endif