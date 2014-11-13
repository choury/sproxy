#ifndef __SPDY_TYPE_H__
#define __SPDY_TYPE_H__

#include <stdint.h>

#include <endian.h>

#define SPDY_VERSION 3

#if (BYTE_ORDER == LITTLE_ENDIAN)
#define LITTLE_ENDIAN_BITFIELD
#else
#define BIG_ENDIAN_BITFIELD
#endif

#if defined (LITTLE_ENDIAN_BITFIELD)
#define CTRL_MAGIC 0x0380
#define DATA_MAGIC 0x0300
#define get24(x) ((x)[0]<<16|(x)[1]<<8|(x)[2])
#define set24(x,y) do{\
    (x)[0]=((y)>>16)&0xff;\
    (x)[1]=((y)>>8)&0xff;\
    (x)[2]=(y)&0xff;\
}while(0)

#elif defined (BIG_ENDIAN_BITFIELD)
#define CTRL_MAGIC 0x8003
#define DATA_MAGIC 0x0003
#define get24(x) ((x)[2]<<16|(x)[1]<<8|(x)[0])
#define set24(x,y) do{\
    (x)[2]=(y)>>16;\
    (x)[1]=(y)>>8;\
    (x)[0]=(y);\
}while(0)
#endif


//marks this frame as the last frame to be transmitted on this stream and puts the sender in the half-closed state.
#define  FLAG_FIN 0x01
//a stream created with this flag puts the recipient in the half-closed state.
#define  FLAG_UNIDIRECTIONAL 0x02  

/*
+----------------------------------+
|C| Version(15bits) | Type(16bits) |
+----------------------------------+
| Flags (8)  |  Length (24 bits)   |
+----------------------------------+
|               Data               |
+----------------------------------+
*/

#define SYN_TYPE            1
#define SYN_REPLY_TYPE      2
#define RST_TYPE            3
#define SETTINGS_TYPE       4
#define PING_TYPE           6
#define GOAWAY_TYPE         7
#define HEADERS_TYPE        8
#define WINDOW_UPDATE_TYPE  9
typedef struct{
    uint16_t magic;
    uint16_t type;
    uint8_t flag;
    uint8_t length[3];
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
    uint32_t id;  //the highest bit must be 0
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
    uint32_t id;
    uint32_t atid;
#if defined (LITTLE_ENDIAN_BITFIELD)
    uint8_t :5;
    uint8_t priority:3;
#elif defined (BIG_ENDIAN_BITFIELD)
    uint8_t priority:3;
    uint8_t :5;
#endif
    uint8_t slot;
}__attribute__ ((packed)) syn_frame;

/*
+------------------------------------+
|1|    version    |         2        |
+------------------------------------+
|  Flags (8)  |  Length (24 bits)    |
+------------------------------------+
|X|           Stream-ID (31bits)     |
+------------------------------------+
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
    uint32_t id;
}__attribute__ ((packed)) syn_reply_frame;

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
    uint32_t id;
//This is a generic error, and should only be used if a more specific error is not available.
#define PROTOCOL_ERROR          1 
//This is returned when a frame is received for a stream which is not active.
#define INVALID_STREAM          2
//Indicates that the stream was refused before any processing has been done on the stream.
#define REFUSED_STREAM          3
//Indicates that the recipient of a stream does not support the SPDY version requested.
#define UNSUPPORTED_VERSION     4
//Used by the creator of a stream to indicate that the stream is no longer needed.
#define CANCEL                  5
/*This is a generic error which can be used when the implementation has internally failed, 
 * not due to anything in the protocol.
 */
#define INTERNAL_ERROR          6
//The endpoint detected that its peer violated the flow control protocol.
#define FLOW_CONTROL_ERROR      7
//The endpoint received a SYN_REPLY for a stream already open.
#define STREAM_IN_USE           8
//The endpoint received a data or SYN_REPLY frame for a stream which is half closed.
#define STREAM_ALREADY_CLOSED   9
/*The endpoint received a frame which this implementation could not support. 
 * If FRAME_TOO_LARGE is sent for a SYN_STREAM, HEADERS,
 * or SYN_REPLY frame without fully processing the compressed portion of those frames, 
 * then the compression state will be out-of-sync with the other endpoint. 
 * In this case, senders of FRAME_TOO_LARGE MUST close the session.
 */
#define FRAME_TOO_LARGE         11
    uint32_t code;
}__attribute__ ((packed)) rst_frame;


#endif