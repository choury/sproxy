//
// Created by 周威 on 2021/8/5.
//

// For http3 draft-34

#ifndef SPROXY_HTTP3_H
#define SPROXY_HTTP3_H

#include "prot/rwer.h"
#include "prot/http/http_header.h"
#include "qpach.h"

//Frame Type	                Value	Specification
#define HTTP3_STREAM_DATA	        0x0	//Section 7.2.1
#define HTTP3_STREAM_HEADERS	    0x1	//Section 7.2.2
//#define HTTP3_STREAM_Reserved	    0x2	//N/A
#define HTTP3_STREAM_CANCEL_PUSH	0x3	//Section 7.2.3
#define HTTP3_STREAM_SETTINGS	    0x4	//Section 7.2.4
#define HTTP3_STREAM_PUSH_PROMISE	0x5	//Section 7.2.5
//#define HTTP3_STREAM_Reserved	    0x6	//N/A
#define HTTP3_STREAM_GOAWAY	        0x7	//Section 7.2.6
//#define HTTP3_STREAM_Reserved	    0x8	//N/A
//#define HTTP3_STREAM_Reserved	    0x9	//N/A
#define HTTP3_STREAM_MAX_PUSH_ID	0xd	//Section 7.2.7


/*Setting Name	Value	Specification	Default
Reserved	    0x0	    N/A	N/A
Reserved	    0x2	    N/A	N/A
Reserved	    0x3	    N/A	N/A
Reserved	    0x4	    N/A	N/A
Reserved	    0x5	    N/A	N/A */
#define HTTP3_SETTING_MAX_FIELD_SECTION_SIZE    0x6	//Section 7.2.4.1	Unlimited
#define HTTP3_SETTING_ENABLE_CONNECT_PROTOCOL   0x8 //rfc9220

//Name	                                    Value	Description	Specification
#define HTTP3_ERR_NO_ERROR	                0x100	//No error	Section 8.1
#define HTTP3_ERR_GENERAL_PROTOCOL_ERROR	0x101	//General protocol error	Section 8.1
#define HTTP3_ERR_INTERNAL_ERROR	        0x102	//Internal error	Section 8.1
#define HTTP3_ERR_STREAM_CREATION_ERROR	    0x103	//Stream creation error	Section 8.1
#define HTTP3_ERR_CLOSED_CRITICAL_STREAM	0x104	//Critical stream was closed	Section 8.1
#define HTTP3_ERR_FRAME_UNEXPECTED	        0x105	//Frame not permitted in the current state	Section 8.1
#define HTTP3_ERR_FRAME_ERROR	            0x106	//Frame violated layout or size rules	Section 8.1
#define HTTP3_ERR_EXCESSIVE_LOAD	        0x107	//Peer generating excessive load	Section 8.1
#define HTTP3_ERR_ID_ERROR	                0x108	//An identifier was used incorrectly	Section 8.1
#define HTTP3_ERR_SETTINGS_ERROR	        0x109	//SETTINGS frame contained invalid values	Section 8.1
#define HTTP3_ERR_MISSING_SETTINGS	        0x10a	//No SETTINGS frame received	Section 8.1
#define HTTP3_ERR_REQUEST_REJECTED	        0x10b	//Request not processed	Section 8.1
#define HTTP3_ERR_REQUEST_CANCELLED	        0x10c	//Data no longer needed	Section 8.1
#define HTTP3_ERR_REQUEST_INCOMPLETE	    0x10d	//Stream terminated early	Section 8.1
#define HTTP3_ERR_MESSAGE_ERROR	            0x10e	//Malformed message	Section 8.1
#define HTTP3_ERR_CONNECT_ERROR	            0x10f	//TCP reset or error on CONNECT request	Section 8.1
#define HTTP3_ERR_VERSION_FALLBACK	        0x110	//Retry over HTTP/1.1	Section 8.1


//Stream Type	                    Value	Specification	Sender
#define HTTP3_STREAM_TYPE_CONTROL	0x00	//Section 6.2.1	Both
#define HTTP3_STREAM_TYPE_PUSH  	0x01	//Section 4.4	Server


class Http3Base{
protected:
#define HTTP3_FLAG_INITED    (1u << 0u)
#define HTTP3_FLAG_GOAWAYED  (1u << 1u)
#define HTTP3_FLAG_ERROR     (1u << 2u)
#define HTTP3_FLAG_CLEANNING (1u << 3u)
#define HTTP3_FLAG_ENABLE_PROTOCOL (1u << 4u)
    uint32_t http3_flag = 0;
    // these ids are ubi stream, can not be 0, so use it as not inited.
    uint64_t ctrlid_local = 0, ctrlid_remote = 0;
    uint64_t qpackeid_local = 0, qpackeid_remote = 0;
    uint64_t qpackdid_local = 0, qpackdid_remote = 0;


    Qpack_encoder qpack_encoder;
    Qpack_decoder qpack_decoder;
    size_t Http3_Proc(Buffer& bb);

    virtual void HeadersProc(uint64_t id, const uchar *header, size_t len) = 0;
    virtual void SettingsProc(const uchar *header, size_t len);
    virtual void GoawayProc(uint64_t id);
    virtual bool DataProc(Buffer& bb) = 0;
    virtual void ErrProc(int errcode) = 0;
    virtual void Reset(uint64_t id, uint32_t code) = 0;

    void Goaway(uint64_t lastid);
    virtual uint64_t CreateUbiStream() = 0;
    virtual void SendData(Buffer&& bb) = 0;
    virtual void PushData(Buffer&& bb);

public:
    Http3Base();
    ~Http3Base() = default;
    void Init();
};

class Http3Requster:public Http3Base{
protected:
    virtual void HeadersProc(uint64_t id, const uchar* header, size_t len) override;
    virtual void ResProc(uint64_t id, std::shared_ptr<HttpResHeader> res) = 0;
public:
    Http3Requster();
};

class Http3Responser: public Http3Base {
protected:
    virtual void HeadersProc(uint64_t id, const uchar* header, size_t len) override;
    virtual void ReqProc(uint64_t id, std::shared_ptr<HttpReqHeader> res) = 0;
public:
    Http3Responser();
};

#endif //SPROXY_HTTP3_H
