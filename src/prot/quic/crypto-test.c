#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#include <assert.h>

#include "quic.h"

static void dumphex(const unsigned char *s, size_t len){
    for(size_t i = 0; i < len; i++){
        printf("%02x", (unsigned char)(s[i]));
        if(i%32==31){
            printf("\n");
        }else if(i%16 == 15){
            printf(" ");
        }
    }
    printf("\n");
}

void slog(int level, const char* fmt, ...){
    va_list ap;
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
}

static char hex2int(char c) {
    if ( c >= '0' && c <= '9'){
        return c - '0';
    }
    if ( c >= 'a' && c <= 'f'){
        return c - 'a' + '\xa';
    }
    if ( c >= 'A' && c <= 'F'){
        return c - 'A' + '\xA';
    }
    return 0;
}


static int s2a(const char* s, unsigned char* data){
    unsigned char code = 0;
    unsigned char code_end = 0;
    unsigned char *pos = data;
    while(*s){
        if(*s == ' ' || *s == '\n' || *s == '\t'){
            s++;
            continue;
        }
        code = (code << 4) + hex2int(*s++);
        if(code_end){
            *pos++ = code;
            code = 0;
        }
        code_end = !code_end;
    }
    return pos - data;
}


uint64_t DecodePacketNumber(uint64_t largest_pn, uint64_t truncated_pn, uint8_t pn_nbits){
    uint64_t expected_pn  = largest_pn + 1;
    uint8_t pn_win       = 1 << pn_nbits;
    uint8_t pn_hwin      = pn_win / 2;
    uint8_t pn_mask      = pn_win - 1;
// The incoming packet number should be greater than
// expected_pn - pn_hwin and less than or equal to
// expected_pn + pn_hwin
//
// This means we cannot just strip the trailing bits from
// expected_pn and add the truncated_pn because that might
// yield a value outside the window.
//
// The following code calculates a candidate value and
// makes sure it's within the packet number window.
// Note the extra checks to prevent overflow and underflow.
    uint64_t candidate_pn = (expected_pn & ~pn_mask) | truncated_pn;
    if ((candidate_pn <= expected_pn - pn_hwin) && (candidate_pn < (1 << 62) - pn_win)){
        return candidate_pn + pn_win;
    }
    if ((candidate_pn > expected_pn + pn_hwin) && (candidate_pn >= pn_win)){
        return candidate_pn - pn_win;
    }
    return candidate_pn;
}

int main() {
    const char *id = "\x83\x94\xc8\xf0\x3e\x51\x57\x08";

    printf("connection id [8]:\n");
    dumphex((unsigned char*)id, 8);

    struct quic_secret ckey;
    quic_generate_initial_key(1, id, 8, &ckey);
    struct quic_secret skey;
    quic_generate_initial_key(0, id, 8, &skey);


    const char* frames =
            "060040f1010000ed0303ebf8fa56f129 39b9584a3896472ec40bb863cfd3e868"
            "04fe3a47f06a2b69484c000004130113 02010000c000000010000e00000b6578"
            "616d706c652e636f6dff01000100000a 00080006001d00170018001000070005"
            "04616c706e0005000501000000000033 00260024001d00209370b2c9caa47fba"
            "baf4559fedba753de171fa71f50f1ce1 5d43e994ec74d748002b000302030400"
            "0d0010000e0403050306030203080408 050806002d00020101001c0002400100"
            "3900320408ffffffffffffffff050480 00ffff07048000ffff08011001048000"
            "75300901100f088394c8f03e51570806 048000ffff";

    char body[1200];
    memset(body, 0, sizeof(body));
    size_t payload_len = s2a(frames, body);
    printf("payload [%zu]:\n", payload_len);
    dumphex(body, payload_len);

    struct quic_packet packet;
    memset(&packet, 0, sizeof(packet));
    packet.buff = body;
    packet.body_len = 1162;

    unsigned char header[1216];
    memset(header, 0, sizeof(header));

    packet.header.dcid_len = 8;
    memcpy(packet.header.dcid, id, 8);

    packet.header.type = QUIC_PACKET_INITIAL;
    packet.header.pn = 2;
    packet.header.pn_length = 4;
    packet.secret = &ckey;
    size_t body_len = quic_encrypt_packet(&packet, header);

    printf("packet [%zu]:\n", body_len);
    // "c300000001088394c8f03e5157080000449e00000002"
    dumphex(header, body_len);

    const char* spacket =
            "cf000000010008f067a5502a4262b500 4075c0d95a482cd0991cd25b0aac406a"
            "5816b6394100f37a1c69797554780bb3 8cc5a99f5ede4cf73c3ec2493a1839b3"
            "dbcba3f6ea46c5b7684df3548e7ddeb9 c3bf9c73cc3f3bded74b562bfb19fb84"
            "022f8ef4cdd93795d77d06edbb7aaf2f 58891850abbdca3d20398c276456cbc4"
            "2158407dd074ee";
    body_len = s2a(spacket, header);
    packet.secret = &skey;
    assert(quic_decrypt_packet(header, body_len, &packet) >= 0);
    assert(quic_unpack_frame(&packet) >= 0);
    quic_packet_release(&packet);


    struct quic_secret tkey;
    unsigned char secret[] = {
            0x9a, 0xc3, 0x12, 0xa7, 0xf8, 0x77, 0x46, 0x8e, 0xbe, 0x69, 0x42,
            0x27, 0x48, 0xad, 0x00, 0xa1, 0x54, 0x43, 0xf1, 0x82, 0x03, 0xa0,
            0x7d, 0x60, 0x60, 0xf6, 0x88, 0xf3, 0x0f, 0x21, 0x63, 0x2b,
    };
    quic_secret_set_key(&tkey, secret , 0x03001303);
    unsigned char expected_pkt_key[] = {
            0xc6, 0xd9, 0x8f, 0xf3, 0x44, 0x1c, 0x3f, 0xe1, 0xb2, 0x18, 0x20,
            0x94, 0xf6, 0x9c, 0xaa, 0x2e, 0xd4, 0xb7, 0x16, 0xb6, 0x54, 0x88,
            0x96, 0x0a, 0x7a, 0x98, 0x49, 0x79, 0xfb, 0x23, 0xe1, 0xc8,
    };
    assert(memcmp(tkey.key, expected_pkt_key, sizeof(expected_pkt_key)) == 0);

    unsigned char expected_hdr_key[] = {
            0x25, 0xa2, 0x82, 0xb9, 0xe8, 0x2f, 0x06, 0xf2, 0x1f, 0x48, 0x89,
            0x17, 0xa4, 0xfc, 0x8f, 0x1b, 0x73, 0x57, 0x36, 0x85, 0x60, 0x85,
            0x97, 0xd0, 0xef, 0xcb, 0x07, 0x6b, 0x0a, 0xb7, 0xa7, 0xa4,
    };
    assert(memcmp(tkey.hp, expected_hdr_key, sizeof(expected_hdr_key)) == 0);

    char unsigned expected_iv_key[] = {0xe0, 0x45, 0x9b, 0x34, 0x74, 0xbd, 0xd0, 0xe4, 0x4a, 0x41, 0xc1, 0x44};
    assert(memcmp(tkey.iv, expected_iv_key, sizeof(expected_iv_key)) == 0);

}
