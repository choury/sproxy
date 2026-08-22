//quic帧编解码回归测试：QuicCursor varint向量 + pack/unpack往返 + 截断负向量
#include "prot/quic/quic_pack.h"
#include "misc/buffer.h"

#include <inttypes.h>
#include <string.h>

//单测不链接整个 sproxy，桩掉依赖的全局符号(均为extern "C"链接)
void slog(int, const char*, ...) {}
struct debug_flags_map debug[128] = {};
//quic_pack.cpp的retry完整性校验与buffer.cpp的日志路径会引用，本测试不触达
extern "C" {
struct Destination;
EVP_PKEY* get_default_key(void) { return nullptr; }
int sign_data(EVP_PKEY*, const void*, int, char**, unsigned int*) { return -1; }
const char* dumpDest(const Destination*) { return ""; }
}

static int failures = 0;

static void check(bool ok, const char* what){
    if(ok){
        printf("PASS %s\n", what);
    }else{
        failures++;
        printf("FAIL %s\n", what);
    }
}

//往返：pack_frame写出 → pack_frame_len一致 → get_frame解回 → 字段一致 → 游标耗尽
//帧为值语义：返回写出的字节数，供截断负向量使用
static size_t roundtrip(const quic_frame& f, const char* what){
    char buf[512];
    size_t plen = pack_frame_len(f);
    QuicCursor pc(buf, sizeof(buf));
    if(plen == 0 || !pc.put_frame(f) || sizeof(buf) - pc.length() != plen){
        failures++;
        printf("FAIL %s: packed %zd != pack_frame_len %zd\n",
               what, sizeof(buf) - pc.length(), plen);
        return 0;
    }
    QuicCursor c(buf, plen);
    auto g = c.get_frame();
    if(!g){
        failures++;
        printf("FAIL %s: unpack failed\n", what);
        return plen;
    }
    if(c.length() != 0){
        failures++;
        printf("FAIL %s: %zd bytes left after unpack\n", what, c.length());
    }
    if(g->type != f.type){
        failures++;
        printf("FAIL %s: type 0x%" PRIx64 " != 0x%" PRIx64 "\n", what, g->type, f.type);
        return plen;
    }
    printf("PASS %s roundtrip\n", what);
    return plen;
}

int main() {
    //---- QuicCursor varint向量：编码规则按RFC 9000 §16手推 ----
    {
        unsigned char v1[] = {0x25};
        QuicCursor c(v1, sizeof(v1));
        auto r = c.variable_decode();
        check(r && *r == 37 && c.length() == 0, "varint 1-byte");
    }
    {
        unsigned char v2[] = {0x7b, 0xd1};
        QuicCursor c(v2, sizeof(v2));
        auto r = c.variable_decode();
        check(r && *r == ((0x3bu << 8) | 0xd1u) && c.length() == 0, "varint 2-byte");
    }
    {
        unsigned char v4[] = {0x80, 0x01, 0x02, 0x03};
        QuicCursor c(v4, sizeof(v4));
        auto r = c.variable_decode();
        check(r && *r == 0x010203u && c.length() == 0, "varint 4-byte");
    }
    {
        unsigned char v8[] = {0xc1, 0, 0, 0, 0, 0, 0, 1};
        QuicCursor c(v8, sizeof(v8));
        auto r = c.variable_decode();
        check(r && *r == ((1ull << 56) + 1) && c.length() == 0, "varint 8-byte");
    }
    {
        unsigned char v8[] = {0xc1, 0, 0, 0, 0, 0, 0};
        QuicCursor c(v8, sizeof(v8));
        check(!c.variable_decode(), "varint truncated");
    }
    {
        QuicCursor c((const void*)"", 0);
        check(!c.variable_decode(), "varint empty");
    }
    {
        //advance(0)是合法的空推进：成功且不动游标，空游标上亦然
        unsigned char b[] = {0x25};
        QuicCursor c(b, sizeof(b));
        check(c.advance(0) && c.length() == 1 && c.advance(1) && c.length() == 0
              && c.advance(0) && !c.advance(1), "advance(0) is no-op success");
    }

    //---- varint编码：写出字节与编码-解码往返 ----
    {
        //37 -> 1字节；16383 -> 0x3fff(2字节上限)；16384 -> 4字节形式
        unsigned char buf[8] = {0};
        QuicCursor c(buf, sizeof(buf));
        check(c.variable_encode(37) && buf[0] == 0x25 && c.length() == 7, "varint encode 1-byte");
    }
    {
        unsigned char buf[8] = {0};
        QuicCursor c(buf, sizeof(buf));
        check(c.variable_encode(16383) && buf[0] == 0x7f && buf[1] == 0xff,
              "varint encode 2-byte max");
    }
    {
        unsigned char buf[8] = {0};
        QuicCursor c(buf, sizeof(buf));
        check(c.variable_encode(16384) && buf[0] == 0x80 && buf[1] == 0x00 && buf[2] == 0x40 && buf[3] == 0x00,
              "varint encode 4-byte min");
    }
    {
        //超出2^62-1编码不可表示，必须拒绝
        unsigned char buf[8] = {0};
        QuicCursor c(buf, sizeof(buf));
        check(!c.variable_encode(1ull << 62), "varint encode overflow value");
    }
    {
        //空间不足必须整体失败且不推进游标
        unsigned char buf[1] = {0};
        QuicCursor c(buf, sizeof(buf));
        check(!c.variable_encode(64) && c.length() == 1, "varint encode no space");
    }
    {
        for(uint64_t v : {0ull, 63ull, 64ull, 16383ull, 16384ull, 1073741823ull,
                          1073741824ull, 4611686018427387903ull}) {
            unsigned char buf[8] = {0};
            QuicCursor enc(buf, sizeof(buf));
            if(!enc.variable_encode(v)){
                failures++;
                printf("FAIL varint roundtrip encode %llu\n", (unsigned long long)v);
                continue;
            }
            QuicCursor dec(buf, sizeof(buf) - enc.length());
            auto r = dec.variable_decode();
            if(!r || *r != v || dec.length() != 0){
                failures++;
                printf("FAIL varint roundtrip %llu -> %s\n", (unsigned long long)v,
                       r ? std::to_string(*r).c_str() : "nullopt");
            }
        }
        printf("PASS varint encode-decode roundtrips\n");
    }

    //---- 帧往返 ----
    {
        quic_frame f{QUIC_FRAME_PING};
        roundtrip(f, "ping");
    }
    {
        quic_frame f{QUIC_FRAME_MAX_DATA};
        f.extra = 987654;
        roundtrip(f, "max_data");
    }
    {
        quic_frame f{QUIC_FRAME_CRYPTO};
        f.crypto.offset = 128;
        f.crypto.length = 5;
        f.crypto.buffer = new Buffer(5);
        memcpy(f.crypto.buffer->mutable_data(), "hello", 5);
        f.crypto.buffer->truncate(5);
        size_t plen = roundtrip(f, "crypto");
        //负向量：crypto帧的任何真前缀都必须被拒绝(offset/length varint或body截断)
        char buf[512];
        QuicCursor pc(buf, sizeof(buf));
        pc.put_frame(f);
        size_t packed = sizeof(buf) - pc.length();
        bool all_rejected = true;
        for(size_t cut = 0; cut < packed; cut++){
            QuicCursor c(buf, cut);
            if(c.get_frame()){
                all_rejected = false;
            }
        }
        check(plen && packed == plen && all_rejected, "crypto truncated prefixes rejected");
    }
    {
        quic_frame f{QUIC_FRAME_ACK_ECN};
        f.ack.acknowledged = 1000;
        f.ack.delay = 33;
        f.ack.range_count = 2;
        f.ack.first_range = 40;
        quic_ack_range ranges[] = {{5, 60}, {7, 200}};
        f.ack.ranges = new quic_ack_range[2];
        memcpy(f.ack.ranges, ranges, sizeof(ranges));
        f.ack.ecn_ect0 = 1;
        f.ack.ecn_ect1 = 2;
        f.ack.ecn_ce = 3;
        char buf[512];
        size_t plen = pack_frame_len(f);
        QuicCursor pc(buf, sizeof(buf));
        bool packed_ok = pc.put_frame(f);
        QuicCursor c(buf, plen);
        auto g = c.get_frame();
        bool ok = packed_ok && sizeof(buf) - pc.length() == plen && g && c.length() == 0 &&
                  g->ack.acknowledged == 1000 && g->ack.delay == 33 &&
                  g->ack.range_count == 2 && g->ack.first_range == 40 &&
                  g->ack.ranges[0].gap == 5 && g->ack.ranges[0].length == 60 &&
                  g->ack.ranges[1].gap == 7 && g->ack.ranges[1].length == 200 &&
                  g->ack.ecn_ect0 == 1 && g->ack.ecn_ect1 == 2 && g->ack.ecn_ce == 3;
        check(ok, "ack_ecn roundtrip");
    }
    {
        quic_frame f{QUIC_FRAME_STREAM_START_ID | QUIC_FRAME_STREAM_OFF_F | QUIC_FRAME_STREAM_LEN_F | QUIC_FRAME_STREAM_FIN_F};
        f.stream.id = 8;
        f.stream.offset = 4096;
        f.stream.length = 4;
        f.stream.buffer = new Buffer(4);
        memcpy(f.stream.buffer->mutable_data(), "abcd", 4);
        f.stream.buffer->truncate(4);
        char buf[512];
        size_t plen = pack_frame_len(f);
        QuicCursor pc(buf, sizeof(buf));
        bool packed_ok = pc.put_frame(f);
        QuicCursor c(buf, plen);
        auto g = c.get_frame();
        bool ok = packed_ok && g && c.length() == 0 &&
                  g->stream.id == 8 && g->stream.offset == 4096 && g->stream.length == 4 &&
                  g->stream.buffer->len == 4 &&
                  memcmp(g->stream.buffer->data(), "abcd", 4) == 0;
        check(ok, "stream roundtrip");
    }
    {
        //无LEN标志的stream帧：长度隐式为剩余全部
        unsigned char b[] = {0x08, 0x04, 'a', 'b'};
        QuicCursor c(b, sizeof(b));
        auto g = c.get_frame();
        bool ok = g && c.length() == 0 &&
                  g->stream.id == 4 && g->stream.offset == 0 && g->stream.length == 2 &&
                  g->stream.buffer->len == 2 &&
                  memcmp(g->stream.buffer->data(), "ab", 2) == 0;
        check(ok, "stream without len");
    }
    {
        quic_frame f{QUIC_FRAME_NEW_CONNECTION_ID};
        f.new_id.seq = 3;
        f.new_id.retired = 1;
        f.new_id.length = 8;
        char id[8] = {1, 2, 3, 4, 5, 6, 7, 8};
        f.new_id.id = new char[8];
        memcpy(f.new_id.id, id, 8);
        memset(f.new_id.token, 0xab, sizeof(f.new_id.token));
        char buf[512];
        size_t plen = pack_frame_len(f);
        QuicCursor pc(buf, sizeof(buf));
        bool packed_ok = pc.put_frame(f);
        QuicCursor c(buf, plen);
        auto g = c.get_frame();
        bool ok = packed_ok && g && c.length() == 0 &&
                  g->new_id.seq == 3 && g->new_id.retired == 1 && g->new_id.length == 8 &&
                  memcmp(g->new_id.id, id, 8) == 0 &&
                  memcmp(g->new_id.token, f.new_id.token, sizeof(f.new_id.token)) == 0;
        check(ok, "new_connection_id roundtrip");
    }
    {
        quic_frame f{QUIC_FRAME_CONNECTION_CLOSE};
        f.close.error = 0x10;
        f.close.frame_type = QUIC_FRAME_CRYPTO;
        f.close.reason_len = 6;
        f.close.reason = new char[6];
        memcpy(f.close.reason, "no no!", 6);
        roundtrip(f, "close");
    }
    {
        quic_frame f{QUIC_FRAME_DATAGRAM_LEN};
        f.datagram.length = 3;
        f.datagram.buffer = new Buffer(3);
        memcpy(f.datagram.buffer->mutable_data(), "xyz", 3);
        f.datagram.buffer->truncate(3);
        char buf[512];
        size_t plen = pack_frame_len(f);
        QuicCursor pc(buf, sizeof(buf));
        bool packed_ok = pc.put_frame(f);
        QuicCursor c(buf, plen);
        auto g = c.get_frame();
        bool ok = packed_ok && g && c.length() == 0 &&
                  g->datagram.length == 3 && g->datagram.buffer->len == 3 &&
                  memcmp(g->datagram.buffer->data(), "xyz", 3) == 0;
        check(ok, "datagram roundtrip");
    }
    {
        quic_frame f{QUIC_FRAME_PATH_CHALLENGE};
        memset(f.path_data, 0x5a, sizeof(f.path_data));
        char buf[512];
        size_t plen = pack_frame_len(f);
        QuicCursor pc(buf, sizeof(buf));
        bool packed_ok = pc.put_frame(f);
        QuicCursor c(buf, plen);
        auto g = c.get_frame();
        bool ok = packed_ok && g && c.length() == 0 &&
                  memcmp(g->path_data, f.path_data, sizeof(f.path_data)) == 0;
        check(ok, "path_challenge roundtrip");
    }

    //---- 连续多帧：游标逐帧推进 ----
    {
        char buf[512];
        QuicCursor pc(buf, sizeof(buf));
        quic_frame f1{QUIC_FRAME_PING};
        pc.put_frame(f1);
        quic_frame f2{QUIC_FRAME_MAX_DATA};
        f2.extra = 300;
        pc.put_frame(f2);
        quic_frame f3{QUIC_FRAME_HANDSHAKE_DONE};
        pc.put_frame(f3);
        QuicCursor c(buf, sizeof(buf) - pc.length());
        int count = 0;
        bool ok = true;
        while(c.length()){
            auto g = c.get_frame();
            if(!g){
                ok = false;
                break;
            }
            count++;
        }
        check(ok && count == 3, "multi-frame sequence");
    }

    //---- 负向量 ----
    {
        //打包空间不足必须整体失败
        quic_frame f{QUIC_FRAME_CRYPTO};
        f.crypto.offset = 128;
        f.crypto.length = 5;
        f.crypto.buffer = new Buffer(5);
        memcpy(f.crypto.buffer->mutable_data(), "hello", 5);
        f.crypto.buffer->truncate(5);
        char small[7]; //完整需要8字节: type+offset+len+5
        QuicCursor pc(small, sizeof(small));
        check(!pc.put_frame(f), "pack insufficient space");
    }
    {
        //padding帧：type字节+extra-1个0，与pack_frame_len一致
        quic_frame f{QUIC_FRAME_PADDING};
        f.extra = 4;
        roundtrip(f, "padding");
    }
    {
        //ack range_count声称远超剩余字节
        unsigned char b[] = {0x02, 0x00, 0x00, 0x64, 0x00};
        QuicCursor c(b, sizeof(b));
        check(!c.get_frame(), "ack oversized range_count");
    }
    {
        //datagram长度varint声称2^56，body为空：必须在分配前拒绝
        unsigned char b[] = {0x31, 0xc1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
        QuicCursor c(b, sizeof(b));
        check(!c.get_frame(), "datagram huge length");
    }
    {
        //crypto长度varint(4字节)声称16384，body为空
        unsigned char b[] = {0x06, 0x00, 0x80, 0x00, 0x40, 0x00};
        QuicCursor c(b, sizeof(b));
        check(!c.get_frame(), "crypto huge length");
    }
    {
        //new_connection_id声明length=255但无内容
        unsigned char b[] = {0x18, 0x00, 0x00, 0xff};
        QuicCursor c(b, sizeof(b));
        check(!c.get_frame(), "new_connection_id truncated");
    }
    {
        //未知帧类型
        unsigned char b[] = {0x1f};
        QuicCursor c(b, sizeof(b));
        check(!c.get_frame(), "unknown frame type");
    }

    //---- unpack_meta：报文头元信息解析 ----
    {
        //长头Initial：flags 0xC0 + version1 + dcid8 + scid4 + token3 + payload10
        unsigned char pkt[64];
        size_t n = 0;
        pkt[n++] = 0xC0;
        pkt[n++] = 0; pkt[n++] = 0; pkt[n++] = 0; pkt[n++] = 1;
        pkt[n++] = 8;
        for(int i = 1; i <= 8; i++) pkt[n++] = i;
        pkt[n++] = 4;
        pkt[n++] = 'a'; pkt[n++] = 'b'; pkt[n++] = 'c'; pkt[n++] = 'd';
        pkt[n++] = 3;
        pkt[n++] = 't'; pkt[n++] = 'o'; pkt[n++] = 'k';
        pkt[n++] = 10;
        for(int i = 0; i < 10; i++) pkt[n++] = 0xEE;
        QuicCursor mc(pkt, n);
        auto meta = unpack_meta(mc, 0);
        bool ok = meta && mc.length() == 0 &&
                  meta->type == QUIC_PACKET_INITIAL &&
                  meta->version == QUIC_VERSION_1 && meta->dcid.size() == 8 &&
                  (unsigned char)meta->dcid[0] == 1 && (unsigned char)meta->dcid[7] == 8 &&
                  meta->scid == "abcd" && meta->token == "tok";
        check(ok, "unpack_meta initial");
        //尾部拼接垃圾(合并包场景)：游标只推进本包长度
        pkt[n] = 0xFF; pkt[n+1] = 0xFF;
        QuicCursor mc2(pkt, n + 2);
        auto meta2 = unpack_meta(mc2, 0);
        check(meta2 && mc2.length() == 2, "unpack_meta coalesced");
    }
    {
        //retry包：头部后跟3字节body + 16字节tag，token取body
        unsigned char pkt[64];
        size_t n = 0;
        pkt[n++] = 0xF0; //long | fixed | retry(0x3<<4)
        pkt[n++] = 0; pkt[n++] = 0; pkt[n++] = 0; pkt[n++] = 1;
        pkt[n++] = 0; //dcid空
        pkt[n++] = 0; //scid空
        pkt[n++] = 'x'; pkt[n++] = 'y'; pkt[n++] = 'z';
        for(int i = 0; i < 16; i++) pkt[n++] = 0x11;
        QuicCursor mc(pkt, n);
        auto meta = unpack_meta(mc, 0);
        bool ok = meta && mc.length() == 0 &&
                  meta->type == QUIC_PACKET_RETRY && meta->token == "xyz";
        check(ok, "unpack_meta retry");
        //截掉tag：失败
        QuicCursor mc2(pkt, n - 16);
        check(!unpack_meta(mc2, 0), "unpack_meta retry no tag");
    }
    {
        //短包：dcid长度由调用方预填，内容从第2字节覆写
        unsigned char pkt[16] = {0};
        pkt[0] = 0x40;
        for(int i = 1; i <= 9; i++) pkt[i] = i;
        QuicCursor mc(pkt, 10);
        auto meta = unpack_meta(mc, 8);
        bool ok = meta && mc.length() == 0 &&
                  meta->type == QUIC_PACKET_1RTT &&
                  meta->dcid.size() == 8 && (unsigned char)meta->dcid[0] == 1 &&
                  (unsigned char)meta->dcid[7] == 8;
        check(ok, "unpack_meta short packet");
        QuicCursor mc2(pkt, 9);
        check(!unpack_meta(mc2, 8), "unpack_meta short too small");
    }
    {
        //负向量：空包/固定位缺失/头截断
        QuicCursor empty((const void*)"", 0);
        check(!unpack_meta(empty, 0), "unpack_meta empty");
        unsigned char bad_fixed[] = {0x00};
        QuicCursor bf(bad_fixed, sizeof(bad_fixed));
        check(!unpack_meta(bf, 0), "unpack_meta no fixed bit");
        unsigned char trunc[] = {0xC0, 0, 0};
        QuicCursor tc(trunc, sizeof(trunc));
        check(!unpack_meta(tc, 0), "unpack_meta truncated header");
    }

    //---- 报文级加解密往返：pack_header/encode_packet/decode_packet/aead/hp ----
        //QUIC密钥按发送方派生：服务端解收客户端Initial用客户端密钥(guest_sni同此)
    {
        const char dcid[] = "12345678";
        quic_secret csecret, ssecret;
        if(quic_generate_initial_key(1, dcid, 8, &csecret, QUIC_VERSION_1) != 0 ||
           quic_generate_initial_key(0, dcid, 8, &ssecret, QUIC_VERSION_1) != 0)
        {
            failures++;
            printf("FAIL packet roundtrip: initial key\n");
        }else{
            quic_pkt_header header;
            header.type = QUIC_PACKET_INITIAL;
            header.dcid = dcid;     //收方cid
            header.scid = dcid;     //发方cid，测试里复用
            header.version = QUIC_VERSION_1;
            header.token = "";
            header.pn = 42;
            header.pn_length = 4;
            header.pn_base = 0;

            //payload: PING + CRYPTO("hello") + MAX_DATA(300)
            char payload[16];
            QuicCursor pc(payload, sizeof(payload));
            quic_frame f1{QUIC_FRAME_PING};
            pc.put_frame(f1);
            quic_frame fc{QUIC_FRAME_CRYPTO};
            fc.crypto.length = 5;
            fc.crypto.buffer = new Buffer(5);
            memcpy(fc.crypto.buffer->mutable_data(), "hello", 5);
            fc.crypto.buffer->truncate(5);
            pc.put_frame(fc);
            quic_frame f2{QUIC_FRAME_MAX_DATA};
            f2.extra = 300;
            pc.put_frame(f2);
            size_t plen = sizeof(payload) - pc.length();

            char out[256];
            QuicCursor oc(out, sizeof(out));
            size_t packet_len = encode_packet(cursor(payload, plen), &header, &csecret, oc);
            if(packet_len == 0){
                failures++;
                printf("FAIL packet roundtrip: encode_packet\n");
            }else{
                //容量不足必须整体失败
                char tiny[8];
                QuicCursor tc(tiny, sizeof(tiny));
                check(encode_packet(cursor(payload, plen), &header, &csecret, tc) == 0,
                      "encode_packet no space");

                //解密会原地写回：留一份原始密文给错误密钥的负向量
                char wire[256];
                memcpy(wire, out, packet_len);

                //接收侧：先解元信息再解密
                quic_pkt_header rx;
                static_cast<quic_meta&>(rx) = quic_meta{};
                QuicCursor mc(wire, packet_len);
                auto meta = unpack_meta(mc, 0);
                bool meta_ok = meta && mc.length() == 0;
                if(meta_ok){
                    static_cast<quic_meta&>(rx) = std::move(*meta);
                }
                rx.pn_base = 42; //decode_pn窗口对齐发送pn
                std::deque<quic_frame> frames;
                auto status = decode_packet(Buffer(wire, packet_len), &rx, &csecret, &frames);
                //帧在decode_packet返回后仍持零拷贝载荷：生命周期由共享指针保证(ASan验证)
                bool ok = meta_ok && status == quic_decode_status::ok && frames.size() == 3 &&
                          frames.front().type == QUIC_FRAME_PING &&
                          frames[1].type == QUIC_FRAME_CRYPTO &&
                          frames[1].crypto.length == 5 &&
                          frames[1].crypto.buffer->len == 5 &&
                          memcmp(frames[1].crypto.buffer->data(), "hello", 5) == 0 &&
                          frames.back().type == QUIC_FRAME_MAX_DATA &&
                          frames.back().extra == 300;
                check(ok, "packet encrypt-decrypt roundtrip");

                //共享源经COW解密：原始密文不受影响，同一密文可重复解出(guest_sni重扫场景)
                Buffer src(wire, packet_len);
                std::deque<quic_frame> f1, f2;
                bool cow_ok = decode_packet(Buffer(src), &rx, &csecret, &f1) == quic_decode_status::ok &&
                              f1.size() == 3 &&
                              decode_packet(Buffer(src), &rx, &csecret, &f2) == quic_decode_status::ok &&
                              f2.size() == 3 && f2.back().extra == 300 &&
                              memcmp(src.data(), wire, packet_len) == 0;
                check(cow_ok, "packet decode via shared COW buffer");
                //密钥不匹配必须解密失败(drop)且不产出帧
                std::deque<quic_frame> bad_frames;
                check(decode_packet(Buffer(out, packet_len), &rx, &ssecret, &bad_frames)
                      == quic_decode_status::drop, "packet decrypt with wrong key");

                //已认证的明文里出现畸形帧：必须报conn_error而非静默丢弃
                char bad_payload[1] = {0x1f}; //未知帧类型
                cursor bpc(bad_payload, sizeof(bad_payload));
                QuicCursor boc(out, sizeof(out));
                size_t bad_len = encode_packet(bpc, &header, &csecret, boc);
                std::deque<quic_frame> err_frames;
                check(bad_len && decode_packet(Buffer(out, bad_len), &rx, &csecret, &err_frames)
                      == quic_decode_status::conn_error, "malformed frame in authed packet");
            }
        }
    }

    printf(failures ? "=== %d FAILURES ===\n" : "=== ALL PASS ===\n", failures);
    return failures ? 1 : 0;
}
