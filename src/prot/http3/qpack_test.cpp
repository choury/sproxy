//qpack 回归测试：混合字段类型、静态名+字面量值、huffman、异常输入
#include "qpach.h"
#include "prot/http/http_code.h"

#include <string.h>

//单测不链接整个 sproxy，桩掉依赖的全局符号
void slog(int, const char*, ...) {}
struct debug_flags_map debug[128] = {};

//捕获 UnpackHttp3Req 解出的头，替代真实的 HttpReqHeader 构造
static HeaderMap g_headers;
std::shared_ptr<HttpReqHeader> HttpReqHeader::create(HeaderMap&& headers) {
    g_headers = std::move(headers);
    return nullptr;
}
//Apple clang在-O0下引用HttpReqHeader的typeinfo，桩出全部非inline虚函数，
//使vtable/typeinfo随关键函数(Normalize)在本测试TU内发射；测试本身不调用它们
bool HttpReqHeader::no_body() const { return true; }
bool HttpReqHeader::no_end() const { return false; }
std::multimap<std::string, std::string> HttpReqHeader::Normalize() const { return {}; }
size_t HttpReqHeader::mem_usage() { return 0; }
//HttpHeader/HttpResHeader 的成员函数只在 qpack.o 中被引用，这里一并桩掉
HttpHeader::HttpHeader() {}
size_t HttpHeader::mem_usage() { return 0; }
std::multimap<std::string, std::string> HttpResHeader::Normalize() const { return {}; }
bool HttpResHeader::no_body() const { return false; }
bool HttpResHeader::no_end() const { return false; }
HttpResHeader::HttpResHeader(HeaderMap&& headers) {
    g_headers = std::move(headers);
}

static int failures = 0;

static void expect(const char* what, std::multimap<std::string, std::string> want) {
    if(g_headers.size() == want.size()) {
        auto i = g_headers.begin();
        auto j = want.begin();
        for(; i != g_headers.end(); ++i, ++j) {
            if(i->first != j->first || i->second != j->second) break;
        }
        if(i == g_headers.end()) {
            printf("PASS %s (%zu headers)\n", what, g_headers.size());
            return;
        }
    }
    failures++;
    printf("FAIL %s: got %zu headers:\n", what, g_headers.size());
    for(auto& h : g_headers) printf("    %s: %s\n", h.first.c_str(), h.second.c_str());
    printf("  want %zu headers:\n", want.size());
    for(auto& h : want) printf("    %s: %s\n", h.first.c_str(), h.second.c_str());
}

static void expect_null(const char* what, std::shared_ptr<HttpReqHeader> req) {
    if(req == nullptr && g_headers.empty()) {
        printf("PASS %s\n", what);
    } else {
        failures++;
        printf("FAIL %s\n", what);
    }
}

static void check(bool ok, const char* what) {
    if(ok) {
        printf("PASS %s\n", what);
    } else {
        failures++;
        printf("FAIL %s\n", what);
    }
}

int main() {
    g_headers.clear();
    //三种字段类型混排：索引字段(c1=:path /)、静态名+字面量值(50 :authority)、双字面量
    //回归点：字段标志位须逐字段读取；静态名的字面量值不能丢失
    unsigned char b1[] = {
        0x00, 0x00, // ric=0, delta=0
        0xc1,       // indexed static 1: :path /
        0x50, 0x0f, // literal, static name 0(:authority), raw value
        'w','w','w','.','e','x','a','m','p','l','e','.','c','o','m',
        0x26, 'x','-','t','e','s','t', 0x05, 'h','e','l','l','o'
    };
    Qpack_decoder::UnpackHttp3Req(b1, sizeof(b1));
    expect("mixed field types", {{":path", "/"},
                                 {":authority", "www.example.com"},
                                 {"x-test", "hello"}});

    g_headers.clear();
    //静态名 + huffman 值(huffman("www.example.com") 同 HPACK C.4.1)
    unsigned char b2[] = {
        0x00, 0x00,
        0x50, 0x8c,
        0xf1,0xe3,0xc2,0xe5,0xf2,0x3a,0x6b,0xa0,0xab,0x90,0xf4,0xff
    };
    Qpack_decoder::UnpackHttp3Req(b2, sizeof(b2));
    expect("static name + huffman value", {{":authority", "www.example.com"}});

    g_headers.clear();
    //huffman 字面量后再跟索引字段：huffman 只消费声明的长度，后续字段正常解析
    unsigned char b3[] = {
        0x00, 0x00,
        0x50, 0x8c,
        0xf1,0xe3,0xc2,0xe5,0xf2,0x3a,0x6b,0xa0,0xab,0x90,0xf4,0xff,
        0xc1
    };
    Qpack_decoder::UnpackHttp3Req(b3, sizeof(b3));
    expect("huffman literal then indexed", {{":authority", "www.example.com"},
                                            {":path", "/"}});

    g_headers.clear();
    //多字节长度 varint: 双字面量 + 300 字节明文值(长度 varint = 7f ad 01)
    unsigned char b4[512];
    b4[0] = 0x00; b4[1] = 0x00;
    b4[2] = 0x21; b4[3] = 'k'; // literal, name len 1
    b4[4] = 0x7f; b4[5] = 0xad; b4[6] = 0x01; // value len = 300
    memset(b4 + 7, 'v', 300);
    Qpack_decoder::UnpackHttp3Req(b4, 7 + 300);
    if(g_headers.size() == 1 && g_headers.begin()->first == "k" &&
       g_headers.begin()->second == std::string(300, 'v')) {
        printf("PASS multi-byte length varint\n");
    } else {
        failures++;
        printf("FAIL multi-byte length varint: %zu headers\n", g_headers.size());
    }

    g_headers.clear();
    unsigned char empty[] = {0x00};
    expect_null("empty block", Qpack_decoder::UnpackHttp3Req(empty, 0));

    g_headers.clear();
    unsigned char truncated[] = {0x00, 0x50}; // 值缺字面量
    expect_null("truncated block", Qpack_decoder::UnpackHttp3Req(truncated, sizeof(truncated)));

    g_headers.clear();
    //值内嵌 CR/LF 必须拒绝(防 h1 降级走私)
    unsigned char crlf[] = {0x00, 0x00, 0x21, 'k', 0x02, '\r', '\n'};
    expect_null("CRLF in value", Qpack_decoder::UnpackHttp3Req(crlf, sizeof(crlf)));

    g_headers.clear();
    //N位(0x10)与H位(0x08)语义钉死(RFC 9204 §4.5.6)：N=1的raw名(0x32)不能被误当Huffman解
    unsigned char nbit[] = {0x00, 0x00, 0x32, 'a', 'b', 0x05, 'h', 'e', 'l', 'l', 'o'};
    Qpack_decoder::UnpackHttp3Req(nbit, sizeof(nbit));
    expect("N=1 raw name", {{"ab", "hello"}});

    g_headers.clear();
    //N=1且H=1的Huffman名：len=12超出3-bit前缀单字节上限(7)，varint为0x3f 0x05
    unsigned char nbit_hfm[] = {
        0x00, 0x00, 0x3f, 0x05,
        0xf1,0xe3,0xc2,0xe5,0xf2,0x3a,0x6b,0xa0,0xab,0x90,0xf4,0xff,
        0x05, 'h','e','l','l','o'
    };
    Qpack_decoder::UnpackHttp3Req(nbit_hfm, sizeof(nbit_hfm));
    expect("N=1 huffman name", {{"www.example.com", "hello"}});

    //---- 编码路径：Qpack_encoder::encode(含Huffman) + 往返 + 恰好耗尽负向量 ----
    Qpack_encoder qenc(nullptr); //构造以初始化静态表
    {
        //索引字段行：(:path,/)在静态表中 → 单字节 0xC0|1，与解码测试的0xc1一致
        unsigned char buf[64];
        HttpCursor c(buf, sizeof(buf));
        bool ok = Qpack_encoder::encode(c, ":path", "/");
        check(ok && sizeof(buf) - c.length() == 1 && buf[0] == 0xc1,
              "encode indexed field");
    }
    {
        //静态名+Huffman值：输出必须与解码侧已知向量逐字节一致
        //(huffman("www.example.com") = f1e3c2e5f23a6ba0ab90f4ff, 同HPACK C.4.1)
        static const unsigned char want[] = {
            0x50, 0x8c,
            0xf1,0xe3,0xc2,0xe5,0xf2,0x3a,0x6b,0xa0,0xab,0x90,0xf4,0xff
        };
        unsigned char buf[64];
        HttpCursor c(buf, sizeof(buf));
        bool ok = Qpack_encoder::encode(c, ":authority", "www.example.com");
        check(ok && sizeof(buf) - c.length() == sizeof(want) &&
              memcmp(buf, want, sizeof(want)) == 0,
              "encode static name + huffman value");
    }
    {
        //双字面量：name与value都走Huffman且解码往返一致
        unsigned char buf[128];
        HttpCursor c(buf, sizeof(buf));
        bool ok = Qpack_encoder::encode(c, "x-custom-key", std::string(24, 'a'));
        size_t packed = sizeof(buf) - c.length();
        //raw需 1+12+1+24 = 38字节，Huffman后必然更短
        if(ok && packed < 38) {
            unsigned char block[64] = {0x00, 0x00};
            memcpy(block + 2, buf, packed);
            g_headers.clear();
            Qpack_decoder::UnpackHttp3Req(block, 2 + packed);
            expect("encode double literal huffman roundtrip",
                   {{"x-custom-key", std::string(24, 'a')}});
        } else {
            failures++;
            printf("FAIL encode double literal huffman: ok=%d packed=%zd\n", (int)ok, packed);
        }
    }
    {
        //恰好耗尽负向量1(越界写回归)：静态名索引varint恰好填满1字节，value无空间
        //旧实现此处向*mutable_data()=0x00写在界外(堆缓冲下即越界写)，必须整体失败
        unsigned char* small = new unsigned char[1];
        HttpCursor c(small, 1);
        bool ok = Qpack_encoder::encode(c, ":authority", "www.example.com");
        delete[] small;
        check(!ok, "encode exhausted after static name");
    }
    {
        //恰好耗尽负向量2：2字符名的Huffman不省字节走raw，恰好填满后value无空间
        unsigned char* small = new unsigned char[3];
        HttpCursor c(small, 3);
        bool ok = Qpack_encoder::encode(c, "ab", "hello");
        delete[] small;
        check(!ok, "encode exhausted after literal name");
    }

    printf(failures ? "=== %d FAILURES ===\n" : "=== ALL PASS ===\n", failures);
    return failures ? 1 : 0;
}
