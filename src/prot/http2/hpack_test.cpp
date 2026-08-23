//hpack/http_code 回归测试：RFC 7541 附录 C 标准向量 + varint/字面量原语往返
#include "hpack.h"
#include "prot/http/http_code.h"

#include <string.h>

//单测不链接整个 sproxy，桩掉依赖的全局符号
void slog(int, const char*, ...) {}
struct debug_flags_map debug[128] = {};

//捕获 UnpackHttp2Req 解出的头，替代真实的 HttpReqHeader 构造。
//HttpHeader/HttpResHeader 的成员函数只在 hpack.o 中被引用，这里一并桩掉
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

int main() {
    //---- HttpCursor 原语 ----
    //RFC 7541 C.1.1/C.1.2 varint 向量
    unsigned char v1[] = {0x1f, 0x9a, 0x0a};
    HttpCursor c1(v1, sizeof(v1));
    auto r1 = c1.integer_decode(5);
    if(!r1 || *r1 != 1337 || c1.length() != 0) {
        failures++;
        printf("FAIL integer_decode C.1.2: %s\n", r1 ? std::to_string(*r1).c_str() : "nullopt");
    } else {
        printf("PASS integer_decode C.1.2\n");
    }

    //多字节 varint 编码-解码往返
    for(uint64_t value : {127ull, 128ull, 300ull, 1337ull, 65535ull, 987654ull}) {
        unsigned char buf[16] = {0};
        HttpCursor enc(buf, sizeof(buf));
        if(!enc.integer_encode(value, 7)) {
            failures++;
            printf("FAIL integer_encode %llu: no space\n", (unsigned long long)value);
            continue;
        }
        HttpCursor dec(buf, sizeof(buf));
        auto rt = dec.integer_decode(7);
        if(!rt || *rt != value) {
            failures++;
            printf("FAIL integer roundtrip %llu -> %s\n", (unsigned long long)value,
                   rt ? std::to_string(*rt).c_str() : "nullopt");
        }
    }
    printf("PASS integer roundtrips\n");

    //literal 编码-解码往返(huffman 与明文路径)
    for(const char* s : {"", "a", "www.example.com", "/index.html",
                         "custom-key custom-value 0123456789", "no-cache"}) {
        unsigned char buf[512] = {0};
        HttpCursor enc(buf, sizeof(buf));
        if(!enc.literal_encode(s, 7)) {
            failures++;
            printf("FAIL literal_encode '%s'\n", s);
            continue;
        }
        HttpCursor dec(buf, sizeof(buf) - enc.length());
        auto rt = dec.literal_decode(7);
        if(!rt || *rt != s || dec.length() != 0) {
            failures++;
            printf("FAIL literal roundtrip '%s' -> %s\n", s, rt ? rt->c_str() : "nullopt");
        }
    }
    printf("PASS literal roundtrips\n");

    //空游标/截断保护
    HttpCursor empty((const void*)nullptr, 0);
    if(empty.integer_decode(7) || empty.literal_decode(7)) {
        failures++;
        printf("FAIL empty cursor guard\n");
    } else {
        printf("PASS empty cursor guard\n");
    }
    unsigned char trunc[] = {0x7f};
    HttpCursor ctrunc(trunc, sizeof(trunc));
    if(ctrunc.integer_decode(7)) {
        failures++;
        printf("FAIL incomplete varint guard\n");
    } else {
        printf("PASS incomplete varint guard\n");
    }

    //---- hpack 解码：RFC 7541 附录 C 请求向量 ----
    Hpack_decoder dec; // 同一实例，跨请求保持动态表状态

    g_headers.clear();
    //C.3.1 无 huffman 首请求
    unsigned char c31[] = {
        0x82, 0x86, 0x84, 0x41, 0x0f,
        'w','w','w','.','e','x','a','m','p','l','e','.','c','o','m'
    };
    dec.UnpackHttp2Req(c31, sizeof(c31));
    expect("C.3.1", {{":method", "GET"}, {":scheme", "http"}, {":path", "/"},
                     {":authority", "www.example.com"}});

    g_headers.clear();
    //C.3.2 动态表索引 0xbe + cache-control 字面量(索引 24)
    unsigned char c32[] = {
        0x82, 0x86, 0x84, 0xbe, 0x58, 0x08,
        'n','o','-','c','a','c','h','e'
    };
    dec.UnpackHttp2Req(c32, sizeof(c32));
    expect("C.3.2", {{":method", "GET"}, {":scheme", "http"}, {":path", "/"},
                     {":authority", "www.example.com"}, {"cache-control", "no-cache"}});

    g_headers.clear();
    //C.3.3 新名字面量 custom-key；0xbf=动态63(:authority，头插后旧条目后移)
    unsigned char c33[] = {
        0x82, 0x87, 0x85, 0xbf, 0x40,
        0x0a, 'c','u','s','t','o','m','-','k','e','y',
        0x0c, 'c','u','s','t','o','m','-','v','a','l','u','e'
    };
    dec.UnpackHttp2Req(c33, sizeof(c33));
    expect("C.3.3", {{":method", "GET"}, {":scheme", "https"}, {":path", "/index.html"},
                     {":authority", "www.example.com"}, {"custom-key", "custom-value"}});

    g_headers.clear();
    //C.4.1 huffman 首请求
    unsigned char c41[] = {
        0x82, 0x86, 0x84, 0x41, 0x8c,
        0xf1,0xe3,0xc2,0xe5,0xf2,0x3a,0x6b,0xa0,0xab,0x90,0xf4,0xff
    };
    dec.UnpackHttp2Req(c41, sizeof(c41));
    expect("C.4.1", {{":method", "GET"}, {":scheme", "http"}, {":path", "/"},
                     {":authority", "www.example.com"}});

    g_headers.clear();
    //C.4.2 huffman + 动态表索引
    unsigned char c42[] = {
        0x82, 0x86, 0x84, 0xbe, 0x58, 0x86,
        0xa8,0xeb,0x10,0x64,0x9c,0xbf
    };
    dec.UnpackHttp2Req(c42, sizeof(c42));
    expect("C.4.2", {{":method", "GET"}, {":scheme", "http"}, {":path", "/"},
                     {":authority", "www.example.com"}, {"cache-control", "no-cache"}});

    g_headers.clear();
    //C.4.3 huffman 新名 + 动态表
    unsigned char c43[] = {
        0x82, 0x87, 0x85, 0xbf, 0x40, 0x88,
        0x25,0xa8,0x49,0xe9,0x5b,0xa9,0x7d,0x7f, 0x89,
        0x25,0xa8,0x49,0xe9,0x5b,0xb8,0xe8,0xb4,0xbf
    };
    dec.UnpackHttp2Req(c43, sizeof(c43));
    expect("C.4.3", {{":method", "GET"}, {":scheme", "https"}, {":path", "/index.html"},
                     {":authority", "www.example.com"}, {"custom-key", "custom-value"}});

    //多字节长度 varint: 300 字节明文值(长度 varint = 7f ad 01)
    g_headers.clear();
    unsigned char longval[512];
    longval[0] = 0x82; // :method GET
    longval[1] = 0x00; // 无索引新名字面量
    longval[2] = 0x01; longval[3] = 'k';
    longval[4] = 0x7f; longval[5] = 0xad; longval[6] = 0x01; // len = 300
    memset(longval + 7, 'v', 300);
    dec.UnpackHttp2Req(longval, 7 + 300);
    if(g_headers.size() == 2 && g_headers.count("k") &&
       g_headers.find("k")->second == std::string(300, 'v')) {
        printf("PASS multi-byte length varint\n");
    } else {
        failures++;
        printf("FAIL multi-byte length varint: %zu headers\n", g_headers.size());
    }

    //异常输入必须被拒绝且不产生头
    g_headers.clear();
    unsigned char empty_block[] = {0x00};
    expect_null("empty block", dec.UnpackHttp2Req(empty_block, 0));

    g_headers.clear();
    unsigned char truncated[] = {0x41, 0x7f}; // 长度 varint 未完结
    expect_null("truncated block", dec.UnpackHttp2Req(truncated, sizeof(truncated)));

    g_headers.clear();
    //值内嵌 CR/LF 必须拒绝(防 h1 降级走私)
    unsigned char crlf[] = {0x00, 0x01, 'k', 0x02, '\r', '\n'};
    expect_null("CRLF in value", dec.UnpackHttp2Req(crlf, sizeof(crlf)));

    printf(failures ? "=== %d FAILURES ===\n" : "=== ALL PASS ===\n", failures);
    return failures ? 1 : 0;
}
