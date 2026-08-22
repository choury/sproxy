#include "dns.h"
#include "misc/net.h"

static char test_dns_1[] = "\x95\x3a\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x05\x73\x74\x61"
                           "\x74\x73\x05\x6a\x70\x75\x73\x68\x02\x63\x6e\x00\x00\x1c\x00\x01";

static char test_dns_2[] = "\x8b\xb7\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07\x61\x6e\x64"
                           "\x72\x6f\x69\x64\x0a\x67\x6f\x6f\x67\x6c\x65\x61\x70\x69\x73\x03"
                           "\x63\x6f\x6d\x00\x00\x01\x00\x01";

static char test_dns_3[] = "\xd7\xca\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x01\x34\x01\x35"
                           "\x01\x38\x01\x34\x01\x38\x01\x39\x01\x35\x01\x33\x01\x31\x01\x36"
                           "\x01\x63\x01\x38\x01\x61\x01\x35\x01\x34\x01\x65\x01\x64\x01\x63"
                           "\x01\x62\x01\x65\x01\x33\x01\x33\x01\x32\x01\x33\x01\x36\x01\x35"
                           "\x01\x35\x01\x38\x01\x38\x01\x30\x01\x34\x01\x32\x03\x69\x70\x36"
                           "\x04\x61\x72\x70\x61\x00\x00\x0c\x00\x01";

static char test_dns_4[] = "\x7b\xa8\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x02\x31\x32\x01"
                           "\x30\x02\x31\x38\x03\x31\x39\x38\x07\x69\x6e\x2d\x61\x64\x64\x72"
                           "\x04\x61\x72\x70\x61\x00\x00\x0c\x00\x01";

static char test_dns_5[] = "\x68\x75\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x1c\x00\x01";
static char test_dns_6[] = "\x5c\x43\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x01";

static char test_dns_7[] = "\x66\x55\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07"
                           "example\x03""com\x00\x00\x01\x00\x01";
static char test_dns_8[] = "\x66\x56\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07"
                           "example\x03""com\xc0\x00\x00\x01\x00\x01";
static char test_dns_9[] = "\x66\x57\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\xc0\x12\x00\x01"
                           "\x00\x01\x07""example\x03""com\x00";
static char test_dns_10[] ="\x66\x58\x01\x00\x00\x01\x00\x00\x00\x00\x00\x01\xc0\x12\x00\x01"
                           "\x00\x01\x07""example\x03""com\x00\x00\x01\x00\x01\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00";

static char test_dns_11[] = "\x43\x21\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
                           "\x04""test\x07""example\x03""com\x00\x00\x0f\x00\x01";

static char test_dns_12[] = "\x56\x78\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
                           "\x04""_sip\x04""_tcp\x07""example\x03""com\x00\x00\x21\x00\x01";

//自指压缩指针：\xc0\x0c指向偏移12(即指针自身)，必须被递归深度限制拒绝
static char test_dns_13[] = "\x66\x59\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
                            "\xc0\x0c\x00\x01\x00\x01";

//qname截断："3com"后缺少根标签，报文即结束
static char test_dns_14[] = "\x66\x5a\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03com";

//标签声明长度越过报文尾
static char test_dns_15[] = "\x66\x5b\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
                            "\x0b""short\x00\x01\x00\x01";

//A应答：question(example.com A) + 1条A记录(93.184.216.34, ttl 3600)
static char test_res_1[] = "\x66\x5c\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00"
                           "\x07""example\x03""com\x00\x00\x01\x00\x01"
                           "\xc0\x0c\x00\x01\x00\x01\x00\x00\x0e\x10\x00\x04"
                           "\x5d\xb8\xd8\x22";

//链式压缩指针：qname→偏移18("www"+指针→偏移34("example.com"))
//回归点：子游标的base必须保持报文起点，否则内层指针按错误的起点解析
static char test_dns_16[] = "\x66\x5d\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
                            "\xc0\x12\x00\x01\x00\x01"
                            "\x03""www\xc0\x22"
                            "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                            "\x07""example\x03""com\x00";

struct dns_test{
    const char *query;
    size_t query_len;
    const char *domain;
    uint16_t id;
    uint16_t type;
};

dns_test query_tests[] = {
        {test_dns_1, sizeof(test_dns_1)-1, "stats.jpush.cn", 0x953a, 28},
        {test_dns_2, sizeof(test_dns_2)-1, "android.googleapis.com", 0x8bb7, 1},
        {test_dns_3, sizeof(test_dns_3)-1, "4.5.8.4.8.9.5.3.1.6.c.8.a.5.4.e.d.c.b.e.3.3.2.3.6.5.5.8.8.0.4.2.ip6.arpa", 0xd7ca, 12},
        {test_dns_4, sizeof(test_dns_4)-1, "12.0.18.198.in-addr.arpa", 0x7ba8, 12},
        {test_dns_5, sizeof(test_dns_5)-1, "", 0x6875, 28},
        {test_dns_6, sizeof(test_dns_6)-1, "", 0x5c43, 1},
        {test_dns_7, sizeof(test_dns_7)-1, "example.com", 0x6655, 1},
        {test_dns_9, sizeof(test_dns_9)-1, "example.com", 0x6657, 1},
        {test_dns_10, sizeof(test_dns_10)-1, "example.com", 0x6658, 1},
        {test_dns_11, sizeof(test_dns_11)-1, "test.example.com", 0x4321, 15},
        {test_dns_12, sizeof(test_dns_12)-1, "_sip._tcp.example.com", 0x5678, 33},
        {test_dns_16, sizeof(test_dns_16)-1, "www.example.com", 0x665d, 1},
};

dns_test build_tests[] = {
        {test_dns_1, sizeof(test_dns_1)-1, "stats.jpush.cn.", 0x953a, 28},
        {test_dns_1, sizeof(test_dns_1)-1, "stats.jpush.cn", 0x953a, 28},
        {test_dns_2, sizeof(test_dns_2)-1, "android.googleapis.com.", 0x8bb7, 1},
        {test_dns_3, sizeof(test_dns_3)-1, "4.5.8.4.8.9.5.3.1.6.c.8.a.5.4.e.d.c.b.e.3.3.2.3.6.5.5.8.8.0.4.2.ip6.arpa.", 0xd7ca, 12},
        {test_dns_3, sizeof(test_dns_3)-1, "4.5.8.4.8.9.5.3.1.6.c.8.a.5.4.e.d.c.b.e.3.3.2.3.6.5.5.8.8.0.4.2.ip6.arpa", 0xd7ca, 12},
        {test_dns_4, sizeof(test_dns_4)-1, "12.0.18.198.in-addr.arpa.", 0x7ba8, 12},
        {test_dns_4, sizeof(test_dns_4)-1, "12.0.18.198.in-addr.arpa", 0x7ba8, 12},
        {test_dns_5, sizeof(test_dns_5)-1, ".", 0x6875, 28},
        {test_dns_5, sizeof(test_dns_5)-1, "", 0x6875, 28},
        {test_dns_6, sizeof(test_dns_6)-1, ".", 0x5c43, 1},
        {test_dns_6, sizeof(test_dns_6)-1, "", 0x5c43, 1},
};

//负向量：畸形报文必须整体拒绝为invalid
struct dns_invalid_test{
    const char* query;
    size_t query_len;
    const char* why;
};

dns_invalid_test invalid_tests[] = {
        //qname末尾的压缩指针指向偏移0(报文ID字段)，必须整体拒绝而非续读垃圾
        {test_dns_8, sizeof(test_dns_8)-1, "pointer to offset 0"},
        {test_dns_13, sizeof(test_dns_13)-1, "self-referential pointer"},
        {test_dns_14, sizeof(test_dns_14)-1, "truncated qname"},
        {test_dns_15, sizeof(test_dns_15)-1, "label beyond packet end"},
};

struct debug_flags_map debug[]{
        {},
        {},
        {"dns", true},
        {},
        {},
        {},
        {},
        {},
        {},
        {},
        {},
        {},
        {},
        {},
};

int main() {
    for(auto t : query_tests){
        Dns_Query query(t.query, t.query_len);
        if(!query.valid) {
            LOGE("query is invalid: 0x%x", t.id);
            return -1;
        }
        if (query.id != t.id) {
            LOGE("id error for: 0x%x\n", t.id);
            return 1;
        }
        if (query.type != t.type) {
            LOGE("type error for: 0x%x\n", t.id);
            return 1;
        }
        if(strcmp(query.domain, t.domain) != 0) {
            LOGE("name error for: 0x%x\n", t.id);
            return 1;
        }
    }
    for(auto t: build_tests){
        Dns_Query query(t.domain, t.type, t.id);
        uchar buff[1500];
        size_t len = query.build(buff, sizeof(buff));
        if(len != t.query_len){
            LOGE("build len error: 0x%x\n", t.id);
            return 1;
        }
        if(memcmp(t.query, buff, len) != 0){
            LOGE("build buff error: 0x%x\n", t.id);
            return 1;
        }
    }
    for(auto t: invalid_tests){
        Dns_Query query(t.query, t.query_len);
        if(query.valid) {
            LOGE("invalid query accepted: %s\n", t.why);
            return 1;
        }
    }
    //A应答解析
    {
        Dns_Result res(test_res_1, sizeof(test_res_1)-1);
        sockaddr_in* addr4 = (sockaddr_in*)&res.addrs[0];
        if(res.error != 0 || res.id != 0x665c || res.addrs.size() != 1 ||
           addr4->sin_family != AF_INET || addr4->sin_addr.s_addr != htonl(0x5db8d822) ||
           res.ttl != 3600)
        {
            LOGE("response parse error: error: %d, id: 0x%x, addrs: %zd, ttl: %u\n",
                 res.error, res.id, res.addrs.size(), res.ttl);
            return 1;
        }
    }
    //往返：build后重新解析(含尾点形式)
    for(const char* d: {"www.example.com", "www.example.com."}){
        Dns_Query build_q(d, ns_t_a, 0x1234);
        uchar buff[BUF_LEN];
        size_t len = build_q.build(buff, sizeof(buff));
        if(len == 0){
            LOGE("build failed for %s\n", d);
            return 1;
        }
        Dns_Query parsed((const char*)buff, len);
        if(!parsed.valid || parsed.id != 0x1234 || parsed.type != ns_t_a ||
           strcmp(parsed.domain, "www.example.com") != 0)
        {
            LOGE("roundtrip error for %s: %s\n", d, parsed.domain);
            return 1;
        }
    }
    //过小缓冲必须失败：放得下头+问题区但放不下域名
    {
        Dns_Query build_q("www.example.com", ns_t_a, 0x1234);
        uchar buff[20];
        if(build_q.build(buff, sizeof(buff)) != 0){
            LOGE("small buffer should fail\n");
            return 1;
        }
    }
    //PTR应答构造：rdlength由rdata子游标写入前后length()差得出
    {
        Dns_Query query("4.3.2.1.in-addr.arpa", ns_t_ptr, 0x4321);
        Dns_Result result("host.example.com");
        result.ttl = 300;
        uchar buff[BUF_LEN];
        size_t len = result.build(&query, buff, sizeof(buff));
        //头12 + 问题名22(4/3/2/1/in-addr/arpa) + que4 + 应答名22 + RR头10 + rdata18
        static const uchar rdata[] = "\x04""host\x07""example\x03""com\x00";
        if(len != 88 || memcmp(buff + 68, "\x00\x12", 2) != 0 ||
           memcmp(buff + 70, rdata, 18) != 0)
        {
            LOGE("ptr build error: len: %zd, rdlength: 0x%x 0x%x\n",
                 len, buff[68], buff[69]);
            return 1;
        }
    }
}

int storage_aton(const char* ipstr, uint16_t port, struct sockaddr_storage* addr){
    memset(addr, 0, sizeof(struct sockaddr_storage));
    struct sockaddr_in* addr4 = (struct sockaddr_in*)addr;
    if (inet_pton(AF_INET, ipstr, &addr4->sin_addr) == 1) {
        addr4->sin_family = AF_INET;
        addr4->sin_port = htons(port);
        return 1;
    }
    struct sockaddr_in6* addr6 = (struct sockaddr_in6*)addr;
    if (inet_pton(AF_INET6, ipstr, &addr6->sin6_addr) == 1) {
        addr6->sin6_family = AF_INET6;
        addr6->sin6_port = htons(port);
        return 1;
    }
    return 0;
}

void slog(int level, const char* fmt, ...){
    (void)level;
    va_list ap;
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
}
