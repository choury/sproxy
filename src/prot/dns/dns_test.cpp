#include "dns.h"



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
        {test_dns_8, sizeof(test_dns_8)-1, "example.com", 0x6656, 1},
        {test_dns_9, sizeof(test_dns_9)-1, "example.com", 0x6657, 1},
        {test_dns_10, sizeof(test_dns_10)-1, "example.com", 0x6658, 1},
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

uint32_t debug = DDNS;

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
        size_t len = query.build(buff);
        if(len != t.query_len){
            LOGE("build len error: 0x%x\n", t.id);
            return 1;
        }
        if(memcmp(t.query, buff, len)){
            LOGE("build buff error: 0x%x\n", t.id);
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
