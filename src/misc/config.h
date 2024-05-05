#ifndef CONFIG_H__
#define CONFIG_H__

#include "common/common.h"
#include <stdbool.h>
#include <openssl/ssl.h>

#ifdef __APPLE__
#include <sys/event.h>
#else
#include <sys/epoll.h>
#endif

#ifdef  __cplusplus
extern "C" {
#endif


#define HTTPSPORT 443u
#define HTTPPORT  80u
#define DNSPORT   53u
#define QUICPORT  443u

struct DnsConfig{
    int    timeout;
    size_t namecount;
    struct sockaddr_storage server[20];
};

void getDnsConfig(struct DnsConfig* config);

enum auto_mode{
    Disable = 0,
    Enable = 1,
    Auto = 2,
};

struct arg_list{
    const char* arg;
    struct arg_list* next;
};

struct cert_pair{
    X509     *crt;
    EVP_PKEY *key;
};

struct options{
    const char *admin;
    const char *cafile;
    const char *cakey;
    struct cert_pair ca;
    const char *certfile;
    const char *keyfile;
    struct cert_pair cert;
    const char *config_file;
    const char *rootdir;
    const char *index_file;
    const char *interface;
    const char *ua;
    const char *pcap_file;
    const char *alt_svc;
    bool disable_http2;
    bool sni_mode;
    bool quic_mode;
    bool daemon_mode;
    bool ignore_cert_error;
    bool autoindex;
    bool ipv6_enabled;
    bool alter_method;
    bool set_dns_route;

    FILE* policy_read;
    FILE* policy_write;
    const char* CHOST;
    uint64_t    CPORT;
    uint64_t pcap_len;
    struct Destination Server;
    char rewrite_auth[DOMAINLIMIT];
    enum auto_mode ipv6_mode;
    enum auto_mode mitm_mode;
    struct arg_list request_headers;
};

extern struct options opt;
extern volatile uint32_t will_contiune;

void neglect();

void network_changed();
int parseConfigFile(const char* config_file);
void parseConfig(int argc, char **argv);
void postConfig();
int loadproxy(const char* proxy, struct Destination* server);
bool debugon(const char* module, bool enable);

void flushdns();
void flushconnect();

uint64_t nextId();

const char* getDeviceInfo();
#ifdef __cplusplus
}
#endif

#endif
