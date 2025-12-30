#ifndef CONFIG_H__
#define CONFIG_H__

#include "common/common.h"
#include <stdbool.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#ifdef __APPLE__
#include <sys/event.h>
#else
#include <sys/epoll.h>
#endif

#ifdef  __cplusplus
extern "C" {
#endif

/*
 * Ensure GNU basename behavior on musl/mac
 */
 #ifndef __GLIBC__
 #define basename(path) \
        (strrchr((path), '/') ? strrchr((path),'/') + 1 : (path))
 #endif

#define HTTPSPORT 443u
#define HTTPPORT  80u
#define DNSPORT   53u
#define QUICPORT  443u

struct DnsConfig{
    int    timeout;
    size_t namecount;
    struct sockaddr_storage server[20];
    struct Destination doh;
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

struct dest_list{
    struct Destination dest;
    struct dest_list* next;
};

struct cert_pair{
    STACK_OF(X509)   *chain;
    EVP_PKEY         *key;
};

static inline X509* cert_pair_leaf(const struct cert_pair* pair) {
    if(pair == NULL || pair->chain == NULL || sk_X509_num(pair->chain) == 0) {
        return NULL;
    }
    return sk_X509_value(pair->chain, 0);
}

struct options{
    const char *cafile;
    const char *cakey;
    struct cert_pair ca;
    struct cert_pair cert;
    const char *config_file;
    const char *rootdir;
    const char *webdav_root;
    const char *index_file;
    const char *interface;
    const char *ua;
    const char *pcap_file;
    const char *alt_svc;
    const char *rproxy_name;
    const char *bpf_cgroup;
    const char *acme_state;
    bool disable_http2;
    bool disable_fakeip;
    bool sni_mode;
    bool daemon_mode;
    bool ignore_cert_error;
    bool ignore_hosts;
    bool autoindex;
    bool ipv6_enabled;
    bool ipv6_prefer;
    bool alter_method;
    bool set_dns_route;
    bool tun_mode;
    int  tun_fd;
    int  trace_time;
    bool redirect_http;
    bool restrict_local;
    bool rproxy_keep_src;
    bool systemd_socket;
    const char* quic_cc_algorithm;  // QUIC congestion control algorithm: "cubic" or "bbr"
    uint64_t quic_version;         // QUIC version: QUIC_VERSION_1 or QUIC_VERSION_2
    const char* doh_server;        // DNS over HTTPS server URL

    FILE* policy_read;
    FILE* policy_write;
    struct dest_list* http_list;
    struct dest_list* ssl_list;
    struct dest_list* quic_list;
    struct Destination admin;
    struct Destination tproxy;
    uint64_t pcap_len;
    uint64_t fwmark;
    uint64_t bpf_fwmark;
    struct Destination Server;
    char rewrite_auth[DOMAINLIMIT];
    enum auto_mode ipv6_mode;
    enum auto_mode mitm_mode;
    struct arg_list request_headers;
    struct arg_list forward_headers;

    uint cert_version;
};

extern struct options opt;
extern volatile uint32_t will_contiune;

void exit_loop();
void neglect();

void network_changed();
int parseConfigFile(const char* config_file);
void parseConfig(int argc, char **argv);
void postConfig();
int parseDest(const char* proxy, struct Destination* server);
bool debugon(const char* module, bool enable);
bool is_http_listen_port(uint16_t port);
void append_dest_list(struct dest_list*** tail, const struct Destination* dest);

void flushdns();
void flushconnect();
int flushcert();

uint64_t nextId();

const char* getDeviceInfo();
int is_kernel_version_ge(int required_major, int required_minor);

#ifdef __cplusplus
}
#endif

#endif
