#ifndef CONFIG_H__
#define CONFIG_H__

#include "common.h"
#include <stdbool.h>
#ifdef  __cplusplus
extern "C" {
#endif

struct DnsConfig{
    int namecount;
    union sockaddr_un server[3];
};

void getDnsConfig(struct DnsConfig* config);

enum ipv6_mode{
    Disable = 0,
    Enable = 1,
    Auto = 2,
};

struct arg_list{
    const char* arg;
    struct arg_list* next;
};

struct options{
    const char *cafile;
    const char *cert;
    const char *key;
    const char *config_file;
    const char *policy_file;
    const char *rootdir;
    const char *index_file;
    const char *interface;
    bool disable_http2;
    bool sni_mode;
    bool daemon_mode;
    bool ignore_cert_error;
    bool autoindex;
    bool ipv6_enabled;
    bool alter_method;

    int64_t CPORT;
    struct Destination Server;
    char auth_string[DOMAINLIMIT];
    char rewrite_auth[DOMAINLIMIT];
    enum ipv6_mode ipv6_mode;
    struct arg_list request_headers;
};

extern struct options opt;

void prepare();
int parseConfigFile(const char* config_file);
void parseConfig(int argc, char **argv);
int loadproxy(const char* proxy, struct Destination* server);
#ifdef __cplusplus
}
#endif

#endif
