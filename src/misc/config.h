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

struct options{
    const char *cafile;
    const char *cert;
    const char *key;
    const char *config_file;
    const char *policy_file;
    const char *rootdir;
    const char *index_file;
    const char *interface;
    bool disable_ipv6;
    bool disable_http2;
    bool sni_mode;
    bool daemon_mode;
    bool ignore_cert_error;
    bool autoindex;

    uint16_t CPORT;
    struct Destination Server;
    char auth_string[DOMAINLIMIT];
    char rewrite_auth[DOMAINLIMIT];
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
