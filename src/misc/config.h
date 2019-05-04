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
    const char *index_file;
    const char *interface;
    bool disable_ipv6;
    bool disable_http2;
    bool sni_mode;
    bool rudp_mode;
    bool daemon_mode;
    bool ignore_cert_error;
    bool autoindex;

    uint16_t CPORT;
    uint16_t SPORT;
    char SPROT[DOMAINLIMIT];
    char SHOST[DOMAINLIMIT];
    char auth_string[DOMAINLIMIT];
    char rewrite_auth[DOMAINLIMIT];
};

extern struct options opt;

void prepare();
void parseConfigFile(const char* config_file);
void parseConfig(int argc, char **argv);
int setproxy(const char* proxy);
int getproxy(char *buff, size_t buflen);
void flushproxy2(int force);
void change_process_name(const char *name);
#ifdef __cplusplus
}
#endif
