#include "common.h"
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
    int disable_ipv6;
    int disable_http2;
    int sni_mode;
    int rudp_mode;
    int daemon_mode;
    int ignore_cert_error;
    int autoindex;

    uint16_t CPORT;
    uint16_t SPORT;
    char SPROT[DOMAINLIMIT];
    char SHOST[DOMAINLIMIT];
    char auth_string[DOMAINLIMIT];
    char rewrite_auth[DOMAINLIMIT];
};

extern struct options opt;

void parseConfig(int argc, char **argv);
int setproxy(const char* proxy);
int getproxy(char *buff, size_t buflen);
void flushproxy2(int force);
void change_process_name(const char *name);
#ifdef __cplusplus
}
#endif
