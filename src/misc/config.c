#define _XOPEN_SOURCE
#define _GNU_SOURCE
#ifdef __APPLE__
#define _DARWIN_C_SOURCE
#endif
#include "config.h"
#include "util.h"
#include "strategy.h"
#include "net.h"
#include "common/version.h"
#include "network_notify.h"
#include "cert_manager.h"

#include <ctype.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <unistd.h>
#include <sys/socket.h>
#include <signal.h>
#include <inttypes.h>
#include <sys/utsname.h>
#include <sys/stat.h>
#ifndef __APPLE__
#include <sys/prctl.h>
#include <sys/resource.h>
#else
#include <pthread.h>
#endif
#include <openssl/ssl.h>
#include <openssl/x509.h>

static char** main_argv = NULL;
static char* auto_options[] = {"disable", "enable", "auto", NULL};
static char* server_string = NULL;
static char* policy_file = NULL;
static struct arg_list secrets = {NULL, NULL};
static struct arg_list debug_list = {NULL, NULL};
static struct arg_list http_listens = {NULL, NULL};
static struct arg_list ssl_listens = {NULL, NULL};
static struct arg_list quic_listens = {NULL, NULL};
static uint64_t id = 100000;

static const char *certfile = NULL;
static const char *keyfile = NULL;

static char* admin_listen = NULL;
static char* tproxy_listen = NULL;

volatile uint32_t will_contiune = 1;
int efd = -1;
void openefd(){
    if(efd >= 0){
        return;
    }
#if __linux__
    efd = epoll_create1(EPOLL_CLOEXEC);
#elif __APPLE__
    efd = kqueue();
#else
#error "Only macOS and linux are supported"
#endif
    if(efd < 0){
        LOGF("event fd create: %s\n", strerror(errno));
    }
}

struct options opt = {
    .cafile            = NULL,
    .cakey             = NULL,
    .ca                = {
        .chain = NULL,
        .key = NULL,
    },
    .cert              = {
        .chain = NULL,
        .key = NULL,
    },
    .rootdir           = NULL,
    .webdav_root       = NULL,
    .index_file        = NULL,
    .interface         = NULL,
    .ua                = NULL,
    .pcap_file         = NULL,
    .alt_svc           = NULL,
    .rproxy_name       = NULL,
    .bpf_cgroup        = NULL,
    .acme_state        = NULL,
    .disable_http2     = false,
    .disable_fakeip    = false,
    .sni_mode          = false,
    .daemon_mode       = false,
    .ignore_cert_error = false,
    .ignore_hosts      = false,
    .autoindex         = false,
    .ipv6_enabled      = true,
    .ipv6_prefer       = false,
    .alter_method      = false,
    .socks5_fast       = false,
    .set_dns_route     = false,
    .tun_mode          = false,
    .tun_fd            = -1,
    .trace_time        = 0,
    .redirect_http     = false,
    .restrict_local    = false,
    .rproxy_keep_src   = false,
    .systemd_socket    = false,
    .quic_cc_algorithm = NULL,
    .quic_version      = 1,  // Default to QUIC v1
    .doh_server        = NULL,

    .policy_read    = NULL,
    .policy_write   = NULL,
    .http_list      = NULL,
    .ssl_list       = NULL,
    .quic_list      = NULL,
    .tproxy         = {
        .scheme     = {0},
        .protocol   = {0},
        .hostname   = {0},
        .port       = 0,
        .systemd_fd = -1,
    },
    .admin          = {
        .scheme     = {0},
        .protocol   = {0},
        .hostname   = {0},
        .port       = 0,
        .systemd_fd = -1,
    },
    .Server         = {
        .scheme     = {0},
        .protocol   = {0},
        .hostname   = {0},
        .port       = 0,
        .systemd_fd = -1,
    },
    .rewrite_auth   = {0},
    .ipv6_mode      = Auto,
    .mitm_mode      = Auto,
    .request_headers = {
        .arg        = NULL,
        .next       = NULL,
    },
    .forward_headers = {
        .arg        = NULL,
        .next       = NULL,
    },
    .pcap_len       = INT32_MAX,
    .fwmark         = 0,
    .bpf_fwmark     = 0,

    .cert_version   = 0,
};

enum option_type{
    option_bool,
    option_int64,
    option_uint64,
    option_base64,
    option_string,
    option_enum,
    option_bitwise,
    option_list,
};

static const char* getopt_option = ":D1hikb:q:r:s:I:c:P:v";
static struct option long_options[] = {
    {"admin",         required_argument, NULL,  0 },
    {"acme",          required_argument, NULL,  0 },
    {"autoindex",     no_argument,       NULL, 'i'},
    {"alt-svc",       required_argument, NULL,  0 },
#ifdef HAVE_BPF
    {"bpf",           required_argument, NULL, 'b'},
    {"bpf-fwmark",    required_argument, NULL,  0 },
#endif
    {"cafile",        required_argument, NULL,  0 },
    {"cakey",         required_argument, NULL,  0 },
    {"cert",          required_argument, NULL,  0 },
    {"config",        required_argument, NULL, 'c'},
#ifndef __ANDROID__
    {"daemon",        no_argument,       NULL, 'D'},
#endif
    {"disable-fakeip",no_argument,       NULL,  0 },
    {"disable-http2", no_argument,       NULL, '1'},
    {"doh",           optional_argument, NULL,  0 },
    {"fwmark",        required_argument, NULL,  0 },
    {"help",          no_argument,       NULL, 'h'},
    {"http",          required_argument, NULL,  0 },
    {"mitm",          required_argument, NULL,  0 },
    {"ignore-hosts",  no_argument,       NULL,  0 },
    {"index",         required_argument, NULL,  0 },
    {"insecure",      no_argument,       NULL, 'k'},
#if __linux__
    {"interface",     required_argument, NULL, 'I'},
#endif
    {"ipv6",          required_argument, NULL,  0 },
    {"ipv6-prefer",   no_argument,       NULL,  0 },
    {"key",           required_argument, NULL,  0 },
    {"pcap",          required_argument, NULL,  0 },
    {"pcap-len",      required_argument, NULL,  0 },
    {"policy-file",   required_argument, NULL, 'P'},
#ifdef HAVE_QUIC
    {"quic",          required_argument, NULL, 'q'},
    {"quic-cc",       required_argument, NULL,  0 },
    {"quic-version",  required_argument, NULL,  0 },
#endif
    {"redirect-http", no_argument,       NULL,  0 },
    {"restrict-local",no_argument,       NULL,  0 },
    {"rewrite-auth",  required_argument, NULL, 'r'},
    {"root-dir",      required_argument, NULL,  0 },
#ifdef HAVE_WEBDAV
    {"webdav",        required_argument, NULL,  0 },
#endif
    {"secret",        required_argument, NULL, 's'},
#if __linux__
    {"set-dns-route", no_argument,       NULL,  0 },
    {"rproxy-kp",     no_argument,       NULL,  0 },
#endif
    {"sni",           no_argument,       NULL,  0 },
    {"ssl",           required_argument, NULL,  0 },
    {"alter-method",  no_argument,       NULL,  0 },
    {"socks5-fast",   no_argument,       NULL,  0 },
    {"rproxy",        required_argument, NULL,  0 },
    {"request-header",required_argument, NULL,  0 },
    {"forward-header",required_argument, NULL,  0 },
#if __linux__
    {"tun",           no_argument,       NULL,  0 },
    {"tun-fd",        required_argument, NULL,  0 },
    {"tproxy",        required_argument, NULL,  0 },
    {"trace",         required_argument, NULL,  0 },
    {"ua",            required_argument, NULL,  0 },
#endif
    {"version",       no_argument,       NULL, 'v'},
#ifndef NDEBUG
    {"debug",         required_argument, NULL,  0 },
#endif
    {NULL,            0,                 NULL,  0 }
};


struct option_detail {
    const char*      name;
    const char*      details;
    enum option_type type;
    void*            result;
    void*            value;
};

static struct option_detail option_detail[] = {
    {"admin", "set admin socket path for cli (/var/run/sproxy.sock is default for root and /tmp/sproxy.sock for others)", option_string, &admin_listen, NULL},
    {"alter-method", "use Alter-Method to define real method (for obfuscation), http1 only", option_bool, &opt.alter_method, (void*)true},
    {"acme", "Enable automatic certificate management (ACME) with state directory", option_string, &opt.acme_state, NULL},
    {"alt-svc", "Add alt-svc header to response or send ALTSVC frame", option_string, &opt.alt_svc, NULL},
    {"autoindex", "Enables the directory listing output (local server)", option_bool, &opt.autoindex, (void*)true},
    {"bpf", "load bpf prog to redirect for tproxy on cgroup (!!NOT WORK IN CONTAINER!!)", option_string, &opt.bpf_cgroup, NULL},
    {"bpf-fwmark", "set fwmark for the packet of replying rproxy in bpf prog", option_uint64, &opt.bpf_fwmark, NULL},
    {"cafile", "CA certificate for server (ssl/quic)", option_string, &opt.cafile, NULL},
    {"cakey", "CA key for server (mitm)", option_string, &opt.cakey, NULL},
    {"cert", "Certificate file for server (ssl/quic)", option_string, &certfile, NULL},
    {"config", "Configure file (default "PREFIX"/etc/sproxy/sproxy.conf and ./sproxy.conf)", option_string, &opt.config_file, NULL},
    {"daemon", "Run as daemon", option_bool, &opt.daemon_mode, (void*)true},
    {"disable-http2", "Use http/1.1 only", option_bool, &opt.disable_http2, (void*)true},
    {"disable-fakeip", "Do not use fakeip for vpn and tproxy", option_bool, &opt.disable_fakeip, (void*)true},
    {"doh", "DNS over HTTPS server (e.g., https://1.1.1.1), use server address if no argument", option_string, &opt.doh_server, ""},
    {"forward-header", "append the header (name:value) when forward http request", option_list, &opt.forward_headers, NULL},
    {"fwmark", "Set fwmark for output packet", option_uint64, &opt.fwmark, NULL},
    {"help", "Print this usage", option_bool, NULL, NULL},
    {"http", "Listen for http server", option_list, &http_listens, NULL},
    {"ignore-hosts", "Dont read entries from /etc/hosts ", option_bool, &opt.ignore_hosts, (void*)true},
    {"index", "Index file for path (local server)", option_string, &opt.index_file, NULL},
    {"insecure", "Ignore the cert error of server (SHOULD NOT DO IT)", option_bool, &opt.ignore_cert_error, (void*)true},
    {"interface", "Out interface (use for vpn), will skip bind if set to empty", option_string, &opt.interface, NULL},
    {"ipv6", "The ipv6 mode ([auto], enable, disable)", option_enum, &opt.ipv6_mode, auto_options},
    {"ipv6-prefer", "Prefer IPv6 address; error if IPv6 is unavailable", option_bool, &opt.ipv6_prefer, (void*)true},
    {"key", "Private key file name (ssl/quic)", option_string, &keyfile, NULL},
    {"mitm", "Mitm mode for https request ([auto], enable, disable), require cakey", option_enum, &opt.mitm_mode, auto_options},
    {"pcap", "Save packets in pcap file for vpn", option_string, &opt.pcap_file, NULL},
    {"pcap-len", "Max packet length to save in pcap file", option_uint64, &opt.pcap_len, NULL},
    {"policy-file", "The file of policy ("PREFIX"/etc/sproxy/sites.list as default)", option_string, &policy_file, NULL},
    {"quic", "Listen for QUIC server", option_list, &quic_listens, NULL},
    {"quic-cc", "QUIC congestion control algorithm (cubic, bbr)", option_string, &opt.quic_cc_algorithm, NULL},
    {"quic-version", "QUIC version (1 for QUIC v1, 2 for QUIC v2)", option_uint64, &opt.quic_version, NULL},
    {"redirect-http", "Return 308 to redirect http to https", option_bool, &opt.redirect_http, (void*)true},
    {"request-header", "append the header (name:value) before handle http request", option_list, &opt.request_headers, NULL},
    {"restrict-local", "check method and dst port for local strategy", option_bool, &opt.restrict_local, (void*)true},
    {"rewrite-auth", "[DEPRECATED]", option_base64, opt.rewrite_auth, NULL},
    {"root-dir", "The work dir (current dir if not set)", option_string, &opt.rootdir, NULL},
    {"rproxy", "name for rproxy mode (via http2/http3)", option_string, &opt.rproxy_name, (void*)true},
    {"rproxy-kp", "keep the source of rproxy request (via IP[V6]_TRANSPARENT)", option_bool, &opt.rproxy_keep_src, (void*)true},
    {"secret", "Set user and passwd for proxy (user:password), default is none.", option_list, &secrets, NULL},
    {"server", "default proxy server (can ONLY set in config file)", option_string, &server_string, NULL},
    {"set-dns-route", "set route for dns server (via vpn interface)", option_bool, &opt.set_dns_route, (void*)true},
    {"sni", "Act as a sni proxy", option_bool, &opt.sni_mode, (void*)true},
    {"socks5-fast", "Send socks5 greeting/auth/request without waiting for replies", option_bool, &opt.socks5_fast, (void*)true},
    {"ssl", "Listen for ssl server (require cert file and key)", option_list, &ssl_listens, NULL},
    {"tun", "tun mode (vpn mode, require root privilege)", option_bool, &opt.tun_mode, (void*)true},
    {"tun-fd", "tun fd (vpn mode, recv fd before execve)", option_int64, &opt.tun_fd, NULL},
    {"tproxy", "tproxy listen (get dst via SO_ORIGINAL_DST)", option_string, &tproxy_listen, (void*)true},
    {"trace", "print trace time if response time is larger than it", option_int64, &opt.trace_time, NULL},
    {"ua", "set user-agent for vpn auto request", option_string, &opt.ua, NULL},
    {"version", "show the version of this programme", option_bool, NULL, NULL},
    {"webdav", "Enable webdav and set its root directory", option_string, &opt.webdav_root, NULL},
    {"debug", "set debug output for module", option_list, &debug_list, NULL},
    {NULL, NULL, option_bool, NULL, NULL},
};

void network_changed(){
    LOG("handle network changed\n");
    if(opt.ipv6_mode == Auto){
        opt.ipv6_enabled = hasIpv6Address();
    }
    flushdns();
    flushconnect();
}


void releaseall();
void dump_stat();

void neglect(){
    flushdns();
    releaseall();
    EVP_PKEY_free(opt.ca.key);
    opt.ca.key = NULL;
    if(opt.ca.chain) {
        sk_X509_pop_free(opt.ca.chain, X509_free);
        opt.ca.chain = NULL;
    }
    EVP_PKEY_free(opt.cert.key);
    opt.cert.key = NULL;
    if(opt.cert.chain) {
        sk_X509_pop_free(opt.cert.chain, X509_free);
        opt.cert.chain = NULL;
    }
    release_key_pair();
}

static void usage(const char * program){
    LOG("Usage: %s [host:port]\n" , program);
    for(int i =0; option_detail[i].name; i++){
        bool found = false;
        char short_name = 0;
        for(int j=0; long_options[j].name; j++){
            if(strcmp(option_detail[i].name, long_options[j].name)){
                continue;
            }
            found = true;
            if(long_options[j].val){
                short_name = (char)long_options[j].val;
            }
            break;
        }
        if(!found) {
            continue;
        }
        if(short_name){
            LOG("-%c, ", short_name);
        }else{
            LOG("    ");
        }
        LOG("--%s\t%s\n", option_detail[i].name, option_detail[i].details);
    }
}

const char* getDeviceInfo(){
    static char infoString[DOMAINLIMIT+5] = {0};
    if(strlen(infoString)){
        return infoString;
    }
    struct utsname info;
    if(uname(&info)){
        LOGE("uname failed: %s\n", strerror(errno));
        return "Unkown platform";
    }
    snprintf(infoString, sizeof(infoString), "%s %s; %s", info.sysname, info.machine, info.release);
    return infoString;
}

static void show_version(){
    LOG("%s version: %s, build time: %s\n", main_argv[0], getVersion(), getBuildTime());
}

static void parseArgs(const char* name, const char* args){
#ifdef static_assert
    static_assert(sizeof(long long) == 8, "require 64bit long long");
#else
    assert(sizeof(long long) == 8);
#endif
    for(int i=0; option_detail[i].name; i++){
        if(strcmp(name, option_detail[i].name) == 0){
            switch(option_detail[i].type){
            char* pos;
            int64_t iresult;
            uint64_t uresult;
            char** pargstr;
            struct arg_list* apos;
            case option_bool:
                *(bool*)option_detail[i].result = (bool)option_detail[i].value;
                LOG("set option %s: %s\n", name, option_detail[i].result?"true":"false");
                break;
            case option_string:
                pargstr = (char**)option_detail[i].result;
                if(*pargstr){
                    free(*pargstr);
                }
                if(args == NULL) {
                    *pargstr = option_detail[i].value ? strdup(option_detail[i].value) : NULL;
                } else {
                    *pargstr = strdup(args);
                }
                LOG("set option %s: %s\n", name, *pargstr ? *pargstr : "(null)");
                break;
            case option_int64:
                iresult = strtoll(args, &pos, 0);
                if(iresult == LLONG_MAX || iresult == LLONG_MIN || args == pos) {
                    LOGE("wrong int format: %s\n", args);
                }
                *(int64_t*)option_detail[i].result = iresult;
                LOG("set option %s: %" PRIi64"\n", name, *(int64_t*)option_detail[i].result);
                break;
            case option_uint64:
                uresult = strtoull(args, &pos, 0);
                if (uresult == ULLONG_MAX || args == pos) {
                    LOGE("wrong uint format: %s\n", args);
                }
                *(uint64_t*)option_detail[i].result = uresult;
                LOG("set option %s: %" PRIu64"\n", name, *(uint64_t*)option_detail[i].result);
                break;
            case option_base64:
                Base64Encode(args, strlen(args), (char*)option_detail[i].result);
                LOG("set option %s: %s\n", name, (char*)option_detail[i].result);
                break;
            case option_bitwise:
                *(uint32_t*)option_detail[i].result |= (uint32_t)(intptr_t)option_detail[i].value;
                LOG("set option %s: 0x%08X\n", name, (uint32_t)(intptr_t)option_detail[i].value);
                break;
            case option_enum:
                uresult = 0;
                for(pargstr = (char**)option_detail[i].value; *pargstr; pargstr++ ){
                    if(strcmp(args, *pargstr) == 0){
                        *(int*)option_detail[i].result = uresult;
                        break;
                    }
                    uresult++;
                }
                if(*pargstr == NULL){
                    LOGE("unknown option %s for %s\n", args, name);
                    exit(1);
                }else{
                    LOG("set option %s: %d\n", name, *(int*)option_detail[i].result);
                }
                break;
            case option_list:
                apos = (struct arg_list*)option_detail[i].result;
                while(apos->next){
                    apos = apos->next;
                }
                apos->next = malloc(sizeof(struct arg_list));
                apos = apos->next;
                apos->arg = strdup(args);
                apos->next = NULL;
                LOG("append option %s: %s\n", name, apos->arg);
                break;
            }
            return;
        }
    }
    LOGF("UNKNOWN option: %s\n", name);
}

int parseDest(const char* proxy, struct Destination* server){
    memset(server, 0, sizeof(struct Destination));
    server->systemd_fd = -1;
    if(spliturl(proxy, server, NULL)){
        return -1;
    }
    const char* scheme = server->scheme;
    if(scheme[0] == 0 || strcasecmp(scheme, "https") == 0 || strcasecmp(scheme, "ssl") == 0){
        strcpy(server->scheme, "https");
        strcpy(server->protocol, "ssl");
    }else if(strcasecmp(scheme, "http") == 0 || strcasecmp(scheme, "tcp") == 0) {
        strcpy(server->scheme, "http");
        strcpy(server->protocol, "tcp");
#ifdef HAVE_QUIC
    }else if(strcasecmp(scheme, "quic") == 0) {
        strcpy(server->scheme, "https");
        strcpy(server->protocol, "quic");
#endif
    }else if(strcasecmp(scheme, "socks5") == 0 || strcasecmp(scheme, "socks") == 0) {
        strcpy(server->scheme, "socks5");
        strcpy(server->protocol, "tcp");
    }else{
        LOGE("unkonw scheme for server: %s\n", scheme);
        return -1;
    }
    if(server->port != 0) {
        return 0;
    }
    if(strcasecmp(server->scheme, "http") == 0){
        server->port = HTTPPORT;
    }
    if(strcasecmp(server->scheme, "https") == 0){
        server->port = HTTPSPORT;
    }
    if(strcasecmp(server->scheme, "socks5") == 0){
        server->port = 1080;
    }
    return 0;
}

int parseConfigFile(const char* config_file){
    FILE* conf = fopen(config_file, "re");
    if(conf == NULL) {
        return -errno;
    }
    char* line = NULL;
    size_t len = 0;
    while(getline(&line, &len, conf) >= 0){
        // Trim leading spaces
        char* start = line;
        while(*start == ' ' || *start == '\t') start++;
        // Ignore comments and empty lines
        if(*start == '#' || *start == '\n'){
            continue;
        }
        char option[1024] = {0}, args[1024] = {0};
        int ret = sscanf(start, "%1023s%*[ \t]%1023[^\n]", option, args);
        if(ret <= 0){
            LOGE("config file parse failed: %s", start);
            break;
        }
        size_t argsLen = strlen(args);
        while(argsLen > 0 && (args[argsLen-1] == ' ' || args[argsLen-1] == '\t')){
            args[--argsLen] = 0;
        }
        if(args[0] == '\"' && args[argsLen - 1] == '\"'){
            args[argsLen - 1] = 0;
            memmove(args, args+1, argsLen - 1);
        }
        if(args[0] == '\'' && args[argsLen - 1] == '\''){
            args[argsLen - 1] = 0;
            memmove(args, args+1, argsLen - 1);
        }
        parseArgs(option, args);
    }
    free(line);
    fclose(conf);
    return 0;
}

static const char* confs[] = {
    "/etc/sproxy/sproxy.conf",
    PREFIX "/etc/sproxy/sproxy.conf",
    "sproxy.conf",
    NULL,
};

void exit_loop() {
    LOG("will exit soon...\n");
    fflush(stdout);
    will_contiune = 0;
}

void free_arg_list(struct arg_list* list) {
    if(list == NULL) {
        return;
    }
    free_arg_list(list->next);
    free((char*)list->arg);
    free(list);
}

void append_dest_list(struct dest_list*** tail, const struct Destination* dest) {
    struct dest_list* node = malloc(sizeof(struct dest_list));
    if(node == NULL) {
        LOGE("alloc listen failed: %s\n", strerror(errno));
        exit(1);
    }
    node->dest = *dest;
    node->next = NULL;
    **tail = node;
    *tail = &node->next;
}

static void free_fdnames(char** names) {
    if(names == NULL) {
        return;
    }
    free(names[0]);
    free(names);
}

static char** split_fdnames(const char* names, size_t* count) {
    *count = 0;
    if(names == NULL || names[0] == '\0') {
        return NULL;
    }
    char* copy = strdup(names);
    if(copy == NULL) {
        return NULL;
    }
    size_t slots = 1;
    for(char* p = copy; *p; ++p) {
        if(*p == ':') {
            slots++;
        }
    }
    char** out = (char**)malloc(slots * sizeof(char*));
    if(out == NULL) {
        free(copy);
        return NULL;
    }
    size_t idx = 0;
    out[idx++] = copy;
    for(char* p = copy; *p; ++p) {
        if(*p == ':') {
            *p = '\0';
            if(p[1] != '\0' && idx < slots) {
                out[idx++] = p + 1;
            }
        }
    }
    *count = idx;
    return out;
}

static void build_dest_list(struct arg_list* arguments,
                            struct dest_list** destinations,
                            const char* option_name) {
    if(destinations == NULL) {
        return;
    }
    struct dest_list* node = *destinations;
    while(node) {
        struct dest_list* next = node->next;
        free(node);
        node = next;
    }
    *destinations = NULL;
    if(arguments == NULL) {
        return;
    }
    struct arg_list* item = arguments->next;
    if(item == NULL) {
        return;
    }
    struct dest_list** tail = destinations;
    for(; item; item = item->next) {
        struct Destination dest;
        if(parseBind(item->arg, &dest)) {
            LOGE("wrong %s listen: %s\n", option_name, item->arg);
            exit(1);
        }
        append_dest_list(&tail, &dest);
    }
}

void postConfig(){
    const char* listen_pid = getenv("LISTEN_PID");
    const char* listen_fds = getenv("LISTEN_FDNAMES");
    if(listen_pid && listen_fds && (pid_t)atoi(listen_pid) == getpid()) {
        opt.systemd_socket = true;
        LOG("systemd sockets detected, config listens ignored\n");
        size_t name_count = 0;
        char** names = split_fdnames(listen_fds, &name_count);
        if(names == NULL || name_count == 0) {
            free_fdnames(names);
            LOGE("systemd socket has no valid fd names\n");
            exit(1);
        }
        struct dest_list** http_tail = &opt.http_list;
        struct dest_list** ssl_tail = &opt.ssl_list;
        struct dest_list** quic_tail = &opt.quic_list;

        for(size_t i = 0; i < name_count; ++i) {
            int fd = 3 + (int)i;
            const char* fd_name = names[i];
            int type = 0;
            socklen_t type_len = sizeof(type);
            if(getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &type_len) < 0) {
                LOGE("systemd socket getsockopt failed for %d: %s\n", fd, strerror(errno));
                continue;
            }
            struct sockaddr_storage addr;
            socklen_t addr_len = sizeof(addr);
            if(getsockname(fd, (struct sockaddr*)&addr, &addr_len) < 0) {
                LOGE("systemd socket getsockname failed for %d: %s\n", fd, strerror(errno));
                continue;
            }
            struct Destination dest;
            storage2Dest(&addr, &dest);
            dest.systemd_fd = fd;
            if(fd_name && fd_name[0]) {
                snprintf(dest.scheme, sizeof(dest.scheme), "%s", fd_name);
            }
            if(dest.port == 0) {
                LOGE("systemd socket %d has no port\n", fd);
                continue;
            }

            if(type == SOCK_STREAM && strcmp(fd_name, "http") == 0) {
                append_dest_list(&http_tail, &dest);
                continue;
            }
            if(type == SOCK_STREAM && strcmp(fd_name, "ssl") == 0) {
                append_dest_list(&ssl_tail, &dest);
                continue;
            }
            if(type == SOCK_DGRAM && strcmp(fd_name, "quic") == 0) {
                append_dest_list(&quic_tail, &dest);
                continue;
            }
        }
        free_fdnames(names);
    } else {
        build_dest_list(&http_listens, &opt.http_list, "http");
        build_dest_list(&ssl_listens, &opt.ssl_list, "ssl");
        build_dest_list(&quic_listens, &opt.quic_list, "quic");
        if(tproxy_listen && parseBind(tproxy_listen, &opt.tproxy)) {
            LOGE("wrong tproxy listen: %s\n", tproxy_listen);
            exit(1);
        }
    }

    if(server_string && parseDest(server_string, &opt.Server)){
        LOGE("wrong server format: %s\n", server_string);
        exit(1);
    }
    if(opt.redirect_http && (opt.ssl_list == NULL && opt.quic_list == NULL)) {
        LOGE("redirect-http must use with ssl\n");
        exit(1);
    }
    LOG("server %s\n", dumpDest(&opt.Server));

    if(opt.rproxy_name) {
        if(opt.rproxy_name[0] == '\0' || strlen(opt.rproxy_name) >= 100) {
            LOGE("length of rproxy name should between 1 and 100\n");
            exit(1);
        }
        if(opt.Server.hostname[0] == '\0') {
            LOGE("rproxy mode require server name\n");
            exit(1);
        }
    } else if(opt.rproxy_keep_src) {
        LOGE("rproxy-kp require rproxy name set\n");
        exit(1);
    }

    // 设置QUIC拥塞控制算法默认值
    if(opt.quic_cc_algorithm == NULL) {
        opt.quic_cc_algorithm = strdup("cubic");
    }

    if(policy_file == NULL){
        policy_file = PREFIX "/etc/sproxy/sites.list";
    }
    if((opt.policy_read == NULL) && (opt.policy_read = fopen(policy_file, "re")) == NULL){
        LOGE("failed to open policy file: %s\n", strerror(errno));
    }else if((opt.policy_write == NULL) && (opt.policy_write = fopen(policy_file, "r+e")) == NULL){
        LOG("failed to open policy file for write: %s, it won't be updated\n", strerror(errno));
    }
    if(opt.rootdir && chdir(opt.rootdir)){
        LOGE("chdir failed: %s\n", strerror(errno));
    }
    free((void*)opt.rootdir);
    opt.rootdir = (char*)malloc(PATH_MAX);
    (void)!getcwd((char*)opt.rootdir, PATH_MAX);

    if (opt.webdav_root) {
        struct stat st;
        if (stat(opt.webdav_root, &st) < 0) {
            LOGE("access webdav root %s failed: %s\n", opt.webdav_root, strerror(errno));
            exit(1);
        }
        if (!S_ISDIR(st.st_mode)) {
            LOGE("webdav root %s is not a directory\n", opt.webdav_root);
            exit(1);
        }
    }

    if (opt.cafile && access(opt.cafile, R_OK)) {
        LOGE("access cafile %s failed: %s\n", opt.cafile, strerror(errno));
        exit(1);
    }
    if (opt.cafile && opt.cakey && load_cert_key(opt.cafile, opt.cakey, &opt.ca)) {
        LOGE("failed to load cafile or cakey\n");
        exit(1);
    }

    if(opt.acme_state) {
        if(opt.acme_state[0] == '\0') {
            LOGE("acme mode requires a valid state directory\n");
            exit(1);
        }
        if(certfile == NULL || certfile[0] == '\0' || keyfile == NULL || keyfile[0] == '\0') {
            LOGE("acme mode require cert/key\n");
            exit(1);
        }
        setenv("SPROXY_ACME_STATE", opt.acme_state, 1);
        setenv("SPROXY_ACME_CERT", certfile, 1);
        setenv("SPROXY_ACME_KEY", keyfile, 1);
    }

    bool certfile_ok = false;
    if(certfile) {
        if(access(certfile, R_OK) == 0) {
            certfile_ok = true;
        } else if(opt.acme_state && errno == ENOENT) {
            LOG("cert file %s missing, waiting for ACME provisioning\n", certfile);
        } else {
            LOGE("access cert file %s failed: %s\n", certfile, strerror(errno));
            exit(1);
        }
    }

    bool keyfile_ok = false;
    if(keyfile) {
        if(access(keyfile, R_OK) == 0) {
            keyfile_ok = true;
        } else if(opt.acme_state && errno == ENOENT) {
            LOG("key file %s missing, waiting for ACME provisioning\n", keyfile);
        } else {
            LOGE("access key file %s failed: %s\n", keyfile, strerror(errno));
            exit(1);
        }
    }

    if(certfile_ok && keyfile_ok && load_cert_key(certfile, keyfile, &opt.cert)) {
        LOGE("failed to load certificate or private key\n");
        exit(1);
    }

    if ((opt.ssl_list || opt.quic_list) &&
        (cert_pair_leaf(&opt.cert) == NULL || opt.cert.key == NULL) &&
        opt.mitm_mode != Enable && !opt.sni_mode && !opt.acme_state)
    {
        LOGE("ssl/quic mode require cert and key file\n");
        exit(1);
    }
    if(opt.sni_mode && !opt.ssl_list && !opt.quic_list) {
        LOGE("sni mode require ssl or quic\n");
        exit(1);
    }
    if (opt.mitm_mode == Enable && opt.ca.key == NULL) {
        LOGE("mitm mode require cakey\n");
        exit(1);
    }
    if (opt.tproxy.port && geteuid() != 0) {
        LOGE("tproxy require root privilege to set IP[V6]_TRANSPARENT\n");
        exit(1);
    }
    if (opt.set_dns_route && opt.interface == NULL) {
        LOGE("set-dns-route require option interface\n");
        exit(1);
    }
    if (opt.tun_mode && opt.tun_fd >= 0) {
        LOGE("tun mode and tun-fd can't be used together\n");
        exit(1);
    }
    if (opt.doh_server && opt.doh_server[0] == 0 && opt.Server.hostname[0] == 0) {
        LOGE("doh without argument require server address\n");
        exit(1);
    }
    for(struct arg_list* p = secrets.next; p != NULL; p = p->next){
        addsecret(p->arg);
    }
    for(struct arg_list* p = debug_list.next; p != NULL; p = p->next){
        if(!debugon(p->arg, true)){
            LOGE("set debug on %s failed\n", p->arg);
            exit(1);
        }
    }
#ifndef __ANDROID__
    if (admin_listen == NULL){
        if(geteuid() == 0){
            admin_listen = "unix:/var/run/sproxy.sock";
        }else{
            admin_listen = "unix:/tmp/sproxy.sock";
        }
    }
#endif
    if(admin_listen && parseBind(admin_listen, &opt.admin)) {
        LOGE("wrong admin listen: %s\n", admin_listen);
        exit(1);
    }

    SSL_library_init();    // SSL初库始化
    SSL_load_error_strings();  // 载入所有错误信息
    signal(SIGPIPE, SIG_IGN);
    signal(SIGCHLD, SIG_IGN);
    reloadstrategy();
    srandom(time(NULL));
    setvbuf(stdout, NULL, _IOLBF, BUFSIZ);
#ifndef __ANDROID__
    if (opt.daemon_mode) {
        if(daemon(1, 0) < 0) {
            LOGE("start daemon error:%s\n", strerror(errno));
            exit(1);
        }
        openlog(basename(main_argv[0]), LOG_PID | LOG_PERROR, LOG_LOCAL0);
    }
#else
    opt.daemon_mode = false;
#endif
    struct rlimit limits;
    if(getrlimit(RLIMIT_NOFILE, &limits)){
        LOGE("getrlimit nofile failed: %s\n", strerror(errno));
    }else if(limits.rlim_cur < 16384){
        limits.rlim_cur = MIN(limits.rlim_max, 16384);
        if(setrlimit(RLIMIT_NOFILE, &limits)) {
            LOGE("setrlimit failed: %s\n", strerror(errno));
        }
    }
#if defined(__has_feature)
#   if __has_feature(address_sanitizer) // for clang
#       define __SANITIZE_ADDRESS__ 1 // GCC already sets this
#   endif
#endif

#ifndef __SANITIZE_ADDRESS__
    if(getrlimit(RLIMIT_CORE, &limits)) {
        LOGE("getrlimit core failed: %s\n", strerror(errno));
    }else if(limits.rlim_cur == 0) {
        limits.rlim_cur = limits.rlim_max;
        if(setrlimit(RLIMIT_CORE, &limits)) {
            LOGE("setrlimit core failed: %s\n", strerror(errno));
        }
    }
#endif
    openefd();
    if(opt.ipv6_mode == Auto){
        opt.ipv6_enabled = hasIpv6Address();
        LOG("auto detected ipv6: %s\n", opt.ipv6_enabled?"enable":"disable");
    }else{
        opt.ipv6_enabled = opt.ipv6_mode;
    }
    if(opt.ipv6_prefer && !opt.ipv6_enabled){
        LOGE("ipv6-prefer requires ipv6 enabled\n");
        exit(1);
    }
    register_network_change_cb(network_changed);
}

bool is_http_listen_port(uint16_t port) {
    if(port == 0) {
        return false;
    }
    if(opt.http_list == NULL) {
        return false;
    }
    for(struct dest_list* node = opt.http_list; node; node = node->next) {
        if(node->dest.port == port) {
            return true;
        }
    }
    return false;
}

void parseConfig(int argc, char **argv){
    main_argv = argv;
    int c;
    while((c = getopt_long(argc, argv, getopt_option, long_options, NULL)) != EOF){
        switch(c){
        case '?':
            LOG("unkown option: %s\n", argv[optind-1]);
            usage(argv[0]);
            exit(1);
        case 'h':
            usage(argv[0]);
            exit(0);
        case ':':
            LOG("option %s need argument\n", argv[optind-1]);
            usage(argv[0]);
            exit(1);
        case 'v':
            show_version();
            exit(0);
        case 'c':
            opt.config_file = strdup(optarg);
            break;
        default:
            break;
        }
    }
    if(opt.config_file){
        if(strlen(opt.config_file)) {
            LOG("read config file from: %s\n", opt.config_file);
            if (parseConfigFile(opt.config_file)) {
                LOGE("parse config file failed: %s\n", strerror(errno));
                exit(2);
            }
        }
    }else{
        for(int i = 0; confs[i]; i++) {
            if(access(confs[i], R_OK)){
                continue;
            }
            LOG("read config file from: %s\n", confs[i]);
            parseConfigFile(confs[i]);
            break;
        }
    }
    optind = 0;
    while (1) {
        int option_index = 0;
        c = getopt_long(argc, argv, getopt_option, long_options, &option_index);
        if (c == -1)
            break;

        if( c != 0){
            for(int i=0; long_options[i].name; i++){
                if(long_options[i].val == c){
                    parseArgs(long_options[i].name, optarg);
                    break;
                }
            }
            continue;
        }
        parseArgs(long_options[option_index].name, optarg);
    }
    if(optind != argc && optind+1 != argc){
        usage(argv[0]);
        exit(1);
    }

    if (optind < argc) {
        free(server_string);
        server_string = strdup(argv[optind]);
    }
    postConfig();
}

struct debug_flags_map debug[] = {
        {"", false},
        {"EVENT", false},
        {"DNS", false},
        {"SSL", false},
        {"HTTP2", false},
        {"JOB", false},
        {"VPN", false},
        {"HPACK", false},
        {"HTTP", false},
        {"FILE", false},
        {"NET", false},
        {"QUIC", false},
        {"HTTP3", false},
        {"RWER", false},
        {"SOCKS", false},
        {NULL, false},
};

bool debugon(const char* module, bool enable){
    if(strcasecmp(module, "all") == 0) {
        for (int i = 0; debug[i].name != NULL; i++) {
            debug[i].enabled = enable;
        }
        return true;
    }
    for(int i=0; debug[i].name; i++){
        if(strcasecmp(debug[i].name, module) == 0){
            debug[i].enabled = enable;
            return true;
        }
    }
    return false;
}


#ifndef ANDROID_APP
void vslog(int level, const char* fmt, va_list arg){
    if(opt.daemon_mode){
        vsyslog(level, fmt, arg);
    }else{
        if(level <= LOG_ERR){
            vfprintf(stderr, fmt, arg);
        }else{
            vfprintf(stdout, fmt, arg);
        }
    }
}
#endif

void slog(int level, const char* fmt, ...){
    va_list ap;
    va_start(ap, fmt);
    VLOG(level, fmt, ap);
    va_end(ap);
}

void change_process_name(const char *name){
#ifdef __APPLE__
    pthread_setname_np(name);
#else
    prctl(PR_SET_NAME, name);
#endif
    size_t len  = 0;
    int i;
    for(i = 0;main_argv[i]; i++){
        len += strlen(main_argv[i]) + 1;
    }
    memset(main_argv[0], 0, len);
    snprintf(main_argv[0], len, "%s", name);
}

uint64_t nextId(){
    return id++;
}

/**
 * @brief 检查当前运行的内核版本是否大于或等于指定的版本。
 * * @param required_major 需要的主版本号
 * @param required_minor 需要的次版本号
 * @return int 1 如果当前版本 >= 指定版本，否则返回 0。如果出错则返回 -1。
 */
int is_kernel_version_ge(int required_major, int required_minor) {
    struct utsname kernel_info;
    int major, minor;

    if (uname(&kernel_info) != 0) {
        LOGE("uname failed: %s\n", strerror(errno));
        return -1; // 获取内核信息失败
    }

    // 从 release 字符串中解析主版本号和次版本号
    // 例如 "6.8.9-arch1-2", sscanf 会成功解析出 6 和 8
    if (sscanf(kernel_info.release, "%d.%d", &major, &minor) < 2) {
        LOGE("Failed to parse kernel version from: %s\n", kernel_info.release);
        return -1; // 解析失败
    }

    // 比较版本号
    if (major > required_major) {
        return 1; // 主版本号更大
    }
    if (major == required_major && minor >= required_minor) {
        return 1; // 主版本号相同，次版本号大于或等于
    }
    return 0; // 版本过旧
}

int flushcert() {
    // 先清理动态生成的证书缓存
    release_key_pair();

    // 重新加载服务器证书
    if(certfile && keyfile) {
        if(access(certfile, R_OK) != 0) {
            LOGE("reload cert failed, access %s: %s\n", certfile, strerror(errno));
            return errno ? -errno : -1;
        }
        if(access(keyfile, R_OK) != 0) {
            LOGE("reload key failed, access %s: %s\n", keyfile, strerror(errno));
            return errno ? -errno : -1;
        }
        int server_ret = reload_cert_key(certfile, keyfile, &opt.cert);
        if(server_ret != 0) {
            return server_ret;
        }
    }

    // 重新加载CA证书（如果配置了的话）
    if(opt.cafile && opt.cakey) {
        if(access(opt.cafile, R_OK) != 0) {
            LOGE("reload cafile failed, access %s: %s\n", opt.cafile, strerror(errno));
            return errno ? -errno : -1;
        }
        if(access(opt.cakey, R_OK) != 0) {
            LOGE("reload cakey failed, access %s: %s\n", opt.cakey, strerror(errno));
            return errno ? -errno : -1;
        }
        int ca_ret = reload_cert_key(opt.cafile, opt.cakey, &opt.ca);
        if(ca_ret != 0) {
            return ca_ret;
        }
    }

    opt.cert_version ++;
    LOG("Certificate reload completed successfully, version: %u\n", opt.cert_version);
    return 0;
}
