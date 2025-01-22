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

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <unistd.h>
#include <signal.h>
#include <inttypes.h>
#include <sys/utsname.h>
#ifndef __APPLE__
#include <sys/prctl.h>
#include <sys/resource.h>
#else
#include <pthread.h>
#include <libgen.h>
#endif
#include <openssl/ssl.h>

static char** main_argv = NULL;
static char* auto_options[] = {"disable", "enable", "auto", NULL};
static char* server_string = NULL;
static char* policy_file = NULL;
static struct arg_list secrets = {NULL, NULL};
static struct arg_list debug_list = {NULL, NULL};
static uint64_t id = 100000;

static const char *certfile = NULL;
static const char *keyfile = NULL;

static char* http_listen = NULL;
static char* ssl_listen = NULL;
static char* quic_listen = NULL;
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
        .crt = NULL,
        .key = NULL,
    },
    .cert              = {
        .crt = NULL,
        .key = NULL,
    },
    .rootdir           = NULL,
    .index_file        = NULL,
    .interface         = NULL,
    .ua                = NULL,
    .pcap_file         = NULL,
    .alt_svc           = NULL,
    .rproxy_name       = NULL,
    .bpf_cgroup        = NULL,
    .disable_http2     = false,
    .disable_fakeip    = false,
    .sni_mode          = false,
    .daemon_mode       = false,
    .ignore_cert_error = false,
    .ignore_hosts      = false,
    .autoindex         = false,
    .ipv6_enabled      = true,
    .alter_method      = false,
    .set_dns_route     = false,
    .tun_mode          = false,
    .tun_fd            = -1,
    .redirect_http     = false,

    .policy_read    = NULL,
    .policy_write   = NULL,
    .http           = {
        .scheme     = {0},
        .protocol   = {0},
        .hostname   = {0},
        .port       = 0,
    },
    .ssl            = {
        .scheme     = {0},
        .protocol   = {0},
        .hostname   = {0},
        .port       = 0,
    },
    .quic           = {
        .scheme     = {0},
        .protocol   = {0},
        .hostname   = {0},
        .port       = 0,
    },
    .tproxy         = {
        .scheme     = {0},
        .protocol   = {0},
        .hostname   = {0},
        .port       = 0,
    },
    .admin          = {
        .scheme     = {0},
        .protocol   = {0},
        .hostname   = {0},
        .port       = 0,
    },
    .Server         = {
        .scheme     = {0},
        .protocol   = {0},
        .hostname   = {0},
        .port       = 0,
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
    {"autoindex",     no_argument,       NULL, 'i'},
    {"alt-svc",       required_argument, NULL,  0 },
#ifdef HAVE_BPF
    {"bpf",           required_argument, NULL, 'b'},
#endif
    {"cafile",        required_argument, NULL,  0 },
    {"cakey",         required_argument, NULL,  0 },
    {"cert",          required_argument, NULL,  0 },
    {"config",        required_argument, NULL, 'c'},
    {"daemon",        no_argument,       NULL, 'D'},
    {"disable-fakeip",no_argument,       NULL, '1'},
    {"disable-http2", no_argument,       NULL, '1'},
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
    {"key",           required_argument, NULL,  0 },
    {"pcap",          required_argument, NULL,  0 },
    {"pcap-len",      required_argument, NULL,  0 },
    {"policy-file",   required_argument, NULL, 'P'},
#ifdef HAVE_QUIC
    {"quic",          required_argument, NULL, 'q'},
#endif
    {"redirect-http", no_argument,       NULL,  0 },
    {"rewrite-auth",  required_argument, NULL, 'r'},
    {"root-dir",      required_argument, NULL,  0 },
    {"secret",        required_argument, NULL, 's'},
#if __linux__
    {"set-dns-route", no_argument,       NULL,  0 },
#endif
    {"sni",           no_argument,       NULL,  0 },
    {"ssl",           required_argument, NULL,  0 },
    {"alter-method",  no_argument,       NULL,  0 },
    {"rproxy",        required_argument, NULL,  0 },
    {"request-header",required_argument, NULL,  0 },
    {"forward-header",required_argument, NULL,  0 },
#if __linux__
    {"tun",           no_argument,       NULL,  0 },
    {"tun-fd",        required_argument, NULL,  0 },
    {"tproxy",        required_argument, NULL,  0 },
    {"ua",            required_argument, NULL,  0 },
#endif
    {"version",       no_argument,       NULL, 'v'},
#ifndef NDEBUG
    {"debug",         required_argument, NULL,  0 },
#endif
    {NULL,       0,                NULL,  0 }
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
    {"alt-svc", "Add alt-svc header to response or send ALTSVC frame", option_string, &opt.alt_svc, NULL},
    {"autoindex", "Enables the directory listing output (local server)", option_bool, &opt.autoindex, (void*)true},
#ifdef HAVE_BPF
    {"bpf", "load bpf prog to redirect for tproxy on cgroup", option_string, &opt.bpf_cgroup, NULL},
#endif
    {"cafile", "CA certificate for server (ssl/quic)", option_string, &opt.cafile, NULL},
    {"cakey", "CA key for server (mitm)", option_string, &opt.cakey, NULL},
    {"cert", "Certificate file for server (ssl/quic)", option_string, &certfile, NULL},
    {"config", "Configure file (default "PREFIX"/etc/sproxy/sproxy.conf and ./sproxy.conf)", option_string, &opt.config_file, NULL},
#ifndef __ANDROID__
    {"daemon", "Run as daemon", option_bool, &opt.daemon_mode, (void*)true},
#endif
    {"disable-http2", "Use http/1.1 only", option_bool, &opt.disable_http2, (void*)true},
    {"disable-fakeip", "Do not use fakeip for vpn and tproxy", option_bool, &opt.disable_fakeip, (void*)true},
    {"fwmark", "Set fwmark for output packet", option_uint64, &opt.fwmark, NULL},
    {"help", "Print this usage", option_bool, NULL, NULL},
    {"http", "Listen for http server", option_string, &http_listen, NULL},
    {"ignore-hosts", "Dont read entries from /etc/hosts ", option_bool, &opt.ignore_hosts, (void*)true},
    {"index", "Index file for path (local server)", option_string, &opt.index_file, NULL},
    {"insecure", "Ignore the cert error of server (SHOULD NOT DO IT)", option_bool, &opt.ignore_cert_error, (void*)true},
#if __linux__
    {"interface", "Out interface (use for vpn), will skip bind if set to empty", option_string, &opt.interface, NULL},
#endif
    {"ipv6", "The ipv6 mode ([auto], enable, disable)", option_enum, &opt.ipv6_mode, auto_options},
    {"key", "Private key file name (ssl/quic)", option_string, &keyfile, NULL},
    {"mitm", "Mitm mode for https request ([auto], enable, disable), require cakey", option_enum, &opt.mitm_mode, auto_options},
    {"pcap", "Save packets in pcap file for vpn", option_string, &opt.pcap_file, NULL},
    {"pcap-len", "Max packet length to save in pcap file", option_uint64, &opt.pcap_len, NULL},
    {"policy-file", "The file of policy ("PREFIX"/etc/sproxy/sites.list as default)", option_string, &policy_file, NULL},
#ifdef HAVE_QUIC
    {"quic", "Listen for QUIC server (experiment)", option_string, &quic_listen, NULL},
#endif
    {"redirect-http", "Return 308 to redirect http to https", option_bool, &opt.redirect_http, (void*)true},
    {"request-header", "append the header (name:value) before handle http request", option_list, &opt.request_headers, NULL},
    {"forward-header", "append the header (name:value) when forward http request", option_list, &opt.forward_headers, NULL},
    {"rewrite-auth", "rewrite the auth info (user:password) to proxy server", option_base64, opt.rewrite_auth, NULL},
    {"root-dir", "The work dir (current dir if not set)", option_string, &opt.rootdir, NULL},
    {"rproxy", "name for rproxy mode (via http2)", option_string, &opt.rproxy_name, (void*)true},
    {"secret", "Set user and passwd for proxy (user:password), default is none.", option_list, &secrets, NULL},
    {"server", "default proxy server (can ONLY set in config file)", option_string, &server_string, NULL},
#if __linux__
    {"set-dns-route", "set route for dns server (via vpn interface)", option_bool, &opt.set_dns_route, (void*)true},
#endif
    {"sni", "Act as a sni proxy", option_bool, &opt.sni_mode, (void*)true},
    {"ssl", "Listen for ssl server (require cert file and key)", option_string, &ssl_listen, NULL},
#if __linux__
    {"tun", "tun mode (vpn mode, require root privilege)", option_bool, &opt.tun_mode, (void*)true},
    {"tun-fd", "tun fd (vpn mode, recv fd before execve)", option_int64, &opt.tun_fd, NULL},
    {"tproxy", "tproxy listen (get dst via SO_ORIGINAL_DST)", option_string, &tproxy_listen, (void*)true},
    {"ua", "set user-agent for vpn auto request", option_string, &opt.ua, NULL},
#endif
    {"version", "show the version of this programme", option_bool, NULL, NULL},
#ifndef NDEBUG
    {"debug", "set debug output for module", option_list, &debug_list, NULL},
#endif
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
    X509_free(opt.ca.crt);
    opt.ca.crt = NULL;
    EVP_PKEY_free(opt.ca.key);
    opt.ca.key = NULL;
    X509_free(opt.cert.crt);
    opt.cert.crt = NULL;
    EVP_PKEY_free(opt.cert.key);
    opt.cert.key = NULL;
    release_key_pair();
}

static void usage(const char * program){
    LOG("Usage: %s [host:port]\n" , program);
    for(int i =0; option_detail[i].name; i++){
        char short_name = 0;
        for(int j=0; long_options[j].name; j++){
            if(strcmp(option_detail[i].name, long_options[j].name) == 0 && long_options[j].val){
                short_name = (char)long_options[j].val;
                break;
            }
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
                *pargstr = strdup(args);
                LOG("set option %s: %s\n", name, *pargstr);
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
        char option[1024], args[1024];
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
    will_contiune = 0;
}

static int parseBind(const char* addr, struct Destination* info) {
    memset(info, 0, sizeof(*info));
    if(addr == NULL || addr[0] == 0) {
        return 0;
    }
    if (strncmp(addr, "unix:", 5) == 0) {
        // unix:/var/lib/sproxy.sock
        strcpy(info->hostname, addr + 5);
        return 0;
    }
    if(strchr(addr, ':')) {
        return parseDest(addr, info);
    }
    strcpy(info->hostname, "[::]");
    info->port = atoi(addr);
    return !(info->port > 0 && info->port < 65535);
}

void free_arg_list(struct arg_list* list) {
    if(list == NULL) {
        return;
    }
    free_arg_list(list->next);
    free((char*)list->arg);
    free(list);
}

void postConfig(){
    if(opt.rproxy_name) {
        if(http_listen || ssl_listen || quic_listen || tproxy_listen) {
            LOGE("rproxy mode can only used separately\n");
            exit(1);
        }
        if(secrets.next) {
            LOG("secret will be ignored in rproxy mode\n");
            free_arg_list(secrets.next);
            secrets.next = NULL;
        }
    }
    if(parseBind(http_listen, &opt.http)) {
        LOGE("wrong http listen: %s\n", http_listen);
        exit(1);
    }
    if(parseBind(ssl_listen, &opt.ssl)) {
        LOGE("wrong ssl listen: %s\n", ssl_listen);
        exit(1);
    }
    if(parseBind(quic_listen, &opt.quic)) {
        LOGE("wrong quic listen: %s\n", quic_listen);
        exit(1);
    }
    if(parseBind(tproxy_listen, &opt.tproxy)) {
        LOGE("wrong tproxy listen: %s\n", tproxy_listen);
        exit(1);
    }
    if(server_string && parseDest(server_string, &opt.Server)){
        LOGE("wrong server format: %s\n", server_string);
        exit(1);
    }
    LOG("server %s\n", dumpDest(&opt.Server));

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

    if (opt.cafile && access(opt.cafile, R_OK)) {
        LOGE("access cafile %s failed: %s\n", opt.cafile, strerror(errno));
        exit(1);
    }
    if (opt.cafile && opt.cakey && load_cert_key(opt.cafile, opt.cakey, &opt.ca)) {
        LOGE("failed to load cafile or cakey\n");
        exit(1);
    }
    if ((certfile || keyfile) && load_cert_key(certfile, keyfile, &opt.cert)) {
        LOGE("access cert file failed: %s\n", strerror(errno));
        exit(1);
    }
    if ((opt.ssl.hostname[0] || opt.quic.hostname[0]) && 
        (opt.cert.crt == NULL || opt.cert.key == NULL) && 
        opt.mitm_mode != Enable && !opt.sni_mode) 
    {
        LOGE("ssl/quic mode require cert and key file\n");
        exit(1);
    }
    if(opt.sni_mode && !opt.ssl.hostname[0] && !opt.quic.hostname[0]) {
        LOGE("sni mode require ssl or quic\n");
        exit(1);
    }
    if (opt.mitm_mode == Enable && opt.ca.key == NULL) {
        LOGE("mitm mode require cakey\n");
        exit(1);
    }
    if (opt.tproxy.port && getuid() != 0) {
        LOGE("tproxy require root privilege to set IP[V6]_TRANSPARENT\n");
        exit(1);
    }
    if (opt.bpf_cgroup && opt.tproxy.port == 0){
        LOGE("bpf require tproxy mode\n");
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
    for(struct arg_list* p = secrets.next; p != NULL; p = p->next){
        char secret_encode[DOMAINLIMIT];
        Base64Encode(p->arg, strlen(p->arg), secret_encode);
        addsecret(secret_encode);
    }
    for(struct arg_list* p = debug_list.next; p != NULL; p = p->next){
        if(!debugon(p->arg, true)){
            LOGE("set debug on %s failed\n", p->arg);
            exit(1);
        }
    }
#ifndef __ANDROID__
    if (admin_listen == NULL){
        if(getuid() == 0){
            admin_listen = "unix:/var/run/sproxy.sock";
        }else{
            admin_listen = "unix:/tmp/sproxy.sock";
        }
    }
#endif
    if(parseBind(admin_listen, &opt.admin)) {
        LOGE("wrong admin listen: %s\n", admin_listen);
        exit(1);
    }

    SSL_library_init();    // SSL初库始化
    SSL_load_error_strings();  // 载入所有错误信息
    signal(SIGPIPE, SIG_IGN);
    signal(SIGCHLD, SIG_IGN);
#if Backtrace_FOUND
    signal(SIGABRT, dump_trace);
#endif
    signal(SIGHUP,  (sig_t)reloadstrategy);
    signal(SIGUSR1, (sig_t)(void(*)())dump_stat);
    signal(SIGUSR2, (sig_t)exit_loop);
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
    register_network_change_cb(network_changed);
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


#ifndef __ANDROID__
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
