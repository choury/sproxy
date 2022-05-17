#include "config.h"
#include "util.h"
#include "strategy.h"
#include "net.h"
#include "common/version.h"
#include "network_notify.h"

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
#endif
#include <openssl/ssl.h>

uint32_t debug = 0;
static char** main_argv = NULL;
static char* ipv6_options[] = {"disable", "enable", "auto", NULL};
static char* server_string = NULL;
static char* policy_file = NULL;
static struct arg_list secrets = {NULL, NULL};

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
    .cert              = NULL,
    .key               = NULL,
    .rootdir           = NULL,
    .index_file        = NULL,
    .interface         = NULL,
    .socket            = NULL,
    .ua                = NULL,
    .pcap_file         = NULL,
    .alt_svc           = NULL,
    .disable_http2     = false,
    .sni_mode          = false,
    .quic_mode         = false,
    .daemon_mode       = false,
    .ignore_cert_error = false,
    .autoindex         = false,
    .ipv6_enabled      = true,
    .alter_method      = false,
    .set_dns_route     = false,

    .policy_read    = NULL,
    .policy_write   = NULL,
    .CPORT          = 0,
    .Server         = {
        .scheme     = {0},
        .hostname   = {0},
        .port       = 0,
    },
    .rewrite_auth   = {0},
    .ipv6_mode      = Auto,
    .request_headers = {
        .arg        = NULL,
        .next       = NULL,
    },
};

enum option_type{
    option_bool,
    option_int64,
    option_base64,
    option_string,
    option_enum,
    option_bitwise,
    option_list,
};

static const char* getopt_option = ":D1hikqr:s:p:I:c:P:v";
static struct option long_options[] = {
    {"autoindex",     no_argument,       NULL, 'i'},
    {"alt-svc",       required_argument, NULL, 0},
    {"cafile",        required_argument, NULL,  0 },
    {"cert",          required_argument, NULL,  0 },
    {"config",        required_argument, NULL, 'c'},
    {"daemon",        no_argument,       NULL, 'D'},
    {"disable-http2", no_argument,       NULL, '1'},
    {"help",          no_argument,       NULL, 'h'},
    {"index",         required_argument, NULL,  0 },
    {"insecure",      no_argument,       NULL, 'k'},
    {"interface",     required_argument, NULL, 'I'},
    {"ipv6",          required_argument, NULL,  0 },
    {"key",           required_argument, NULL,  0 },
    {"pcap",          required_argument, NULL,  0 },
    {"port",          required_argument, NULL, 'p'},
    {"policy-file",   required_argument, NULL, 'P'},
    {"quic",          no_argument,       NULL, 'q'},
    {"rewrite-auth",  required_argument, NULL, 'r'},
    {"root-dir",      required_argument, NULL,  0 },
    {"secret",        required_argument, NULL, 's'},
    {"set-dns-route", no_argument,       NULL,  0 },
    {"skip-interface-binding", no_argument, NULL, 0},
    {"sni",           no_argument,       NULL,  0 },
    {"socket",        required_argument, NULL,  0 },
    {"alter-method",  no_argument,       NULL,  0 },
    {"request-header",required_argument, NULL,  0 },
    {"ua",            required_argument, NULL,  0 },
    {"version",       no_argument,       NULL, 'v'},
#ifndef NDEBUG
    {"debug-event",   no_argument,   NULL,  0 },
    {"debug-dns",     no_argument,   NULL,  0 },
    {"debug-http2",   no_argument,   NULL,  0 },
    {"debug-http3",   no_argument,   NULL,  0 },
    {"debug-job",     no_argument,   NULL,  0 },
    {"debug-vpn",     no_argument,   NULL,  0 },
    {"debug-hpack",   no_argument,   NULL,  0 },
    {"debug-http",    no_argument,   NULL,  0 },
    {"debug-file",    no_argument,   NULL,  0 },
    {"debug-net",     no_argument,   NULL,  0 },
    {"debug-quic",    no_argument,   NULL,  0 },
    {"debug-all",     no_argument,   NULL,  0 },
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
    {"autoindex", "Enables the directory listing output (local server)", option_bool, &opt.autoindex, (void*)true},
    {"alt-svc", "Add alt-svc header to response or send ALTSVC frame", option_string, &opt.alt_svc, NULL},
    {"cafile", "CA certificate for server (ssl)", option_string, &opt.cafile, NULL},
    {"cert", "Certificate file for server (ssl)", option_string, &opt.cert, NULL},
    {"config", "Configure file (default "PREFIX"/etc/sproxy/sproxy.conf and ./sproxy.conf)", option_string, &opt.config_file, NULL},
    {"daemon", "Run as daemon", option_bool, &opt.daemon_mode, (void*)true},
    {"disable-http2", "Use http/1.1 only", option_bool, &opt.disable_http2, (void*)true},
    {"help", "Print this usage", option_bool, NULL, NULL},
    {"index", "Index file for path (local server)", option_string, &opt.index_file, NULL},
    {"insecure", "Ignore the cert error of server (SHOULD NOT DO IT)", option_bool, &opt.ignore_cert_error, (void*)true},
    {"interface", "Out interface (use for vpn), will skip bind if set to empty", option_string, &opt.interface, NULL},
    {"ipv6", "The ipv6 mode ([auto], enable, disable)", option_enum, &opt.ipv6_mode, ipv6_options},
    {"key", "Private key file name (ssl)", option_string, &opt.key, NULL},
    {"pcap", "Save packets in pcap file for vpn (generated pseudo ethernet header)", option_string, &opt.pcap_file, NULL},
    {"port", "The port to listen, default is 80 but 443 for ssl/sni/quic", option_int64, &opt.CPORT, NULL},
    {"policy-file", "The file of policy ("PREFIX"/etc/sproxy/sites.list as default)", option_string, &policy_file, NULL},
#ifdef HAVE_QUIC
    {"quic", "Server for QUIC (experiment)", option_bool, &opt.quic_mode, (void*)true},
#endif
    {"rewrite-auth", "rewrite the auth info (user:password) to proxy server", option_base64, opt.rewrite_auth, NULL},
    {"root-dir", "The work dir (current dir if not set)", option_string, &opt.rootdir, NULL},
    {"secret", "Set user and passwd for proxy (user:password), default is none.", option_list, &secrets, NULL},
    {"sni", "Act as a sni proxy", option_bool, &opt.sni_mode, (void*)true},
    {"server", "default proxy server (can ONLY set in config file)", option_string, &server_string, NULL},
    {"set-dns-route", "set route for dns server (via VPN interface)", option_bool, &opt.set_dns_route, (void*)true},
    {"socket", "set listen socket path for cli (/var/run/sproxy.sock is default for root and /tmp/sproxy.sock for others)", option_string, &opt.socket, NULL},
    {"alter-method", "use Alter-Method to define real method (for obfuscation), http1 only", option_bool, &opt.alter_method, (void*)true},
    {"request-header", "append the header (name:value) for plain http request", option_list, &opt.request_headers, NULL},
    {"ua", "set user-agent for vpn auto request", option_string, &opt.ua, NULL},
    {"version", "show the version of this programme", option_bool, NULL, NULL},
#ifndef NDEBUG
    {"debug-event", "debug-event", option_bitwise, &debug, (void*)DEVENT},
    {"debug-dns", "\tdebug-dns", option_bitwise, &debug, (void*)DDNS},
    {"debug-http2", "debug-http2", option_bitwise, &debug, (void*)DHTTP2},
    {"debug-http3", "debug-http3", option_bitwise, &debug, (void*)DHTTP3},
    {"debug-job", "\tdebug-job", option_bitwise, &debug, (void*)DJOB},
    {"debug-vpn", "\tdebug-vpn", option_bitwise, &debug, (void*)DVPN},
    {"debug-hpack", "debug-hpack", option_bitwise, &debug, (void*)DHPACK},
    {"debug-http", "debug-http",  option_bitwise, &debug, (void*)DHTTP},
    {"debug-file", "debug-file",  option_bitwise, &debug, (void*)DFILE},
    {"debug-net", "\tdebug-net",  option_bitwise, &debug, (void*)DNET},
    {"debug-quic", "debug-quic", option_bitwise, &debug,  (void*)DQUIC},
    {"debug-all", "\tdebug-all", option_bitwise, &debug, (void*)0xffffffff},
#endif
    {NULL, NULL, option_bool, NULL, NULL},
};

void network_changed(){
    LOG("handle network changed\n");
    if(opt.ipv6_mode == Auto){
        opt.ipv6_enabled = hasIpv6Address();
    }
    flushdns();
    flushproxy2();
}


void releaseall();
void dump_stat();

void prepare(){
    SSL_library_init();    // SSL初库始化
    SSL_load_error_strings();  // 载入所有错误信息
    signal(SIGPIPE, SIG_IGN);
    signal(SIGCHLD, SIG_IGN);
#if Backtrace_FOUND
    signal(SIGABRT, dump_trace);
#endif
    signal(SIGHUP,  (sig_t)reloadstrategy);
    signal(SIGUSR1, (sig_t)(void(*)())dump_stat);
    reloadstrategy();
    srandom(time(NULL));
    setvbuf(stdout, NULL, _IOLBF, BUFSIZ);
#ifndef __ANDROID__
    if (opt.daemon_mode) {
        if(daemon(1, 0) < 0) {
            LOGE("start daemon error:%s\n", strerror(errno));
            exit(1);
        }
        openlog("sproxy", LOG_PID | LOG_PERROR, LOG_LOCAL0);
    }
#else
    opt.daemon_mode = false;
#endif
    struct rlimit limits;
    if(getrlimit(RLIMIT_NOFILE, &limits)){
        LOGE("getrlimit failed: %s\n", strerror(errno));
    }else if(limits.rlim_cur < 16384){
        limits.rlim_cur = Min(limits.rlim_max, 16384);
        if(setrlimit(RLIMIT_NOFILE, &limits)) {
            LOGE("setrlimit failed: %s\n", strerror(errno));
        }
    }
    openefd();
    register_network_change_cb(network_changed);
}

void neglect(){
    flushdns();
    releaseall();
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

const char* getVersion() {
    return VERSION;
}

const char* getBuildTime() {
    return BUILDTIME;
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
    snprintf(infoString, sizeof(infoString), "%s %s; %s %s", info.sysname, info.machine, info.nodename, info.release);
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
            long long result;
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
                result = strtoll(args, &pos, 0);
                if(result == LLONG_MAX || result == LLONG_MIN || args == pos) {
                    LOGE("wrong int format: %s\n", args);
                }
                *(long long*)option_detail[i].result = result;
                LOG("set option %s: %lld\n", name, *(long long*)option_detail[i].result);
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
                result = 0;
                for(pargstr = (char**)option_detail[i].value; *pargstr; pargstr++ ){
                    if(strcmp(args, *pargstr) == 0){
                        *(int*)option_detail[i].result = result;
                        break;
                    }
                    result++;
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

int loadproxy(const char* proxy, struct Destination* server){
    memset(server, 0, sizeof(struct Destination));
    if(spliturl(proxy, server, NULL)){
        return -1;
    }
    if(server->scheme[0] == 0){
        strcpy(server->scheme, "https");
    }
    if(strcasecmp(server->scheme, "http") != 0
       && strcasecmp(server->scheme, "https") != 0
#ifdef HAVE_QUIC
       && strcasecmp(server->scheme, "quic") != 0)
#else
       )
#endif
    {
        LOGE("unkonw scheme for server: %s\n", server->scheme);
        return -1;
    }
    if(server->port == 0){
        if(strcasecmp(server->scheme, "http") == 0){
            server->port = HTTPPORT;
        }
        if(strcasecmp(server->scheme, "https") == 0){
            server->port = HTTPSPORT;
        }
        if(strcasecmp(server->scheme, "quic") == 0){
            server->port = QUICPORT;
        }
    }
    return 0;
}

int parseConfigFile(const char* config_file){
    FILE* conf = fopen(config_file, "re");
    if(conf){
        char line[1024];
        while(fgets(line, sizeof(line), conf)){
            if(line[0] == '#' || line[0] == '\n'){
                continue;
            }
            char option[1024], args[1024];
            int ret = sscanf(line, "%1023s%*[ \t]%1023[^\n]", option, args);
            if(ret <= 0){
                LOGE("config file parse failed: %s", line);
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
            parseArgs(option, args);
        }
        fclose(conf);
        return 0;
    }
    return -errno;
}

static const char* confs[] = {
    "/etc/sproxy/sproxy.conf",
    PREFIX "/etc/sproxy/sproxy.conf",
    "sproxy.conf",
    NULL,
};

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

    if(opt.CPORT < 0 || opt.CPORT >= 65535){
        LOGE("wrong port: %" PRId64 "\n", opt.CPORT);
        exit(1);
    }
    if(server_string && loadproxy(server_string, &opt.Server)){
        LOGE("wrong server format: %s\n", server_string);
        exit(1);
    }
    LOG("server %s\n", dumpDest(&opt.Server));

    if(policy_file == NULL){
        policy_file = PREFIX "/etc/sproxy/sites.list";
    }
    if((opt.policy_read = fopen(policy_file, "re")) == NULL){
        LOGE("failed to open policy file: %s\n", strerror(errno));
    }else if((opt.policy_write = fopen(policy_file, "r+e")) == NULL){
        LOG("failed to open policy file for write: %s, it won't be updated\n", strerror(errno));
    }
    if(opt.rootdir && chdir(opt.rootdir)){
        LOGE("chdir failed: %s\n", strerror(errno));
    }
    free((void*)opt.rootdir);
    opt.rootdir = (char*)malloc(PATH_MAX);
    getcwd((char*)opt.rootdir, PATH_MAX);

    if(opt.ipv6_mode == Auto){
        opt.ipv6_enabled = hasIpv6Address();
        LOG("auto detected ipv6: %s\n", opt.ipv6_enabled?"enable":"disable");
    }else{
        opt.ipv6_enabled = opt.ipv6_mode;
    }
    if (opt.cafile && access(opt.cafile, R_OK)){
        LOGE("access cafile failed: %s\n", strerror(errno));
        exit(1);
    }
    if (opt.cert && access(opt.cert, R_OK)){
        LOGE("access cert file failed: %s\n", strerror(errno));
        exit(1);
    }
    if (opt.key && access(opt.key, R_OK)){
        LOGE("access key file failed: %s\n", strerror(errno));
        exit(1);
    }
    for(struct arg_list* p = secrets.next; p != NULL; p = p->next){
        char secret_encode[DOMAINLIMIT];
        Base64Encode(p->arg, strlen(p->arg), secret_encode);
        addsecret(secret_encode);
    }
 #ifndef __ANDROID__
    if (opt.socket == NULL){
        if(getuid() == 0){
            opt.socket = "/var/run/sproxy.sock";
        }else{
            opt.socket = "/tmp/sproxy.sock";
        }
    }
 #endif
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
    strncpy(main_argv[0], name, len - 1);
}
