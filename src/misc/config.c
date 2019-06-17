#include "config.h"
#include "util.h"
#include "strategy.h"
#include "net.h"

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
#ifndef __APPLE__
#include <sys/prctl.h>
#else
#include <pthread.h>
#endif
#include <openssl/ssl.h>

static char **main_argv;

struct options opt = {
    .cafile            = NULL,
    .cert              = NULL,
    .key               = NULL,
    .index_file        = NULL,
    .interface         = NULL,
    .disable_ipv6      = false,
    .disable_http2     = false,
    .sni_mode          = false,
    .daemon_mode       = false,
    .ignore_cert_error = false,
    .autoindex         = false,

    .CPORT          = 0,
    .Server         = {
        .protocol   = {0},
        .hostname   = {0},
        .port       = 0,
    },
    .auth_string    = {0},
    .rewrite_auth   = {0},
};

enum option_type{
    option_boolargs,
    option_int64args,
    option_base64args,
    option_stringargs,
    option_extargs,
};


struct option_detail {
    const char*      name;
    const char*      details;
    enum option_type type;
    void*            args;
};

static struct option long_options[] = {
    {"autoindex",    no_argument,       NULL, 'i'},
    {"cafile",       required_argument, NULL,  0 },
    {"cert",         required_argument, NULL,  0 },
    {"daemon",       no_argument,       NULL, 'D'},
    {"disable-ipv6", no_argument,       NULL,  0 },
    {"disable-http2",no_argument,       NULL, '1'},
    {"help",         no_argument,       NULL, 'h'},
    {"index",        required_argument, NULL,  0 },
    {"insecure",     no_argument,       NULL, 'k'},
    {"interface",    required_argument, NULL, 'I'},
    {"key",          required_argument, NULL,  0 },
    {"port",         required_argument, NULL, 'p'},
    {"rewrite-auth", required_argument, NULL, 'r'},
    {"secret",       required_argument, NULL, 's'},
    {"sni",          no_argument,       NULL,  0 },
#ifndef NDEBUG
    {"debug-event",  no_argument,   NULL,  0 },
    {"debug-dns",    no_argument,   NULL,  0 },
    {"debug-http2",  no_argument,   NULL,  0 },
    {"debug-job",    no_argument,   NULL,  0 },
    {"debug-hpack",  no_argument,   NULL,  0 },
    {"debug-http",   no_argument,   NULL,  0 },
    {"debug-all",    no_argument,   NULL,  0 },
#endif
    {NULL,       0,                NULL,  0 }
};

struct option_detail option_detail[] = {
    {"autoindex", "Enables or disables the directory listing output", option_boolargs, &opt.autoindex},
    {"cafile", "CA certificate for server (ssl)", option_stringargs, &opt.cafile},
    {"cert", "Certificate file for server (ssl)", option_stringargs, &opt.cert},
    {"daemon", "Run as daemon", option_boolargs, &opt.daemon_mode},
    {"disable-ipv6", "Disable ipv6 when querying dns", option_boolargs, &opt.disable_ipv6},
    {"disable-http2", "Use http/1.1 only", option_boolargs, &opt.disable_http2},
    {"help", "Print this usage", option_extargs, NULL},
    {"index", "Index file for path (when as a http(s) server)", option_stringargs, &opt.index_file},
    {"insecure", "Ignore the cert error of server (SHOULD NOT DO IT)", option_boolargs, &opt.ignore_cert_error},
    {"interface", "Out interface (use for vpn)", option_stringargs, &opt.interface},
    {"key", "Private key file name (ssl)", option_stringargs, &opt.key},
    {"port", "The port to listen, default is 80 but 443 for ssl/sni", option_extargs, &opt.CPORT},
    {"rewrite-auth", "rewrite the auth info (user:password) to proxy server", option_base64args, opt.rewrite_auth},
    {"secret", "Set a user and passwd for proxy (user:password), default is none.", option_base64args, opt.auth_string},
    {"sni", "Act as a sni proxy", option_boolargs, &opt.sni_mode},
    {"server", "default proxy server (can ONLY set in config file)", option_extargs, NULL},
#ifndef NDEBUG
    {"debug-event", "debug-event", option_extargs, NULL},
    {"debug-dns", "\tdebug-dns", option_extargs, NULL},
    {"debug-http2", "debug-http2", option_extargs, NULL},
    {"debug-job", "\tdebug-job", option_extargs, NULL},
    {"debug-vpn", "\tdebug-vpn", option_extargs, NULL},
    {"debug-hpack", "debug-hpack", option_extargs, NULL},
    {"debug-http", "debug-http",  option_extargs, NULL},
    {"debug-all", "\tdebug-all", option_extargs, NULL},
#endif
    {NULL, NULL, option_extargs, NULL},
};

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
    srandom(time(0));
    setvbuf(stdout, NULL, _IOLBF, BUFSIZ);
}

static void usage(const char * programe){
    printf("Usage: %s [host:port]\n" , programe);
    for(int i =0; option_detail[i].name;i++){
        int short_name = 0;
        for(int j=0; long_options[j].name; j++){
            if(strcmp(option_detail[i].name, long_options[j].name) == 0 && long_options[j].val){
                printf("-%c, ", long_options[i].val);
                short_name = 1;
                break;
            }
        }
        if(short_name == 0){
            printf("    ");
        }
        printf("--%s\t%s\n", option_detail[i].name, option_detail[i].details);
    }
}

static void parseExtargs(const char* name, const char* args){
    if(strcmp(name, "server") == 0){
        if(loadproxy(args, &opt.Server)){
            fprintf(stderr, "wrong server format: %s\n", args);
            exit(0);
        }
        printf(": %s", dumpDest(&opt.Server));
    }else if(strcmp(name, "port") == 0){
        opt.CPORT = atoi(args);
        printf(": %d", opt.CPORT);
    }else if(strcmp(name, "help") == 0){
        printf("\n");
        usage(main_argv[0]);
        exit(0);
    }else if(strcmp(name, "debug-event") == 0){
        debug |= DEVENT;
    }else if(strcmp(name, "debug-dns") == 0){
        debug |= DDNS;
    }else if(strcmp(name, "debug-http2") == 0){
        debug |= DHTTP2;
    }else if(strcmp(name, "debug-job") == 0){
        debug |= DJOB;
    }else if(strcmp(name, "debug-vpn") == 0){
        debug |= DVPN;
    }else if(strcmp(name, "debug-hpack") == 0){
        debug |= DHPACK;
    }else if(strcmp(name, "debug-http") == 0){
        debug |= DHTTP;
    }else if(strcmp(name, "debug-all") == 0){
        debug = (uint32_t)(-1);
    }else{
        assert(0);
    }
}

static void parseArgs(const char* name, const char* args){
    printf("set option %s", name);
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
            case option_boolargs:
                *(bool*)option_detail[i].args = !*(bool*)option_detail[i].args;
                printf(": %s", *(bool*)option_detail[i].args?"true":"false");
                break;
            case option_stringargs:
                *(char**)option_detail[i].args = strdup(args);
                printf(": %s", *(char**)option_detail[i].args);
                break;
            case option_int64args:
                result = strtoll(args, &pos, 0);
                if(result == LLONG_MAX || result == LLONG_MIN || args == pos) {
                    fprintf(stderr, "wrong int format: %s\n", args);
                }
                *(long long*)option_detail[i].args = result;
                printf(": %lld", *(long long*)option_detail[i].args);
                break;
            case option_base64args:
                Base64Encode(args, strlen(args), (char*)option_detail[i].args);
                printf(": %s", (char*)option_detail[i].args);
                break;
            case option_extargs:
                parseExtargs(option_detail[i].name, args);
                break;
            }
            printf("\n");
            return;
        }
    }
    printf(": UNKNOWN\n");
}

int loadproxy(const char* proxy, struct Destination* server){
    memset(server, 0, sizeof(struct Destination));
    if(spliturl(proxy, server, NULL)){
        return -1;
    }
    if(server->protocol[0] == 0){
        strcpy(server->protocol, "https");
    }
    if(strcasecmp(server->protocol, "http") && strcasecmp(server->protocol, "https")){
        LOGE("unkonw protocol for server: %s\n", server->protocol);
        return -1;
    }
    if(server->port == 0){
        if(strcasecmp(server->protocol, "http") == 0){
            server->port = HTTPPORT;
        }
        if(strcasecmp(server->protocol, "https") == 0){
            server->port = HTTPSPORT;
        }
    }
    return 0;
}

void parseConfigFile(const char* config_file){
    FILE* conf = fopen(config_file, "re");
    if(conf){
        char line[1024];
        while(fgets(line, sizeof(line), conf)){
            char option[1024], args[1024];
            int ret = sscanf(line, "%s %s", option, args);
            if(ret <= 0){
                fprintf(stderr, "config file parse failed: %s", line);
                break;
            }
            if(option[0] == '#'){
                continue;
            }
            parseArgs(option, args);
        }
        fclose(conf);
    }
}

static const char* confs[] = {
    "/etc/sproxy/sproxy.conf",
    "/usr/local/etc/sproxy.conf",
    "sproxy.conf",
    NULL,
};

void parseConfig(int argc, char **argv){
    main_argv = argv;
    for(int i = 0; confs[i]; i++) {
        if(access(confs[i], R_OK)){
            continue;
        }
        printf("read config file from: %s\n", confs[i]);
        parseConfigFile(confs[i]);
        break;
    }
    while (1) {
        int option_index = 0;
        int c = getopt_long(argc, argv, "D1hikr:s:p:I:", long_options, &option_index);
        if (c == -1)
            break;
        if (c == '?' || c == ':'){
            usage(argv[0]);
            exit(1);
        }
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
        if(loadproxy(argv[optind], &opt.Server)){
            fprintf(stderr, "wrong server format: %s\n", argv[optind]);
            exit(1);
        }
        printf("server %s\n", dumpDest(&opt.Server));
    }
#ifndef __ANDROID__
    if (opt.cafile && access(opt.cafile, R_OK)){
        fprintf(stderr, "access cafile failed: %s\n", strerror(errno));
        exit(1);
    }
    if (opt.cert && access(opt.cert, R_OK)){
        fprintf(stderr, "access cert file failed: %s\n", strerror(errno));
        exit(1);
    }
    if (opt.key && access(opt.key, R_OK)){
        fprintf(stderr, "access key file failed: %s\n", strerror(errno));
        exit(1);
    }
    if (opt.daemon_mode && daemon(1, 0) < 0) {
        fprintf(stderr, "start daemon error:%s\n", strerror(errno));
        exit(1);
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
