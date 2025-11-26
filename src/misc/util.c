#define _GNU_SOURCE
#include "util.h"
#include "config.h"
#include "net.h"

#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <syslog.h>
#include <unistd.h>
#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <dirent.h>
#include <sys/un.h>


#ifndef __APPLE__
/**
 * strnstr - Find the first substring in a length-limited string
 * @s1: The string to be searched
 * @s2: The string to search for
 * @len: the maximum number of characters to search
 */
const char* strnstr(const char* s1, const char* s2, size_t len)
{
    size_t l2 = strlen(s2);
    if (!l2)
        return (char*)s1;
    while (len >= l2) {
        len--;
        if (*s1 == 0)
            break;
        if (!memcmp(s1, s2, l2))
            return (char*)s1;
        s1++;
    }
    return NULL;
}
#endif

char* my_strchrnul (const char* s, int c) {
    char *p = (char *) s;
    while (*p && (*p != c))
        ++p;
    return p;
}

char* strlchrnul (const char* s, int c){
    char *p = (char*)s;
    while(*p)++p;
    char *e = p;
    while(p != s && (*p != c))
        --p;
    if(*p == c){
        return p;
    }
    return e;
}



static int hex2num(char c)
{
    if (c>='0' && c<='9') return c - '0';
    if (c>='a' && c<='z') return c - 'a' + 10;
    if (c>='A' && c<='Z') return c - 'A' + 10;

    LOGE("hex2num: unexpected char: %c\n", c);
    return -1;
}


int URLEncode(char *des, const char* src, size_t len) {
    int j = 0;//for result index
    int strSize;

    if(des==NULL)
        return 0;
    if ((src==NULL) || (strSize=len?len:strlen(src))==0 ) {
        des[0]=0;
        return 0;
    }
    int i;
    for (i=0; i<strSize; ++i) {
        char ch = src[i];
        if (((ch>='A') && (ch<='Z')) ||
            ((ch>='a') && (ch<='z')) ||
            ((ch>='0') && (ch<='9'))) {
            des[j++] = ch;
        } else if (ch == ' ') {
            des[j++] = '+';
        } else if (ch == '.' || ch == '-' || ch == '_' || ch == '*' || ch == '~') {
            des[j++] = ch;
        } else {
            const char hex_digits[] = "0123456789ABCDEF";
            des[j++] = '%';
            des[j++] = hex_digits[(ch >> 4) & 0x0F];
            des[j++] = hex_digits[ch & 0x0F];
        }
    }

    des[j] = '\0';
    return j;
}



int URLDecode(char *des, const char *src, size_t len)
{
    int i;
    int j = 0;//record result index
    int strSize;

    if(des==NULL)
        return 0;
    if ((src==NULL) || (strSize=len?len:strlen(src))==0 ) {
        des[0]=0;
        return 0;
    }

    for ( i=0; i<strSize; ++i) {
        char ch = src[i];
        switch (ch) {
        case '+':
            des[j++] = ' ';
            break;
        case '%':
            if(src[i+1] == '%') {
                des[j++] = '%';
                i++;
                break;
            }
            if (i+2<strSize) {
                int ch1 = hex2num(src[i+1]);//高4位
                int ch2 = hex2num(src[i+2]);//低4位
                if (ch1 >= 0 && ch2 >= 0) {
                    des[j++] = (char)((ch1<<4) | ch2);
                    i += 2;
                    break;
                }
            }
            des[j++] = '%';
            break;
        default:
            des[j++] = ch;
            break;
        }
    }
    des[j] = 0;
    return j;
}

static const char *base64_endigs_normal ="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static const char *base64_endigs_url ="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

static size_t Base64(const char* endigs, const char *s, size_t len, char *dst, bool nopad){
    size_t i=0,j=0;
    const unsigned char* src = (const unsigned char *)s;
    for(;i+2<len;i+=3){
        dst[j++] = endigs[src[i]>>2];
        dst[j++] = endigs[((src[i]<<4) & 0x30) | src[i+1]>>4];
        dst[j++] = endigs[((src[i+1]<<2) & 0x3c) | src[i+2]>>6];
        dst[j++] = endigs[src[i+2] & 0x3f];
    }
    if(i == len-1){
        dst[j++] = endigs[src[i]>>2];
        dst[j++] = endigs[(src[i]<<4) & 0x30];
        if (!nopad) {
            dst[j++] = '=';
            dst[j++] = '=';
        }
    }else if(i == len-2){
        dst[j++] = endigs[src[i]>>2];
        dst[j++] = endigs[((src[i]<<4) & 0x30) | src[i+1]>>4];
        dst[j++] = endigs[(src[i+1]<<2) & 0x3c];
        if (!nopad) dst[j++] = '=';
    }
    dst[j] = 0;
    return j;
}

size_t Base64Encode(const char *s, size_t len, char *dst){
    return Base64(base64_endigs_normal, s, len, dst, false);
}

size_t Base64EnUrl(const char *s, size_t len, char *dst){
    return Base64(base64_endigs_url, s, len, dst, true);
}

static const char base64_dedigs_url[128] =
{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
 0,0,0,0,0,0,0,0,0,0,0,0,0,62,0,0,
 52,53,54,55,56,57,58,59,60,61,0,0,0,0,0,0,
 0,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,
 15,16,17,18,19,20,21,22,23,24,25,0,0,0,0,63,
 0,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
 41,42,43,44,45,46,47,48,49,50,51,0,0,0,0,0
};


static size_t DeBase64(const char* base64_dedigs, const char *src, size_t len, char* dst) {
    size_t i=0, j = 0;
    for(;i<len; i+= 4){
        char ch1 = (base64_dedigs[(int)src[i]]<<2) | (base64_dedigs[(int)src[i+1]] >>4);
        dst[j++] = ch1;
        if(i+2 >= len || src[i+2] == '='){
            break;
        }
        char ch2 = (base64_dedigs[(int)src[i+1]]<<4) | (base64_dedigs[(int)src[i+2]] >>2);
        dst[j++] = ch2;
        if(i+3 >= len || src[i+3] == '='){
            break;
        }
        char ch3 = (base64_dedigs[(int)src[i+2]]<<6) | base64_dedigs[(int)src[i+3]];
        dst[j++] = ch3;
    }
    dst[j] = 0;
    return j;
}

size_t Base64DeUrl(const char *src, size_t len, char* dst){
    return DeBase64(base64_dedigs_url, src, len, dst);
}

const char * protstr(Protocol p) {
    if(p == TCP){
        return "tcp";
    }
    if(p == UDP){
        return "udp";
    }
    if(p == ICMP){
        return "icmp";
    }
    if(p == QUIC){
        return "quic";
    }
    return "unknown";
}

void* memdup(const void* ptr, size_t size){
   void *dup = malloc(size);
   assert(dup);
   if(dup && size){
       memcpy(dup, ptr, size);
   }
   return dup;
}

char* avsprintf(size_t* size, const char* fmt, va_list ap){
    va_list cp;
    va_copy(cp, ap);
    size_t len = vsnprintf(NULL, 0, fmt, ap);
    char* const buff = malloc(len+1);
    vsnprintf(buff, len+1, fmt, cp);
    if(size){
        *size = len;
    }
    va_end(cp);
    return buff;
}

const char* findprogram(ino_t inode){
    static char program[DOMAINLIMIT+1];
#ifdef __APPLE__
    snprintf(program, sizeof(program), "Unkown-pid(%llu)", inode);
#else
    snprintf(program, sizeof(program), "Unkown-pid(%lu)", inode);
#endif
    int found = 0;
    DIR* dir = opendir("/proc");
    if(dir == NULL){
        LOGE("open proc dir failed: %s\n", strerror(errno));
        return 0;
    }
    char socklink[20];
#ifdef __APPLE__
    snprintf(socklink, sizeof(socklink), "socket:[%llu]", inode);
#else
    snprintf(socklink, sizeof(socklink), "socket:[%lu]", inode);
#endif
    struct dirent *ptr;
    while((ptr = readdir(dir)) != NULL && found == 0)
    {
        //如果读取到的是"."或者".."则跳过，读取到的不是文件夹名字也跳过
        if((strcmp(ptr->d_name, ".") == 0) || (strcmp(ptr->d_name, "..") == 0)) continue;
        if(ptr->d_type != DT_DIR) continue;

        char fddirname[30];
        snprintf(fddirname, sizeof(fddirname), "/proc/%.20s/fd", ptr->d_name);
        DIR *fddir = opendir(fddirname);
        if(fddir == NULL){
            continue;
        }
        struct dirent *fdptr;
        while((fdptr = readdir(fddir)) != NULL){
            char fname[50];
            //example:  /proc/1111/fd/222
            snprintf(fname, sizeof(fname), "%.20s/%.20s", fddirname, fdptr->d_name);
            char linkname[URLLIMIT];
            int ret = readlink(fname, linkname, sizeof(linkname));
            if(ret > 0 && ret < 20 && memcmp(linkname, socklink, ret) == 0){
                snprintf(fname, sizeof(fname), "/proc/%.20s/exe", ptr->d_name);
                ret = readlink(fname, linkname, sizeof(linkname)),
                linkname[ret] = 0;
                snprintf(program, sizeof(program), "%s/%s", basename(linkname), ptr->d_name);
                found = 1;
                break;
            }
        }
        closedir(fddir);
    }
    closedir(dir);
    return program;
}

#ifndef s6_addr32
#define	s6_addr32   __u6_addr.__u6_addr32
#endif

struct in6_addr mapIpv4(struct in_addr addr, const char* prefix) {
    struct in6_addr addr6;
    memcpy(addr6.s6_addr, prefix, 12);
    addr6.s6_addr32[3] = addr.s_addr;
    return addr6;
}

struct in_addr getMapped(struct in6_addr addr, const char* prefix) {
    struct in_addr addr4;
    if(memcmp(addr.s6_addr, prefix, 12) == 0){
        addr4.s_addr = addr.s6_addr32[3];
    }else{
        addr4.s_addr = INADDR_NONE;
    }
    return addr4;
}

#if Backtrace_FOUND || defined(ANDROID_APP)
void demangle_func(char* stack, int depth);

void dump_trace(int signum) {
    fflush(stdout);
    void *stack_trace[100] = {0};
    /* 获取栈中各层调用函数地址 */
    int stack_depth = backtrace(stack_trace, 100);

    /* 查找符号表将函数调用地址转换为函数名称 */
    char** stack_strings = (char **)backtrace_symbols(stack_trace, stack_depth);
    if (NULL == stack_strings) {
        LOGE(" Memory is not enough while dump Stack Trace! \n");
        return;
    }

    /* 打印调用栈 */
    LOGE(" Stack Trace [%d]: \n", signum);
    for (int i = 0; i < stack_depth; ++i) {
        demangle_func(stack_strings[i], i);
    }

    /* 获取函数名称时申请的内存需要自行释放 */
    free(stack_strings);
    stack_strings = NULL;
    signal(signum, SIG_DFL);
    kill(getpid(), signum);
}
#endif

static int parse_port(const char *s, uint16_t *out) {
    char *endptr;
    long val;
    if (!s || !*s)
        return -1;
    errno = 0;
    val = strtol(s, &endptr, 10);
    // 检查是否是纯数字、没有溢出、范围合法
    if (errno != 0 || *endptr != '\0' || val <= 0 || val > 65535)
        return -1;
    *out = (uint16_t)val;
    return 0;
}

int spliturl(const char* url, struct Destination* server, char* path) {
    if (url == NULL) {
        return -1; // Invalid input
    }

    if (url[0] == '/' && path) {
        strcpy(path, url);
        return 0;
    }

    if (!server) {
        return -1;
    }

    const char* url_end = url + strlen(url);
    // scan scheme by '://'
    const char *scan_pos = strstr(url, "://");
    size_t scheme_len = 0;
    if (scan_pos) {
        scheme_len = scan_pos - url;
        scan_pos += 3;
    } else {
        scan_pos = url;
    }
    if(scheme_len){
        memcpy(server->scheme, url, scheme_len);
        server->scheme[scheme_len] = 0;
    }
    url = scan_pos;
    const char* addrsplit;
    char tmpaddr[DOMAINLIMIT];
    // scan path by '/'
    if ((addrsplit = strchr(url, '/'))) {
        int copylen = MIN(url_end-addrsplit, (URLLIMIT-1));
        if (path) {
            memcpy(path, addrsplit, copylen);
            path[copylen] = 0;
        }
        copylen = MIN((size_t)(addrsplit - url),  sizeof(tmpaddr)-1);
        memcpy(tmpaddr, url, copylen);
        tmpaddr[copylen] = 0;
    } else {
        if (path) {
            strcpy(path, "/");
        }
        snprintf(tmpaddr, sizeof(tmpaddr), "%s", url);
    }

    if (tmpaddr[0] == '[') {
        // this is an ipv6 address
        if (!(addrsplit = strchr(tmpaddr, ']'))) {
            return -2; // Invalid IPv6 address format
        }
        int copylen = addrsplit - tmpaddr + 1;
        memcpy(server->hostname, tmpaddr, copylen);
        server->hostname[copylen] = 0;

        if (addrsplit[1] == ':') {
            if (parse_port(addrsplit + 2, &server->port) != 0) {
                return -3; // Invalid port number
            }
        } else if (addrsplit[1] != 0) {
            return -2; // Invalid IPv6 address format
        }
    } else {
        if ((addrsplit = strchr(tmpaddr, ':'))) {
            memcpy(server->hostname, tmpaddr, addrsplit - tmpaddr);
            server->hostname[addrsplit - tmpaddr] = 0;
            if (parse_port(addrsplit + 1, &server->port) != 0) {
                return -3; // Invalid port number
            }
        } else {
            strcpy(server->hostname, tmpaddr);
        }
    }
    return 0;
}

/*
int dumpDestToBuffer(const struct Destination* Server, char* buff, size_t buflen){
    uint16_t port = Server->port;
    if(strcasecmp(Server->scheme, "http") == 0 && port == HTTPPORT){
        port = 0;
    }
    if(strcasecmp(Server->scheme, "https") == 0 && port == HTTPSPORT){
        port = 0;
    }
    int pos = 0;
    if(Server->scheme[0])
        pos = snprintf(buff, buflen, "%s://%s", Server->scheme, Server->hostname);
    else
        pos = snprintf(buff, buflen, "%s", Server->hostname);
    if(port)
        pos += snprintf(buff + pos, buflen - pos, ":%d", port);
    return pos;
}
*/

const char* dumpDest(const struct Destination* Server){
    static char buff[URLLIMIT];
    uint16_t port = Server->port;
    if(strcasecmp(Server->scheme, "http") == 0 && port == HTTPPORT){
        port = 0;
    }
    if(strcasecmp(Server->scheme, "https") == 0 && port == HTTPSPORT){
        port = 0;
    }
    int pos = 0;
    if(Server->scheme[0]) {
        pos = snprintf(buff, sizeof(buff), "%s://%s", Server->scheme, Server->hostname);
    }else if(Server->protocol[0]) {
        pos = snprintf(buff, sizeof(buff), "%s://%s", Server->protocol, Server->hostname);
    }else {
        pos = snprintf(buff, sizeof(buff), "%s", Server->hostname);
    }
    if(port)
        snprintf(buff + pos, sizeof(buff) - pos, ":%d", port);
    return buff;
}

const char* dumpAuthority(const struct Destination* Server){
    static char buff[URLLIMIT];
    uint16_t port = Server->port;
    if(strcasecmp(Server->scheme, "http") == 0 && port == HTTPPORT){
        port = 0;
    }
    if(strcasecmp(Server->scheme, "https") == 0 && port == HTTPSPORT){
        port = 0;
    }
    if(port){
        snprintf(buff, sizeof(buff), "%s:%d", Server->hostname, Server->port);
        return buff;
    }
    return Server->hostname;
}

void storage2Dest(const struct sockaddr_storage* addr, struct Destination* dest) {
    memset(dest, 0, sizeof(struct Destination));
    addrstring(addr, dest->hostname, sizeof(dest->hostname));
    if(addr->ss_family == AF_INET){
        const struct sockaddr_in* in = (struct sockaddr_in*)addr;
        dest->port = ntohs(in->sin_port);
    }else if(addr->ss_family == AF_INET6){
        const struct sockaddr_in6* in6 = (struct sockaddr_in6*)addr;
        dest->port = ntohs(in6->sin6_port);
    }else if(addr->ss_family == AF_UNIX) {
        dest->port = 0;
    }
}

// full: protocol:hostname:port (tcp:example.com:80 udp:192.168.0.1:53 tcp:[::1]:443)
// short:
//   hostname:port
//   port => [::]:port
// special:
//   unix:path
// return 0 on success, -1 on error
int parseBind(const char* str, struct Destination* dest) {
    if (!str || !*str || !dest)
        return -1;
    memset(dest, 0, sizeof(*dest));

    // special: unix:path
    if(strncmp(str, "unix:", 5) == 0) {
        const char *path = str + 5;
        if (!*path)
            return -1;

        if (sizeof(dest->protocol) <= strlen("unix"))
            return -1;
        strcpy(dest->protocol, "unix");
        if (strlen(path) >= sizeof(dest->hostname))
            return -1;
        strcpy(dest->hostname, path);
        return 0;
    }

    const char *p;
    const char *first_colon = NULL;
    const char *last_colon = NULL;
    int bracket = 0;  // [] 里的 : 不算
    // 找到所有不在 [] 内的冒号位置
    for (p = str; *p; ++p) {
        if (*p == '[') {
            bracket++;
        } else if (*p == ']') {
            if (bracket > 0)
                bracket--;
        } else if (*p == ':' && bracket == 0) {
            if (!first_colon)
                first_colon = p;
            last_colon = p;
        }
    }

    // 情况 1：只有 port => [::]:port
    if (!last_colon) {
        if (parse_port(str, &dest->port) != 0)
            return -1;

        //strcpy(dest->protocol, "tcp");
        strcpy(dest->hostname, "[::]");
        return 0;
    }

    // 下面开始处理 hostname:port / protocol:hostname:port 两类
    // 先解析 port （最后一个冒号后面那段）
    if (parse_port(last_colon + 1, &dest->port) != 0)
        return -1;

    const char *prefix_start = str;
    const char *prefix_end   = last_colon;

    // [prefix_start, prefix_end) 是 hostname 或 protocol:hostname
    if (prefix_start == prefix_end)
        return -1;  // 冒号前为空，非法

    // 判断 prefix 中是否还有一个冒号，如果有就是 protocol:hostname:port，否则是 hostname:port
    if (first_colon && first_colon < prefix_end && first_colon != prefix_end) {
        // protocol:hostname:port
        size_t proto_len = (size_t)(first_colon - prefix_start);
        size_t host_len  = (size_t)(prefix_end   - (first_colon + 1));

        if (proto_len == 0 || host_len == 0)
            return -1;

        if (proto_len >= sizeof(dest->protocol) ||
            host_len  >= sizeof(dest->hostname))
            return -1;

        memcpy(dest->protocol, prefix_start, proto_len);
        memcpy(dest->hostname, first_colon + 1, host_len);
    } else {
        // hostname:port
        size_t host_len = (size_t)(prefix_end - prefix_start);
        if (host_len == 0)
            return -1;

        if (host_len >= sizeof(dest->hostname))
            return -1;

        memcpy(dest->hostname, prefix_start, host_len);
    }
    return 0;
}
