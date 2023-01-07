#include "util.h"
#include "config.h"

#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <syslog.h>
#include <unistd.h>
#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <dirent.h>
#include <libgen.h>

#define PRIOR_HEAD 80
    
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

char* strchrnul (const char* s, int c) {
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

    LOGE("hex2num: unexpected char: %c", c);
    return '0';
}


int URLEncode(char *des, const char* src, size_t len)
{
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
        if (((ch>='A') && (ch<'Z')) ||
            ((ch>='a') && (ch<'z')) ||
            ((ch>='0') && (ch<'9'))) {
            des[j++] = ch;
        } else if (ch == ' ') {
            des[j++] = '+';
        } else if (ch == '.' || ch == '-' || ch == '_' || ch == '*') {
            des[j++] = ch;
        } else {
            sprintf(des+j, "%%%02X", (unsigned char)ch);
            j += 3;
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
            if (i+2<strSize) {
                char ch1 = hex2num(src[i+1]);//高4位
                char ch2 = hex2num(src[i+2]);//低4位
                if ((ch1!='0') && (ch2!='0'))
                    des[j++] = (ch1<<4) | ch2;
                i += 2;
                break;
            } else {
                break;
            }
        default:
            des[j++] = ch;
            break;
        }
    }
    des[j] = 0;
    return j;
}

static const char *base64_digs="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

void Base64Encode(const char *s, size_t len, char *dst){
    size_t i=0,j=0;
    const unsigned char* src = (const unsigned char *)s;
    for(;i+2<len;i+=3){
        dst[j++] = base64_digs[src[i]>>2];
        dst[j++] = base64_digs[((src[i]<<4) & 0x30) | src[i+1]>>4];
        dst[j++] = base64_digs[((src[i+1]<<2) & 0x3c) | src[i+2]>>6];
        dst[j++] = base64_digs[src[i+2] & 0x3f];
    }
    if(i == len-1){
        dst[j++] = base64_digs[src[i]>>2];
        dst[j++] = base64_digs[(src[i]<<4) & 0x30];
        dst[j++] = '=';
        dst[j++] = '=';
    }else if(i == len-2){
        dst[j++] = base64_digs[src[i]>>2];
        dst[j++] = base64_digs[((src[i]<<4) & 0x30) | src[i+1]>>4];
        dst[j++] = base64_digs[(src[i+1]<<2) & 0x3c];
        dst[j++] = '=';
    }
    dst[j++] = 0;
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
    vsprintf(buff, fmt, cp);
    if(size){
        *size = len;
    }
    va_end(cp);
    return buff;
}

const char* findprogram(ino_t inode){
    static char program[DOMAINLIMIT+1];
#ifdef __APPLE__
    sprintf(program, "Unkown-pid(%llu)", inode);
#else
    sprintf(program, "Unkown-pid(%lu)", inode);
#endif
    int found = 0;
    DIR* dir = opendir("/proc");
    if(dir == NULL){
        LOGE("open proc dir failed: %s\n", strerror(errno));
        return 0;
    }
    char socklink[20];
#ifdef __APPLE__
    sprintf(socklink, "socket:[%llu]", inode);
#else
    sprintf(socklink, "socket:[%lu]", inode);
#endif
    struct dirent *ptr;
    while((ptr = readdir(dir)) != NULL && found == 0)
    {
        //如果读取到的是"."或者".."则跳过，读取到的不是文件夹名字也跳过
        if((strcmp(ptr->d_name, ".") == 0) || (strcmp(ptr->d_name, "..") == 0)) continue;
        if(ptr->d_type != DT_DIR) continue;

        char fddirname[30];
        sprintf(fddirname, "/proc/%.20s/fd", ptr->d_name);
        DIR *fddir = opendir(fddirname);
        if(fddir == NULL){
            continue;
        }
        struct dirent *fdptr;
        while((fdptr = readdir(fddir)) != NULL){
            char fname[50];
            //example:  /proc/1111/fd/222
            sprintf(fname, "%.20s/%.20s", fddirname, fdptr->d_name);
            char linkname[URLLIMIT];
            int ret = readlink(fname, linkname, sizeof(linkname));
            if(ret > 0 && ret < 20 && memcmp(linkname, socklink, ret) == 0){
                sprintf(fname, "/proc/%.20s/exe", ptr->d_name);
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

#if Backtrace_FOUND
void demangle_func(char* stack, int depth);

void dump_trace(int signum) {
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
    LOGE(" Stack Trace: \n");
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

int spliturl(const char* url, struct Destination* server, char* path) {
    if (url[0] == '/' && path) {
        strcpy(path, url);
        return 0;
    }
    const char* url_end = url + strlen(url);
    // scan scheme by '://'
    const char *scan_pos = strstr(url, "://");
    size_t scheme_len = 0;
    if (scan_pos) {
        scheme_len = scan_pos - url;
        scan_pos += 3;
    }else{
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
        strncpy(tmpaddr, url, sizeof(tmpaddr) - 1);
    }

    if (tmpaddr[0] == '[') {
        // this is an ipv6 address
        if (!(addrsplit = strchr(tmpaddr, ']'))) {
            return -1;
        }
        int copylen = addrsplit - tmpaddr + 1;
        memcpy(server->hostname, tmpaddr, copylen);
        server->hostname[copylen] = 0;

        if (addrsplit[1] == ':') {
            long dport = strtol(addrsplit + 2, NULL, 10);
            if(dport == 0 || dport > 65535){
                return -1;
            }
            server->port = (uint16_t)dport;
        } else if (addrsplit[1] != 0) {
            return -1;
        }
    } else {
        if ((addrsplit = strchr(tmpaddr, ':'))) {
            memcpy(server->hostname, tmpaddr, addrsplit - tmpaddr);
            server->hostname[addrsplit - tmpaddr] = 0;
            long dport = strtol(addrsplit + 1, NULL, 10);
            if(dport == 0 || dport > 65535){
                return -1;
            }
            server->port = (uint16_t)dport;
        } else {
            strcpy(server->hostname, tmpaddr);
        }
    }
    return 0;
}

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

const char* dumpDest(const struct Destination* Server){
    static char buff[URLLIMIT];
    dumpDestToBuffer(Server, buff, sizeof(buff));
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

