#include "common.h"

#include <string.h>
#include <stdlib.h>
#include <sys/time.h>
    
/**
 * strnstr - Find the first substring in a length-limited string
 * @s1: The string to be searched
 * @s2: The string to search for
 * @len: the maximum number of characters to search
 */
char* strnstr(const char* s1, const char* s2, size_t len)
{
    size_t l2;

    l2 = strlen(s2);
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


int endwith(const char *s1, const char *s2) {
    size_t l1 = strlen(s1);
    size_t l2 = strlen(s2);
    if(l1 < l2)
        return 0;
    return !memcmp(s1+l1-l2, s2, l2);
}

int epoll_my_ctl(int epfd, int op, int fd,struct epoll_event *event){
    if(op == EPOLL_CTL_MOD){
        LOGE("epoll mod %d: %p\n",fd,event->data.ptr);
    }
    if(op == EPOLL_CTL_ADD) {
        LOGE("epoll add %d: %p\n",fd,event->data.ptr);
    }
    if(op == EPOLL_CTL_DEL) {
        LOGE("epoll del %d\n",fd);
    }
    return epoll_ctl(epfd,op,fd,event);
}

int hex2num(char c)
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
    if ((src==NULL) || (des==NULL) || (strSize=len?len:strlen(src))==0 ) {
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
    return 1;
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
                    des[j++] = (char)((ch1<<4) | ch2);
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
    return 1;
}

static const char *base64_digs="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

void Base64Encode(const char *src, size_t len, char *dst){
    int i=0,j=0;
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

uint64_t getutime(){
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec * 1000000ull + tv.tv_usec;
}

void sighandle(int signum){
    fflush(stdout);
    exit(1);
}

#ifndef __ANDROID__
#include <execinfo.h>
void dump_trace() {
    void *stack_trace[100] = {0};
    char **stack_strings = NULL;
    int stack_depth = 0;
    int i = 0;

    /* 获取栈中各层调用函数地址 */
    stack_depth = backtrace(stack_trace, 100);

    /* 查找符号表将函数调用地址转换为函数名称 */
    stack_strings = (char **)backtrace_symbols(stack_trace, stack_depth);
    if (NULL == stack_strings) {
        LOGE(" Memory is not enough while dump Stack Trace! \r\n");
        return;
    }

    /* 打印调用栈 */
    LOGE(" Stack Trace: \r\n");
    for (i = 0; i < stack_depth; ++i) {
        LOGE(" [%d] %s \r\n", i, stack_strings[i]);
    }

    /* 获取函数名称时申请的内存需要自行释放 */
    free(stack_strings);
    stack_strings = NULL;

    return;
}
#endif
