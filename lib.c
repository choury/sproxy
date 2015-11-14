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


int URLEncode(const char* src, char *des)
{
    int j = 0;//for result index
    char ch;
    int strSize=strlen(src);

    if ((src==NULL) || (des==NULL) || (strSize==0) ) {
        return 0;
    }
    int i;
    for (i=0; i<strSize; ++i) {
        ch = src[i];
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



int URLDecode(const char* src, char *des)
{
    char ch,ch1,ch2;
    int i;
    int j = 0;//record result index

    int strSize = strlen(src);

    if ((src==NULL) || (des==NULL) || (strSize<=0) ) {
        return 0;
    }

    for ( i=0; i<strSize; ++i) {
        ch = src[i];
        switch (ch) {
        case '+':
            des[j++] = ' ';
            break;
        case '%':
            if (i+2<strSize) {
                ch1 = hex2num(src[i+1]);//高4位
                ch2 = hex2num(src[i+2]);//低4位
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

uint64_t getutime(){
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec * 1000000 + tv.tv_usec;
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
