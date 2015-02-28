#include <string.h>
#include <stdlib.h>
#include "common.h"
    
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
        if (!memcmp(s1, s2, l2))
            return (char*)s1;
        s1++;
    }
    return NULL;
}

#ifdef __USE_GNU
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