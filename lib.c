#include <string.h>


    
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


