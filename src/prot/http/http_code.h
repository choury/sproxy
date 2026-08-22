#ifndef HTTP_CODE_H__
#define HTTP_CODE_H__
#include <optional>
#include <string>
#include <stdint.h>
#include <stddef.h>
#include "misc/cursor.h"

class HttpCursor: public cursor{
public:
    using cursor::cursor;
    bool hfm_encode(const char *s, size_t len);
    std::optional<std::string> hfm_decode() const;
    bool integer_encode(uint64_t value, int prefix);
    std::optional<uint64_t> integer_decode(int prefix) const;
    bool literal_encode(const char* s, int prefix);
    //带显式长度的字面量编码：串内可含NUL；Huffman位固定在长度前缀上方(1<<prefix)，
    //HPACK字符串字面量与QPACK的name/value字面量(RFC 9204 §4.1.2)均适用
    bool literal_encode(const void* s, size_t len, int prefix);
    std::optional<std::string> literal_decode(int prefix) const;
};

#endif
