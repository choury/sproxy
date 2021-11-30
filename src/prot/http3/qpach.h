//
// Created by 周威 on 2021/8/8.
//

#ifndef SPROXY_QPACH_H
#define SPROXY_QPACH_H
#include "common/common.h"
#include "prot/http/http_header.h"
#include "prot/http/http_code.h"

#include <stddef.h>
#include <functional>
#include <map>
#include <string>

#define HTTP3_STREAM_TYPE_QPACK_ENCODE 0x02
#define HTTP3_STREAM_TYPE_QPACK_DECODE 0x03

#define HTTP3_SETTING_QPACK_MAX_TABLE_CAPACITY  0x01
#define HTTP3_SETTING_QPACK_BLOCKED_STREAMS     0x07

#define HTTP3_ERR_QPACK_DECOMPRESSION_FAILED    0x0200
#define HTTP3_ERR_QPACK_ENCODER_STREAM_ERROR    0x0201
#define HTTP3_ERR_QPACK_DECODER_STREAM_ERROR    0x0202

class Qpack{
    size_t dynamic_table_size_limit_max = 0;
    size_t dynamic_table_size_limit = 0;
    size_t dynamic_table_size = 0;
    std::function<void(PREPTR void* ins, size_t len)> sender;
    bool set_dynamic_table_size(size_t limit);
public:
    explicit Qpack(std::function<void(PREPTR void* ins, size_t len)> sender,
                   size_t dynamic_table_size_limit_max);
    int push_ins(const void* ins, size_t len);
    void set_dynamic_table_size_max(size_t max);
};

class Qpack_decoder: public Qpack {
    std::multimap<std::string, std::string> decode(const unsigned char *s, size_t len);
public:
    explicit Qpack_decoder(std::function<void(PREPTR void* ins, size_t len)> sender,
                           size_t dynamic_table_size_limit_max = 0):
        Qpack(std::move(sender), dynamic_table_size_limit_max){};
    HttpReqHeader* UnpackHttp3Req(const void* data, size_t len);
    HttpResHeader* UnpackHttp3Res(const void* data, size_t len);
};

class Qpack_encoder: public Qpack {
    size_t encode(unsigned char *buf, const char *name, const char *value);
public:
    explicit Qpack_encoder(std::function<void(PREPTR void* ins, size_t len)> sender,
                           size_t dynamic_table_size_limit_max = 0):
        Qpack(std::move(sender), dynamic_table_size_limit_max){};
    size_t PackHttp3Req(const HttpReqHeader* req, void* data, size_t len);
    size_t PackHttp3Res(const HttpResHeader* res, void* data, size_t len);
};

#endif //SPROXY_QPACH_H