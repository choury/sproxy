//
// Created by choury on 2021/8/8.
//

#ifndef SPROXY_QPACH_H
#define SPROXY_QPACH_H
#include "misc/buffer.h"
#include "prot/http/http_header.h"

#include <stddef.h>
#include <functional>
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
    bool set_dynamic_table_size(size_t limit);
    std::function<void(Buffer&&)> sender;
protected:
    static uint32_t getid(const std::string& name, const std::string& value = "") ;
public:
    explicit Qpack(decltype(sender) sender, size_t dynamic_table_size_limit_max);
    static int push_ins(const void* ins, size_t len);
    void set_dynamic_table_size_max(size_t max);
    [[nodiscard]] size_t get_dynamic_table_size() const {
        return dynamic_table_size;
    }
};

class Qpack_decoder: public Qpack {
    static HeaderMap decode(const unsigned char *s, size_t len);
public:
    explicit Qpack_decoder(std::function<void(Buffer&&)> sender, size_t dynamic_table_size_limit_max = 0):
        Qpack(std::move(sender), dynamic_table_size_limit_max){};
    static std::shared_ptr<HttpReqHeader> UnpackHttp3Req(const void* data, size_t len);
    static std::shared_ptr<HttpResHeader> UnpackHttp3Res(const void* data, size_t len);
};

class Qpack_encoder: public Qpack {
    static size_t encode(unsigned char *buf, const std::string& name, const std::string& value);
public:
    explicit Qpack_encoder(std::function<void(Buffer&&)> sender, size_t dynamic_table_size_limit_max = 0):
        Qpack(std::move(sender), dynamic_table_size_limit_max){};
    static size_t PackHttp3Req(std::shared_ptr<const HttpReqHeader> req, void* data, size_t len);
    static size_t PackHttp3Res(std::shared_ptr<const HttpResHeader> res, void* data, size_t len);
};

#endif //SPROXY_QPACH_H
