#ifndef FETCH_H__
#define FETCH_H__

#include "prot/http/http_header.h"

#include <functional>
#include <memory>
#include <string>

//一次性 HTTP 客户端请求,纯传输层:请求构造全权归调用方。dest 为连接目标
//(Host::distribute 钉死,不查本地策略);消息自身的地址取 req->Dest,缺失的
//Host 会在出站序列化时由它生成(h2/h3 的 :authority 同理)。收完完整响应
//(上限 1MB)后 done 回调一次;超时或连接错误时 res 为 nullptr(连接类错误
//通常以 Host 生成的 5xx 错误页应答,res 非空);响应中途断连时 res 为已收到
//的应答码、body 为截断的部分,调用方无法区分
void http_fetch(std::shared_ptr<HttpReqHeader> req, const Destination& dest,
                std::string body,
                std::function<void(std::shared_ptr<HttpResHeader> res, std::string resbody)> done,
                uint32_t timeout_ms = 15000);

#endif
