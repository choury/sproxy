#ifndef RESPONSE_H__
#define RESPONSE_H__

#include "common/base.h"
#include "prot/http/http_header.h"
#include "misc/index.h"

class Requester;
class MemRWer;
struct strategy;

class Responser:public Server{
public:
    //src is usefull to status
    virtual void request(std::shared_ptr<HttpReqHeader> req, std::shared_ptr<MemRWer> rw, Requester* src) = 0;
};

extern bimap<std::string, Responser*> responsers;
bool shouldNegotiate(const std::string& hostname, const strategy* stra = nullptr);
bool shouldNegotiate(std::shared_ptr<const HttpReqHeader> req, Requester* src);
//调用该函数后有可能会立即通过response返回一个错误（比如blocked）
//不少地方对该错误的实现是直接销毁连接，所以应在调用后立即返回主事件循环
void distribute(std::shared_ptr<HttpReqHeader> req, std::shared_ptr<MemRWer> rw, Requester* src);
void response(std::shared_ptr<MemRWer> rw, std::shared_ptr<HttpResHeader> res, const char* body = nullptr);
#endif
