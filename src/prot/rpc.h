#ifndef RPC_H__
#define RPC_H__

#include <json.h>

#include <queue>
#include <string>
#include <functional>
#include <future>


class RpcBase{
protected:
    void sendJson(json_object *content);
    virtual void send(const char* data, size_t len) = 0;
public:
    virtual ssize_t DefaultProc(const char *buff, size_t len) = 0;
};

class RpcServer: public RpcBase{
protected:
    virtual json_object* call(std::string method, json_object *content) = 0;
public:
    virtual ssize_t DefaultProc(const char *buff, size_t len) override;
};

class RpcClient: public RpcBase{
    std::queue<std::function<void(json_object *)>> responser;
protected:
    virtual void call(const std::string method, json_object* body, std::function<void(json_object *)> response);
public:
    virtual ssize_t DefaultProc(const char *buff, size_t len) override;
};

class SproxyServer:virtual public RpcServer {
protected:
    virtual json_object* call(std::string method, json_object *content) override;

    virtual bool AddStrategy(const std::string& host, const std::string& strategy, const std::string& ext) = 0;
    virtual bool DelStrategy(const std::string& host) = 0;
    virtual std::vector<std::string> ListStrategy() = 0;
    virtual std::string TestStrategy(const std::string& host) = 0;

    virtual void FlushCgi() = 0;
    virtual void FlushDns() = 0;
    virtual void FlushStrategy() = 0;

    virtual bool SetServer(const std::string& server) = 0;
    virtual std::string GetServer() = 0;
    virtual bool Login(const std::string& token, const std::string& source) = 0;
    virtual std::string GetStatus() = 0;
};

class SproxyClient:virtual public RpcClient {
    int fd = 0;
    std::thread reader;
public:
    SproxyClient(const char* sock);
    virtual ~SproxyClient();
    virtual void send(const char* data, size_t len) override;

    std::promise<bool>  AddStrategy(const std::string& host, const std::string& strategy, const std::string& ext);
    std::promise<bool>  DelStrategy(const std::string& host);
    std::promise<std::vector<std::string>> ListStrategy();
    std::promise<std::string> TestStrategy(const std::string& host);

    std::promise<void> FlushCgi();
    std::promise<void> FlushDns();
    std::promise<void> FlushStrategy();

    std::promise<bool>  SetServer(const std::string& server);
    std::promise<std::string>  GetServer();
    std::promise<bool> Login(const std::string& token, const std::string& source);
    std::promise<std::string> GetStatus();
};

#endif
