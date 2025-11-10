#ifndef RPC_H__
#define RPC_H__

#include <json.h>

#include <queue>
#include <string>
#include <vector>
#include <functional>
#include <future>


class RpcBase{
protected:
    bool sendJson(json_object *content);
    virtual bool send(const char* data, size_t len) = 0;
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
protected:
    std::queue<std::function<void(json_object *)>> responser;
    virtual void call(const std::string& method, json_object* body, const std::function<void(json_object *)>& response);
public:
    virtual ssize_t DefaultProc(const char *buff, size_t len) override;
};

class SproxyServer:virtual public RpcServer {
protected:
    virtual json_object* call(std::string method, json_object *content) override;

    virtual bool AddStrategy(const std::string& host, const std::string& strategy, const std::string& ext) = 0;
    virtual bool DelStrategy(const std::string& host) = 0;
    virtual std::vector<std::string> DumpStrategy() = 0;
    virtual std::string TestStrategy(const std::string& host) = 0;

    virtual void FlushCgi() = 0;
    virtual void FlushDns() = 0;
    virtual void FlushStrategy() = 0;
    virtual bool FlushCert() = 0;

    virtual bool SetServer(const std::string& server) = 0;
    virtual bool Login(const std::string& token, const std::string& source) = 0;
    virtual bool Debug(const std::string& module, bool enable) = 0;
    virtual bool killCon(const std::string& address) = 0;
    virtual bool HookerAdd(const std::string& hooker, const std::string& lib) = 0;
    virtual bool HookerDel(const std::string& hooker) = 0;

    virtual std::string GetServer() = 0;
    virtual std::string DumpStatus() = 0;
    virtual std::string DumpDns() = 0;
    virtual std::string DumpMemUsage() = 0;
    virtual std::string DumpHooker() = 0;
    virtual bool ListenAdd(const std::string& bind, const std::string& target) = 0;
    virtual bool ListenDel(uint64_t id) = 0;
    virtual std::vector<std::string> ListenList() = 0;
};

class SproxyClient:virtual public RpcClient {
    int fd = 0;
    std::thread reader;
    void callback();
public:
    explicit SproxyClient(int fd);
    explicit SproxyClient(const char* sock);
    virtual ~SproxyClient();
    virtual bool send(const char* data, size_t len) override;

    std::promise<bool>  AddStrategy(const std::string& host, const std::string& strategy, const std::string& ext);
    std::promise<bool>  DelStrategy(const std::string& host);
    std::promise<std::vector<std::string>> DumpStrategy();
    std::promise<std::string> TestStrategy(const std::string& host);

    std::promise<void> FlushCgi();
    std::promise<void> FlushDns();
    std::promise<void> FlushStrategy();
    std::promise<bool> FlushCert();

    std::promise<bool>  SetServer(const std::string& server);
    std::promise<std::string>  GetServer();
    std::promise<std::string> DumpStatus();
    std::promise<std::string> DumpDns();
    std::promise<std::string> DumpMemUsage();
    std::promise<std::string> DumpHooker();
    std::promise<bool> Login(const std::string& token, const std::string& source);
    std::promise<bool> Debug(const std::string& module, bool enable);
    std::promise<bool> killCon(const std::string& address);
    std::promise<bool> HookerAdd(const std::string& hooker, const std::string& lib);
    std::promise<bool> HookerDel(const std::string& hooker);
    std::promise<bool> ListenAdd(const std::string& bind, const std::string& target);
    std::promise<bool> ListenDel(uint64_t id);
    std::promise<std::vector<std::string>> ListenList();
};

#endif
