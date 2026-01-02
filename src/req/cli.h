#ifndef CLI__
#define CLI__

#include "requester.h"
#include "misc/net.h"
#include "prot/rpc.h"

#include <errno.h>
#include <unistd.h>
#include <sys/un.h>

class Cli:public Requester, public SproxyServer {
    uint64_t id;
protected:
    size_t ReadHE(const Buffer& bb);
    void Error(int ret, int code);

    virtual bool send(const char* data, size_t len) override;
    virtual std::shared_ptr<IMemRWerCallback> response(uint64_t) override;
public:
    explicit Cli(int fd, const sockaddr_storage* addr);
    virtual ~Cli() override;

    virtual bool AddStrategy(const std::string& host, const std::string& strategy, const std::string& ext) override;
    virtual bool DelStrategy(const std::string& host) override;
    virtual std::vector<std::string> DumpStrategy() override;
    virtual std::string TestStrategy(const std::string& host) override;

    virtual void FlushCgi() override;
    virtual void FlushDns() override;
    virtual void FlushStrategy() override;
    virtual bool FlushCert() override;

    virtual bool SetServer(const std::string& server) override;
    virtual std::string GetServer() override;
    virtual std::string Login(const std::string& token, const std::string& source) override;
    virtual std::string DumpStatus() override;
    virtual std::string DumpDns() override;
    virtual std::string DumpMemUsage() override;
    virtual std::string DumpHooker() override;
    virtual bool Debug(const std::string& module, bool enable) override;
    virtual bool killCon(const std::string& address) override;
    virtual bool HookerAdd(const std::string& hooker, const std::string& lib) override;
    virtual bool HookerDel(const std::string& hooker) override;
    virtual bool ListenAdd(const std::string& bind, const std::string& target) override;
    virtual bool ListenDel(uint64_t id) override;
    virtual std::vector<std::string> ListenList() override;

    virtual void dump_stat(Dumper dp, void* param) override;
    virtual void dump_usage(Dumper dp, void* param) override;
};

class Cli_server: public Ep {
    virtual void defaultHE(RW_EVENT events) {
        if (!!(events & RW_EVENT::ERROR)) {
            LOGE("Cli server: %d\n", checkSocket(__PRETTY_FUNCTION__));
            return;
        }
        if (!!(events & RW_EVENT::READ)) {
            int clsk;
            struct sockaddr_storage hisaddr;
            socklen_t temp = sizeof(hisaddr);
#ifdef SOCK_CLOEXEC
            if ((clsk = accept4(getFd(), (struct sockaddr *)&hisaddr, &temp, SOCK_CLOEXEC)) < 0) {
#else
            if ((clsk = accept(getFd(), (struct sockaddr *)&hisaddr, &temp)) < 0) {
#endif
                LOGE("accept error:%s\n", strerror(errno));
                return;
            }
            PadUnixPath(&hisaddr, temp);
            LOGD(DNET, "accept %d from %s\n", clsk, storage_ntoa(&hisaddr));
            SetUnixOptions(clsk, &hisaddr);
            new Cli(clsk, &hisaddr);
        } else {
            LOGE("unknown error\n");
            return;
        }
    }
public:
    virtual ~Cli_server() = default;
    explicit Cli_server(int fd): Ep(fd) {
        setEvents(RW_EVENT::READ);
        handleEvent = (void (Ep::*)(RW_EVENT))&Cli_server::defaultHE;
    }
};

#endif
