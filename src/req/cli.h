#ifndef CLI__
#define CLI__

#include "requester.h"
#include "misc/net.h"
#include "prot/rpc.h"

#include <errno.h>
#include <unistd.h>
#include <sys/un.h>

class Cli:public Requester, public SproxyServer {
protected:
    void ReadHE(buff_block& bb);
    void Error(int ret, int code);

    virtual void deleteLater(uint32_t errcode) override;
    virtual void send(const char* data, size_t len) override;
public:
    explicit Cli(int fd, const sockaddr_storage* addr);
    ~Cli();

    virtual void response(void*, HttpRes* res) override { delete res;};
    virtual void dump_stat(Dumper dp, void* param) override;



    virtual bool AddStrategy(const std::string& host, const std::string& strategy, const std::string& ext) override;
    virtual bool DelStrategy(const std::string& host) override;
    virtual std::vector<std::string> ListStrategy() override;
    virtual std::string TestStrategy(const std::string& host) override;

    virtual void FlushCgi() override;
    virtual void FlushDns() override;
    virtual void FlushStrategy() override;

    virtual bool SetServer(const std::string& server) override;
    virtual std::string GetServer() override;
    virtual bool Login(const std::string& token, const std::string& source) override;
    virtual std::string GetStatus() override;
};

class Cli_server: public Ep {
    virtual void defaultHE(RW_EVENT events) {
        if (!!(events & RW_EVENT::ERROR)) {
            LOGE("Cli server: %d\n", checkSocket(__PRETTY_FUNCTION__));
            return;
        }
        if (!!(events & RW_EVENT::READ)) {
            int clsk;
            struct sockaddr_storage myaddr;
            socklen_t temp = sizeof(myaddr);
#ifdef SOCK_CLOEXEC
            if ((clsk = accept4(getFd(), (struct sockaddr *)&myaddr, &temp, SOCK_CLOEXEC)) < 0) {
#else
            if ((clsk = accept(getFd(), (struct sockaddr *)&myaddr, &temp)) < 0) {
#endif
                LOGE("accept error:%s\n", strerror(errno));
                return;
            }

            SetUnixOptions(clsk, &myaddr);
            new Cli(clsk, &myaddr);
        } else {
            LOGE("unknown error\n");
            return;
        }
    }
public:
    virtual ~Cli_server() = default;
    Cli_server(int fd): Ep(fd) {
        setEvents(RW_EVENT::READ);
        handleEvent = (void (Ep::*)(RW_EVENT))&Cli_server::defaultHE;
    }
};

#endif
