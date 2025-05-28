#ifndef TUNIO_H__
#define TUNIO_H__
#include "prot/rwer.h"
#include "misc/index.h"
#include "ipbase.h"

struct VpnKey{
    Protocol    protocol;
    sockaddr_storage src;
    sockaddr_storage dst;
    explicit VpnKey(std::shared_ptr<const Ip> ip);
    const VpnKey& reverse();
};

bool operator<(const VpnKey& a, const VpnKey& b);

struct ITunCallback: public IRWerCallback {
    std::function<void(uint64_t, std::shared_ptr<const Ip>)> reqProc = [](uint64_t, std::shared_ptr<const Ip>){};
    std::function<void(uint64_t, uint32_t)> resetHanlder = [](uint64_t, uint32_t){};

    template<typename F>
    std::shared_ptr<ITunCallback> onReq(F&& func) {
        reqProc = std::forward<F>(func);
        return std::dynamic_pointer_cast<ITunCallback>(shared_from_this());
    }

    template<typename F>
    std::shared_ptr<ITunCallback> onReset(F&& func) {
        resetHanlder = std::forward<F>(func);
        return std::dynamic_pointer_cast<ITunCallback>(shared_from_this());
    }

    static std::shared_ptr<ITunCallback> create() {
        return std::make_shared<ITunCallback>();
    }
};

class TunRWer: public RWer{
    int pcap = -1;
    bool enable_offload;
    Index2<uint64_t, VpnKey, std::shared_ptr<IpStatus>> statusmap;
    uint64_t GetId(std::shared_ptr<const Ip> pac);
    std::shared_ptr<IpStatus> GetStatus(uint64_t id);
    void Clean(uint64_t id);
    void SendPkg(std::shared_ptr<const Ip> pac, const void* data, size_t len);
    void ErrProc(std::shared_ptr<const Ip> pac, uint32_t code);
    void ReqProc(std::shared_ptr<const Ip> pac);
    size_t DataProc(std::shared_ptr<const Ip> pac, Buffer&& bb);
    void AckProc(std::shared_ptr<const Ip> pac);

    //virtual ssize_t Write(const void* buff, size_t len, uint64_t id) override;
protected:
public:
    explicit TunRWer(int fd, bool enable_offload, std::shared_ptr<IRWerCallback> cb);
    virtual ~TunRWer() override;
    virtual void Send(Buffer&& bb) override;
    virtual void ReadData() override;
    virtual void ConsumeRData(uint64_t id) override;
    virtual size_t rlength(uint64_t id) override;
    virtual ssize_t cap(uint64_t id) override;
    virtual bool idle(uint64_t id) override;
    virtual Destination getSrc() const override {
        Destination src{};
        strcpy(src.hostname, "<tun>");
        return src;
    }
    virtual void dump_status(Dumper dp, void* param) override;
    virtual size_t mem_usage() override;

#define TUN_MSG_SYN     1   //send syn for tcp, none for others
#define TUN_MSG_BLOCK   2   //send rst for tcp, UNREACH_HOST/UNREACH_ADDR for udp
#define TUN_MSG_UNREACH 4   //send icmp UNREACH_PORT/UNREACH_NOPORT for udp and tcp
    void sendMsg(uint64_t id, uint32_t msg);
    //void setResetHandler(std::function<void(uint64_t id, uint32_t error)> func);
};


#endif
