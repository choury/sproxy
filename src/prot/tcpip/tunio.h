#ifndef TUNIO_H__
#define TUNIO_H__
#include "prot/rwer.h"
#include "misc/index.h"
#include "tcp.h"
#include "udp.h"
#include "icmp.h"

struct VpnKey{
    Protocol    protocol;
    sockaddr_storage src;
    sockaddr_storage dst;
    explicit VpnKey(std::shared_ptr<const Ip> ip);
    const VpnKey& reverse();
};

bool operator<(const VpnKey& a, const VpnKey& b);

class TunRWer: public RWer{
    char rbuff[BUF_LEN];
    uint64_t next_id = 1;
    int pcap = -1;
    Index2<uint64_t, VpnKey, std::shared_ptr<IpStatus>> statusmap;
    uint64_t GetId(std::shared_ptr<const Ip> pac);
    std::shared_ptr<IpStatus> GetStatus(uint64_t id);
    void Clean(uint64_t id);
    void SendPkg(std::shared_ptr<const Ip> pac, const void* data, size_t len);
    void ErrProc(std::shared_ptr<const Ip> pac, uint32_t code);
    void ReqProc(std::shared_ptr<const Ip> pac);
    size_t DataProc(std::shared_ptr<const Ip> pac, const void* data, size_t len);
    void AckProc(std::shared_ptr<const Ip> pac);

    virtual ssize_t Write(const void* buff, size_t len, uint64_t id) override;
protected:
    std::function<void(uint64_t, std::shared_ptr<const Ip>)> reqProc;
    std::function<void(uint64_t, uint32_t)> resetHanlder = [](uint64_t, uint32_t){};
public:
    explicit TunRWer(int fd,
                     std::function<void(uint64_t, std::shared_ptr<const Ip>)> reqProc,
                     std::function<void(int ret, int code)> errorCB);
    virtual ~TunRWer() override;
    virtual buff_iterator buffer_insert(buff_iterator where, Buffer&& bb) override;
    virtual void ReadData() override;
    virtual void ConsumeRData(uint64_t id) override;
    virtual size_t rlength(uint64_t id) override;
    virtual ssize_t cap(uint64_t id) override;
    virtual bool idle(uint64_t id) override;
    virtual const char* getPeer() override {return "tun-rwer";}
    virtual void dump_status(Dumper dp, void* param) override;
    virtual size_t mem_usage() override;

#define TUN_MSG_SYN     1   //send syn for tcp, none for others
#define TUN_MSG_BLOCK   2   //send rst for tcp, UNREACH_HOST/UNREACH_ADDR for udp
#define TUN_MSG_UNREACH 4   //send icmp UNREACH_PORT/UNREACH_NOPORT for udp and tcp
    void sendMsg(uint64_t id, uint32_t msg);
    void setResetHandler(std::function<void(uint64_t id, uint32_t error)> func);
};


#endif
