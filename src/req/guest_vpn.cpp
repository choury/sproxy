#include "guest_vpn.h"

#include "res/fdns.h"
#include "prot/netio.h"
#include "misc/config.h"
#include "misc/util.h"

#include <fstream>

#include <string.h>
#include <stdlib.h>
#include <inttypes.h>
#include <assert.h>


VpnKey::VpnKey(std::shared_ptr<const Ip> ip) {
    src = ip->getsrc();
    sockaddr_in* src_ = (sockaddr_in*)&src;
    dst = ip->getdst();
    sockaddr_in* dst_ = (sockaddr_in*)&dst;
    switch(ip->gettype()){
    case IPPROTO_TCP:
        protocol = Protocol::TCP;
        src_->sin_port = htons(ip->tcp->getsport());
        dst_->sin_port = htons(ip->tcp->getdport());
        break;
    case IPPROTO_UDP:
        protocol = Protocol::UDP;
        src_->sin_port = htons(ip->udp->getsport());
        dst_->sin_port = htons(ip->udp->getdport());
        break;
    case IPPROTO_ICMP:
        protocol = Protocol::ICMP;
        src_->sin_port = htons(ip->icmp->getid());
        dst_->sin_port = htons(ip->icmp->getid());
        break;
    case IPPROTO_ICMPV6:
        protocol = Protocol::ICMP;
        src_->sin_port = htons(ip->icmp6->getid());
        dst_->sin_port = htons(ip->icmp6->getid());
        break;
    default:
        protocol = Protocol::NONE;
        break;
    }
}

const VpnKey& VpnKey::reverse() {
    auto tmp  = dst;
    dst = src;
    src = tmp;
    return *this;
}

char VpnKey::version() const {
    if(dst.ss_family == AF_INET){
        return 4;
    }
    if(dst.ss_family == AF_INET6){
        return 6;
    }
    abort();
    return 0;
}


const char* VpnKey::getString(const char* sep) const{
    static char str[URLLIMIT];
    sockaddr_in* src_ = (sockaddr_in*)&src;
    sockaddr_in* dst_ = (sockaddr_in*)&dst;
    snprintf(str, sizeof(str), "<%s> (%s:%d %s %s:%d)",
             protstr(protocol), getRdns(src).c_str(), ntohs(src_->sin_port),
             sep, getRdns(dst).c_str(), ntohs(dst_->sin_port));
    return str;
}

bool operator<(sockaddr_storage a, sockaddr_storage b) {
    return memcmp(&a, &b, sizeof(sockaddr_storage)) < 0;
}

bool operator<(VpnKey a, VpnKey b) {
    return std::tie(a.protocol, a.src, a.dst) < std::tie(b.protocol, b.src, b.dst);
}

extern "C" void vpn_stop();

Vpn_server::Vpn_server(int fd) {
    rwer = new PacketRWer(fd, nullptr, [](int ret, int code){
        LOGE("vpn_server error: %d/%d\n", ret, code);
        vpn_stop();
    });
    rwer->SetReadCB([this](buff_block& bb){
        buffHE((const char*)bb.buff, bb.len);
        bb.offset = bb.len;
    });
    rwer->SetWriteCB([this](size_t){
        for(const auto& i: statusmap){
            i.second->writed();
        }
    });
}

Vpn_server::~Vpn_server(){
    statusmap.clear();
    delete rwer;
}

void Vpn_server::buffHE(const char* buff, size_t buflen) {
    //先解析
    auto pac = MakeIp(buff, buflen);
    if(pac == nullptr){
        return;
    }
    //打印ip/tcp/udp头
    //pac->dump();
    VpnKey key(pac);

    if(pac->gettype() == IPPROTO_ICMP && pac->icmp->gettype() ==  ICMP_UNREACH){
        auto icmp_pac = MakeIp(buff + pac->gethdrlen(), buflen-pac->gethdrlen());
        if(icmp_pac == nullptr){
            return;
        }
        key = VpnKey(icmp_pac).reverse();
    }
    if(pac->gettype() == IPPROTO_ICMPV6 && pac->icmp6->gettype() == ICMP6_DST_UNREACH){
        auto icmp6_pac = MakeIp(buff + pac->gethdrlen(), buflen-pac->gethdrlen());
        if(icmp6_pac == nullptr){
            return;
        }
        key = VpnKey(icmp6_pac).reverse();
    }

    if(statusmap.count(key) == 0){
        LOGD(DVPN, "new key for %s\n", key.getString("->"));
        statusmap[key] = new Guest_vpn(key, this);
    }
    statusmap.at(key)->packetHE(pac, buff, buflen);
}

int32_t Vpn_server::bufleft() {
    return 4*1024*1024 - rwer->wlength();
}

void Vpn_server::cleanKey(const VpnKey& key) {
    statusmap.erase(key);
}

Guest_vpn::Guest_vpn(const VpnKey& key, Vpn_server* server):Requester(std::make_shared<NullRWer>()), key(key), server(server) {
    memset(&status, 0, sizeof(status));
}


Guest_vpn::~Guest_vpn(){
    delete status.req;
    delete status.res;
    free(status.packet);
    free(status.protocol_info);
}

#if 0
const char * Guest_vpn::getProg() const{
    if(key.version() == 4){
        std::ifstream netfile;
        switch(key.protocol){
        case Protocol::TCP:
            netfile.open("/proc/net/tcp");
            break;
        case Protocol::UDP:
            netfile.open("/proc/net/udp");
            break;
        case Protocol::ICMP:
            netfile.open("/proc/net/icmp");
            break;
        default:
            return "<NONE>";
        }
        if(netfile.good()) {
            std::string line;
            std::getline(netfile, line); //drop the title line
            while (std::getline(netfile, line)) {
                uint32_t srcip, dstip;
                unsigned int srcport, dstport;
                int uid = 0;
                ino_t inode = 0;
                sscanf(line.c_str(), "%*d: %x:%x %x:%x %*x %*x:%*x %*d:%*x %*d %d %*d %lu",
                                    &srcip, &srcport, &dstip, &dstport, &uid, &inode);
                if(key.src.addr_in.sin_port == htons(srcport) &&(
                    key.protocol == Protocol::ICMP || key.protocol == Protocol::UDP ||
                    (key.dst.addr_in.sin_addr.s_addr == dstip &&
                    key.dst.addr_in.sin_port == htons(dstport))))
                {
#ifndef __ANDROID__
                    return findprogram(inode);
#else
                    return getPackageName(uid);
#endif
                }
            }

            netfile.clear();
            netfile.seekg(0);
            while (std::getline(netfile, line)) {
                //LOGD(DVPN, "%s\n", line.c_str());
            }
        }
        LOGD(DVPN, "Get src failed for %s %08X:%04X %08X:%04X\n",
                        protstr(key.protocol),
                        key.src.addr_in.sin_addr.s_addr, ntohs(key.src.addr_in.sin_port),
                        key.dst.addr_in.sin_addr.s_addr, ntohs(key.dst.addr_in.sin_port));
    }
    std::ifstream net6file;
    switch(key.protocol){
    case Protocol::TCP:
        net6file.open("/proc/net/tcp6");
        break;
    case Protocol::UDP:
        net6file.open("/proc/net/udp6");
        break;
    case Protocol::ICMP:
        net6file.open("/proc/net/icmp6");
        break;
    default:
        return "<NONE>";
    }
    if(net6file.good()) {
        std::string line;
        std::getline(net6file, line); //drop the title line
        in6_addr dst;
        if(key.version() == 4){
            memcpy(dst.s6_addr, "\0\0\0\0\0\0\0\0\0\0\xff\xff", 12);
            dst.s6_addr32[3] = key.dst.addr_in.sin_addr.s_addr;
        }else{
            dst = key.dst.addr_in6.sin6_addr;
        }
        while (std::getline(net6file, line)) {
            unsigned int srcport, dstport;
            int uid = 0;
            ino_t inode = 0;
            uint32_t srcip[4], dstip[4];
            sscanf(line.c_str(), "%*d: %8X%8X%8X%8X:%X %8X%8X%8X%8X:%X %*x %*x:%*x %*d:%*x %*d %d %*d %lu",
                                srcip, srcip+1, srcip+2, srcip+3, &srcport,
                                dstip, dstip+1, dstip+2, dstip+3, &dstport, &uid, &inode);
            if(key.src.addr_in6.sin6_port == htons(srcport) &&(
                key.protocol == Protocol::ICMP || key.protocol == Protocol::UDP ||
                (memcmp(&dst, dstip, sizeof(dstip)) == 0 &&
                key.dst.addr_in6.sin6_port == htons(dstport))))
            {
#ifndef __ANDROID__
                return findprogram(inode);
#else
                return getPackageName(uid);
#endif
            }
        }
        net6file.clear();
        net6file.seekg(0);
        while (std::getline(net6file, line)) {
            //LOGD(DVPN, "%s\n", line.c_str());
        }
    }
    LOGD(DVPN, "Get src failed for %s %08X%08X%08X%08X:%04X %08X%08X%08X%08X:%04X\n",
                    protstr(key.protocol),
                    key.src.addr_in6.sin6_addr.s6_addr32[0],
                    key.src.addr_in6.sin6_addr.s6_addr32[1],
                    key.src.addr_in6.sin6_addr.s6_addr32[2],
                    key.src.addr_in6.sin6_addr.s6_addr32[3],
                    ntohs(key.src.addr_in6.sin6_port),
                    key.dst.addr_in6.sin6_addr.s6_addr32[0],
                    key.dst.addr_in6.sin6_addr.s6_addr32[1],
                    key.dst.addr_in6.sin6_addr.s6_addr32[2],
                    key.dst.addr_in6.sin6_addr.s6_addr32[3],
                    ntohs(key.dst.addr_in6.sin6_port));
    return "Unkown inode";
}
#endif

const char* Guest_vpn::generateUA() const {
    static char UA[URLLIMIT];
#ifndef __ANDROID__
    sprintf(UA, "Sproxy/%s (Build %s) (%s)", getVersion(), getBuildTime(), getDeviceInfo());
#else
    sprintf(UA, "Sproxy/%s (Build %s) (%s) App/%s", getVersion(), getBuildTime(), getDeviceName(), appVersion);
#endif
    return UA;
}


void Guest_vpn::packetHE(std::shared_ptr<const Ip> pac, const char* packet, size_t len){
    /* determine protocol */
    switch (pac->gettype()) {
    case IPPROTO_ICMP:
        return icmpHE(pac, packet, len);
    case IPPROTO_ICMPV6:
        return icmp6HE(pac, packet, len);
    case IPPROTO_TCP:
        return tcpHE(pac, packet, len);
    case IPPROTO_UDP:
        return udpHE(pac, packet, len);
    default:
        LOG("unknow protocol: %d\n", pac->gettype());
        return;
    }
}


void Guest_vpn::writed() {
    if(key.protocol == Protocol::TCP){
        return;
    }
    if((status.flags&HTTP_RES_COMPLETED) || (status.flags&HTTP_RES_EOF)){
        return;
    }
    if(status.res){
        status.res->more();
    }
}


void Guest_vpn::response(void*, HttpRes* res) {
    status.res = res;
    HttpLog(getsrc(), status.req, res);
    //创建回包
    if(memcmp(res->header->status, "200", 3) == 0){
        res->setHandler(std::bind(&Guest_vpn::handle, this, _1));
        if(key.protocol != Protocol::TCP){
            res->attach(std::bind(&Guest_vpn::Send_notcp, this, _1, _2),
                        std::bind(&Guest_vpn::bufleft, this));
            return;
        }else{
            res->attach((Channel::recv_const_t)std::bind(&Guest_vpn::Send_tcp, this, _1, _2),
                        std::bind(&Guest_vpn::bufleft, this));

        }
        TcpStatus* tcpStatus = (TcpStatus *)status.protocol_info;
        tcpStatus->status = TCP_ESTABLISHED;
        LOGD(DVPN, "write syn ack packet %s (%u - %u).\n",
             key.getString("<-"), tcpStatus->send_seq, tcpStatus->want_seq);
        auto pac_return = MakeIp(IPPROTO_TCP, &key.dst, &key.src);
        pac_return->tcp
            ->setseq(tcpStatus->send_seq++)
            ->setack(tcpStatus->want_seq)
            ->setwindowscale(tcpStatus->send_wscale)
            ->setwindow(status.req->cap() >> tcpStatus->send_wscale)
            ->setmss(Min(tcpStatus->mss, BUF_LEN))
            ->setflag(TH_ACK | TH_SYN);

        if(tcpStatus->options & (1<<TCPOPT_SACK_PERMITTED)){
            pac_return->tcp->setsack(nullptr);
        }

        tcpStatus->send_ack = tcpStatus->want_seq;
        server->sendPkg(pac_return, (const void*)nullptr, 0);
        return;
    }else if(res->header->status[0] == '4'){
        //site is blocked or bad request, return rst for tcp, icmp for udp
        if(key.protocol == Protocol::TCP){
            TcpStatus* tcpStatus = (TcpStatus*)status.protocol_info;
            assert(tcpStatus);
            LOGD(DVPN, "write rst packet\n");
            auto pac_return = MakeIp(IPPROTO_TCP, &key.dst, &key.src);
            pac_return->tcp
                ->setseq(tcpStatus->send_seq)
                ->setack(tcpStatus->want_seq)
                ->setwindow(server->bufleft() >> tcpStatus->send_wscale)
                ->setflag(TH_RST | TH_ACK);

            tcpStatus->send_ack = tcpStatus->want_seq;
            server->sendPkg(pac_return, (const void *)nullptr, 0);
        }
        if(key.protocol == Protocol::UDP){
            std::shared_ptr<Ip> pac_return;
            if(key.version() == 4){
                LOGD(DVPN, "write icmp unrach packet\n");
                pac_return = MakeIp(IPPROTO_ICMP, &key.dst, &key.src);
                pac_return->icmp
                    ->settype(ICMP_UNREACH)
                    ->setcode(ICMP_UNREACH_HOST);
            }else{
                LOGD(DVPN, "write icmp6 unrach packet\n");
                pac_return = MakeIp(IPPROTO_ICMPV6, &key.dst, &key.src);
                pac_return->icmp6
                    ->settype(ICMP6_DST_UNREACH)
                    ->setcode(ICMP6_DST_UNREACH_ADDR);
            }
            server->sendPkg(pac_return, (const void*)status.packet, status.packet_len);
        }
    }else if(res->header->status[0] == '5'){
        if(key.protocol == Protocol::TCP || key.protocol == Protocol::UDP) {
            std::shared_ptr<Ip> pac_return;
            if (key.version() == 4) {
                LOGD(DVPN, "write icmp unreachable msg: %s\n", key.getString("<-"));
                pac_return = MakeIp(IPPROTO_ICMP, &key.dst, &key.src);
                pac_return->icmp
                        ->settype(ICMP_UNREACH)
                        ->setcode(ICMP_UNREACH_PORT);
            } else {
                LOGD(DVPN, "write icmpv6 unreachable msg: %s\n", key.getString("<-"));
                pac_return = MakeIp(IPPROTO_ICMPV6, &key.dst, &key.src);
                pac_return->icmp6
                        ->settype(ICMP6_DST_UNREACH)
                        ->setcode(ICMP6_DST_UNREACH_ADDR);
            }
            server->sendPkg(pac_return, (const void *) status.packet, status.packet_len);
        }else{
            LOGD(DVPN, "clean this connection\n");
        }
    }else{
        LOGE("unknown response\n");
    }
    deleteLater(PEER_LOST_ERR);
}

void Guest_vpn::tcp_ack() {
    if(status.protocol_info == nullptr){
        return;
    }
    TcpStatus* tcpStatus = (TcpStatus*)status.protocol_info;
    if(tcpStatus->status != TCP_ESTABLISHED){
        return;
    }
    assert(noafter(tcpStatus->send_ack, tcpStatus->want_seq));
    if(tcpStatus->send_ack == tcpStatus->want_seq){
        return;
    }
    assert(status.req);
    int buflen = status.req->cap();
    if(buflen < 0) buflen = 0;
    //创建回包
    auto pac_return = MakeIp(IPPROTO_TCP, &key.dst, &key.src);
    pac_return->tcp
        ->setseq(tcpStatus->send_seq)
        ->setack(tcpStatus->want_seq)
        ->setwindow(buflen >> tcpStatus->send_wscale)
        ->setflag(TH_ACK);

    tcpStatus->send_ack = tcpStatus->want_seq;
    LOGD(DVPN, "%s (%u - %u) ack\n", key.getString("<-"), tcpStatus->send_seq, tcpStatus->want_seq);
    server->sendPkg(pac_return, (const void*)nullptr, 0);
}


void Guest_vpn::tcpHE(std::shared_ptr<const Ip> pac, const char* packet, size_t len) {
    uint32_t seq = pac->tcp->getseq();
    uint32_t ack = pac->tcp->getack();
    uint8_t flag = pac->tcp->getflag();
    size_t datalen = len - pac->gethdrlen();

    LOGD(DVPN, "%s (%u - %u) flag: %d size:%zu\n",
         key.getString("->"), seq, ack, flag, datalen);
    if(flag & TH_SYN){
        if(status.req) {
            LOGD(DVPN, "drop dup syn packet\n");
            return;
        }

        //create a http proxy request
        char buff[HEADLENLIMIT];
        int headlen = sprintf(buff,
                        "CONNECT %s:%d" CRLF
                        "User-Agent: %s" CRLF
                        "Sproxy-vpn: %d" CRLF CRLF,
                getRdns(pac->getdst()).c_str(),
                pac->tcp->getdport(),
                generateUA(),
                pac->tcp->getsport());

        HttpReqHeader* header = UnpackHttpReq(buff, headlen);
        TcpStatus* tcpStatus = (TcpStatus*)malloc(sizeof(TcpStatus));
        tcpStatus->send_seq = getmtime();
        tcpStatus->acked = tcpStatus->send_seq;
        tcpStatus->send_ack = 0;
        tcpStatus->want_seq = seq+1;
        tcpStatus->window = pac->tcp->getwindow();
        tcpStatus->options = pac->tcp->getoptions();
        tcpStatus->mss = pac->tcp->getmss();
        tcpStatus->status = TCP_SYN_RECV;
        if(tcpStatus->options & (1u<<TCPOPT_WINDOW)){
            tcpStatus->recv_wscale = pac->tcp->getwindowscale();
            tcpStatus->send_wscale = VPN_TCP_WSCALE;
        }else{
            tcpStatus->recv_wscale = 0;
            tcpStatus->send_wscale = 0;
        }
        status.protocol_info = tcpStatus;
        status.packet = (char *)memdup(packet, pac->gethdrlen());
        status.packet_len = (uint16_t)pac->gethdrlen();

        status.req = new HttpReq(header, std::bind(&Guest_vpn::response, this, nullptr, _1), [this]{tcp_ack();});
        distribute(status.req, this);
        return;
    }
    if(flag & TH_RST){//rst包，不用回包，直接断开
        LOGD(DVPN, "get rst, checking key\n");
        deleteLater(PEER_LOST_ERR);
        return;
    }
    auto pac_return = MakeIp(IPPROTO_TCP, &key.dst, &key.src);
    if(status.protocol_info == nullptr){     //如果不存在，直接发送rst断开
        pac_return->tcp
            ->setseq(ack)
            ->setack(seq)
            ->setwindow(0)
            ->setflag(TH_ACK | TH_RST);

        LOGD(DVPN, "write rst to break no exists connection.\n");
        server->sendPkg(pac_return, (const void*)nullptr, 0);
        deleteLater(PEER_LOST_ERR);
        return;
    }

    TcpStatus* tcpStatus = (TcpStatus*)status.protocol_info;
    if(seq != tcpStatus->want_seq){
        LOGD(DVPN, "get keepalive pkt or unwanted pkt, reply ack(%u).\n", tcpStatus->want_seq);
        rwer->addjob(std::bind(&Guest_vpn::tcp_ack, this), 0, JOB_FLAGS_AUTORELEASE);
        return;
    }

    tcpStatus->window = pac->tcp->getwindow();
    //下面处理数据
    if(datalen > 0 && status.req){
        if(status.req->cap() < (int)datalen){
            LOGE("%s: responser buff is not enough, drop packet %u\n", key.getString("->"), seq);
            return;
        }else{
            const char* data = packet + pac->gethdrlen();
            status.req->send(data, datalen);
            tcpStatus->want_seq += datalen;
        }
    }

    if(flag & TH_FIN){ //fin包，回ack包
        LOGD(DVPN, "get fin, send ack back\n");
        status.flags &= HTTP_REQ_EOF;
        tcpStatus->want_seq++;
        //创建回包
        pac_return->tcp
            ->setseq(tcpStatus->send_seq)
            ->setack(tcpStatus->want_seq)
            ->setwindow(server->bufleft() >> tcpStatus->send_wscale)
            ->setflag(TH_ACK);

        server->sendPkg(pac_return, (const void*)nullptr, 0);
        switch(tcpStatus->status){
        case TCP_ESTABLISHED:
            tcpStatus->status = TCP_CLOSE_WAIT;
            status.req->trigger(Channel::CHANNEL_SHUTDOWN);
            break;
        case TCP_FIN_WAIT1:
            tcpStatus->status = TCP_CLOSING;
            if((status.flags & HTTP_CLOSED_F)  == 0) {
                status.req->trigger(Channel::CHANNEL_CLOSED);
            }
            status.flags |= HTTP_CLOSED_F;
            break;
        case TCP_FIN_WAIT2:
            tcpStatus->status = TCP_TIME_WAIT;
            if((status.flags & HTTP_CLOSED_F) == 0) {
                status.req->trigger(Channel::CHANNEL_CLOSED);
            }
            status.flags |= HTTP_CLOSED_F;
            aged_job = rwer->updatejob(aged_job, std::bind(&Guest_vpn::aged, this), 1000);
            return;
        case TCP_TIME_WAIT:
            break;
        default:
            LOGE("unexpected status: %d\n", tcpStatus->status);
        }
    }

    if(flag & TH_ACK){
        if(after(ack, tcpStatus->acked)){
            tcpStatus->acked = ack;
        }
        switch(tcpStatus->status){
        case TCP_ESTABLISHED:
            status.res->more();
            break;
        case TCP_FIN_WAIT1:
            tcpStatus->status = TCP_FIN_WAIT2;
            break;
        case TCP_CLOSING:
            tcpStatus->status = TCP_TIME_WAIT;
            aged_job = rwer->updatejob(aged_job, std::bind(&Guest_vpn::aged, this), 1000);
            break;
        case TCP_LAST_ACK:
            LOGD(DVPN, "clean closed connection\n");
            deleteLater(PEER_LOST_ERR);
            return;
        case TCP_CLOSE_WAIT:
            //fall through
        case TCP_FIN_WAIT2:
            //fall through
        case TCP_TIME_WAIT:
            return;
        default:
            LOGE("unexpected status: %d\n", tcpStatus->status);
        }
    }
}

void Guest_vpn::udpHE(std::shared_ptr<const Ip> pac, const char* packet, size_t len) {
    const char* data = packet + pac->gethdrlen();
    size_t datalen = len - pac->gethdrlen();
    if(status.req){
        LOGD(DVPN, "%s size: %zu\n", key.getString("->"), datalen);
        aged_job = rwer->updatejob(aged_job, std::bind(&Guest_vpn::aged, this), 300000);
        if(status.req->cap() < (int)datalen){
            LOGE("responser buff is not enough, drop packet\n");
        }else{
            status.req->send(data, datalen);
        }
    }else{
        LOGD(DVPN, "%s (N) size: %zu\n", key.getString("->"), datalen);
        //create a http proxy request
        char buff[HEADLENLIMIT];
        int headlen = sprintf(buff,
                        "SEND %s:%d" CRLF
                        "User-Agent: %s" CRLF
                        "Sproxy_vpn: %d" CRLF CRLF,
                getRdns(pac->getdst()).c_str(),
                pac->udp->getdport(),
                generateUA(),
                pac->udp->getsport());


        HttpReqHeader* header = UnpackHttpReq(buff, headlen);
        status.req = new HttpReq(header, std::bind(&Guest_vpn::response, this, nullptr, _1), []{});
        status.packet = (char *)memdup(packet, pac->gethdrlen());
        status.packet_len = (uint16_t)pac->gethdrlen();
        aged_job = rwer->updatejob(aged_job, std::bind(&Guest_vpn::aged, this), 60000);
        status.req->send(data, datalen);
        if(pac->udp->getdport() == 53){
            (new FDns())->request(status.req, this);
        }else{
            distribute(status.req, this);
        }
    }
}

void Guest_vpn::icmpHE(std::shared_ptr<const Ip> pac, const char* packet, size_t len) {
    switch(pac->icmp->gettype()){
    case ICMP_ECHO:{
        aged_job = rwer->updatejob(aged_job, std::bind(&Guest_vpn::aged, this), 30000);
        if(status.req){
            LOGD(DVPN, "%s (ping) (%u - %u) size: %zd\n",
                 key.getString("->"), pac->icmp->getid(), pac->icmp->getseq(), len - pac->gethdrlen());
            assert(status.req->cap() >0);
            IcmpStatus* icmpStatus = (IcmpStatus *)status.protocol_info;
            assert(icmpStatus->id == pac->icmp->getid());
            icmpStatus->seq = pac->icmp->getseq();
            status.req->send(packet + pac->gethdrlen(), len - pac->gethdrlen());
        }else{
            LOGD(DVPN, "%s (ping/N) (%u - %u) size: %zd\n",
                 key.getString("->"), pac->icmp->getid(), pac->icmp->getseq(), len - pac->gethdrlen());
            char buff[HEADLENLIMIT];
            int headlen = sprintf(buff,
                            "PING %s:%d" CRLF
                            "User-Agent: %s" CRLF
                            "Sproxy_vpn: %d" CRLF CRLF,
                    getRdns(pac->getdst()).c_str(),
                    pac->icmp->getid(),
                    generateUA(),
                    pac->icmp->getid());
            HttpReqHeader* header = UnpackHttpReq(buff, headlen);
            IcmpStatus *icmpStatus = (IcmpStatus*)malloc(sizeof(IcmpStatus));
            icmpStatus->id = pac->icmp->getid();
            icmpStatus->seq = pac->icmp->getseq();
            status.protocol_info = icmpStatus;
            status.req = new HttpReq(header, std::bind(&Guest_vpn::response, this, nullptr, _1), []{});
            status.req->send(packet + pac->gethdrlen(), len - pac->gethdrlen());
            distribute(status.req, this);
        }
    }break;
    case ICMP_UNREACH:{
        auto icmp_pac = MakeIp(packet+pac->gethdrlen(), len-pac->gethdrlen());

        uint8_t type = icmp_pac->gettype();
        
        LOGD(DVPN, "Get unreach icmp packet %s type: %d\n", key.getString("->"), type);
        if(type != IPPROTO_TCP && type != IPPROTO_UDP){
            LOGE("Get unreach icmp packet unkown protocol:%d\n", type);
            return;
        }
        LOGD(DVPN, "clean this connection\n");
        deleteLater(PEER_LOST_ERR);
    } break;
    default:
        LOGD(DVPN, "Get icmp %s type:%d code: %d, ignore it.\n",
             key.getString("->"),
             pac->icmp->gettype(),
             pac->icmp->getcode());
        deleteLater(PEER_LOST_ERR);
        break;
    }
}


void Guest_vpn::icmp6HE(std::shared_ptr<const Ip> pac, const char* packet, size_t len) {
    switch(pac->icmp6->gettype()){
    case ICMP6_ECHO_REQUEST:{
        aged_job = rwer->updatejob(aged_job, std::bind(&Guest_vpn::aged, this), 30000);
        if(status.req){
            LOGD(DVPN, "%s (ping6) (%u - %u) size: %zd\n",
                 key.getString("->"), pac->icmp6->getid(), pac->icmp6->getseq(), len - pac->gethdrlen());
            assert(status.req->cap()>0);
            IcmpStatus* icmpStatus = (IcmpStatus *)status.protocol_info;
            assert(icmpStatus->id == pac->icmp6->getid());
            icmpStatus->seq = pac->icmp6->getseq();
            status.req->send(packet + pac->gethdrlen(), len - pac->gethdrlen());
        }else{
            LOGD(DVPN, "%s (ping6/N) (%u - %u) size: %zd\n",
                 key.getString("->"), pac->icmp6->getid(), pac->icmp6->getseq(), len - pac->gethdrlen());
            char buff[HEADLENLIMIT];
            int headlen = sprintf(buff,
                            "PING %s:%d" CRLF
                            "User-Agent: %s" CRLF
                            "Sproxy_vpn: %d" CRLF CRLF,
                    getRdns(pac->getdst()).c_str(),
                    pac->icmp6->getid(),
                    generateUA(),
                    pac->icmp6->getid());
            HttpReqHeader* header = UnpackHttpReq(buff, headlen);

            IcmpStatus *icmpStatus = (IcmpStatus*)malloc(sizeof(IcmpStatus));
            icmpStatus->id = pac->icmp6->getid();
            icmpStatus->seq = pac->icmp6->getseq();
            status.protocol_info = icmpStatus;
            status.req = new HttpReq(header, std::bind(&Guest_vpn::response, this, nullptr, _1), []{});
            status.req->send(packet + pac->gethdrlen(), len - pac->gethdrlen());
            distribute(status.req, this);
        }
    }break;
    case ICMP6_DST_UNREACH:{
        auto icmp_pac = MakeIp(packet+pac->gethdrlen(), len-pac->gethdrlen());

        uint8_t type = icmp_pac->gettype();

        LOGD(DVPN, "Get unreach icmp6 packet %s type: %d\n", key.getString("->"), type);
        if(type != IPPROTO_TCP && type != IPPROTO_UDP){
            LOGE("Get unreach icmp packet unkown protocol:%d\n", type);
            return;
        }
        LOGD(DVPN, "clean this connection\n");
        deleteLater(PEER_LOST_ERR);
    } break;
    default:
        LOGD(DVPN, "Get icmp6 %s type:%d code: %d, ignore it.\n",
             key.getString("->"),
             pac->icmp6->gettype(),
             pac->icmp6->getcode());
        deleteLater(PEER_LOST_ERR);
        break;
    }
}

int32_t Guest_vpn::bufleft() {
    if(key.protocol == Protocol::TCP){
        TcpStatus* tcpStatus = (TcpStatus*)status.protocol_info;
        if(tcpStatus->status == TCP_SYN_RECV){
            return 0;
        }
        assert(nobefore(tcpStatus->send_seq, tcpStatus->acked));
        return (int32_t)(tcpStatus->window << tcpStatus->recv_wscale) - (int32_t)(tcpStatus->send_seq - tcpStatus->acked);
    }
    if(key.protocol == Protocol::ICMP){
        return BUF_LEN;
    }
    //udp
    return server->bufleft();
}

void Guest_vpn::Send_tcp(const void* buff, size_t size) {
    if (size == 0) {
        status.flags |= HTTP_RES_COMPLETED;
        return;
    }
    assert(key.protocol == Protocol::TCP);
    TcpStatus *tcpStatus = (TcpStatus *) status.protocol_info;
    assert((tcpStatus->window << tcpStatus->recv_wscale) -
           (tcpStatus->send_seq - tcpStatus->acked) >= size);
    size_t sendlen = size;
    if (size > tcpStatus->mss) {
        LOGD(DVPN, "%s: mss smaller than send size (%zu/%u)!\n", key.getString("<-"), size, tcpStatus->mss);
        sendlen = tcpStatus->mss;
    }
    LOGD(DVPN, "%s (%u - %u) size: %zu\n",
         key.getString("<-"), tcpStatus->send_seq, tcpStatus->want_seq, sendlen);
    auto pac_return = MakeIp(IPPROTO_TCP, &key.dst, &key.src);
    pac_return->tcp
            ->setseq(tcpStatus->send_seq)
            ->setack(tcpStatus->want_seq)
            ->setwindow(status.req->cap() >> tcpStatus->send_wscale)
            ->setflag(TH_ACK | TH_PUSH);

    server->sendPkg(pac_return, buff, sendlen);
    tcpStatus->send_seq += sendlen;
    tcpStatus->send_ack = tcpStatus->want_seq;
    if (size > sendlen) {
        Send_tcp((const char *) buff + sendlen, size - sendlen);
    }
}

void Guest_vpn::Send_notcp(void* buff, size_t size) {
    if(size == 0){
        status.flags |= HTTP_RES_COMPLETED;
        return;
    }
    if(key.protocol == Protocol::UDP){
        LOGD(DVPN, "%s size: %zu\n", key.getString("<-"), size);
        auto pac_return = MakeIp(IPPROTO_UDP, &key.dst, &key.src);

        server->sendPkg(pac_return, buff, size);
        aged_job = rwer->updatejob(aged_job, std::bind(&Guest_vpn::aged, this), 300000);
        return;
    }
    if(key.protocol == Protocol::ICMP){
        IcmpStatus* icmpStatus = (IcmpStatus*)status.protocol_info;
        std::shared_ptr<Ip> pac_return;
        if(key.version() == 4){
            pac_return = MakeIp(IPPROTO_ICMP, &key.dst, &key.src);
            LOGD(DVPN, "%s (ping) (%u - %u) size: %zu\n",
                key.getString("<-"), icmpStatus->id, icmpStatus->seq, size - sizeof(icmphdr));
            pac_return->icmp
                ->settype(ICMP_ECHOREPLY)
                ->setcode(0)
                ->setid(icmpStatus->id)
                ->setseq(icmpStatus->seq);

            server->sendPkg(pac_return, buff, size);
        }else{
            pac_return = MakeIp(IPPROTO_ICMPV6, &key.dst, &key.src);
            LOGD(DVPN, "%s (ping6) (%u - %u) size: %zu\n",
                key.getString("<-"), icmpStatus->id, icmpStatus->seq, size - sizeof(icmphdr));
            pac_return->icmp6
                ->settype(ICMP6_ECHO_REPLY)
                ->setcode(0)
                ->setid(icmpStatus->id)
                ->setseq(icmpStatus->seq);

            server->sendPkg(pac_return, buff, size);
        }
        aged_job = rwer->updatejob(aged_job, std::bind(&Guest_vpn::aged, this), 30000);
        return;
    }
    abort();
}

void Guest_vpn::deleteLater(uint32_t errcode) {
    LOGD(DVPN, "%s deleteLater: %u\n", key.getString("<-"), errcode);
    if ((status.flags & HTTP_CLOSED_F) == 0 && status.req) {
        status.req->trigger(errcode ? Channel::CHANNEL_ABORT : Channel::CHANNEL_CLOSED);
    }
    status.flags |= HTTP_CLOSED_F;
    server->cleanKey(key);
    Server::deleteLater(errcode);
}

void Guest_vpn::handle(Channel::signal s) {
    switch(s){
    case Channel::CHANNEL_CLOSED:
        // release connection on last ack or aged
        status.flags |= HTTP_CLOSED_F;
        // Fall-through
    case Channel::CHANNEL_SHUTDOWN:
        status.flags |= HTTP_RES_EOF;
        if(key.protocol == Protocol::TCP) {
            assert(key.protocol == Protocol::TCP);
            TcpStatus *tcpStatus = (TcpStatus *) status.protocol_info;
            LOGD(DVPN, "write fin packet\n");
            auto pac_return = MakeIp(IPPROTO_TCP, &key.dst, &key.src);
            pac_return->tcp
                    ->setseq(tcpStatus->send_seq++)
                    ->setack(tcpStatus->want_seq)
                    ->setwindow(bufleft() >> tcpStatus->send_wscale)
                    ->setflag(TH_FIN | TH_ACK);

            server->sendPkg(pac_return, (const void *) nullptr, 0);
            switch (tcpStatus->status) {
                case TCP_ESTABLISHED:
                    tcpStatus->status = TCP_FIN_WAIT1;
                    break;
                case TCP_CLOSE_WAIT:
                    tcpStatus->status = TCP_LAST_ACK;
                    break;
            }
        }else{
            aged_job = rwer->updatejob(aged_job, std::bind(&Guest_vpn::aged, this), 0);
        }
        break;
    case Channel::CHANNEL_ABORT:
        if(key.protocol == Protocol::TCP){
            LOGD(DVPN, "write rst packet: %s\n",  key.getString("<-"));
            TcpStatus *tcpStatus = (TcpStatus *) status.protocol_info;
            auto pac_return = MakeIp(IPPROTO_TCP, &key.dst, &key.src);
            pac_return->tcp
                ->setseq(tcpStatus->send_seq)
                ->setack(tcpStatus->want_seq)
                ->setwindow(0)
                ->setflag(TH_RST | TH_ACK);

            server->sendPkg(pac_return, (const void*)nullptr, 0);
        }
        status.flags |= HTTP_CLOSED_F;
        deleteLater(PEER_LOST_ERR);
        break;
    }
}

void Guest_vpn::aged(){
    LOGD(DVPN, "%s aged.\n", key.getString("-"));
    deleteLater(PEER_LOST_ERR);
}

const char * Guest_vpn::getsrc(){
    static char src[INET6_ADDRSTRLEN + 6];
    sockaddr_in* src_ = (sockaddr_in*)&key.src;
    snprintf(src, sizeof(src), "%s:%d", getRdns(key.src).c_str(), ntohs(src_->sin_port));
    return src;
}


static const char* dump_vpnStatus(const VpnKey& key, void* protocol_info){
    if(protocol_info == nullptr){
        return "null";
    }
    static char buff[URLLIMIT];
    switch(key.protocol){
    case TCP:{
        TcpStatus* tcp = (TcpStatus*)protocol_info;
        sprintf(buff, " [window:%u, send_seq:%u, acked:%u, status:%u]",
                tcp->window << tcp->recv_wscale, tcp->send_seq, tcp->acked, tcp->status);
        break;
    }
    case ICMP:{
        IcmpStatus* icmp = (IcmpStatus *)protocol_info;
        sprintf(buff, " [id:%u, seq:%u]", icmp->id, icmp->seq);
    }
    default:
        break;
    }
    return buff;
}

void Guest_vpn::dump_stat(Dumper dp, void* param) {
    dp(param, "Guest_vpn %p, [%" PRIu32 "] %s\n",
        this,  status.req->header->request_id, key.getString("-"));
    dp(param, "  flags: %d status: %s\n", status.flags, dump_vpnStatus(key, status.protocol_info));
}
