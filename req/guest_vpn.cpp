#include "guest_vpn.h"

#include "res/fdns.h"
#include "misc/simpleio.h"
#include "misc/job.h"
#include "misc/util.h"

#include <fstream>

#include <string.h>
#include <stdlib.h>
#include <assert.h>


VpnKey::VpnKey(std::shared_ptr<const Ip> ip) {
    src = ip->getsrc();
    dst = ip->getdst();
    switch(ip->gettype()){
    case IPPROTO_TCP:
        protocol = Protocol::TCP;
        src.addr_in.sin_port = htons(ip->tcp->getsport());
        dst.addr_in.sin_port = htons(ip->tcp->getdport());
        break;
    case IPPROTO_UDP:
        protocol = Protocol::UDP;
        src.addr_in.sin_port = htons(ip->udp->getsport());
        dst.addr_in.sin_port = htons(ip->udp->getdport());
        break;
    case IPPROTO_ICMP:
        protocol = Protocol::ICMP;
        src.addr_in.sin_port = htons(ip->icmp->getid());
        dst.addr_in.sin_port = htons(ip->icmp->getid());
        break;
    case IPPROTO_ICMPV6:
        protocol = Protocol::ICMP;
        src.addr_in.sin_port = htons(ip->icmp6->getid());
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
    if(dst.addr.sa_family == AF_INET){
        return 4;
    }
    if(dst.addr.sa_family == AF_INET6){
        return 6;
    }
    assert(0);
    return 0;
}


const char* VpnKey::getString(const char* sep) const{
    static char str[URLLIMIT];
    snprintf(str, sizeof(str), "<%s> (%s:%d %s %s:%d)",
             protstr(protocol), FDns::getRdns(src).c_str(), ntohs(src.addr_in.sin_port),
             sep, FDns::getRdns(dst).c_str(), ntohs(dst.addr_in.sin_port));
    return str;
}

bool operator<(const VpnKey a, const VpnKey b) {
    return memcmp(&a, &b, sizeof(VpnKey)) < 0;
}


VPN_nanny::VPN_nanny(int fd){
    rwer = new PacketRWer(fd, [](int ret, int code){
        LOGE("VPN_nanny error: %d/%d\n", ret, code);
    });
    rwer->SetReadCB([this](size_t len){
        const char* data = rwer->data();
        buffHE(data, len);
        rwer->consume(data, len);
    });
    rwer->SetWriteCB([this](size_t){
        for(auto i: statusmap){
            assert(!i.second.expired());
            auto vpn = i.second.lock();
            vpn->writed();
        }
    });
}

VPN_nanny::~VPN_nanny(){
    for(auto& i: statusmap){
        if(!i.second.expired())
            i.second.lock()->finish(VPN_AGED_ERR, 0);
    }
    statusmap.clear();
}

void VPN_nanny::buffHE(const char* buff, size_t buflen) {
    //先解析
    try{
        auto pac = MakeIp(buff, buflen);
        //打印ip/tcp/udp头
        //pac->dump();
        VpnKey key(pac);

        if(pac->gettype() == IPPROTO_ICMP && pac->icmp->gettype() ==  ICMP_UNREACH){
            auto icmp_pac = MakeIp(buff + pac->gethdrlen(), buflen-pac->gethdrlen());
            key = VpnKey(icmp_pac).reverse();
        }

        if(statusmap.count(key) == 0 || statusmap[key].expired()){
            statusmap[key] = std::dynamic_pointer_cast<Guest_vpn>((new Guest_vpn(key, this))->shared_from_this());
        }
        assert(!statusmap[key].expired());
        statusmap[key].lock()->packetHE(pac, buff, buflen);
    }catch(...){
        return;
    }
}

int32_t VPN_nanny::bufleft() {
    return 4*1024*1024 - rwer->wlength();
}


void VPN_nanny::cleanKey(const VpnKey& key) {
    statusmap.erase(key);
}


void VPN_nanny::dump_stat(Dumper dp, void* param) {
    dp(param, "vpn_nanny %p (%zd):\n", this, rwer->wlength());
}


Guest_vpn::Guest_vpn(const VpnKey& key, VPN_nanny* nanny):key(key), nanny(nanny) {
    res_index = nullptr;
    packet = nullptr;
    packet_len = 0;
    protocol_info = nullptr;
}


Guest_vpn::~Guest_vpn(){
    free(packet);
}



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
            dst = mapIpv4(key.dst.addr_in.sin_addr);
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
                (memcmp(&dst, dstip, 16) == 0 &&
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

const char* Guest_vpn::generateUA() const {
    static char UA[URLLIMIT];
#ifndef __ANDROID__
    sprintf(UA, "Sproxy/1.0 (%s) %s", getDeviceInfo(), getProg());
#else
    sprintf(UA, "Sproxy/%s (%s) %s", version, getDeviceName(), getProg());
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
    if(key.protocol != Protocol::TCP && !res_ptr.expired()){
        res_ptr.lock()->writedcb(res_index);
    }
}


void Guest_vpn::response(HttpResHeader* res) {
    VpnKey& key  = *(VpnKey *)res->index;
    LOGD(DVPN, "Get response (%s)\n", res->status);
    //创建回包
    if(memcmp(res->status, "200", 3) == 0){
        assert(!res_ptr.expired());
        assert(key.protocol == Protocol::TCP);
        TcpStatus* tcpStatus = (TcpStatus *)protocol_info;
        tcpStatus->status = TCP_ESTABLISHED;
        LOGD(DVPN, "write syn ack packet %s (%u - %u).\n",
             key.getString("<-"), tcpStatus->send_seq, tcpStatus->want_seq);
        auto pac_return = MakeIp(IPPROTO_TCP, &key.dst, &key.src);
        pac_return->tcp
            ->setseq(tcpStatus->send_seq++)
            ->setack(tcpStatus->want_seq)
            ->setwindowscale(tcpStatus->send_wscale)
            ->setwindow(res_ptr.lock()->bufleft(res_index) >> tcpStatus->send_wscale)
            ->setmss(BUF_LEN)
            ->setflag(TH_ACK | TH_SYN);

        nanny->sendPkg(pac_return, (const void*)nullptr, 0);
    }else if(res->status[0] == '4'){
        //site is blocked or bad request, return rst for tcp, icmp for udp
        if(key.protocol == Protocol::TCP){
            TcpStatus* tcpStatus = (TcpStatus*)protocol_info;
            assert(tcpStatus);
            LOGD(DVPN, "write rst packet\n");
            auto pac_return = MakeIp(IPPROTO_TCP, &key.dst, &key.src);
            pac_return->tcp
                ->setseq(tcpStatus->send_seq)
                ->setack(tcpStatus->want_seq)
                ->setwindow(bufleft(0) >> tcpStatus->send_wscale)
                ->setflag(TH_RST | TH_ACK);

            nanny->sendPkg(pac_return, (const void *)nullptr, 0);
        }
        if(key.protocol == Protocol::UDP){
            std::shared_ptr<Ip> pac_return;
            if(key.version() == 4){
                LOGD(DVPN, "write icmp unrach packet\n");
                pac_return = MakeIp(IPPROTO_ICMP, &key.dst, &key.src);
                pac_return->icmp
                    ->settype(ICMP_UNREACH)
                    ->setcode(ICMP_UNREACH_PORT);
            }else{
                LOGD(DVPN, "write icmp6 unrach packet\n");
                pac_return = MakeIp(IPPROTO_ICMPV6, &key.dst, &key.src);
                pac_return->icmp6
                    ->settype(ICMP6_DST_UNREACH)
                    ->setcode(ICMP6_DST_UNREACH_ADDR);
            }
            nanny->sendPkg(pac_return, (const void*)packet, packet_len);
        }
    }else{
        LOGD(DVPN, "ignore this response\n");
    }
    delete res;
    return;
}



void Guest_vpn::transfer(void* index, std::weak_ptr<Responser> res_ptr, void* res_index) {
    assert(index == &key);
    this->res_ptr = res_ptr;
    this->res_index = res_index;
}

int Guest_vpn::tcp_ack() {
    if(protocol_info == nullptr){
        return 0;
    }
    TcpStatus* tcpStatus = (TcpStatus*)protocol_info;
    if(tcpStatus->status != TCP_ESTABLISHED){
        return 0;
    }
    assert(!res_ptr.expired());
    int buflen = res_ptr.lock()->bufleft(res_index);
    if(buflen < 0) buflen = 0;
    //创建回包
    auto pac_return = MakeIp(IPPROTO_TCP, &key.dst, &key.src);
    pac_return->tcp
        ->setseq(tcpStatus->send_seq)
        ->setack(tcpStatus->want_seq)
        ->setwindow(buflen >> tcpStatus->send_wscale)
        ->setflag(TH_ACK);

    LOGD(DVPN, "%s (%u - %u) ack\n", key.getString("<-"), tcpStatus->send_seq, tcpStatus->want_seq);
    nanny->sendPkg(pac_return, (const void*)nullptr, 0);
    return 0;
}


void Guest_vpn::tcpHE(std::shared_ptr<const Ip> pac, const char* packet, size_t len) {
    uint32_t seq = pac->tcp->getseq();
    uint32_t ack = pac->tcp->getack();
    uint8_t flag = pac->tcp->getflag();
    
    size_t datalen = len - pac->gethdrlen();
    
    LOGD(DVPN, "%s (%u - %u) flag: %d size:%zu\n",
         key.getString("->"), seq, ack, flag, datalen);

    if(flag & TH_SYN){
        if(!res_ptr.expired()) {
            LOGD(DVPN, "drop dup syn packet\n");
            return;
        }

        //create a http proxy request
        char buff[HEADLENLIMIT];
        int headlen = sprintf(buff,   "CONNECT %s:%d" CRLF
                        "User-Agent: %s" CRLF
                        "Sproxy-vpn: %d" CRLF CRLF,
                FDns::getRdns(pac->getdst()).c_str(),
                pac->tcp->getdport(),
                generateUA(),
                pac->tcp->getsport());

        HttpReqHeader* req = new HttpReqHeader(buff, headlen, shared_from_this());
        req->index = &key;
        TcpStatus* tcpStatus = (TcpStatus*)malloc(sizeof(TcpStatus));
        tcpStatus->send_seq = getmtime();
        tcpStatus->send_acked = tcpStatus->send_seq;
        tcpStatus->want_seq = seq+1;
        tcpStatus->window = pac->tcp->getwindow();
        tcpStatus->options = pac->tcp->getoptions();
        tcpStatus->mss = pac->tcp->getmss();
        tcpStatus->recv_wscale = pac->tcp->getwindowscale();
        tcpStatus->status = TCP_SYN_RECV;
        if(tcpStatus->options & (1<<TCPOPT_WINDOW)){
            tcpStatus->send_wscale = VPN_TCP_WSCALE;
        }else{
            tcpStatus->send_wscale = 0;
        }
        this->packet = (char *)memdup(packet, pac->gethdrlen());
        this->packet_len = (uint16_t)pac->gethdrlen();
        this->protocol_info = tcpStatus;

        res_ptr = distribute(req, std::weak_ptr<Responser>());
        if(!res_ptr.expired()){
            res_index = res_ptr.lock()->request(std::move(req));
        }else{
            delete req;
            deleteLater(PEER_LOST_ERR);
        }
        return;
    }
    if(flag & TH_RST){//rst包，不用回包，直接断开
        LOGD(DVPN, "get rst, checking key\n");
        //check the map
        if(!res_ptr.expired()){
            res_ptr.lock()->finish(TCP_RESET_ERR, res_index);
        }
        deleteLater(PEER_LOST_ERR);
        return;
    }
    auto pac_return = MakeIp(IPPROTO_TCP, &key.dst, &key.src);
    if(protocol_info == nullptr){     //如果不存在，直接发送rst断开
        pac_return->tcp
            ->setseq(ack)
            ->setack(seq)
            ->setwindow(0)
            ->setflag(TH_ACK | TH_RST);

        LOGD(DVPN, "write rst to break no exists connection.\n");
        nanny->sendPkg(pac_return, (const void*)nullptr, 0);
        deleteLater(PEER_LOST_ERR);
        return;
    }

    TcpStatus* tcpStatus = (TcpStatus*)protocol_info;
    if(seq != tcpStatus->want_seq){
        LOGD(DVPN, "get keepalive pkt or unwanted pkt, reply ack(%u).\n", tcpStatus->want_seq);
        add_postjob(std::bind(&Guest_vpn::tcp_ack, this), nullptr);
        return;
    }

    //下面处理数据
    if(datalen > 0 && !res_ptr.expired()){//有数据，创建ack包
        int buflen = res_ptr.lock()->bufleft(res_index);
        if(buflen <= 0){
            LOGE("(%s): responser buff is full, drop packet %u\n", getProg(), seq);
            return;
        }else{
            const char* data = packet + pac->gethdrlen();
            res_ptr.lock()->Send(data, datalen, res_index);
            tcpStatus->want_seq += datalen;

            add_postjob(std::bind(&Guest_vpn::tcp_ack, this), nullptr);
        }
    }

    if(flag & TH_FIN){ //fin包，回ack包
        LOGD(DVPN, "get fin, send ack back\n");
        tcpStatus->want_seq++;
        //创建回包
        pac_return->tcp
            ->setseq(tcpStatus->send_seq)
            ->setack(tcpStatus->want_seq)
            ->setwindow(bufleft(0) >> tcpStatus->send_wscale)
            ->setflag(TH_ACK);

        nanny->sendPkg(pac_return, (const void*)nullptr, 0);
        switch(tcpStatus->status){
        case TCP_ESTABLISHED:
            res_ptr.lock()->finish(NOERROR, res_index);
            tcpStatus->status = TCP_CLOSE_WAIT;
            return;
        case TCP_FIN_WAIT1:
            tcpStatus->status = TCP_CLOSING;
            if(!res_ptr.expired()){
                res_ptr.lock()->finish(NOERROR | DISCONNECT_FLAG, res_index);
            }
            res_ptr = std::weak_ptr<Responser>();
            res_index = nullptr;
            break;
        case TCP_FIN_WAIT2:
            tcpStatus->status = TCP_TIME_WAIT;
            if(!res_ptr.expired()){
                res_ptr.lock()->finish(NOERROR | DISCONNECT_FLAG, res_index);
            }
            res_ptr = std::weak_ptr<Responser>();
            res_index = nullptr;
            add_delayjob(std::bind(&Guest_vpn::aged, this), nullptr, 1000);
            return;
        }
    }

    tcpStatus->window = pac->tcp->getwindow();
    if(flag & TH_ACK){
        if(after(ack, tcpStatus->send_acked)){
            tcpStatus->send_acked = ack;
        }
        switch(tcpStatus->status){
        case TCP_ESTABLISHED:
            res_ptr.lock()->writedcb(res_index);
            break;
        case TCP_FIN_WAIT1:
            tcpStatus->status = TCP_FIN_WAIT2;
            break;
        case TCP_CLOSING:
            tcpStatus->status = TCP_TIME_WAIT;
            add_delayjob(std::bind(&Guest_vpn::aged, this), nullptr, 1000);
            break;
        case TCP_LAST_ACK:
            LOGD(DVPN, "clean closed connection\n");
            if(!res_ptr.expired()){
                res_ptr.lock()->finish(NOERROR | DISCONNECT_FLAG, res_index);
            }
            deleteLater(PEER_LOST_ERR);
            return;
        }
    }
}

void Guest_vpn::udpHE(std::shared_ptr<const Ip> pac, const char* packet, size_t len) {
    const char* data = packet + pac->gethdrlen();
    size_t datalen = len - pac->gethdrlen();
    if(!res_ptr.expired()){
        LOGD(DVPN, "%s size: %zu\n", key.getString("->"), datalen);
        add_delayjob(std::bind(&Guest_vpn::aged, this), nullptr, 300000);
        if(res_ptr.lock()->bufleft(res_index) <= 0){
            LOGE("responser buff is full, drop packet\n");
        }else{
            res_ptr.lock()->Send(data, datalen, res_index);
        }
    }else{
        LOGD(DVPN, "%s (N) size: %zu\n", key.getString("->"), datalen);
        //create a http proxy request
        char buff[HEADLENLIMIT];
        int headlen = sprintf(buff,   "SEND %s:%d" CRLF
                        "User-Agent: %s" CRLF
                        "Sproxy_vpn: %d" CRLF CRLF,
                FDns::getRdns(pac->getdst()).c_str(),
                pac->udp->getdport(),
                generateUA(),
                pac->udp->getsport());

        HttpReqHeader* req = new HttpReqHeader(buff, headlen, shared_from_this());
        req->index = &key;
        this->packet = (char *)memdup(packet, pac->gethdrlen());
        this->packet_len = (uint16_t)pac->gethdrlen();

        auto responser_ptr = std::weak_ptr<Responser>();
        if(pac->udp->getdport() == 53){
            responser_ptr = FDns::getfdns();
        }else{
            responser_ptr = distribute(req, std::weak_ptr<Responser>());
        }
        if(!responser_ptr.expired()){
            add_delayjob(std::bind(&Guest_vpn::aged, this), nullptr, 60000);
            void* responser_index = responser_ptr.lock()->request(std::move(req));
            assert(responser_index);
            res_ptr = responser_ptr;
            res_index = responser_index;
            responser_ptr.lock()->Send(data, datalen, responser_index);
        }else{
            delete req;
            deleteLater(PEER_LOST_ERR);
        }
    }
}

void Guest_vpn::icmpHE(std::shared_ptr<const Ip> pac, const char* packet, size_t len) {
    switch(pac->icmp->gettype()){
    case ICMP_ECHO:{
        if(!res_ptr.expired()){
            LOGD(DVPN, "%s (ping) (%u - %u) size: %zd\n",
                 key.getString("->"), pac->icmp->getid(), pac->icmp->getseq(), len - pac->gethdrlen());
            add_delayjob(std::bind(&Guest_vpn::aged, this), nullptr, 5000);
            assert(res_ptr.lock()->bufleft(res_index)>0);
            IcmpStatus* icmpStatus = (IcmpStatus *)protocol_info;
            assert(icmpStatus->id == pac->icmp->getid());
            icmpStatus->seq = pac->icmp->getseq();
            res_ptr.lock()->Send(packet + pac->gethdrlen(), len - pac->gethdrlen(), res_index);
        }else{
            LOGD(DVPN, "%s (ping/N) (%u - %u) size: %zd\n",
                 key.getString("->"), pac->icmp->getid(), pac->icmp->getseq(), len - pac->gethdrlen());
            char buff[HEADLENLIMIT];
            int headlen = sprintf(buff,   "PING %s:%d" CRLF
                            "User-Agent: %s" CRLF
                            "Sproxy_vpn: %d" CRLF CRLF,
                    FDns::getRdns(pac->getdst()).c_str(),
                    pac->icmp->getid(),
                    generateUA(),
                    pac->icmp->getid());
            HttpReqHeader* req = new HttpReqHeader(buff, headlen, shared_from_this());
            req->index = &key;

            IcmpStatus *icmpStatus = (IcmpStatus*)malloc(sizeof(IcmpStatus));
            icmpStatus->id = pac->icmp->getid();
            icmpStatus->seq = pac->icmp->getseq();
            this->protocol_info = icmpStatus;
            res_ptr = distribute(req, std::weak_ptr<Responser>());
            if(!res_ptr.expired()){
                add_delayjob(std::bind(&Guest_vpn::aged, this), nullptr, 3000);
                res_index = res_ptr.lock()->request(std::move(req));
                res_ptr.lock()->Send(packet + pac->gethdrlen(), len - pac->gethdrlen(), res_index);
            }else{
                delete req;
                deleteLater(PEER_LOST_ERR);
            }
        }
    }break;
    case ICMP_UNREACH:{
        auto icmp_pac = MakeIp(packet+pac->gethdrlen(), len-pac->gethdrlen());

        uint8_t type = icmp_pac->gettype();
        
        LOGD(DVPN, "Get unreach icmp packet %s type: %d\n", key.getString("->"), type);
        if(type != IPPROTO_TCP && type != IPPROTO_UDP){
            LOGD(DVPN, "Get unreach icmp packet unkown protocol:%d\n", type);
            return;
        }
        if(!res_ptr.expired()) {
            LOGD(DVPN, "clean this connection\n");
            res_ptr.lock()->finish(PEER_LOST_ERR, res_index);
        }else{
            LOGD(DVPN, "connection doesn't exists, ignore it\n");
        }
        deleteLater(PEER_LOST_ERR);
    } break;
    default:
        LOGD(DVPN, "Get icmp type:%d code: %d, ignore it.\n",
             pac->icmp->gettype(),
             pac->icmp->getcode());
        break;
    }
}


void Guest_vpn::icmp6HE(std::shared_ptr<const Ip> pac, const char* packet, size_t len) {
    switch(pac->icmp6->gettype()){
    case ICMP6_ECHO_REQUEST:{
        if(!res_ptr.expired()){
            LOGD(DVPN, "%s (ping6) (%u - %u) size: %zd\n",
                 key.getString("->"), pac->icmp6->getid(), pac->icmp6->getseq(), len - pac->gethdrlen());
            add_delayjob(std::bind(&Guest_vpn::aged, this), nullptr, 5000);
            assert(res_ptr.lock()->bufleft(res_index)>0);
            IcmpStatus* icmpStatus = (IcmpStatus *)protocol_info;
            assert(icmpStatus->id == pac->icmp6->getid());
            icmpStatus->seq = pac->icmp6->getseq();
            res_ptr.lock()->Send(packet + pac->gethdrlen(), len - pac->gethdrlen(), res_index);
        }else{
            LOGD(DVPN, "%s (ping6/N) (%u - %u) size: %zd\n",
                 key.getString("->"), pac->icmp6->getid(), pac->icmp6->getseq(), len - pac->gethdrlen());
            char buff[HEADLENLIMIT];
            int headlen = sprintf(buff,   "PING %s:%d" CRLF
                            "User-Agent: %s" CRLF
                            "Sproxy_vpn: %d" CRLF CRLF,
                    FDns::getRdns(pac->getdst()).c_str(),
                    pac->icmp6->getid(),
                    generateUA(),
                    pac->icmp6->getid());
            HttpReqHeader* req = new HttpReqHeader(buff, headlen, shared_from_this());
            req->index = &key;

            IcmpStatus *icmpStatus = (IcmpStatus*)malloc(sizeof(IcmpStatus));
            icmpStatus->id = pac->icmp6->getid();
            icmpStatus->seq = pac->icmp6->getseq();
            this->protocol_info = icmpStatus;
            res_ptr = distribute(req, std::weak_ptr<Responser>());
            if(!res_ptr.expired()){
                add_delayjob(std::bind(&Guest_vpn::aged, this), nullptr, 3000);
                res_index = res_ptr.lock()->request(std::move(req));
                res_ptr.lock()->Send(packet + pac->gethdrlen(), len - pac->gethdrlen(), res_index);
            }else{
                delete req;
                deleteLater(PEER_LOST_ERR);
            }
        }
    }break;
    case ICMP6_DST_UNREACH:{
        auto icmp_pac = MakeIp(packet+pac->gethdrlen(), len-pac->gethdrlen());

        uint8_t type = icmp_pac->gettype();

        LOGD(DVPN, "Get unreach icmp6 packet %s type: %d\n", key.getString("->"), type);
        if(type != IPPROTO_TCP && type != IPPROTO_UDP){
            LOGD(DVPN, "Get unreach icmp packet unkown protocol:%d\n", type);
            return;
        }
        if(!res_ptr.expired()) {
            LOGD(DVPN, "clean this connection\n");
            res_ptr.lock()->finish(PEER_LOST_ERR, res_index);
        }else{
            LOGD(DVPN, "connection doesn't exists, ignore it\n");
        }
        deleteLater(PEER_LOST_ERR);
    } break;
    default:
        LOGD(DVPN, "Get icmp6 type:%d code: %d, ignore it.\n",
             pac->icmp6->gettype(),
             pac->icmp6->getcode());
        break;
    }
}


int32_t Guest_vpn::bufleft(void* index) {
    assert(index == nullptr || index == &key);
    if(index == nullptr){
        return nanny->bufleft();
    }
    if(key.protocol == Protocol::TCP){
        TcpStatus* tcpStatus = (TcpStatus*)protocol_info;
        assert(tcpStatus);
        return (tcpStatus->window << tcpStatus->recv_wscale) - (tcpStatus->send_seq - tcpStatus->send_acked);
    }
    if(key.protocol == Protocol::ICMP){
        return BUF_LEN;
    }
    //udp
    return nanny->bufleft();
}

void Guest_vpn::Send(void* buff, size_t size, void* index) {
    assert(index == &key);
    if(res_ptr.expired() || size == 0){
        p_free(buff);
        return;
    }
    if(key.protocol == Protocol::TCP){
        TcpStatus* tcpStatus = (TcpStatus*)protocol_info;
        assert(tcpStatus);
        assert((tcpStatus->window << tcpStatus->recv_wscale) - (tcpStatus->send_seq - tcpStatus->send_acked) >= size);
        size_t sendlen = size;
        if(size > tcpStatus->mss){
            LOGD(DVPN, "(%s): mss smaller than send size (%zu/%u)!\n", getProg(), size, tcpStatus->mss);
            sendlen = tcpStatus->mss;
        }
        LOGD(DVPN, "%s (%u - %u) size: %zu\n",
             key.getString("<-"), tcpStatus->send_seq, tcpStatus->want_seq, sendlen);
        auto pac_return = MakeIp(IPPROTO_TCP, &key.dst, &key.src);
        pac_return->tcp
            ->setseq(tcpStatus->send_seq)
            ->setack(tcpStatus->want_seq)
            ->setwindow(res_ptr.lock()->bufleft(res_index) >> tcpStatus->send_wscale)
            ->setflag(TH_ACK | TH_PUSH);

        nanny->sendPkg(pac_return, buff, sendlen);
        tcpStatus->send_seq += sendlen;
        if(size > sendlen){
            Peer::Send((const char*)buff+sendlen, size-sendlen, index);
        }
        return;
    }
    if(key.protocol == Protocol::UDP){
        LOGD(DVPN, "%s size: %zu\n", key.getString("<-"), size);
        auto pac_return = MakeIp(IPPROTO_UDP, &key.dst, &key.src);

        nanny->sendPkg(pac_return, buff, size);
        add_delayjob(std::bind(&Guest_vpn::aged, this), nullptr, 300000);
        return;
    }
    if(key.protocol == Protocol::ICMP){
        IcmpStatus* icmpStatus = (IcmpStatus*)protocol_info;
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

            nanny->sendPkg(pac_return, buff, size);
        }else{
            pac_return = MakeIp(IPPROTO_ICMPV6, &key.dst, &key.src);
            LOGD(DVPN, "%s (ping6) (%u - %u) size: %zu\n",
                key.getString("<-"), icmpStatus->id, icmpStatus->seq, size - sizeof(icmphdr));
            pac_return->icmp6
                ->settype(ICMP6_ECHO_REPLY)
                ->setcode(0)
                ->setid(icmpStatus->id)
                ->setseq(icmpStatus->seq);

            nanny->sendPkg(pac_return, buff, size);
        }
        add_delayjob(std::bind(&Guest_vpn::aged, this), nullptr, 5000);
        return;
    }
    assert(0);
    return;
}


void Guest_vpn::finish(uint32_t flags, void* index) {
    uint8_t errcode = flags & ERROR_MASK;
    LOGD(DVPN, "%s finish: %u\n", key.getString("<-"), errcode);
    if(errcode == VPN_AGED_ERR){
        if(!res_ptr.expired())
            res_ptr.lock()->finish(NOERROR | DISCONNECT_FLAG, res_index);
        deleteLater(errcode);
        return;
    }
    assert(index == &key);
    if(key.protocol == Protocol::TCP){
        TcpStatus* tcpStatus = (TcpStatus*)protocol_info;
        assert(tcpStatus);
        if(errcode == 0){
            LOGD(DVPN, "write fin packet\n");
            auto pac_return = MakeIp(IPPROTO_TCP, &key.dst, &key.src);
            pac_return->tcp
                ->setseq(tcpStatus->send_seq++)
                ->setack(tcpStatus->want_seq)
                ->setwindow(bufleft(0) >> tcpStatus->send_wscale)
                ->setflag(TH_FIN | TH_ACK);

            nanny->sendPkg(pac_return, (const void*)nullptr, 0);
            switch(tcpStatus->status){
            case TCP_ESTABLISHED:
                tcpStatus->status = TCP_FIN_WAIT1;
                break;
            case TCP_CLOSE_WAIT:
                tcpStatus->status = TCP_LAST_ACK;
                break;
            }
            if(flags & DISCONNECT_FLAG){
                res_ptr = std::weak_ptr<Responser>();
                res_index = nullptr;
            }
            return;
        }else if(errcode == CONNECT_TIMEOUT){
            std::shared_ptr<Ip> pac_return;
            if(key.version() == 4){
                LOGD(DVPN, "write icmp unreachable msg: %s\n", key.getString("<-"));
                pac_return = MakeIp(IPPROTO_ICMP, &key.dst, &key.src);
                pac_return->icmp
                    ->settype(ICMP_UNREACH)
                    ->setcode(ICMP_UNREACH_HOST);
            }else{
                LOGD(DVPN, "write icmpv6 unreachable msg: %s\n", key.getString("<-"));
                pac_return = MakeIp(IPPROTO_ICMPV6, &key.dst, &key.src);
                pac_return->icmp6
                    ->settype(ICMP6_DST_UNREACH)
                    ->setcode(ICMP6_DST_UNREACH_ADDR);
            }

            nanny->sendPkg(pac_return, (const void*)packet, packet_len);
        }else{
            LOGD(DVPN, "write rst packet: %s\n",  key.getString("<-"));
            auto pac_return = MakeIp(IPPROTO_TCP, &key.dst, &key.src);
            pac_return->tcp
                ->setseq(tcpStatus->send_seq)
                ->setack(tcpStatus->want_seq)
                ->setwindow(0)
                ->setflag(TH_RST | TH_ACK);

            nanny->sendPkg(pac_return, (const void*)nullptr, 0);
        }
    }
    if(key.protocol == Protocol::UDP){
        if(errcode){
            std::shared_ptr<Ip> pac_return;
            if(key.version() == 4){
                LOGD(DVPN, "write icmp unreachable msg: %s\n", key.getString("<-"));
                pac_return = MakeIp(IPPROTO_ICMP, &key.dst, &key.src);
                pac_return->icmp
                    ->settype(ICMP_UNREACH)
                    ->setcode(ICMP_UNREACH_PORT);
            }else{
                LOGD(DVPN, "write icmp6 unreachable msg: %s\n", key.getString("<-"));
                pac_return = MakeIp(IPPROTO_ICMPV6, &key.dst, &key.src);
                pac_return->icmp6
                    ->settype(ICMP6_DST_UNREACH)
                    ->setcode(ICMP6_DST_UNREACH_ADDR);
            }

            nanny->sendPkg(pac_return, (const void *)packet, packet_len);
        }
    }
    if(key.protocol == Protocol::ICMP){
        //ignore it.
    }
    if(errcode || (flags & DISCONNECT_FLAG)){
        deleteLater(errcode);
    }
}

int Guest_vpn::aged(){
    LOGD(DVPN, "%s aged.\n", key.getString("-"));
    finish(VPN_AGED_ERR, &key);
    return 0;
}

void Guest_vpn::deleteLater(uint32_t error){
    res_ptr = std::weak_ptr<Responser>();
    res_index = nullptr;
    nanny->cleanKey(key);
    del_delayjob(std::bind(&Guest_vpn::aged, this), nullptr);
    del_postjob(std::bind(&Guest_vpn::tcp_ack, this), nullptr);
    return Peer::deleteLater(error);
}


const char * Guest_vpn::getsrc(const void* index){
    assert(index == &key);
    static char src[INET6_ADDRSTRLEN + 6];
    snprintf(src, sizeof(src), "%s:%d",
             FDns::getRdns(key.src).c_str(), ntohs(key.src.addr_in.sin_port));
    return src;
}


static const char* dump_vpnStatus(const VpnKey& key, void* protocol_info){
    static char buff[URLLIMIT];
    switch(key.protocol){
    case TCP:{
        TcpStatus* tcp = (TcpStatus*)protocol_info;
        sprintf(buff, " [%d %d]", tcp->window, tcp->status);
        break;
    }
    case ICMP:{
        IcmpStatus* icmp = (IcmpStatus *)protocol_info;
        sprintf(buff, " [%d %d]", icmp->id, icmp->seq);
    }
    default:
        break;
    }
    return buff;
}

void Guest_vpn::dump_stat(Dumper dp, void* param) {
    if(res_ptr.expired()){
        dp(param, "Guest_vpn %p: %s %s, %p, %p\n", this,
           key.getString("-"), dump_vpnStatus(key, protocol_info), res_ptr.lock().get(), res_index);
    }else{
        dp(param, "Guest_vpn %p: %s %s\n", this, key.getString("-"), dump_vpnStatus(key, protocol_info));
    }
}
