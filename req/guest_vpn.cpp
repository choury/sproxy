#include "guest_vpn.h"
//#include "prot/ip_pack.h"
#include "vpn.h"

//#include "misc/net.h"
#include "misc/job.h"
#include "res/proxy.h"
#include "res/fdns.h"

//#include <unistd.h>

static void vpn_aged(VpnStatus* status){
    LOGD(DVPN, "<%s> %s -> %s aged.\n",
         protstr(status->key->protocol), status->key->getsrc(), status->key->getdst());
    status->res_ptr->clean(VPN_AGED_ERR, status->res_index);
    del_job((job_func)vpn_aged, status);
}

VpnKey::VpnKey(const Ip* ip) {
    memset(&src, 0, sizeof(src));
    memset(&dst, 0, sizeof(dst));
    src.addr.sa_family = AF_INET;
    src.addr_in.sin_addr = *ip->getsrc();
    dst.addr.sa_family = AF_INET;
    dst.addr_in.sin_addr = *ip->getdst();
    assert(ip->gettype() == IPPROTO_TCP || ip->gettype() == IPPROTO_UDP);
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
    }
}

void VpnKey::reverse() {
    auto tmp  = dst;
    dst = src;
    src = tmp;
}


const char * VpnKey::getsrc() const{
    static char str[100];
    
    char sip[INET_ADDRSTRLEN];
    sprintf(str, "%s:%d",
            inet_ntop(AF_INET, &src.addr_in.sin_addr, sip, sizeof(sip)),
            ntohs(src.addr_in.sin_port));
    return str;
}

const char * VpnKey::getdst() const{
    static char str[100];

    char dip[INET_ADDRSTRLEN];
    sprintf(str, "%s:%d",
            inet_ntop(AF_INET, &dst.addr_in.sin_addr, dip, sizeof(dip)),
            ntohs(dst.addr_in.sin_port));
    return str;
}

bool operator<(const VpnKey a, const VpnKey b) {
    const char* acmp = (char*)&a;
    const char* bcmp = (char*)&b;
    for(size_t i=0;i< sizeof(VpnKey); i++){
        if(acmp[i] < bcmp[i]){
            return true;
        }
        if(acmp[i] > bcmp[i]){
            return false;
        }
    }
    return false;
}


Guest_vpn::Guest_vpn(int fd):Requester(fd, "127.0.0.1", 0) {
}


void Guest_vpn::defaultHE(uint32_t events) {
    if (events & EPOLLERR || events & EPOLLHUP) {
        int       error = 0;
        socklen_t errlen = sizeof(error);

        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, (void*)&error, &errlen) == 0) {
            LOGE("(VPN): guest error:%s\n", strerror(error));
        }
        clean(INTERNAL_ERR, 0);
    }

    if (events & EPOLLIN) {
        char recvBuf[VPN_MTU];
        int readlen = read(fd, recvBuf, VPN_MTU);
        if (readlen <= 0) { //error recv, maybe fd is closed or broken
            LOGE("read error:%s\n", strerror(errno));
        }else{
            //give the buf to packetManager
            buffHE(recvBuf, readlen);
        }
    }
    if (events & EPOLLOUT) {
        int ret = Peer::Write_buff();
        if(ret > 0 && ret != WRITE_NOTHING){
            for(auto i: waitlist){
                VpnStatus& status = statusmap.at(*i);
                status.res_ptr->writedcb(status.res_index);
            }
            waitlist.clear();
        }else if(ret <= 0 && showerrinfo(ret, "guest_vpn write error")) {
            clean(WRITE_ERR, 0);
            return;
        }
    }
}

void Guest_vpn::buffHE(char* buff, size_t buflen) {
    //先解析
    try{
        const Ip pac(buff, buflen);
        //打印ip/tcp/udp头
        //pac.print();
        
        /* determine protocol */
        switch (pac.gettype()) {
            case IPPROTO_ICMP:
                return icmpHE(&pac, buff, buflen);
            case IPPROTO_TCP:
                return tcpHE(&pac, buff, buflen);
            case IPPROTO_UDP:
                return udpHE(&pac, buff, buflen);
            default:
                LOG("unknow protocol: %d\n", pac.gettype());
                return;
        }
    }catch(...){
        return;
    }
}

void Guest_vpn::response(HttpResHeader && res) {
    VpnKey& key  = *(VpnKey *)res.index;

    assert(statusmap.count(key));
    VpnStatus& status = statusmap[key];
    LOGD(DVPN, "Get response (%s)\n", res.status);
    //创建回包
    if(memcmp(res.status, "200", 3) == 0){
        assert(key.protocol == Protocol::TCP);
        LOGD(DVPN, "write syn ack packet (%s -> %s) (%u - %u).\n",
             key.getdst(), key.getsrc(), status.seq, status.ack);
        Ip pac_return(IPPROTO_TCP, &key.dst, &key.src);
        pac_return.tcp
            ->setseq(status.seq)
            ->setack(status.ack)
            ->setwindow(status.res_ptr->bufleft(status.res_index))
            ->setmss(BUF_LEN)
            ->setflag(TH_ACK | TH_SYN);
        
        size_t packetlen = 0;
        char* packet = pac_return.build_packet((const void *)nullptr, packetlen);
        status.seq ++;
        
        //write back to vpn fd
        Requester::Write(packet, packetlen, 0);
    }
    if(res.status[0] == '4'){
        //site is blocked or bad request, return rst for tcp, icmp for udp
        if(key.protocol == Protocol::TCP){
            LOGD(DVPN, "write rst packet\n");
            Ip pac_return(IPPROTO_TCP, &key.dst, &key.src);
            pac_return.tcp
                ->setseq(status.seq)
                ->setack(status.ack)
                ->setwindow(bufleft(0))
                ->setflag(TH_RST | TH_ACK);

            size_t packetlen;
            char* packet = pac_return.build_packet((const void *)nullptr, packetlen);
            Requester::Write(packet, packetlen, 0);
            return;
        }
        if(key.protocol == Protocol::UDP){
            Ip pac_return(IPPROTO_ICMP, &key.dst, &key.src);
            pac_return.icmp
                ->settype(ICMP_UNREACH)
                ->setcode(ICMP_UNREACH_PORT);

            size_t packetlen = status.packet_len;
            char* packet = pac_return.build_packet((const void*)status.packet, packetlen);
            Requester::Write(packet, packetlen, 0);
            return;
        }
    }
    return;
}


void Guest_vpn::tcpHE(const Ip* pac, const char* packet, size_t len) {
    uint32_t seq = pac->tcp->getseq();
    uint32_t ack = pac->tcp->getack();
    uint8_t flag = pac->tcp->getflag();
    
    size_t datalen = len - pac->gethdrlen();
    
    VpnKey key(pac);
    LOGD(DVPN, "<tcp> (%s -> %s) (%u - %u) flag: %d size:%zd\n",
         key.getsrc(), key.getdst(), seq, ack, flag, datalen);

    if(flag & TH_SYN){//1握手包，创建握手回包
        if(statusmap.count(key)){
            LOGD(DVPN, "drop dup syn packet\n");
            return;
        }
        seq++;

        //create a http proxy request
        char buff[HEADLENLIMIT];
        uint32_t fip = ntohl(pac->getdst()->s_addr);
        if(fdns_records.count(fip)){
            sprintf(buff, "CONNECT %s:%d" CRLF "Sproxy_vpn: %d" CRLF CRLF,
                fdns_records[fip].c_str(), pac->tcp->getdport(), pac->tcp->getsport());
        }else{
            char dip[INET_ADDRSTRLEN];
            sprintf(buff, "CONNECT %s:%d" CRLF "Sproxy_vpn: %d" CRLF CRLF,
                inet_ntop(AF_INET, pac->getdst(), dip, sizeof(dip)),
                pac->tcp->getdport(), pac->tcp->getsport());
        }
        HttpReqHeader req(buff, this);
        VpnKey *key_index = new VpnKey(key);
        req.index =  key_index;
        statusmap[key] =  VpnStatus{
            nullptr,
            nullptr,
            key_index,
            (char *)memdup(packet, pac->gethdrlen()),
            (uint16_t)pac->gethdrlen(),
            uint32_t(time(0)),
            seq,
            pac->tcp->getwindow(),
        };
        Responser *responser_ptr = distribute(req, nullptr);
        if(responser_ptr){
            void* responser_index = responser_ptr->request(std::move(req));
            statusmap[key].res_ptr = responser_ptr;
            statusmap[key].res_index = responser_index;
        }else{
            free(statusmap[key].packet);
            delete statusmap[key].key;
            statusmap.erase(key);
        }
        return;
    }
    if(flag & TH_RST){//4 rst包，不用回包，直接断开
        //get the key
        LOGD(DVPN, "get rst, checking key\n");
        //check the map
        if (statusmap.count(key)) {
            VpnStatus &status = statusmap[key];
            status.res_ptr->clean(TCP_RESET_ERR, status.res_index);

            free(status.packet);
            delete status.key;
            statusmap.erase(key);
        }
        return;
    }
    if(flag & TH_FIN){ //5 fin包，回两个包，ack包，fin包
        LOGD(DVPN, "get fin, checking key\n");
        seq++;
        //创建回包
        Ip pac_return(IPPROTO_TCP, pac->getdst(), pac->tcp->getdport(), pac->getsrc(), pac->tcp->getsport());
        pac_return.tcp
            ->setseq(ack)
            ->setack(seq)
            ->setwindow(bufleft(0))
            ->setflag(TH_ACK);

        size_t packetlen;
        char* packet = pac_return.build_packet((const void *)nullptr, packetlen);
        //write back to vpn fd
        Requester::Write(packet, packetlen, 0);

        if(statusmap.count(key)){
            pac_return.tcp
                ->setseq(ack)
                ->setack(seq)
                ->setwindow(bufleft(0))
                ->setflag(TH_ACK | TH_FIN);

            packet = pac_return.build_packet((const void *)nullptr, packetlen);
            LOGD(DVPN, "write fin packet.\n");
            //write back to vpn fd
            Requester::Write(packet, packetlen, 0);

            VpnStatus &status = statusmap[key];
            status.res_ptr->clean(0, status.res_index);

            delete status.key;
            free(status.packet);
            statusmap.erase(key);
        }
        return;
    }
    //下面处理数据包和ack包
    if(len > pac->gethdrlen()){//2数据包，创建ack包
        Ip pac_return(IPPROTO_TCP, pac->getdst(), pac->tcp->getdport(), pac->getsrc(), pac->tcp->getsport());
        if(statusmap.count(key) == 0){     //如果不存在，直接发送rst断开
            pac_return.tcp
                ->setseq(ack)
                ->setack(seq)
                ->setwindow(bufleft(0))
                ->setflag(TH_ACK | TH_RST);

            LOGD(DVPN, "write rst to break old connection.\n");

            size_t packetlen;
            char* packet = pac_return.build_packet((const void *)nullptr, packetlen);
            Requester::Write(packet, packetlen, 0);
            return;
        }
        VpnStatus &status = statusmap[key];
        if(seq != status.ack){
            LOGD(DVPN, "drop unwanted data packet\n");
            return;
        }
        int buflen = status.res_ptr->bufleft(status.res_index);
        if(buflen <= 0){
            LOGE("responser buff is full, drop packet\n");
        }else{
            const char* data = packet + pac->gethdrlen();
            status.res_ptr->Write(data, datalen, status.res_index);
            status.ack = seq + datalen;

            //创建回包
            pac_return.tcp
                ->setseq(status.seq)
                ->setack(status.ack)
                ->setwindow(buflen)
                ->setflag(TH_ACK);


            size_t  packetlen;
            char *packet = pac_return.build_packet((const void *)nullptr, packetlen);
            Requester::Write(packet, packetlen, 0);
        }
    }
    if(statusmap.count(key)){     //更新window
        VpnStatus &status = statusmap[key];
        status.window = pac->tcp->getwindow();
        if(flag & TH_ACK){
            status.res_ptr->writedcb(status.res_index);
        }
    }
}

void Guest_vpn::udpHE(const Ip *pac, const char* packet, size_t len) {
    const char* data = packet + pac->gethdrlen();
    size_t datalen = len - pac->gethdrlen();
    
    VpnKey key(pac);

    if(statusmap.count(key)){
        LOGD(DVPN, "<udp> (%s -> %s) size: %zd\n", key.getsrc(), key.getdst(), datalen);
        VpnStatus& status = statusmap[key];
        if(status.res_ptr->bufleft(status.res_index)<=0){
            LOGE("responser buff is full, drop packet\n");
        }else{
            status.res_ptr->Write(data, datalen, status.res_index);
        }
        add_job((job_func)vpn_aged, &status, 300000);
    }else{
        LOGD(DVPN, "<udp> (%s -> %s) (N) size: %zd\n", key.getsrc(), key.getdst(), datalen);
        //create a http proxy request
        char buff[HEADLENLIMIT];
        uint32_t fip = ntohl(pac->getdst()->s_addr);
        if(fdns_records.count(fip)){
            sprintf(buff, "SEND %s:%d" CRLF "Sproxy_vpn: %d" CRLF CRLF,
                fdns_records[fip].c_str(), pac->udp->getdport(), pac->udp->getsport());
        }else{
            char dip[INET_ADDRSTRLEN];
            sprintf(buff, "SEND %s:%d" CRLF "Sproxy_vpn: %d" CRLF CRLF,
                inet_ntop(AF_INET, pac->getdst(), dip, sizeof(dip)),
                pac->udp->getdport(), pac->udp->getsport());
        }
        HttpReqHeader req(buff, this);
        VpnKey *key_index = new VpnKey(key);
        req.index = key_index;
        statusmap[key] =  VpnStatus{
            nullptr,
            nullptr,
            key_index,
            (char *)memdup(packet, pac->gethdrlen()),
            (uint16_t)pac->gethdrlen(),
            0, 0, 0};

        Responser *responser_ptr = nullptr;
        if(pac->udp->getdport() == 53){
            responser_ptr = FDns::getfdns();
        }else{
            responser_ptr = distribute(req, nullptr);
        }
        if(responser_ptr){
            void* responser_index = responser_ptr->request(std::move(req));
            statusmap[key].res_ptr = responser_ptr;
            statusmap[key].res_index = responser_index;
            responser_ptr->Write(data, datalen, responser_index);
            add_job((job_func)vpn_aged, &statusmap[key], 60000);
        }else{
            free(statusmap[key].packet);
            delete statusmap[key].key;
            statusmap.erase(key);
        }
    }
}

void Guest_vpn::icmpHE(const Ip* pac, const char* packet, size_t len) {
    switch(pac->icmp->gettype()){
    case ICMP_ECHO:
        LOGD(DVPN, "Want ping %s, we don't reply ping\n", inet_ntoa(*pac->getdst()));
        break;
    case ICMP_UNREACH:{
        Ip icmp_pac(packet+pac->gethdrlen(), len-pac->gethdrlen());
        uint8_t type = icmp_pac.gettype();
        VpnKey key(&icmp_pac);
        key.reverse();
        
        LOGD(DVPN, "Get unreach icmp packet <%s> (%s -> %s) type: %d\n",
             protstr(key.protocol), key.getsrc(), key.getdst(), type);
        if(type != IPPROTO_TCP && type != IPPROTO_UDP){
            LOGD(DVPN, "Get unreach icmp packet unkown protocol:%d\n", type);
            return;
        }
        if(statusmap.count(key)){
            LOGD(DVPN, "clean this connection\n");
            VpnStatus& status = statusmap[key];
            del_job((job_func)vpn_aged, &status);

            status.res_ptr->clean(PEER_LOST_ERR, status.res_index);
            delete status.key;
            free(status.packet);
            statusmap.erase(key);

        }else{
            LOGD(DVPN, "key not exist, ignore\n");
        }
    } break;
    default:
        LOGD(DVPN, "Get icmp type:%d code: %d, ignore it.\n",
             pac->icmp->gettype(),
             pac->icmp->getcode());
        break;
    }
}



ssize_t Guest_vpn::Write(void* buff, size_t size, void* index) {
    if(size == 0){
        return 0;
    }
    VpnKey& key  = *(VpnKey *)index;
    assert(statusmap.count(key));
    VpnStatus& status = statusmap[key];
    if(status.res_ptr == nullptr){
        return size;
    }
    if(key.protocol == Protocol::TCP){
        assert(size <= status.window);
        LOGD(DVPN, "write tcp back (%s -> %s) (%u - %u) size: %zu\n",
             key.getdst(), key.getsrc(), status.seq, status.ack, size);
        Ip pac_return(IPPROTO_TCP, &key.dst, &key.src);
        pac_return.tcp
            ->setseq(status.seq)
            ->setack(status.ack)
            ->setwindow(status.res_ptr->bufleft(status.res_index))
            ->setflag(TH_ACK | TH_PUSH);


        size_t packetlen = size;
        char* packet = pac_return.build_packet(buff, packetlen);

        status.seq = status.seq + size;
        Requester::Write(packet, packetlen, 0);
        return size;
    }
    if(key.protocol == Protocol::UDP){
        LOGD(DVPN, "write udp back (%s -> %s) size: %zu\n", key.getdst(), key.getsrc(), size);
        Ip pac_return(IPPROTO_UDP, &key.dst, &key.src);

        size_t packetlen = size;
        char *packet = pac_return.build_packet(buff, packetlen);
        Requester::Write(packet, packetlen, 0);
        add_job((job_func)vpn_aged, &status, 300000);
        return size;
    }
    assert(0);
    return 0;
}

void Guest_vpn::wait(void* index) {
    waitlist.insert((VpnKey *)index);
}

int32_t Guest_vpn::bufleft(void* index) {
    VpnKey *key = (VpnKey *)index;
    assert(index == nullptr || statusmap.count(*key));
    if(key && key->protocol == Protocol::TCP){
        return statusmap[*key].window;
    }
    return Requester::bufleft(0);
}


void Guest_vpn::clean(uint32_t errcode, void* index) {
    VpnKey* key = (VpnKey *)index;
    LOGD(DVPN, "<%s> (%s -> %s) clean: %d\n",
         protstr(key->protocol), key->getsrc(), key->getdst(), errcode);
    if(key == nullptr){
        for(auto i: statusmap){
            i.second.res_ptr->clean(errcode, i.second.res_index);
            delete i.second.key;
            free(i.second.packet);
        }
        statusmap.clear();
        return Peer::clean(errcode, 0);
    }
    assert(statusmap.count(*key));
    VpnStatus& status = statusmap[*key];
    assert(status.key == key);
    if(key->protocol == Protocol::UDP){
        if(errcode){
            LOGD(DVPN, "write icmp unreachable msg: <udp> (%s -> %s)\n", key->getsrc(), key->getdst());
            Ip pac_return(IPPROTO_ICMP, &key->dst, &key->src);
            pac_return.icmp
                ->settype(ICMP_UNREACH)
                ->setcode(ICMP_UNREACH_PORT);

            size_t packetlen = status.packet_len;
            char* packet = pac_return.build_packet((const void*)status.packet, packetlen);
            Requester::Write(packet, packetlen, 0);
        }
        del_job((job_func)vpn_aged, &status);
    }else{
        if(errcode == 0){
            LOGD(DVPN, "write fin packet\n");
            Ip pac_return(IPPROTO_TCP, &key->dst, &key->src);
            pac_return.tcp
                ->setseq(status.seq)
                ->setack(status.ack)
                ->setwindow(bufleft(0))
                ->setflag(TH_FIN | TH_ACK);

            size_t packetlen;
            char *packet = pac_return.build_packet((const void*)nullptr, packetlen);
            //write back to vpn fd
            Requester::Write(packet, packetlen, 0);
        }else if(errcode == CONNECT_TIMEOUT){
            LOGD(DVPN, "write icmp unreachable msg: <tcp> (%s -> %s)\n", key->getsrc(), key->getdst());
            Ip pac_return(IPPROTO_ICMP, &key->dst, &key->src);
            pac_return.icmp
                ->settype(ICMP_UNREACH)
                ->setcode(ICMP_UNREACH_HOST);

            size_t packetlen = status.packet_len;
            char* packet = pac_return.build_packet((const void*)status.packet, packetlen);
            Requester::Write(packet, packetlen, 0);
        }else{
            LOGD(DVPN, "write rst packet: %s -> %s\n", key->getsrc(), key->getdst());
            Ip pac_return(IPPROTO_TCP, &key->dst, &key->src);
            pac_return.tcp
                ->setseq(status.seq)
                ->setack(status.ack)
                ->setwindow(bufleft(0))
                ->setflag(TH_RST | TH_ACK);

            size_t packetlen;
            char* packet = pac_return.build_packet((const void *)nullptr, packetlen);
            Requester::Write(packet, packetlen, 0);
        }
    }
    free(status.packet);
    statusmap.erase(*key);
    delete key;
}

void Guest_vpn::dump_stat() {
    LOG("Guest_vpn %p:\n", this);
    for(auto i: statusmap){
        LOG("<%s> (%s -> %s) %p: %p, %p\n",
            protstr(i.first.protocol), i.first.getsrc(), i.first.getdst(),
            i.second.key, i.second.res_ptr, i.second.res_index);
    }
    if(!waitlist.empty()){
        LOG(">>> waitlist (may due to low connect):\n");
        for(auto i: waitlist){
            LOG("%p\n", i);
        }
    }
}

