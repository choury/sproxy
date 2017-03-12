#include "guest_vpn.h"
#include "prot/ip_pack.h"
#include "vpn.h"

#include "misc/net.h"
#include "res/responser.h"

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
            LOGE("read error:%m\n");
        }else{
            //give the buf to packetManager
            buffHE(recvBuf, readlen);
        }
    }
    if (events & EPOLLOUT) {
        int ret = Peer::Write_buff();
        if(ret > 0 && ret != WRITE_NOTHING){
            for(auto i: waitlist){
                VpnStatus& status = statusmap.at(i);
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
//        pac.print();
        
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
    char *key  = (char *)res.index;
    char sip[INET_ADDRSTRLEN];
    char dip[INET_ADDRSTRLEN];
    int sport, dport;
    char protocol[20];
    sscanf(key, "%s %d %s %d %s", sip, &sport, dip, &dport, protocol);
    assert(memcmp(protocol, "tcp", 4) == 0);
    assert(statusmap.count(key));
    VpnStatus& status = statusmap[key];
    //创建回包
    LOGD(DVPN, "write syn ack packet (%s) (%u - %u).\n", key, status.seq, status.ack);
    Ip pac_return(IPPROTO_TCP, dip, dport, sip, sport);
    pac_return.tcp
    ->setseq(status.seq)
    ->setack(status.ack)
    ->setwindow(status.res_ptr->bufleft(status.res_index))
    ->setflag(TH_ACK | TH_SYN);

    size_t packetlen = 0;
    char* packet = pac_return.build_packet(nullptr, packetlen);
    status.seq ++;

    //write back to vpn fd
    Requester::Write(packet, packetlen, 0);
    return;
}


void Guest_vpn::tcpHE(const Ip* pac, const char* packet, size_t len) {
    uint32_t seq = pac->tcp->getseq();
    uint32_t ack = pac->tcp->getack();
    char sip[INET_ADDRSTRLEN];
    char dip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, pac->getsrc(), sip, sizeof(sip));
    inet_ntop(AF_INET, pac->getdst(), dip, sizeof(dip));
    int sport = pac->tcp->getsport();
    int dport = pac->tcp->getdport();
    char key[100];
    sprintf(key, "%s %d %s %d tcp", sip, sport, dip, dport);

    uint8_t flag = pac->tcp->getflag();
    LOGD(DVPN, "key:(%s) (%u - %u ) packet type: %d\n", key, seq, ack, flag);
    if(flag & TH_SYN){//1握手包，创建握手回包
        if(statusmap.count(key)){
            LOGD(DVPN, "drop dup syn packet\n");
            return;
        }
        if (seq > UINT32_MAX - 1) { //溢出情况，即计算后的ack将大于UINT32_MAX，这里只可能是先等于UINT32_MAX
            seq = 0;
            LOG("ack reach to %u, restart from 0.\n", UINT32_MAX);
        } else{
            seq++;
        }

        //create a http proxy request
        char buff[HEADLENLIMIT];
        sprintf(buff, "CONNECT %s:%d" CRLF "Sproxy_vpn: %d" CRLF CRLF, dip, dport, sport);
        HttpReqHeader req(buff, this);
        void *key_index = (void *)strdup(key);
        req.index =  key_index;
        Responser *responser_ptr = distribute(req, nullptr);
        if(responser_ptr){
            void* responser_index = responser_ptr->request(std::move(req));
            statusmap[key] =  VpnStatus{
                responser_ptr,
                responser_index,
                key_index,
                (char *)memdup(packet, pac->gethdrlen()),
                (uint16_t)pac->gethdrlen(),
                uint32_t(time(0)), seq };
        }else{
            free(req.index);
            LOGE("connect to %s:%d failed\n", dip, dport);
        }
    }
    if(flag & TH_RST){//4 rst包，不用回包，直接断开
        //get the key
        LOGD(DVPN, "get rst, checking key: %s \n", key);
        //check the map
        if (statusmap.count(key)) {
            VpnStatus &status = statusmap[key];
            status.res_ptr->clean(TCP_RESET_ERR, status.res_index);
            free(status.key);
            free(status.packet);
            statusmap.erase(key);
        }
    }
    if(flag & TH_FIN){ //5 fin包，回两个包，ack包，fin包
        LOGD(DVPN, "get fin, checking key: %s \n", key);
        seq++;
        //创建回包
        Ip pac_return(IPPROTO_TCP, pac->getdst(), pac->tcp->getdport(), pac->getsrc(), pac->tcp->getsport());
        pac_return.tcp
        ->setseq(ack)
        ->setack(seq)
        ->setwindow(bufleft(0))
        ->setflag(TH_ACK);

        size_t packetlen;
        char* packet = pac_return.build_packet(nullptr, packetlen);
        //write back to vpn fd
        Requester::Write(packet, packetlen, 0);

        if(statusmap.count(key)){
            pac_return.tcp
            ->setseq(ack)
            ->setack(seq)
            ->setwindow(bufleft(0))
            ->setflag(TH_ACK | TH_FIN);

            packet = pac_return.build_packet(nullptr, packetlen);
            LOGD(DVPN, "write fin packet.\n");
            //write back to vpn fd
            Requester::Write(packet, packetlen, 0);

            VpnStatus &status = statusmap[key];
            status.res_ptr->clean(0, status.res_index);
            free(status.key);
            free(status.packet);
            statusmap.erase(key);
        }
    }
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
            char* packet = pac_return.build_packet(nullptr, packetlen);
            Requester::Write(packet, packetlen, 0);
            return;
        }
        VpnStatus &status = statusmap[key];
        if(seq < status.ack){
            LOGD(DVPN, "drop dup data packet\n");
            return;
        }
        size_t datalen = len - pac->gethdrlen();
        if (seq > UINT32_MAX - datalen) { //溢出情况，即计算后的ack将大于UINT32_MAX
            seq = datalen - (UINT32_MAX - seq);
            LOG("ack reach to %u, restart from %u.\n", UINT32_MAX, seq);
        } else{
            seq = seq + datalen;
        }

        const char* data = packet + pac->gethdrlen();
        status.res_ptr->Write(data, datalen, status.res_index);
        status.ack = seq;

        //创建回包
        pac_return.tcp
        ->setseq(status.seq)
        ->setack(status.ack)
        ->setwindow(status.res_ptr->bufleft(status.res_index))
        ->setflag(TH_ACK);


        size_t  packetlen;
        char *packet = pac_return.build_packet(nullptr, packetlen);
        Requester::Write(packet, packetlen, 0);
    }
}

void Guest_vpn::udpHE(const Ip *pac, const char* packet, size_t len) {
    int sport = pac->udp->getsport();
    int dport = pac->udp->getdport();
    char sip[INET_ADDRSTRLEN];
    char dip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, pac->getsrc(), sip, sizeof(sip));
    inet_ntop(AF_INET, pac->getdst(), dip, sizeof(dip));
    char key[100];
    sprintf(key, "%s %d %s %d udp", sip, sport, dip, dport);

    const char* data = packet + pac->gethdrlen();
    size_t datalen = len - pac->gethdrlen();
    if(statusmap.count(key)){
        LOGD(DVPN, "send udp data (%s).\n", key);
        VpnStatus& status = statusmap[key];
        status.res_ptr->Write(data, datalen, status.res_index);
    }else{
        LOGD(DVPN, "send udp data(N) (%s).\n", key);
        //create a http proxy request
        char buff[HEADLENLIMIT];
        sprintf(buff, "SEND %s:%d" CRLF "Sproxy_vpn: %d" CRLF CRLF, dip, dport, sport);
        HttpReqHeader req(buff, this);
        void *key_index = (void *)strdup(key);
        req.index = key_index;
        Responser *responser_ptr = distribute(req, nullptr);
        if(responser_ptr){
            void* responser_index = responser_ptr->request(std::move(req));
            statusmap[key] =  VpnStatus{
                responser_ptr,
                responser_index,
                key_index,
                (char *)memdup(packet, pac->gethdrlen()),
                (uint16_t)pac->gethdrlen(),
                0, 0};

                responser_ptr->Write(data, datalen, responser_index);
        }else{
            free(req.index);
            LOGE("send to %s:%d failed\n", dip, dport);
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

        int dport = icmp_pac.udp->getsport();
        int sport = icmp_pac.udp->getdport();
        char sip[INET_ADDRSTRLEN];
        char dip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, icmp_pac.getsrc(), dip, sizeof(dip));
        inet_ntop(AF_INET, icmp_pac.getdst(), sip, sizeof(sip));
        char key[100];
        switch(icmp_pac.gettype()){
        case IPPROTO_TCP:
            sprintf(key, "%s %d %s %d tcp", sip, sport, dip, dport);
            break;
        case IPPROTO_UDP:
            sprintf(key, "%s %d %s %d udp", sip, sport, dip, dport);
            break;
        default:
            LOGD(DVPN, "Get unreach icmp packet unkown protocol:%d\n", icmp_pac.gettype());
            return;
        }
        LOGD(DVPN, "Get unreach icmp packet (%s) \n", key);
        if(statusmap.count(key)){
            LOGD(DVPN, "clean this connection\n");
            VpnStatus& status = statusmap[key];

            status.res_ptr->clean(PEER_LOST_ERR, status.res_index);
            free(status.key);
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



ssize_t Guest_vpn::Write(const void* buff, size_t size, void* index) {
    char *key  = (char *)index;
    char sip[INET_ADDRSTRLEN];
    char dip[INET_ADDRSTRLEN];
    int sport, dport;
    char protocol[20];
    sscanf(key, "%s %d %s %d %s", sip, &sport, dip, &dport, protocol);
    assert(statusmap.count(key));
    VpnStatus& status = statusmap[key];
    if(memcmp(protocol, "tcp", 4)==0){
        LOGD(DVPN, "write tcp back (%s) (%u - %u) size: %zu\n", key, status.seq, status.ack, size);
        Ip pac_return(IPPROTO_TCP, dip, dport, sip, sport);
        pac_return.tcp
        ->setseq(status.seq)
        ->setack(status.ack)
        ->setwindow(status.res_ptr->bufleft(status.res_index))
        ->setflag(TH_ACK | TH_PUSH);


        size_t packetlen = size;
        char* packet = pac_return.build_packet(buff, packetlen);

        if (status.seq > UINT32_MAX - size) { //溢出情况，即计算后的ack将大于UINT32_MAX
            status.seq = size - (UINT32_MAX - status.seq);
            LOG("seq reach to %u, restart from %u.\n", UINT32_MAX, status.seq);
        }
        else{
            status.seq = status.seq + size;
        }
        Requester::Write(packet, packetlen, 0);
        return size;
    }
    if(memcmp(protocol, "udp", 4) == 0){
        LOGD(DVPN, "write udp back (%s)\n", key);
        Ip pac_return(IPPROTO_UDP, dip, dport, sip, sport);

        size_t packetlen = size;
        char *packet = pac_return.build_packet(buff, packetlen);
        Requester::Write(packet, packetlen, 0);
        return size;
    }
    assert(0);
    return 0;
}

ssize_t Guest_vpn::Write(void* buff, size_t size, void* index) {
    ssize_t ret = Guest_vpn::Write((const void*)buff, size, index);
    p_free(buff);
    return ret;
}


void Guest_vpn::wait(void* index) {
    waitlist.insert((char *)index);
}

void Guest_vpn::ResetResponser(Responser* r, void* index) {
    char* key = (char *)index;
    assert(statusmap.count(key));
    if(r){
        statusmap[key].res_ptr = r;
    }else{
        statusmap.erase(key);
    }
}


void Guest_vpn::clean(uint32_t errcode, void* index) {
    char* key = (char*)index;
    LOGD(DVPN, "(%s) clean: %d\n", key, errcode);
    if(key == 0){
        for(auto i: statusmap){
            i.second.res_ptr->clean(errcode, i.second.res_index);
            free(i.second.key);
            free(i.second.packet);
        }
        statusmap.clear();
        return Peer::clean(errcode, 0);
    }
    assert(statusmap.count(key));
    char sip[INET_ADDRSTRLEN];
    char dip[INET_ADDRSTRLEN];
    int sport, dport;
    char protocol[20];
    sscanf(key, "%s %d %s %d %s", sip, &sport, dip, &dport, protocol);
    VpnStatus& status = statusmap[key];
    if(strcmp(protocol, "udp") == 0){
        if(errcode){
            LOGD(DVPN, "write icmp unreachable msg for udp clean\n");
            Ip pac_return(IPPROTO_ICMP, dip, 0, sip, 0);
            pac_return.icmp
            ->settype(ICMP_UNREACH)
            ->setcode(ICMP_UNREACH_PORT);
            size_t packetlen = status.packet_len;
            char* packet = pac_return.build_packet(status.packet, packetlen);
            Requester::Write(packet, packetlen, 0);
        }
    }else{
        if(errcode == 0){
            LOGD(DVPN, "write fin packet\n");
            Ip pac_return(IPPROTO_TCP, dip, dport, sip, sport);
            pac_return.tcp
            ->setseq(status.seq)
            ->setack(status.ack)
            ->setwindow(bufleft(0))
            ->setflag(TH_FIN | TH_ACK);

            size_t packetlen;
            char *packet = pac_return.build_packet(nullptr, packetlen);
            //write back to vpn fd
            Requester::Write(packet, packetlen, 0);
        }else if(errcode == CONNECT_TIMEOUT){
            LOGD(DVPN, "write icmp unreachable msg: %s\n", key);
            Ip pac_return(IPPROTO_ICMP, dip, 0, sip, 0);
            pac_return.icmp
            ->settype(ICMP_UNREACH)
            ->setcode(ICMP_UNREACH_HOST);
            size_t packetlen = status.packet_len;
            char* packet = pac_return.build_packet(status.packet, packetlen);
            Requester::Write(packet, packetlen, 0);
        }else{
            LOGD(DVPN, "write rst packet\n");
            Ip pac_return(IPPROTO_TCP, dip, dport, sip, sport);
            pac_return.tcp
            ->setseq(status.seq)
            ->setack(status.ack)
            ->setwindow(bufleft(0))
            ->setflag(TH_RST | TH_ACK);

            size_t packetlen;
            char* packet = pac_return.build_packet(nullptr, packetlen);
            Requester::Write(packet, packetlen, 0);
        }
    }
    free(status.packet);
    statusmap.erase(key);
    free(index);
}
