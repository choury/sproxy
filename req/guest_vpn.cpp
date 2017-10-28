#include "guest_vpn.h"
#include "vpn.h"

#include "misc/job.h"
#include "res/proxy.h"
#include "res/fdns.h"

#include <fstream>

int vpn_aged(VpnStatus* status){
    LOGD(DVPN, "<%s> ( -> %s) aged.\n",
         protstr(status->key->protocol), status->key->getdst());
    status->res_ptr->finish(VPN_AGED_ERR, status->res_index);
    return 0;
}

VpnKey::VpnKey(const Ip* ip) {
    memset(this, 0, sizeof(VpnKey));
    src.addr.sa_family = AF_INET;
    src.addr_in.sin_addr = *ip->getsrc();
    dst.addr.sa_family = AF_INET;
    dst.addr_in.sin_addr = *ip->getdst();
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
        break;
    default:
        assert(0);
    }
}

void VpnKey::reverse() {
    auto tmp  = dst;
    dst = src;
    src = tmp;
}


const char * VpnKey::getsrc() const{
    static char str[100];
    sprintf(str, "%s:%d",FDns::getRdns(&src.addr_in.sin_addr),
            ntohs(src.addr_in.sin_port));
    return str;
}

const char * VpnKey::getdst() const{
    static char str[100];
    sprintf(str, "%s:%d", FDns::getRdns(&dst.addr_in.sin_addr),
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


Guest_vpn::Guest_vpn(int fd):Requester(fd, "VPN", 0) {
}

Guest_vpn::~Guest_vpn(){
    for(auto& i: statusmap){
        delete i.second.key;
        free(i.second.packet);
        del_delayjob((job_func)vpn_aged, &i.second);
    }
    statusmap.clear();
}

void Guest_vpn::defaultHE(uint32_t events) {
    if (events & EPOLLERR || events & EPOLLHUP) {
        int       error = 0;
        socklen_t errlen = sizeof(error);

        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, (void*)&error, &errlen) == 0) {
            LOGE("(VPN): guest error:%s\n", strerror(error));
        }
        deleteLater(INTERNAL_ERR);
        return;
    }

    if (events & EPOLLOUT) {
        if(buffer.length >= 1024*1024){
            LOGD(DVPN, "active all udp because of buff full\n");
            for(auto i: statusmap){
                VpnStatus& status = i.second;
                if(i.first.protocol == Protocol::UDP){
                    status.res_ptr->writedcb(status.res_index);
                }
            }
        }
        int ret = buffer.Write([this](const void* buff, size_t size){
            return Write(buff, size);
        });
        if(ret < 0 && showerrinfo(ret, "guest_vpn write error")) {
            deleteLater(WRITE_ERR);
            return;
        }
        if(buffer.length == 0){
            updateEpoll(this->events & ~EPOLLOUT);
        }
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

void Guest_vpn::response(HttpResHeader* res) {
    VpnKey& key  = *(VpnKey *)res->index;

    assert(statusmap.count(key));
    VpnStatus& status = statusmap[key];
    LOGD(DVPN, "Get response (%s)\n", res->status);
    //创建回包
    if(memcmp(res->status, "200", 3) == 0){
        assert(key.protocol == Protocol::TCP);
        TcpStatus* tcpStatus = (TcpStatus *)status.protocol_info;
        assert(tcpStatus);
        LOGD(DVPN, "write syn ack packet ( <- %s) (%u - %u).\n",
             key.getdst(), tcpStatus->send_seq, tcpStatus->want_seq);
        Ip pac_return(IPPROTO_TCP, &key.dst, &key.src);
        pac_return.tcp
            ->setseq(tcpStatus->send_seq++)
            ->setack(tcpStatus->want_seq)
            ->setwindowscale(0)
            ->setwindow(status.res_ptr->bufleft(status.res_index))
            ->setmss(BUF_LEN)
            ->setflag(TH_ACK | TH_SYN);

        sendPkg(&pac_return, (const void*)nullptr, 0);
    }
    if(res->status[0] == '4'){
        //site is blocked or bad request, return rst for tcp, icmp for udp
        if(key.protocol == Protocol::TCP){
            TcpStatus* tcpStatus = (TcpStatus*)status.protocol_info;
            assert(tcpStatus);
            LOGD(DVPN, "write rst packet\n");
            Ip pac_return(IPPROTO_TCP, &key.dst, &key.src);
            pac_return.tcp
                ->setseq(tcpStatus->send_seq)
                ->setack(tcpStatus->want_seq)
                ->setwindow(bufleft(0))
                ->setflag(TH_RST | TH_ACK);

            sendPkg(&pac_return, (const void *)nullptr, 0);
        }
        if(key.protocol == Protocol::UDP){
            Ip pac_return(IPPROTO_ICMP, &key.dst, &key.src);
            pac_return.icmp
                ->settype(ICMP_UNREACH)
                ->setcode(ICMP_UNREACH_PORT);

            sendPkg(&pac_return, (const void*)status.packet, status.packet_len);
        }
    }
    delete res;
    return;
}

template <class T>
void Guest_vpn::sendPkg(Ip* pac, T* buff, size_t len){
    char* packet = pac->build_packet(buff, len);
    buffer.push(packet, len);
    updateEpoll(events | EPOLLOUT);
}


void Guest_vpn::transfer(void* index, Responser* res_ptr, void* res_index) {
    VpnKey& key  = *(VpnKey *)index;
    assert(statusmap.count(key));
    VpnStatus& status = statusmap[key];
    status.res_ptr = res_ptr;
    status.res_index = res_index;
}


void Guest_vpn::tcpHE(const Ip* pac, const char* packet, size_t len) {
    uint32_t seq = pac->tcp->getseq();
    uint32_t ack = pac->tcp->getack();
    uint8_t flag = pac->tcp->getflag();
    
    size_t datalen = len - pac->gethdrlen();
    
    VpnKey key(pac);
    LOGD(DVPN, "<tcp> ( -> %s) (%u - %u) flag: %d size:%zu\n",
         key.getdst(), seq, ack, flag, datalen);

    if(flag & TH_SYN){//1握手包，创建握手回包
        if(statusmap.count(key)){
            LOGD(DVPN, "drop dup syn packet\n");
            return;
        }

        //create a http proxy request
        char buff[HEADLENLIMIT];
        sprintf(buff, "CONNECT %s:%d" CRLF "Sproxy_vpn: %d" CRLF CRLF,
                FDns::getRdns(pac->getdst()),
                pac->tcp->getdport(), pac->tcp->getsport());

        HttpReqHeader* req = new HttpReqHeader(buff, this);
        VpnKey *key_index = new VpnKey(key);
        req->index =  key_index;
        TcpStatus* tcpStatus = (TcpStatus*)malloc(sizeof(TcpStatus));
        tcpStatus->send_seq = time(0);
        tcpStatus->send_acked = tcpStatus->send_seq;
        tcpStatus->want_seq = seq+1;
        tcpStatus->window = pac->tcp->getwindow();
        tcpStatus->window_scale = pac->tcp->getwindowscale();
        tcpStatus->flags = 0;
        statusmap[key] =  VpnStatus{
            nullptr,
            nullptr,
            key_index,
            (char *)memdup(packet, pac->gethdrlen()),
            (uint16_t)pac->gethdrlen(),
            tcpStatus,
        };
        Responser *responser_ptr = distribute(req, nullptr);
        if(responser_ptr){
            void* responser_index = responser_ptr->request(std::move(req));
            statusmap[key].res_ptr = responser_ptr;
            statusmap[key].res_index = responser_index;
        }else{
            delete req;
            cleanKey(&key);
        }
        return;
    }
    if(flag & TH_RST){//4 rst包，不用回包，直接断开
        //get the key
        LOGD(DVPN, "get rst, checking key\n");
        //check the map
        if (statusmap.count(key)) {
            VpnStatus &status = statusmap[key];
            if(status.res_ptr)
                status.res_ptr->finish(TCP_RESET_ERR, status.res_index);
            cleanKey(&key);
        }
        return;
    }
    Ip pac_return(IPPROTO_TCP, pac->getdst(), pac->tcp->getdport(), pac->getsrc(), pac->tcp->getsport());
    if(statusmap.count(key) == 0){     //如果不存在，直接发送rst断开
        pac_return.tcp
            ->setseq(ack)
            ->setack(seq)
            ->setwindow(0)
            ->setflag(TH_ACK | TH_RST);

        LOGD(DVPN, "write rst to break no exists connection.\n");

        sendPkg(&pac_return, (const void*)nullptr, 0);
        return;
    }

    VpnStatus &status = statusmap[key];
    TcpStatus* tcpStatus = (TcpStatus*)status.protocol_info;
    assert(tcpStatus);

    if(seq == tcpStatus->want_seq - 1){
        LOGD(DVPN, "get keepalive packet, reply it.\n");
        pac_return.tcp
            ->setseq(tcpStatus->send_seq)
            ->setack(tcpStatus->want_seq)
            ->setwindow(bufleft(0))
            ->setflag(TH_ACK);
        sendPkg(&pac_return, (const void*)nullptr, 0);
    }else if(seq != tcpStatus->want_seq){
        LOGE("(%s): drop unwanted data packet %u/%u\n", getsrc(&key), seq, tcpStatus->want_seq);
        return;
    }

    if(flag & TH_FIN){ //5 fin包，回ack包
        LOGD(DVPN, "get fin, send ack back\n");
        tcpStatus->want_seq++;
        //创建回包
        pac_return.tcp
            ->setseq(tcpStatus->send_seq)
            ->setack(tcpStatus->want_seq)
            ->setwindow(bufleft(0))
            ->setflag(TH_ACK);

        sendPkg(&pac_return, (const void*)nullptr, 0);

        if(tcpStatus->flags & FIN_SEND){
            status.res_ptr->finish(NOERROR | DISCONNECT_FLAG, status.res_index);
            LOGD(DVPN, "clean up connection\n");
            cleanKey(&key);
        }else{
            status.res_ptr->finish(NOERROR, status.res_index);
            tcpStatus->flags |= FIN_RECV;
        }
        return;
    }
    //下面处理数据包和ack包
    if(datalen > 0){//2数据包，创建ack包
        int buflen = status.res_ptr->bufleft(status.res_index);
        if(buflen <= 0){
            LOGE("(%s): responser buff is full, drop packet %u\n", getsrc(&key), seq);
        }else{
            const char* data = packet + pac->gethdrlen();
            status.res_ptr->Send(data, datalen, status.res_index);
            tcpStatus->want_seq = seq + datalen;

            //创建回包
            pac_return.tcp
                ->setseq(tcpStatus->send_seq)
                ->setack(tcpStatus->want_seq)
                ->setwindow(buflen)
                ->setflag(TH_ACK);

            sendPkg(&pac_return, (const void*)nullptr, 0);
        }
    }
    tcpStatus->window = pac->tcp->getwindow();
    if(flag & TH_ACK){
        if(ack > tcpStatus->send_acked){
            tcpStatus->send_acked = ack;
        }
        if(status.res_ptr){
            status.res_ptr->writedcb(status.res_index);
        }else{
            LOGD(DVPN, "clean closed connection\n");
            cleanKey(&key);
        }
    }
}

void Guest_vpn::udpHE(const Ip *pac, const char* packet, size_t len) {
    const char* data = packet + pac->gethdrlen();
    size_t datalen = len - pac->gethdrlen();
    
    VpnKey key(pac);

    if(statusmap.count(key)){
        LOGD(DVPN, "<udp> ( -> %s) size: %zu\n", key.getdst(), datalen);
        VpnStatus& status = statusmap[key];
        add_delayjob((job_func)vpn_aged, &status, 300000);
        if(status.res_ptr->bufleft(status.res_index)<=0){
            LOGE("responser buff is full, drop packet\n");
        }else{
            status.res_ptr->Send(data, datalen, status.res_index);
        }
    }else{
        LOGD(DVPN, "<udp> ( -> %s) (N) size: %zu\n", key.getdst(), datalen);
        //create a http proxy request
        char buff[HEADLENLIMIT];
        sprintf(buff, "SEND %s:%d" CRLF "Sproxy_vpn: %d" CRLF CRLF,
                FDns::getRdns(pac->getdst()),
                pac->udp->getdport(), pac->udp->getsport());

        HttpReqHeader* req = new HttpReqHeader(buff, this);
        VpnKey *key_index = new VpnKey(key);
        req->index = key_index;
        statusmap[key] =  VpnStatus{
            nullptr,
            nullptr,
            key_index,
            (char *)memdup(packet, pac->gethdrlen()),
            (uint16_t)pac->gethdrlen(),
            nullptr,
        };

        Responser *responser_ptr = nullptr;
        if(pac->udp->getdport() == 53){
            responser_ptr = FDns::getfdns();
        }else{
            responser_ptr = distribute(req, nullptr);
        }
        if(responser_ptr){
            add_delayjob((job_func)vpn_aged, &statusmap[key], 60000);
            void* responser_index = responser_ptr->request(std::move(req));
            assert(responser_index);
            statusmap[key].res_ptr = responser_ptr;
            statusmap[key].res_index = responser_index;
            responser_ptr->Send(data, datalen, responser_index);
        }else{
            delete req;
            cleanKey(key_index);
        }
    }
}

void Guest_vpn::icmpHE(const Ip* pac, const char* packet, size_t len) {
    switch(pac->icmp->gettype()){
    case ICMP_ECHO:{
        VpnKey key(pac);
        if(statusmap.count(key)){
            LOGD(DVPN, "<ping> ( -> %s) (%u - %u) size: %zd\n",
                 key.getdst(), pac->icmp->getid(), pac->icmp->getseq(), len - pac->gethdrlen());
            VpnStatus& status = statusmap[key];
            add_delayjob((job_func)vpn_aged, &status, 5000);
            assert(status.res_ptr->bufleft(status.res_index)>0);
            status.packet_len = pac->getid();
            IcmpStatus* icmpStatus = (IcmpStatus *)status.protocol_info;
            assert(icmpStatus->id == pac->icmp->getid());
            icmpStatus->seq = pac->icmp->getseq();
            status.res_ptr->Send(packet + pac->hdrlen, len - pac->hdrlen, status.res_index);
        }else{
            LOGD(DVPN, "<ping> ( -> %s) (N) (%u - %u) size: %zd\n",
                 key.getdst(), pac->icmp->getid(), pac->icmp->getseq(), len - pac->gethdrlen());
            char buff[HEADLENLIMIT];
            sprintf(buff, "PING %s" CRLF "Sproxy_vpn: %d" CRLF CRLF,
                    FDns::getRdns(pac->getdst()), pac->icmp->getid());
            HttpReqHeader* req = new HttpReqHeader(buff, this);

            VpnKey *key_index = new VpnKey(key);
            req->index = key_index;
            IcmpStatus *icmpStatus = (IcmpStatus*)malloc(sizeof(IcmpStatus));
            icmpStatus->id = pac->icmp->getid();
            icmpStatus->seq = pac->icmp->getseq();
            statusmap[key] =  VpnStatus{
                nullptr,
                nullptr,
                key_index,
                nullptr,
                0,
                icmpStatus,
            };
            Responser* responser_ptr = distribute(req, nullptr);
            if(responser_ptr){
                add_delayjob((job_func)vpn_aged, &statusmap[key], 3000);
                void* responser_index = responser_ptr->request(std::move(req));
                assert(responser_index);
                statusmap[key].res_ptr = responser_ptr;
                statusmap[key].res_index = responser_index;
                responser_ptr->Send(packet + pac->hdrlen, len - pac->hdrlen, responser_index);
            }else{
                delete req;
                cleanKey(key_index);
            }
        }
    }break;
    case ICMP_UNREACH:{
        Ip icmp_pac(packet+pac->gethdrlen(), len-pac->gethdrlen());
        uint8_t type = icmp_pac.gettype();
        VpnKey key(&icmp_pac);
        key.reverse();
        
        LOGD(DVPN, "Get unreach icmp packet <%s> ( -> %s) type: %d\n",
             protstr(key.protocol), key.getdst(), type);
        if(type != IPPROTO_TCP && type != IPPROTO_UDP){
            LOGD(DVPN, "Get unreach icmp packet unkown protocol:%d\n", type);
            return;
        }
        if(statusmap.count(key)){
            LOGD(DVPN, "clean this connection\n");
            VpnStatus& status = statusmap[key];

            status.res_ptr->finish(PEER_LOST_ERR, status.res_index);
            del_delayjob((job_func)vpn_aged, &status);
            cleanKey(&key);
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

int32_t Guest_vpn::bufleft(void* index) {
    VpnKey *key = (VpnKey *)index;
    assert(key == nullptr || statusmap.count(*key));
    if(key && key->protocol == Protocol::TCP){
        VpnStatus& status = statusmap[*key];
        TcpStatus* tcpStatus = (TcpStatus*)status.protocol_info;
        assert(tcpStatus);
        return (tcpStatus->window << tcpStatus->window_scale) - (tcpStatus->send_seq - tcpStatus->send_acked);
    }
    return 4*1024*1024 - buffer.length;
}

ssize_t Guest_vpn::Send(void* buff, size_t size, void* index) {
    VpnKey& key  = *(VpnKey *)index;
    assert(statusmap.count(key));
    VpnStatus& status = statusmap[key];
    if(status.res_ptr == nullptr || size == 0){
        p_free(buff);
        return size;
    }
    if(key.protocol == Protocol::TCP){
        TcpStatus* tcpStatus = (TcpStatus*)status.protocol_info;
        assert(tcpStatus);
        size_t winlen = (tcpStatus->window << tcpStatus->window_scale) - (tcpStatus->send_seq - tcpStatus->send_acked);
        if(size > winlen){
            LOGE("(%s): window left smaller than send size!\n", getsrc(&key));
            size = winlen;
        }
        LOGD(DVPN, "<tcp> ( <- %s) (%u - %u) size: %zu\n",
             key.getdst(), tcpStatus->send_seq, tcpStatus->want_seq, size);
        Ip pac_return(IPPROTO_TCP, &key.dst, &key.src);
        pac_return.tcp
            ->setseq(tcpStatus->send_seq)
            ->setack(tcpStatus->want_seq)
            ->setwindow(status.res_ptr->bufleft(status.res_index))
            ->setflag(TH_ACK | TH_PUSH);

        sendPkg(&pac_return, buff, size);
        tcpStatus->send_seq += size;
        return size;
    }
    if(key.protocol == Protocol::UDP){
        LOGD(DVPN, "<udp> ( <- %s) size: %zu\n", key.getdst(), size);
        Ip pac_return(IPPROTO_UDP, &key.dst, &key.src);

        sendPkg(&pac_return, buff, size);
        status.res_ptr->writedcb(status.res_index);
        add_delayjob((job_func)vpn_aged, &status, 300000);
        return size;
    }
    if(key.protocol == Protocol::ICMP){
        Ip pac_return(IPPROTO_ICMP, &key.dst, &key.src);
        IcmpStatus* icmpStatus = (IcmpStatus*)status.protocol_info;
        const Icmp *icmp = (const Icmp*)buff;

        assert(icmp->gettype() == ICMP_ECHOREPLY && icmp->getcode() == 0);
        LOGD(DVPN, "<ping> ( <- %s) (%u - %u) size: %zu\n",
             key.getdst(), icmpStatus->id, icmpStatus->seq, size - sizeof(icmphdr));
        pac_return.icmp
            ->settype(ICMP_ECHOREPLY)
            ->setcode(0)
            ->setid(icmpStatus->id)
            ->setseq(icmpStatus->seq);

        buff = p_move(buff, sizeof(icmphdr));
        sendPkg(&pac_return, buff, size - sizeof(icmphdr));
        status.res_ptr->writedcb(status.res_index);
        add_delayjob((job_func)vpn_aged, &status, 5000);
        return size;
    }
    assert(0);
    return 0;
}

void Guest_vpn::cleanKey(const VpnKey* key) {
    assert(statusmap.count(*key));
    VpnStatus& status = statusmap[*key];
    free(status.protocol_info);
    VpnKey* key_ptr = status.key;
    free(status.packet);
    assert(check_delayjob(job_func(vpn_aged), &status) == 0);
    statusmap.erase(*key);
    assert(statusmap.count(*key_ptr) == 0);
    delete key_ptr;
}


bool Guest_vpn::finish(uint32_t flags, void* index) {
    assert(index);
    VpnKey* key = (VpnKey *)index;
    uint8_t errcode = flags & ERROR_MASK;
    LOGD(DVPN, "<%s> ( -> %s) finish: %u\n",
         protstr(key->protocol),  key->getdst(), errcode);
    assert(statusmap.count(*key));
    VpnStatus& status = statusmap[*key];
    if(key->protocol == Protocol::TCP){
        TcpStatus* tcpStatus = (TcpStatus*)status.protocol_info;
        assert(tcpStatus);
        if(errcode == 0){
            LOGD(DVPN, "write fin packet\n");
            Ip pac_return(IPPROTO_TCP, &key->dst, &key->src);
            pac_return.tcp
                ->setseq(tcpStatus->send_seq++)
                ->setack(tcpStatus->want_seq)
                ->setwindow(bufleft(0))
                ->setflag(TH_FIN | TH_ACK);

            sendPkg(&pac_return, (const void*)nullptr, 0);
            if(tcpStatus->flags & FIN_RECV){
                status.res_ptr = nullptr;
                status.res_index = nullptr;
                return false;
            }else{
                tcpStatus->flags |=  FIN_SEND;
                return true;
            }
        }else if(errcode == CONNECT_TIMEOUT){
            LOGD(DVPN, "write icmp unreachable msg: <tcp> ( -> %s)\n", key->getdst());
            Ip pac_return(IPPROTO_ICMP, &key->dst, &key->src);
            pac_return.icmp
                ->settype(ICMP_UNREACH)
                ->setcode(ICMP_UNREACH_HOST);

            sendPkg(&pac_return, (const void*)status.packet, status.packet_len);
        }else{
            LOGD(DVPN, "write rst packet:  -> %s\n",  key->getdst());
            Ip pac_return(IPPROTO_TCP, &key->dst, &key->src);
            pac_return.tcp
                ->setseq(tcpStatus->send_seq)
                ->setack(tcpStatus->want_seq)
                ->setwindow(0)
                ->setflag(TH_RST | TH_ACK);

            sendPkg(&pac_return, (const void*)nullptr, 0);
        }
    }
    if(key->protocol == Protocol::UDP){
        if(errcode && errcode != VPN_AGED_ERR){
            LOGD(DVPN, "write icmp unreachable msg: <udp> ( -> %s)\n", key->getdst());
            Ip pac_return(IPPROTO_ICMP, &key->dst, &key->src);
            pac_return.icmp
                ->settype(ICMP_UNREACH)
                ->setcode(ICMP_UNREACH_PORT);

            sendPkg(&pac_return, (const void *)status.packet, status.packet_len);
        }
        del_delayjob((job_func)vpn_aged, &status);
    }
    if(key->protocol == Protocol::ICMP){
        del_delayjob((job_func)vpn_aged, &status);
    }
    cleanKey(key);
    return false;
}

#ifndef __ANDROID__
#include<dirent.h>
#include <res/ping.h>
const char* findprogram(ino_t inode){
    static char program[URLLIMIT];
    sprintf(program, "Unkown pid(%lu)", inode);
    bool found = false;
    DIR* dir = opendir("/proc");
    if(dir == nullptr){
        LOGE("open proc dir failed: %s\n", strerror(errno));
        return 0;
    }
    char socklink[20];
    sprintf(socklink, "socket:[%lu]", inode);
    struct dirent *ptr;
    while((ptr = readdir(dir)) != nullptr && found == false)
    {
        //如果读取到的是"."或者".."则跳过，读取到的不是文件夹名字也跳过
        if((strcmp(ptr->d_name, ".") == 0) || (strcmp(ptr->d_name, "..") == 0)) continue;
        if(ptr->d_type != DT_DIR) continue;

        char fddirname[30];
        sprintf(fddirname, "/proc/%.20s/fd", ptr->d_name);
        DIR *fddir = opendir(fddirname);
        if(fddir == nullptr){
            continue;
        }
        struct dirent *fdptr;
        while((fdptr = readdir(fddir)) != nullptr){
            char fname[50];
            //example:  /proc/1111/fd/222
            sprintf(fname, "%s/%.20s", fddirname, fdptr->d_name);
            char linkname[URLLIMIT];
            int ret = readlink(fname, linkname, sizeof(linkname));
            if(ret > 0 && ret < 20 && memcmp(linkname, socklink, ret) == 0){
                sprintf(fname, "/proc/%.20s/exe", ptr->d_name);
                ret = readlink(fname, linkname, sizeof(linkname)),
                linkname[ret] = 0;
                sprintf(program, "%s/%s", basename(linkname), ptr->d_name);
                found = true;
                break;
            }
        }
        closedir(fddir);
    }
    closedir(dir);
    return program;
}
#else
const char* getpackagename(int uid);
#endif
const char * Guest_vpn::getsrc(void* index) {
    VpnKey* key = (VpnKey*)index;
    if(index == nullptr){
        return "Myself";
    }
    std::ifstream netfile;
    if(key->protocol == Protocol::TCP){
        netfile.open("/proc/net/tcp");
    }
    if(key->protocol == Protocol::UDP){
        netfile.open("/proc/net/udp");
    }
    if(key->protocol == Protocol::ICMP){
        netfile.open("/proc/net/icmp");
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
            if(key->src.addr_in.sin_port == htons(srcport) &&(
                (key->protocol == Protocol::ICMP) ||
                (key->dst.addr_in.sin_addr.s_addr == dstip &&
                key->dst.addr_in.sin_port == htons(dstport))))
            {
#ifndef __ANDROID__
                return findprogram(inode);
#else
                return getpackagename(uid);
#endif
            }
        }
    }
    std::ifstream net6file;
    if(key->protocol == Protocol::TCP){
        net6file.open("/proc/net/tcp6");
    }
    if(key->protocol == Protocol::UDP){
        net6file.open("/proc/net/udp6");
    }
    if(key->protocol == Protocol::ICMP){
        netfile.open("/proc/net/icmp6");
    }
    if(net6file.good()) {
        std::string line;
        std::getline(net6file, line); //drop the title line
        while (std::getline(net6file, line)) {
            unsigned int srcport, dstport;
            int uid = 0;
            ino_t inode = 0;
            uint32_t srcip[4], dstip[4];
            sscanf(line.c_str(), "%*d: %8X%8X%8X%8X:%X %8X%8X%8X%8X:%X %*x %*x:%*x %*d:%*x %*d %d %*d %lu",
                                srcip, srcip+1, srcip+2, srcip+3, &srcport,
                                dstip, dstip+1, dstip+2, dstip+3, &dstport, &uid, &inode);
            if(key->src.addr_in.sin_port == htons(srcport) &&
                key->dst.addr_in.sin_addr.s_addr == dstip[3] &&
                key->dst.addr_in.sin_port == htons(dstport))
            {
#ifndef __ANDROID__
                return findprogram(inode);
#else
                return getpackagename(uid);
#endif
            }
        }
    }
    LOGE("Get src failed for %s %08X:%04X %08X:%04X\n",
                    protstr(key->protocol),
                    key->src.addr_in.sin_addr.s_addr,
                    ntohs(key->src.addr_in.sin_port),
                    key->dst.addr_in.sin_addr.s_addr,
                    ntohs(key->dst.addr_in.sin_port));
    return "Unkown inode";
}


void Guest_vpn::dump_stat() {
    LOG("Guest_vpn %p (%zd):\n", this, (4*1024*1024 - buffer.length));
    for(auto i: statusmap){
        LOG("<%s> ( -> %s) %p: %p, %p\n",
            protstr(i.first.protocol), i.first.getdst(),
            i.second.key, i.second.res_ptr, i.second.res_index);
    }
}

