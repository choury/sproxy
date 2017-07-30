#include "guest_vpn.h"
#include "vpn.h"

#include "misc/job.h"
#include "res/proxy.h"
#include "res/fdns.h"

#include <fstream>

int vpn_aged(VpnStatus* status){
    LOGD(DVPN, "<%s> %s -> %s aged.\n",
         protstr(status->key->protocol), status->key->getsrc(), status->key->getdst());
    status->res_ptr->finish(VPN_AGED_ERR, status->res_index);
    return 0;
}

VpnKey::VpnKey(const Ip* ip) {
    memset(this, 0, sizeof(VpnKey));
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
        int ret = buffer.Write([this](const void* buff, size_t size){
            return Write(buff, size);
        });
        if(ret < 0 && showerrinfo(ret, "guest_vpn write error")) {
            deleteLater(WRITE_ERR);
            return;
        }
        if(buffer.length == 0){
            updateEpoll(EPOLLIN);
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
        LOGD(DVPN, "write syn ack packet (%s -> %s) (%u - %u).\n",
             key.getdst(), key.getsrc(), status.seq, status.ack);
        Ip pac_return(IPPROTO_TCP, &key.dst, &key.src);
        pac_return.tcp
            ->setseq(status.seq)
            ->setack(status.ack)
            ->setwindowscale(0)
            ->setwindow(status.res_ptr->bufleft(status.res_index))
            ->setmss(BUF_LEN)
            ->setflag(TH_ACK | TH_SYN);

        sendPkg(&pac_return, (const void*)nullptr, 0);
        status.seq ++;
    }
    if(res->status[0] == '4'){
        //site is blocked or bad request, return rst for tcp, icmp for udp
        if(key.protocol == Protocol::TCP){
            LOGD(DVPN, "write rst packet\n");
            Ip pac_return(IPPROTO_TCP, &key.dst, &key.src);
            pac_return.tcp
                ->setseq(status.seq)
                ->setack(status.ack)
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
    LOGD(DVPN, "<tcp> (%s -> %s) (%u - %u) flag: %d size:%zu\n",
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
        HttpReqHeader* req = new HttpReqHeader(buff, this);
        VpnKey *key_index = new VpnKey(key);
        req->index =  key_index;
        uint16_t window = pac->tcp->getwindow();
        uint8_t  scale = pac->tcp->getwindowscale();
        statusmap[key] =  VpnStatus{
            nullptr,
            nullptr,
            key_index,
            (char *)memdup(packet, pac->gethdrlen()),
            (uint16_t)pac->gethdrlen(),
            uint32_t(time(0)),
            seq,
            uint16_t(window >> scale),
            scale,
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
            status.res_ptr->finish(TCP_RESET_ERR, status.res_index);
            cleanKey(&key);
        }
        return;
    }
    if(flag & TH_FIN){ //5 fin包，回ack包
        LOGD(DVPN, "get fin, checking key\n");
        seq++;
        //创建回包
        Ip pac_return(IPPROTO_TCP, pac->getdst(), pac->tcp->getdport(), pac->getsrc(), pac->tcp->getsport());
        pac_return.tcp
            ->setseq(ack)
            ->setack(seq)
            ->setwindow(bufleft(0))
            ->setflag(TH_ACK);

        sendPkg(&pac_return, (const void*)nullptr, 0);

        if(statusmap.count(key)){
            VpnStatus &status = statusmap[key];
            status.res_ptr->finish(NOERROR, status.res_index);
            status.ack = seq;
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

            sendPkg(&pac_return, (const void*)nullptr, 0);
            return;
        }
        VpnStatus &status = statusmap[key];
        if(seq != status.ack){
            LOGD(DVPN, "drop unwanted data packet\n");
            return;
        }
        int buflen = status.res_ptr->bufleft(status.res_index);
        if(buflen <= 0){
            LOGE("(%s): responser buff is full, drop packet\n", getsrc(&key));
        }else{
            const char* data = packet + pac->gethdrlen();
            status.res_ptr->Send(data, datalen, status.res_index);
            status.ack = seq + datalen;

            //创建回包
            pac_return.tcp
                ->setseq(status.seq)
                ->setack(status.ack)
                ->setwindow(buflen)
                ->setflag(TH_ACK);

            sendPkg(&pac_return, (const void*)nullptr, 0);
        }
    }
    if(statusmap.count(key)){     //更新window
        VpnStatus &status = statusmap[key];
        status.window = pac->tcp->getwindow();
        if(status.window == 0){
            LOGE("(%s): Get zero tcp window, reset it!\n", getsrc(&key));
            status.res_ptr->finish(TCP_RESET_ERR, status.res_index);
            cleanKey(&key);
            return;
        }
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
        LOGD(DVPN, "<udp> (%s -> %s) size: %zu\n", key.getsrc(), key.getdst(), datalen);
        VpnStatus& status = statusmap[key];
        add_delayjob((job_func)vpn_aged, &status, 300000);
        if(status.res_ptr->bufleft(status.res_index)<=0){
            LOGE("responser buff is full, drop packet\n");
        }else{
            status.res_ptr->Send(data, datalen, status.res_index);
        }
    }else{
        LOGD(DVPN, "<udp> (%s -> %s) (N) size: %zu\n", key.getsrc(), key.getdst(), datalen);
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
        HttpReqHeader* req = new HttpReqHeader(buff, this);
        VpnKey *key_index = new VpnKey(key);
        req->index = key_index;
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
            add_delayjob((job_func)vpn_aged, &statusmap[key], 60000);
            void* responser_index = responser_ptr->request(std::move(req));
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
        return status.window << status.window_scale;
    }
    return 1024*1024 - buffer.length;
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
        if(size > uint32_t(status.window << status.window_scale)){
            LOGE("(%s): window size smaller than send size!\n", getsrc(&key));
        }
        LOGD(DVPN, "write tcp back (%s -> %s) (%u - %u) size: %zu\n",
             key.getdst(), key.getsrc(), status.seq, status.ack, size);
        Ip pac_return(IPPROTO_TCP, &key.dst, &key.src);
        pac_return.tcp
            ->setseq(status.seq)
            ->setack(status.ack)
            ->setwindow(status.res_ptr->bufleft(status.res_index))
            ->setflag(TH_ACK | TH_PUSH);

        sendPkg(&pac_return, buff, size);
        status.seq = status.seq + size;
        return size;
    }
    if(key.protocol == Protocol::UDP){
        LOGD(DVPN, "write udp back (%s -> %s) size: %zu\n", key.getdst(), key.getsrc(), size);
        Ip pac_return(IPPROTO_UDP, &key.dst, &key.src);

        sendPkg(&pac_return, buff, size);
        status.res_ptr->writedcb(status.res_index);
        add_delayjob((job_func)vpn_aged, &status, 300000);
        return size;
    }
    assert(0);
    return 0;
}

void Guest_vpn::cleanKey(const VpnKey* key) {
    assert(statusmap.count(*key));
    VpnStatus& status = statusmap[*key];
    VpnKey* key_ptr = status.key;
    free(status.packet);
    assert(check_delayjob(job_func(vpn_aged), &status) == 0);
    statusmap.erase(*key);
    delete key_ptr;
}


void Guest_vpn::finish(uint32_t errcode, void* index) {
    assert(index);
    VpnKey* key = (VpnKey *)index;
    assert(statusmap.count(*key));
    LOGD(DVPN, "<%s> (%s -> %s) clean: %d\n",
         protstr(key->protocol), key->getsrc(), key->getdst(), errcode);
    VpnStatus& status = statusmap[*key];
    key = status.key;
    if(key->protocol == Protocol::UDP){
        if(errcode && errcode != VPN_AGED_ERR){
            LOGD(DVPN, "write icmp unreachable msg: <udp> (%s -> %s)\n", key->getsrc(), key->getdst());
            Ip pac_return(IPPROTO_ICMP, &key->dst, &key->src);
            pac_return.icmp
                ->settype(ICMP_UNREACH)
                ->setcode(ICMP_UNREACH_PORT);

            sendPkg(&pac_return, (const void *)status.packet, status.packet_len);
        }
        del_delayjob((job_func)vpn_aged, &status);
    }else{
        if(errcode == 0){
            LOGD(DVPN, "write fin packet\n");
            Ip pac_return(IPPROTO_TCP, &key->dst, &key->src);
            pac_return.tcp
                ->setseq(status.seq)
                ->setack(status.ack)
                ->setwindow(bufleft(0))
                ->setflag(TH_FIN | TH_ACK);

            sendPkg(&pac_return, (const void*)nullptr, 0);
        }else if(errcode == CONNECT_TIMEOUT){
            LOGD(DVPN, "write icmp unreachable msg: <tcp> (%s -> %s)\n", key->getsrc(), key->getdst());
            Ip pac_return(IPPROTO_ICMP, &key->dst, &key->src);
            pac_return.icmp
                ->settype(ICMP_UNREACH)
                ->setcode(ICMP_UNREACH_HOST);

            sendPkg(&pac_return, (const void*)status.packet, status.packet_len);
        }else{
            LOGD(DVPN, "write rst packet: %s -> %s\n", key->getsrc(), key->getdst());
            Ip pac_return(IPPROTO_TCP, &key->dst, &key->src);
            pac_return.tcp
                ->setseq(status.seq)
                ->setack(status.ack)
                ->setwindow(bufleft(0))
                ->setflag(TH_RST | TH_ACK);

            sendPkg(&pac_return, (const void*)nullptr, 0);
        }
    }
    free(status.packet);
    assert(check_delayjob(job_func(vpn_aged), &status) == 0);
    statusmap.erase(*key);
    delete key;
}

#ifndef __ANDROID__
#include<dirent.h>
const char* findpid(ino_t inode){
    static char pid[30];
    sprintf(pid, "Unkown pid(%lu)", inode);
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

        char fddirname[20];
        sprintf(fddirname, "/proc/%s/fd", ptr->d_name);
        DIR *fddir = opendir(fddirname);
        if(fddir == nullptr){
            continue;
        }
        struct dirent *fdptr;
        while((fdptr = readdir(fddir)) != nullptr){
            char fdname[50];
            sprintf(fdname, "%s/%s", fddirname, fdptr->d_name);
            char iname[20];
            int ret = readlink(fdname, iname, sizeof(iname));
            if(ret > 0 && memcmp(iname, socklink, ret) == 0){
                strcpy(pid, ptr->d_name);
                found = true;
                break;
            }
        }
        closedir(fddir);
    }
    closedir(dir);
    return pid;
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
            if(key->src.addr_in.sin_port == htons(srcport) &&
                key->dst.addr_in.sin_addr.s_addr == dstip &&
                key->dst.addr_in.sin_port == htons(dstport))
            {
#ifndef __ANDROID__
                return findpid(inode);
#else
                return getpackagename(uid);
#endif
            }
        }
        netfile.close();
    }
    std::ifstream net6file;
    if(key->protocol == Protocol::TCP){
        net6file.open("/proc/net/tcp6");
    }
    if(key->protocol == Protocol::UDP){
        net6file.open("/proc/net/udp6");
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
                return findpid(inode);
#else
                return getpackagename(uid);
#endif
            }
        }
        netfile.close();
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
    LOG("Guest_vpn %p:\n", this);
    for(auto i: statusmap){
        LOG("<%s> (%s -> %s) %p: %p, %p\n",
            protstr(i.first.protocol), i.first.getsrc(), i.first.getdst(),
            i.second.key, i.second.res_ptr, i.second.res_index);
    }
}

