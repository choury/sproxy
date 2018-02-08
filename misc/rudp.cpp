#include "rudp.h"
#include "job.h"
#include "misc/util.h"
#include "misc/net.h"
#include "req/guest2.h"
#include "prot/dns.h"

#include <queue>

#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <assert.h>

int RudpRWer::rudp_send(RudpRWer* rudp) {
    rudp->send();
    return 0;
}

int RudpRWer::rudp_ack(RudpRWer* rudp){
    rudp->ack();
    return 0;
}

/*
 * * The next routines deal with comparing 32 bit unsigned ints
 * * and worry about wraparound (automatic with unsigned arithmetic).
 * */
static inline int before(uint32_t seq1, uint32_t seq2)
{
    return (int32_t)(seq1-seq2) < 0;
}

static inline int noafter(uint32_t seq1, uint32_t seq2)
{
    return (int32_t)(seq1-seq2) <= 0;
}
#define after(seq2, seq1) before(seq1, seq2)
#define nobefore(seq2, seq1) noafter(seq1, seq2)

class TTL{
    std::queue<std::pair<uint32_t, uint32_t>> data;
    uint32_t sum = 0;
public:
    void add(uint32_t value);
    uint32_t getsum(uint32_t now);
};


void TTL::add(uint32_t value) {
    if(value){
        data.push(std::make_pair(getmtime(), value));
        sum += value;
    }
}

uint32_t TTL::getsum(uint32_t now) {
    while(!data.empty()){
        if( now - data.front().first > 100){
            sum -= data.front().second;
            data.pop();
        }else{
            break;
        }
    }
    return sum;
}


RudpRWer::RudpRWer(int fd, uint32_t id, Rudp_server* ord):RWer(nullptr, fd),id(id), ord(ord) {
    read_seqs.push_back(std::make_pair(0,0));
    tick_time = data_time = ack_time = getmtime();
    recv_pkgs = new TTL();
    connected();
}

RudpRWer::RudpRWer(const char* hostname, uint16_t port):RWer(nullptr), port(port){
    strcpy(this->hostname, hostname);
    query(hostname, (DNSCBfunc)RudpRWer::Dnscallback, this);
    read_seqs.push_back(std::make_pair(0,0));
    tick_time = data_time = ack_time = getmtime();
    recv_pkgs = new TTL();
}

void RudpRWer::connected(){
    if(connectCB){
        connectCB();
    }
    setEpoll(EPOLLIN | EPOLLOUT);
    handleEvent = (void (Ep::*)(uint32_t))&RudpRWer::defaultHE;
}

void RudpRWer::Dnscallback(RudpRWer* rwer, const char*, std::list<sockaddr_un> addrs) {
    for(auto& i: addrs){
        i.addr_in6.sin6_port = htons(rwer->port);
        int fd = Connect(&i, SOCK_DGRAM);
        if(fd > 0){
            rwer->fd = fd;
            memcpy(&rwer->addr, &i, sizeof(sockaddr_un));
            rwer->connected();
            return;
        }
    }
    return rwer->errorCB(CONNECT_FAILED, 0);
}

RudpRWer::~RudpRWer(){
    if(ord){
        ord->evict(id);
    }
    del_delayjob((job_func)rudp_send, this);
    del_delayjob((job_func)rudp_ack, this);
    del_postjob((job_func)rudp_send, this);
    query_cancel(hostname, (DNSCBfunc)RudpRWer::Dnscallback, this);
    delete recv_pkgs;
}

bool RudpRWer::supportReconnect() {
    return true;
}

void RudpRWer::Reconnect() {
    int fd = Connect(&addr, SOCK_DGRAM);
    if(fd > 0){
        setEpoll(0);
        close(this->fd);
        this->fd = fd;
        setEpoll(EPOLLIN | EPOLLOUT);
    }
}


size_t RudpRWer::rlength(){
    return read_seqs.begin()->second - read_seqs.begin()->first;
}

const char *RudpRWer::data(){
    uint32_t size = read_seqs.begin()->second - read_seqs.begin()->first;
    uint32_t start_pos = read_seqs.begin()->first;
    uint32_t from = start_pos % sizeof(read_buff);

    if(size <= sizeof(read_buff) - from){
        return  (char*)read_buff + from;
    }else{
        char* buff = (char*)malloc(size);
        size_t l = sizeof(read_buff) - from;
        memcpy(buff, read_buff + from, l);
        memcpy((char *)buff + l, read_buff, size - l);
        return  buff;
    }
}

void RudpRWer::consume(const char* data, size_t l){
    read_seqs.begin()->first += l;
    assert(read_seqs.begin()->first <= read_seqs.begin()->second);
    if(data < (char*)read_buff || data >= (char*)read_buff + sizeof(read_buff)){
        free((char*)data);
    }
}

ssize_t RudpRWer::Write(const void* buff, size_t size) {
    if(flags & RUDP_SEND_TIMEOUT) {
        errno = ETIMEDOUT;
        return -1;
    }
    if(after(write_seq + size, recv_ack + sizeof(write_buff))){
        errno = EAGAIN;
        return -1;
    }
    uint32_t from = write_seq % sizeof(write_buff);
    size_t l = Min(sizeof(write_buff) - from, size);
    memcpy(write_buff+from, buff, l);
    memcpy(write_buff, (const char*)buff + l, size -l);
    write_seq += size;
    return size;
}

void RudpRWer::handle_pkg(const Rudp_head* head, size_t size, Rudp_stats* stats) {
    if(checksum8((uchar*)head, size)){
        LOGD(DRUDP, "drop error checksum packet!\n");
        return;
    }
    const uint32_t id = ntohl(head->id);
    const uint32_t seq = ntohl(head->seq);
    const uint32_t time = ntohl(head->time);
    const uint16_t len = size - sizeof(Rudp_head);

    stats->tick_recvpkg ++ ;
    uint32_t now = getmtime();

    if(this->id == 0){
        this->id = id;
        LOGD(DRUDP, "get id: %d\n", id);
    }

    bucket_limit = (bucket_limit*8 + ntohs(head->window)*2)/10;
    bucket_limit = Max(bucket_limit,1);

    if(head->type == RUDP_TYPE_DATA){
        data_time = now;
        stats->tick_recvdata ++ ;
#ifndef NDEBUG
        if(stats->recv_begin == 0){
            stats->recv_begin = seq;
        }
        if(stats->recv_end && stats->recv_end != seq){
            LOGD(DRUDP, "[%d] get pkg: %x -- %x [%u]\n", 
                id, stats->recv_begin, stats->recv_end, 
                stats->recv_end - stats->recv_begin);
            stats->recv_begin = seq;
        }
        stats->recv_end = seq + len;
#endif

        uint32_t full_pos = read_seqs.begin()->second;
        if(after(seq + len, full_pos) &&
            before(seq + len , read_seqs.begin()->first + sizeof(read_buff)))
        {
            uint32_t start_pos = after(seq, full_pos)?seq:full_pos;
            auto i = read_seqs.begin();
            for(;i!=read_seqs.end();i++){
                if(nobefore(i->first, start_pos))
                    break;
            }
            read_seqs.insert(i, std::make_pair(start_pos, seq+len));

            for(auto i= read_seqs.begin(); ;){
                auto pre = i++;
                if(i == read_seqs.end())
                    break;
                if(nobefore(pre->second, i->first)){
                    pre->second = after(pre->second, i->second)?pre->second:i->second;
                    read_seqs.erase(i);
                    i = pre;
                }
            }
            size_t size = seq - start_pos + len;
            size_t from = start_pos  % sizeof(read_buff);
            size_t l = Min(sizeof(read_buff) - from, size);
            memcpy(read_buff+ from , (const char*)(head+1) + (start_pos-seq), l);
            memcpy(read_buff , (const char*)(head+1) + (start_pos + l -seq), size - l);
 #ifndef NDEBUG
        }else{
            if(stats->discard_begin == 0){
                stats->discard_begin = seq;
            }
            if(stats->discard_end && stats->discard_end != seq){
                LOGD(DRUDP, "[%d] discard pkg: %x -- %x [%u] (%x)\n",
                    id, stats->discard_begin, stats->discard_end,
                    stats->discard_end - stats->discard_begin, full_pos);
                stats->discard_begin = seq;
            }
            stats->discard_end = seq + len;
#endif
        }
        recv_time = time>recv_time?time:recv_time;
    }else{
        rtt_time = (rtt_time * 8 + (now-time) * 2)/10;
        gap_num = 0;
        uint32_t *gap_ptr = (uint32_t *)(head+1);
        while((uchar*)gap_ptr - (uchar*)head < (int)size){
            gaps[gap_num++] = ntohl(*gap_ptr++);
        }
        if(after(seq, recv_ack)){
            recv_ack = seq;
            ack_time = now;
            ackhold_times = 0;
#ifdef NDEBUG
        }else if(seq == recv_ack){
            ackhold_times ++;
        }
#else
            LOGD(DRUDP, "[%d] ack: %x  window: %u  rtt: %u/%u\n",
                id, seq, bucket_limit, now-time, rtt_time);
        }else{
            LOGD(DRUDP, "[%d] ack [R]: %x (%x) window: %u  rtt: %u/%u\n",
                id, seq, recv_ack, bucket_limit, now-time, rtt_time);
            if(seq == recv_ack){
                ackhold_times ++ ;
            }
        }
#endif
    }
}

void RudpRWer::finish_recv(Rudp_stats* stats){
    auto begin = read_seqs.begin();
#ifndef NDEBUG
    if(stats->recv_end){
        LOGD(DRUDP, "[%d] get pkg: %x -- %x [%u]\n",
            id, stats->recv_begin, stats->recv_end, 
            stats->recv_end - stats->recv_begin);
    }
    if(stats->discard_end){
        LOGD(DRUDP, "[%d] discard pkg: %x -- %x [%u] (%x)\n",
            id, stats->discard_begin, stats->discard_end, 
            stats->discard_end - stats->discard_begin, begin->second);
    }
#endif
    if(recv_ack == write_seq){
        ackhold_times = 0;
    }
    if((begin->second > begin->first) && readCB){
        readCB(begin->second - begin->first);
    }
    recv_pkgs->add(stats->tick_recvpkg);
    if(stats->tick_recvdata && !check_delayjob((job_func)rudp_ack, this)){
        add_delayjob((job_func)rudp_ack, this, 10);
    }
}

void RudpRWer::defaultHE(uint32_t events) {
    if (events & EPOLLERR || events & EPOLLHUP) {
        errorCB(SOCKET_ERR, Checksocket(fd));
        return;
    }
    if(events & EPOLLIN){
        assert(!read_seqs.empty());
        Rudp_stats stats;
        int ret;
        unsigned char buff[RUDP_MTU];
        while((ret = read(fd, buff, RUDP_MTU)) > 0){
            Rudp_head *head = (Rudp_head *)buff;
            handle_pkg(head, ret, &stats);
        }
        if(errno != EAGAIN){
            errorCB(READ_ERR, errno);
            return;
        }
        finish_recv(&stats);
    }
    if(events & EPOLLOUT){
        size_t writed = 0;
        while(wb.length()){
            int ret = wb.Write(std::bind(&RudpRWer::Write, this, _1, _2));
            assert(ret != 0);
            if(ret > 0){
                writed += ret;
                continue;
            }
            if(errno == EAGAIN){
                break;
            }
            errorCB(WRITE_ERR, errno);
            return;
        }
        if(writed && writeCB){
            writeCB(writed);
        }
        if(wb.length() == 0){
            delEpoll(EPOLLOUT);
        }
        add_postjob((job_func)rudp_send, this);
        del_delayjob((job_func)rudp_send, this);
    }
}

int RudpRWer::send() {
    uint32_t now = getmtime();
    uint32_t recvp_num = recv_pkgs->getsum(now);
    assert(bucket_limit>0);
    uint32_t buckets = (now - tick_time) * (bucket_limit+30)/90;
    if(ackhold_times >= 3){
#ifndef NDEBUG
        LOGD(DRUDP, "[%d] ackhold %u times reset resend_pos(%x) to %x\n",
            id, ackhold_times, resend_pos, recv_ack);
#endif
        resend_pos = recv_ack;
        ackhold_times = 0;
    }

    if(recv_ack == send_pos){
        ack_time = now;
    }

    if(buckets){
        if(buckets > bucket_limit){
            buckets = bucket_limit;
        }
        if(before(recv_ack, write_seq) &&
           now - ack_time > Max(2,rtt_time*1.2) + 10 &&
           now - resend_time > Max(2, rtt_time*1.2) + 10)
        {
            if(now - data_time >= 60000 && now - ack_time >= 60000){
                LOGE("[RUDP] %05u:[%d] data diff %u, ack diff %u, timeout\n",
                    getmtime()%100000, id, now-data_time, now-ack_time);
                flags |= RUDP_SEND_TIMEOUT;
                errno = ETIMEDOUT;
                return -1;
            }
#ifndef NDEBUG
            LOGD(DRUDP, "[%d] acktime %05u diff %u/%u, begin resend\n",
                id, ack_time%100000, now-ack_time, now-resend_time);
#endif
            resend_pos = after(recv_ack, resend_pos)?recv_ack: resend_pos;
            if(gap_num){
                for(size_t i =0;i<gap_num;i+=2){
                    resend_pos = after(gaps[i], resend_pos)?gaps[i]:resend_pos;
#ifndef NDEBUG
                    uint32_t send_begin = resend_pos;
#endif
                    while(buckets && before(resend_pos, gaps[i+1])){
                        resend_pos += send_pkg(resend_pos, recvp_num, Min(RUDP_LEN, (int32_t)write_seq - (int32_t)resend_pos));
                        buckets--;
                    }
#ifndef NDEBUG
                    if(send_begin != resend_pos){
                        LOGD(DRUDP, "[%d] send pkg: %x - %x [%u], left buckets: %d [R]\n",
                            id, send_begin, resend_pos, resend_pos-send_begin, buckets);
                    }
#endif
                    if(buckets == 0){
                        break;
                    }
                }
            }else{
#ifndef DDEBUG
                uint32_t send_begin = resend_pos;
#endif
                while(buckets && before(resend_pos, send_pos)){
                    resend_pos += send_pkg(resend_pos, recvp_num, Min(RUDP_LEN, (int32_t)write_seq - (int32_t)resend_pos));
                    buckets--;
                }
#ifndef DDEBUG
                if(send_begin != resend_pos){
                    LOGD(DRUDP, "[%d] send pkg: %x - %x [%u], left buckets: %d [SR]\n",
                        id, send_begin, resend_pos, resend_pos-send_begin,buckets);
                }
#endif
            }
            if(buckets){
                resend_pos = recv_ack;
                resend_time = now;
                rtt_time += rtt_time /2;
            }
            bucket_limit = Max(bucket_limit-1, 1);
        }
#ifndef NDEBUG
        uint32_t send_begin = send_pos;

#endif
        while(buckets && before(send_pos, write_seq)) {
            send_pos += send_pkg(send_pos, recvp_num, Min(RUDP_LEN, (int32_t)write_seq-(int32_t)send_pos));
            buckets --;
        }
#ifndef NDEBUG
        if(send_begin != send_pos){
            LOGD(DRUDP, "[%d] send pkg: %x - %x [%u], left buckets: %d\n",
                id, send_begin, send_pos, send_pos-send_begin, buckets);
        }
#endif
        tick_time = now - buckets*100/bucket_limit;
    }
    if(recv_ack != write_seq){
        if(buckets){
            add_delayjob((job_func)rudp_send, this, Max(2, rtt_time*1.2));
        }else{
            add_delayjob((job_func)rudp_send, this, Max(5, 100/bucket_limit));
        }
    }
    return 0;
}

void RudpRWer::ack() {
    unsigned char buff[RUDP_MTU];
    Rudp_head *head = (Rudp_head *)buff;
    auto seq = read_seqs.begin();
    uint32_t now = getmtime();
    LOGD(DRUDP, "[%d] send ack: %x, time: %05u/%u\n", id, seq->second, recv_time%100000, (now-data_time));
    head->id = htonl(id);
    head->seq = htonl(seq->second);
    head->time = htonl(recv_time + (now - data_time));
    head->window = htons(recv_pkgs->getsum(now));
    head->type = RUDP_TYPE_ACK;
    head->checksum = 0;
    uint32_t *gaps= (uint32_t *)(head+1);
    decltype(seq) pre = seq;
    while(1){
        pre = seq++;
        if(seq == read_seqs.end() ||
            (size_t)((unsigned char*)gaps-buff) >= (size_t)RUDP_MTU)
            break;
        assert(before(pre->second, seq->first));
        *(gaps++)=htonl(pre->second);
        *(gaps++)=htonl(seq->first);
    }
    size_t len = (unsigned char*)gaps-buff;
    head->checksum = checksum8(buff, len);
    if(write(fd, buff, len) <= 0){
        LOGE("[RUDP] write: %s\n", strerror(errno));
        Reconnect();
    }
}

uint32_t RudpRWer::send_pkg(uint32_t seq, uint32_t window, size_t len) {
    assert(len && len <= RUDP_LEN);
    assert(window < 65536);
    unsigned char buff[RUDP_MTU];
    Rudp_head *head = (Rudp_head *)buff;
    head->id = htonl(id);
    head->seq = htonl(seq);
    head->time = htonl(getmtime());
    head->window = htons(window);
    head->type = RUDP_TYPE_DATA;
    head->checksum = 0;
    uint32_t from = seq % sizeof(write_buff);
    size_t l = Min(sizeof(write_buff) - from, len);
    memcpy(head+1, write_buff + from, l);
    memcpy((char *)(head+1) + l, write_buff, len - l);
    head->checksum = checksum8((uchar*)head, len + sizeof(Rudp_head));
    if(write(fd, buff, len + sizeof(Rudp_head)) <= 0){
        LOGE("[RUDP] write: %s\n", strerror(errno));
        Reconnect();
    }
    return len;
}

int RudpRWer::PushPkg(const Rudp_head* pkg, size_t len, const sockaddr_un* addr) {
    if(connect(fd, &addr->addr, sizeof(sockaddr_un))){
        errorCB(CONNECT_FAILED, errno);
        return 0;
    }
    memcpy(&this->addr, addr, sizeof(sockaddr_un));
    Rudp_stats stats;
    handle_pkg(pkg, len, &stats);
    finish_recv(&stats);
    return 0;
}

bool operator< (const sockaddr_un a, const sockaddr_un b){
    if(a.addr.sa_family == AF_INET && b.addr.sa_family == AF_INET){
        return memcmp(&a.addr_in, &b.addr_in, sizeof(a.addr_in)) < 0;
    }
    if(a.addr.sa_family == AF_INET6 && b.addr.sa_family == AF_INET6){
        return memcmp(&a.addr_in6, &b.addr_in6, sizeof(a.addr_in6)) < 0;
    }
    return false;
}

#ifndef __ANDROID__

void Rudp_server::defaultHE(uint32_t events){
    if (events & EPOLLERR || events & EPOLLHUP) {
        LOGE("Rudp server: %d\n", Checksocket(fd));
        return;
    }
    if(events & EPOLLIN){
        sockaddr_un addr;
        socklen_t addr_len = sizeof(addr);
        int ret;
        while((ret = recvfrom(fd, buff, RUDP_MTU, 0, (struct sockaddr*)&addr, &addr_len)) > 0){
            Rudp_head *head = (Rudp_head *)buff;
            uint32_t id = ntohl(head->id);
            if(id){
                if(connections.Get(id) == nullptr){
                    LOGD(DRUDP, "not found id: %d\n", id);
                    continue;
                }
                LOGD(DRUDP, "connection %d addr changed\n", id);
                connections.Get(id)->data->PushPkg(head, ret, &addr);
            }else{
                auto container = connections.Get(addr);
                if(container != nullptr){
                    LOGD(DRUDP, "dup syn packet: %d\n", container->t1);
                    container->data->PushPkg(head, ret, &addr);
                }else{
                    Maxid ++;
                    int fd = Bind(SOCK_DGRAM, port, &addr);
                    RudpRWer* rwer = new RudpRWer(fd, Maxid, this);
                    rwer->PushPkg(head, ret, &addr);
                    connections.Add(Maxid, addr, rwer);
                    LOGD(DRUDP, "new connection %d accept\n", Maxid);
                    new Guest2(&addr, rwer);
                }
            }
        }
    }else{
        LOGE("unknown error\n");
        return;
    }
}

#endif

void Rudp_server::evict(int id) {
    connections.Delete(id);
}