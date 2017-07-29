#include "dtls.h"
#include "common.h"
#include "job.h"

#include <string.h>
#include <math.h>
#include <arpa/inet.h>

#define DTLS_BUF_LEN (4*1024*1024ull)

struct Dtls_head{
    uint32_t seq;
    uint32_t time;
    uint16_t window;
#define DTLS_TYPE_DATA  0
#define DTLS_TYPE_ACK   1
    uint8_t  type;
    uint8_t _;
}__attribute__((packed));


void Dtls::dtls_send(Dtls* dtls) {
    dtls->send();
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



void TTL::add(uint32_t value) {
    if(value){
        data.push(std::make_pair(getmtime(), value));
        sum += value;
    }
}

uint32_t TTL::getsum() {
    uint32_t  now =getmtime();
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


Dtls::Dtls(SSL* ssl):Ssl(ssl) {
    read_seqs.push_back(std::make_pair(0,0));
    tick_time = ack_time = getmtime();
    write_buff = new unsigned char[DTLS_BUF_LEN];
    read_buff = new unsigned char[DTLS_BUF_LEN];
}

Dtls::~Dtls(){
    del_job((job_func)dtls_send, this);
    delete []write_buff;
    delete []read_buff;
}

ssize_t Dtls::read(void* buff, size_t size) {
    if(flags & DTLS_SEND_TIMEOUT) {
        errno = ETIMEDOUT;
        return -1;
    }
    if(recv() < 0){
        errno = EIO;
        return -1;
    }
    if(read_seqs.begin()->first == read_seqs.begin()->second){
        errno = EAGAIN;
        return -1;
    }
    uint32_t start_pos = read_seqs.begin()->first;
    if(read_seqs.begin()->second - read_seqs.begin()->first < size){
        size = read_seqs.begin()->second - read_seqs.begin()->first;
    }
    read_seqs.begin()->first += size;

    uint32_t from = start_pos &(DTLS_BUF_LEN-1);
    size_t l = Min(DTLS_BUF_LEN - from, size);
    memcpy(buff, read_buff + from, l);
    memcpy((char *)buff + l, read_buff, size - l);
    return size;
}


ssize_t Dtls::write(const void* buff, size_t size) {
    if(flags & DTLS_SEND_TIMEOUT) {
        errno = ETIMEDOUT;
        return -1;
    }
    if(after(write_seq + size, recv_ack + DTLS_BUF_LEN)){
        if(send() < 0){
            errno= EIO;
        }else{
            errno = EAGAIN;
        }
        return -1;
    }
    uint32_t from = write_seq &(DTLS_BUF_LEN-1);
    size_t l = Min(DTLS_BUF_LEN - from, size);
    memcpy(write_buff+from, buff, l);
    memcpy(write_buff, (const char*)buff + l, size -l);
    write_seq += size;
    if(send() < 0){
        errno = EIO;
        return -1;
    }
    return size;
}

int Dtls::recv(){
    assert(!read_seqs.empty());
    unsigned char buff[DTLS_MTU];
    uint32_t tick_recvpkg = 0;
    uint32_t recv_time = 0;
    uint32_t org_ack = 0;
    int ret;
#ifndef NDEBUG
    uint32_t recv_begin = 0;
    uint32_t recv_end = 0;
    uint32_t discard_begin = 0;
    uint32_t discard_end = 0;
#endif
    while((ret = SSL_read(ssl, buff, DTLS_MTU)) > 0){
        Dtls_head *head = (Dtls_head *)buff;
        const uint32_t seq = ntohl(head->seq);
        const uint32_t time = ntohl(head->time);
        const uint16_t len = ret - sizeof(Dtls_head);

        bucket_limit = bucket_limit*0.8 + ntohs(head->window)*0.2;
        bucket_limit = Max(bucket_limit,10);

        tick_recvpkg ++;
        if(head->type == DTLS_TYPE_DATA){
#ifndef NDEBUG
            if(recv_begin == 0){
                recv_begin = seq;
            }
            if(recv_end && recv_end != seq){
                LOGD(DDTLS, "%u: get pkg: %x -- %x [%u]\n", getmtime()&0xffff, recv_begin, recv_end, recv_end-recv_begin);
                recv_begin = seq;
            }
            recv_end = seq + len;
#endif
            uint32_t full_pos = read_seqs.begin()->second;
            if(after(seq + len, full_pos) &&
               before(seq + len , read_seqs.begin()->first + DTLS_BUF_LEN))
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
                size_t from = start_pos  & (DTLS_BUF_LEN-1);
                size_t l = Min(DTLS_BUF_LEN - from, size);
                memcpy(read_buff+ from , (const char*)(head+1) + (start_pos-seq), l);
                memcpy(read_buff , (const char*)(head+1) + (start_pos + l -seq), size - l);

            }
#ifndef NDEBUG
            else{
                if(discard_begin == 0){
                    discard_begin = seq;
                }
                if(discard_end && discard_end != seq){
                    LOGD(DDTLS, "%u: discard pkg: %x -- %x [%u] (%x)\n",
                        getmtime()&0xffff, discard_begin, discard_end, discard_end-discard_begin, full_pos);
                    discard_begin = seq;
                }
                discard_end = seq + len;
            }
#endif
            recv_time = time>recv_time?time:recv_time;
        }else{
            uint32_t now = getmtime();
            if(org_ack == 0){
                org_ack = recv_ack;
            }
            rtt_time = rtt_time * 0.8 + (now-time) * 0.2;
            gap_num = 0;
            uint32_t *gap_ptr = (uint32_t *)(head+1);
            while((unsigned char*)gap_ptr - buff <ret){
                gaps[gap_num++] = ntohl(*gap_ptr++);
            }
            if(after(seq, recv_ack)){
                recv_ack = seq;
                ack_time = now;
#ifdef NDEBUG
            }
#else
                LOGD(DDTLS, "%u: ack: %x  window: %u  rtt: %u\n",
                    now&0xffff, seq, bucket_limit, rtt_time);
            } else{
                LOGD(DDTLS, "%u: ack [R]: %x (%x) window: %u  rtt: %u\n",
                    now&0xffff, seq, recv_ack, bucket_limit, rtt_time);
            }
#endif
        }
    }
#ifndef NDEBUG
    if(recv_end){
        LOGD(DDTLS, "%u: get pkg: %x -- %x [%u]\n",
            getmtime()&0xffff, recv_begin, recv_end, recv_end-recv_begin);
    }
    if(discard_end){
        LOGD(DDTLS, "%u: discard pkg: %x -- %x [%u] (%x)\n",
            getmtime()&0xffff, discard_begin, discard_end, discard_end-discard_begin, read_seqs.begin()->second);
    }
#endif
    if(ret < 0 && !BIO_should_retry(SSL_get_rbio(ssl))){
       return -1;
    }
    if(org_ack && recv_ack != write_seq && org_ack == recv_ack){
        ackhold_times ++;
    }else{
        ackhold_times = 0;
    }
    recv_pkgs.add(tick_recvpkg);
    send_ack(recv_time, recv_pkgs.getsum());
    return send();
}

int Dtls::send() {
    uint32_t recvp_num = recv_pkgs.getsum();
    uint32_t now = getmtime();
    uint32_t buckets;
    assert(bucket_limit>=10);
    if(bucket_limit < 50){
        buckets = (now - tick_time) * sqrt(bucket_limit*100) /100;
    }else{
        buckets = (now - tick_time) * (bucket_limit+5) /80;
    }
    if(ackhold_times >= 3){
#ifndef NDEBUG
        LOGD(DDTLS, "%u: ackhold %u times reset resend_pos(%x) to %x\n",
            getmtime()&0xffff, ackhold_times, resend_pos, recv_ack);
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
           now - ack_time >= Max(2,rtt_time*1.3) &&
           now - resend_time >= Max(2, rtt_time*1.2))
        {
            if(now - ack_time >= 10000){
                LOGE("[DTLS] %u: acktime %u diff %u, timeout\n",
                    getmtime()&0xffff, ack_time&0xffff, now-ack_time);
                del_job((job_func)dtls_send, this);
                flags |= DTLS_SEND_TIMEOUT;
                return -1;
            }
#ifndef NDEBUG
            LOGD(DDTLS, "%u: acktime %u diff %u/%u, begin resend\n",
                getmtime()&0xffff, ack_time&0xffff, now-ack_time, (now-resend_time)&0xffff);
#endif
            resend_pos = after(recv_ack, resend_pos)?recv_ack: resend_pos;
            if(gap_num){
                for(size_t i =0;i<gap_num;i+=2){
                    resend_pos = after(gaps[i], resend_pos)?gaps[i]:resend_pos;
#ifndef NDEBUG
                    uint32_t send_begin = resend_pos;
#endif
                    while(buckets && before(resend_pos, gaps[i+1])){
                        resend_pos += send_pkg(resend_pos, recvp_num, Min(DTLS_LEN, (int32_t)write_seq - (int32_t)resend_pos));
                        buckets--;
                    }
#ifndef NDEBUG
                    if(send_begin != resend_pos){
                        LOGD(DDTLS, "%u: send pkg: %x - %x [%u], left buckets: %d [R]\n",
                            getmtime()&0xffff, send_begin, resend_pos, resend_pos-send_begin, buckets);
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
                    resend_pos += send_pkg(resend_pos, recvp_num, Min(DTLS_LEN, (int32_t)write_seq - (int32_t)resend_pos));
                    buckets--;
                }
#ifndef DDEBUG
                if(send_begin != resend_pos){
                    LOGD(DDTLS, "%u: send pkg: %x - %x [%u], left buckets: %d [SR]\n",
                        getmtime()&0xffff, send_begin, resend_pos, resend_pos-send_begin,buckets);
                }
#endif
            }
            if(buckets){
                resend_pos = recv_ack;
                resend_time = now;
            }
        }
#ifndef NDEBUG
        uint32_t send_begin = send_pos;

#endif
        while(buckets && before(send_pos, write_seq)) {
            send_pos += send_pkg(send_pos, recvp_num, Min(DTLS_LEN, (int32_t)write_seq-(int32_t)send_pos));
            buckets --;
        }
#ifndef NDEBUG
        if(send_begin != send_pos){
            LOGD(DDTLS, "%u: send pkg: %x - %x [%u], left buckets: %d\n",
                getmtime()&0xffff, send_begin, send_pos, send_pos-send_begin, buckets);
        }
#endif
        tick_time = now - buckets*100/bucket_limit;
    }
    if(recv_ack == write_seq){
        del_job((job_func)dtls_send, this);
    }else if(buckets){
        add_job((job_func)dtls_send, this, Max(2,rtt_time*1.2));
    }else{
        add_job((job_func)dtls_send, this, Max(5, 100/bucket_limit));
    }
    return 0;
}

void Dtls::send_ack(uint32_t time, uint32_t window) {
    if(time){
        assert(window && window < 65536);
        unsigned char buff[DTLS_MTU];
        Dtls_head *head = (Dtls_head *)buff;
        auto seq = read_seqs.begin();
        head->seq = htonl(seq->second);
        head->time = htonl(time);
        head->window = htons(window);
        head->type = DTLS_TYPE_ACK;
        uint32_t *gaps= (uint32_t *)(head+1);
        decltype(seq) pre = seq;
        while(1){
            pre = seq++;
            if(seq == read_seqs.end() || 
               (size_t)((unsigned char*)gaps-buff) >= (size_t)DTLS_MTU)
                break;
            assert(before(pre->second, seq->first));
            *(gaps++)=htonl(pre->second);
            *(gaps++)=htonl(seq->first);
        }
        SSL_write(ssl , buff, (unsigned char*)gaps-buff);
    }
}

uint32_t Dtls::send_pkg(uint32_t seq, uint32_t window, size_t len) {
    assert(len && len <= DTLS_LEN);
    assert(window < 65536);
    unsigned char buff[DTLS_MTU];
    Dtls_head *head = (Dtls_head *)buff;
    head->seq = htonl(seq);
    head->time = htonl(getmtime());
    head->window = htons(window);
    head->type = DTLS_TYPE_DATA;
    uint32_t from = seq & (DTLS_BUF_LEN-1);
    size_t l = Min(DTLS_BUF_LEN - from, len);
    memcpy(head+1, write_buff + from, l);
    memcpy((char *)(head+1) + l, write_buff, len - l);
    int ret = SSL_write(ssl ,buff, len + sizeof(Dtls_head));
    if(ret > 0){
        assert((size_t)ret == len + sizeof(Dtls_head));
    }else{
        void(0); //TODO put some error info
    }
    return len;
}

