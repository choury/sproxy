#include "dtls.h"
#include <iostream>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/time.h>

#define DTLS_BUF_LEN (4*1024*1024ull)

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

void Dtls_tick(void *ptr){
    Dtls *dtls = (Dtls *)ptr;
    dtls->send();
}

Dtls::Dtls(SSL* ssl):Ssl(ssl) {
    add_tick_func(Dtls_tick, this);
    read_seqs.push_back(std::make_pair(0,0));
    tick_time = ack_time = getmtime();
    write_buff = new unsigned char[DTLS_BUF_LEN];
    read_buff = new unsigned char[DTLS_BUF_LEN];
}

Dtls::~Dtls(){
    del_tick_func(Dtls_tick, this);
    delete []write_buff;
    delete []read_buff;
}

ssize_t Dtls::read(void* buff, size_t size) {
    recv();
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
    if(after(write_seq + size, recv_ack + DTLS_BUF_LEN)){
        send();
        errno = EAGAIN;
        return -1;
    }
    uint32_t from = write_seq &(DTLS_BUF_LEN-1);
    size_t l = Min(DTLS_BUF_LEN - from, size);
    memcpy(write_buff+from, buff, l);
    memcpy(write_buff, (const char*)buff + l, size -l);
    write_seq += size;
    send();
    return size;
}

void Dtls::recv(){
    assert(!read_seqs.empty());
    unsigned char buff[DTLS_MTU];
    uint32_t tick_recvpkg = 0;
    uint32_t recv_time = 0;
    int ret;
    while((ret = SSL_read(ssl, buff, DTLS_MTU)) > 0){
        Dtls_head *head = (Dtls_head *)buff;
        const uint32_t ack = ntohl(head->ack);
        const uint32_t seq = ntohl(head->seq);
        const uint32_t time = ntohl(head->time);
        const uint16_t len = ret - sizeof(Dtls_head);

        bucket_limit = bucket_limit*0.8 + ntohs(head->window)*0.2;
        bucket_limit = Max(bucket_limit,10);

        tick_recvpkg ++;
        if(head->type == DTLS_TYPE_DATA){
#ifdef DEBUG_DTLS
            fprintf(stderr, "%d: get a packge: %x -- %x\n", getmtime(), seq, seq+len);
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
                
            }else{
#ifdef DEBUG_DTLS
                fprintf(stderr, "discard package %x -- %x (%x)\n", seq, seq+len, full_pos);
#endif
            }
            recv_time = time;
        }else{
            rtt_time = rtt_time * 0.8 + (getmtime()-time) * 0.2;
            gap_num = 0;
            uint32_t *gap_ptr = (uint32_t *)(head+1);
            while((unsigned char*)gap_ptr - buff <ret){
                gaps[gap_num++] = ntohl(*gap_ptr++);
            }
#ifdef DEBUG_DTLS
            fprintf(stderr, "%d: ack: %x window: %u  rtt: %u\n",getmtime(), ack, bucket_limit, rtt_time);
#endif
        }
        if(after(ack, recv_ack)){
            recv_ack = ack;
            ack_time = time;
        }
    }
    recv_pkgs.add(tick_recvpkg);
    send_ack(recv_time, recv_pkgs.getsum());

}

void Dtls::send() {
    uint32_t recvp_num = recv_pkgs.getsum();
    uint32_t now = getmtime();
    uint32_t buckets = (now - tick_time) * bucket_limit /70;
    assert(bucket_limit>=10);
    if(buckets){
        if(buckets > bucket_limit){
            buckets = bucket_limit;
        }
        if(now-ack_time >= Max(2,rtt_time*1.2) && before(recv_ack, write_seq)){
            resend_pos = after(recv_ack, resend_pos)?recv_ack: resend_pos;
            if(gap_num){
                for(size_t i =0;i<gap_num;i+=2){
                    resend_pos = after(gaps[i], resend_pos)?gaps[i]:resend_pos;
                    while(buckets && before(resend_pos, gaps[i+1])){
#ifdef DEBUG_DTLS
                        fprintf(stderr, "%d: resend a pkg: %x -- %x, buckets: %d rtt: %d\n",
                            getmtime(), resend_pos, Min(resend_pos+DTLS_LEN, write_seq), buckets, rtt_time);
#endif
                        resend_pos += send_pkg(resend_pos, recvp_num, Min(DTLS_LEN, (int32_t)write_seq - (int32_t)resend_pos));
                        buckets--;
                    }
                    if(buckets == 0){
                        break;
                    }
                }
            }else{
                while(buckets && before(resend_pos, send_pos)){
#ifdef DEBUG_DTLS
                    fprintf(stderr, "%d: resend a pkg: %x -- %x, buckets: %d rtt: %d\n",
                            getmtime(), resend_pos, Min(resend_pos+DTLS_LEN, write_seq), buckets, rtt_time);
#endif
                    resend_pos += send_pkg(resend_pos, recvp_num, Min(DTLS_LEN, (int32_t)write_seq - (int32_t)resend_pos));
                    buckets--;
                }
            }
            if(buckets){
                resend_pos = recv_ack;
                ack_time = now;
            }
        }
        while(buckets && before(send_pos, write_seq)) {
#ifdef DEBUG_DTLS
            fprintf(stderr, "%d: send a pkg: %x -- %x, buckets: %d rtt: %d\n",
                    getmtime(), send_pos, Min(resend_pos+DTLS_LEN, write_seq), buckets, rtt_time);
#endif
            send_pos += send_pkg(send_pos, recvp_num, Min(DTLS_LEN, (int32_t)write_seq-(int32_t)send_pos));
            buckets --;
        }
        tick_time = now - buckets*100/bucket_limit;
    }
}

void Dtls::send_ack(uint32_t time, uint32_t window) {
    if(time){
        assert(window && window < 65536);
        unsigned char buff[DTLS_MTU];
        Dtls_head *head = (Dtls_head *)buff;
        auto seq = read_seqs.begin();
        head->ack = htonl(seq->second);
        head->seq = 0;
        head->time = htonl(time);
        head->window = htons(window);
        head->type = DTLS_TYPE_ACK;
        uint32_t *gaps= (uint32_t *)(head+1);
        decltype(seq) pre = seq;
        while(1){
            pre = seq++;
            if(seq == read_seqs.end() || (unsigned char*)gaps-buff >= (uint32_t)DTLS_MTU)
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
    head->ack = htonl(read_seqs.begin()->second);
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
#ifdef DEBUG_DTLS
//    fprintf(stderr, "%d: send a pkg: %x -- %x\n",getmtime(), seq, seq+(uint32_t)len);
#endif
    return len;
}

