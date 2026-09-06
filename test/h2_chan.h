#ifndef H2_CHAN_H__
#define H2_CHAN_H__
//h2层channel：在下层channel(通常是协商出alpn h2的TLS层)上开一条CONNECT流
//(RFC 9113 §8.3)，构造时发送preface+SETTINGS+HEADERS并等待响应状态；
//之后本channel就是流1的双向字节管道：write切成DATA帧发出，read汇集
//DATA载荷，END_STREAM/RST/GOAWAY映射为EOF与标记行。
//帧头定义与HPACK编解码复用src/prot/http2，测试侧只保留同步泵胶水。
//简化：不处理流量控制(不发WINDOW_UPDATE，受初始窗口65535限制)，单流
#include "channel.h"
#include "prot/http2/http2.h"

#include <string>
#include <memory>
#include <stdint.h>

struct H2Channel final : Channel {
    std::unique_ptr<Channel> base;
    std::string rbuf;   //下层读到、尚未成帧的字节
    std::string datbuf; //流1已收到、待上层读的DATA载荷
    uint32_t sid = 1;
    bool ok = false;      //CONNECT应答为2xx
    bool fin = false;     //对端END_STREAM(读尽datbuf后为EOF)，区别于本端半关
    bool half_closed = false; //本端已发END_STREAM(shutdown_wr)
    bool rst = false;     //流1被RST
    bool goaway = false;
    explicit H2Channel(std::unique_ptr<Channel> base, const std::string& authority);
    int read(void* buf, size_t n, int timeout_ms) override;
    int write(const void* buf, size_t n) override;
    void shutdown_wr() override;
    void close() override;
private:
    bool send_frame(uint8_t type, uint8_t flags, uint32_t fsid,
                    const void* payload, size_t len); //len<=16384(默认MAX_FRAME_SIZE)
    bool read_frame(uint8_t& type, uint8_t& flags, uint32_t& fsid,
                    std::string& payload, int timeout_ms);
    //读一帧并处理：应答SETTINGS/PING，汇集流1的DATA。返回0=流1有事件
    //(数据就绪/fin/rst)，-1=超时或连接错误；其余帧型循环跳过
    int pump(int timeout_ms);
};

#endif
