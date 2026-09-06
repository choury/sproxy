#ifndef CHANNEL_H__
#define CHANNEL_H__
//sproxy_test的可组合传输层。每个channel只依赖下层channel的读写原语，
//可以任意嵌套：connect建fd层，tlsconnect包一层TLS(mem-BIO，不依赖socket)，
//h2connect再包一层h2 CONNECT流，即ssl{fd}、h2{ssl{fd}}、ssl{h2{ssl{fd}}}…
//send/read/shutdown/close等命令只操作栈顶channel，语义不随层级变化
#include <stddef.h>
#include <stdint.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <poll.h>
#include <sys/socket.h>

struct Channel {
    //读至多n字节：>0为读到的字节数，0=对端干净EOF，-1=超时，-2=错误。
    //timeout_ms<0无限阻塞(与裸fd读一致)，>=0限时等待
    virtual int read(void* buf, size_t n, int timeout_ms = -1) = 0;
    virtual int write(const void* buf, size_t n) = 0; //0成功，-1失败
    //写半关：fd层=SHUT_WR，tls层=close_notify，h2流=空DATA+END_STREAM
    virtual void shutdown_wr() = 0;
    virtual void close() = 0; //关闭并释放整个下层栈
    //裸fd层才有有效返回(reset命令用)，其余层返回-1
    virtual int fd() const { return -1; }
    virtual ~Channel() = default;
};

//裸socket层(TCP/UDP)，栈的最底层
struct RawChannel final : Channel {
    int sockfd;
    explicit RawChannel(int fd): sockfd(fd) {}
    int read(void* buf, size_t n, int timeout_ms) override {
        if(timeout_ms >= 0) {
            struct pollfd pfd = {(short)sockfd, POLLIN, 0};
            if(poll(&pfd, 1, timeout_ms) == 0) {
                return -1;
            }
        }
        int r = ::recv(sockfd, buf, n, 0);
        return r >= 0 ? r : -2;
    }
    int write(const void* buf, size_t n) override {
        const char* p = (const char*)buf;
        while(n > 0) {
            ssize_t w = ::send(sockfd, p, n, MSG_NOSIGNAL);
            if(w < 0) {
                if(errno == EINTR) {
                    continue;
                }
                return -1;
            }
            p += w;
            n -= (size_t)w;
        }
        return 0;
    }
    void shutdown_wr() override {
        shutdown(sockfd, SHUT_WR);
    }
    void close() override {
        if(sockfd >= 0) {
            ::close(sockfd);
            sockfd = -1;
        }
    }
    int fd() const override { return sockfd; }
};

#endif
