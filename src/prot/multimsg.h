//
// Created by choury on 2023/1/1.
//

#ifndef SPROXY_MULTIMSG_H
#define SPROXY_MULTIMSG_H

#include <sys/uio.h>

#ifndef IOV_MAX
#define IOV_MAX UIO_MAXIOV
#endif

#ifdef  __cplusplus
extern "C" {
#endif

ssize_t readm(int fd, struct iovec *iov, int iovcnt);
// 和writv类似，但是每个iov都会发送单独的包，只用于发送udp报文，返回值为发送成功的报文数目
ssize_t writem(int fd, const struct iovec *iov, int iovcnt);

#ifdef  __cplusplus
}
#endif

#endif //SPROXY_MULTIMSG_H
