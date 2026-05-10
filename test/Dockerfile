FROM debian:13

LABEL maintainer="zhouwei400@gmail.com"

# 安装sproxy运行时和测试所需的依赖
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        vim \
        curl \
        netcat-openbsd \
        lsof \
        tcpdump \
        strace \
        iptables \
        iproute2 \
        iputils-ping \
        openssl \
        ca-certificates \
        libjson-c5 \
        zlib1g \
        libelf1 \
        libreadline8 \
        liburing2 \
        libjemalloc2 \
        libxml2 \
        procps \
        libasan8 \
    && rm -rf /var/lib/apt/lists/*

# 使用时挂载构建目录和测试目录：
# 基础测试: docker run -v $(pwd)/build:/build -v $(pwd)/test:/test --cap-add=NET_ADMIN sproxy-test bash -c "cd /test && ./test.sh /build"
# 扩展测试: docker run -v $(pwd)/build:/build -v $(pwd)/test:/test --cap-add=NET_ADMIN --device /dev/net/tun --security-opt seccomp=unconfined sproxy-test bash -c "cd /test && ./test.sh --ex /build"
