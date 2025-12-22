FROM debian:13 as builder

LABEL maintainer="zhouwei400@gmail.com"


COPY . /root/sproxy
RUN apt-get  update && \
    apt-get install -y --no-install-recommends  \
    gcc g++ cmake binutils-gold make pkg-config git ca-certificates \
    libssl-dev libz-dev libelf-dev libjson-c-dev libreadline-dev liburing-dev libjemalloc-dev libxml2-dev cargo && \
    mkdir /root/sproxy/build && \
    cd /root/sproxy/build && \
    cmake .. -DCMAKE_BUILD_TYPE=RelWithDebInfo && \
    make VERBOSE=1 && \
    cpack -G DEB && \
    true

FROM debian:13 as worker
COPY --from=0 /root/sproxy/build/sproxy-*-Linux.deb .
RUN apt-get update && \
    apt-get install -y --no-install-recommends openssl iproute2 ca-certificates libjson-c5 zlib1g libelf1 libreadline8 liburing2 libjemalloc2 libxml2 && \
    dpkg -i sproxy-*-Linux.deb && \
    apt-get clean

EXPOSE 80
WORKDIR /var/lib/sproxy
CMD ["sproxy", "--http", "80"]
