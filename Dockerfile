FROM debian:12 as builder

LABEL maintainer="zhouwei400@gmail.com"


COPY . /root/sproxy
RUN apt-get  update && \
    apt-get install -y --no-install-recommends  gcc g++ cmake make pkg-config libssl-dev libz-dev git libelf-dev libjson-c-dev libreadline-dev && \
    mkdir /root/sproxy/build && \
    cd /root/sproxy/build && \
    cmake .. && \
    make VERBOSE=1 && \
    cpack -G DEB && \
    true

FROM debian:12 as worker
COPY --from=0 /root/sproxy/build/sproxy-*-Linux.deb .
RUN apt-get update && \
    apt-get install -y --no-install-recommends openssl libjson-c5 zlib1g && \
    dpkg -i sproxy-*-Linux.deb

EXPOSE 80
WORKDIR /var/lib/sproxy
CMD ["sproxy"]
