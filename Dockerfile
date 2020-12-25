FROM debian:10 as builder

LABEL maintainer="zhouwei400@gmail.com"


COPY . /root/sproxy
RUN apt-get  update && \
    apt-get install -y --no-install-recommends  gcc g++ cmake make libssl-dev libz-dev git libjson-c-dev && \
    cd /root/sproxy && \
    cmake . && \
    make sproxy VERBOSE=1 && \
    cpack -G DEB && \
    true

FROM debian:10 as worker
COPY --from=0 /root/sproxy/sproxy-*-Linux.deb .
RUN apt-get update && \
    apt-get install -y --no-install-recommends openssl libjson-c3 zlib1g && \
    dpkg -i sproxy-*-Linux.deb

EXPOSE 80
WORKDIR /var/lib/sproxy
CMD ["sproxy"]
