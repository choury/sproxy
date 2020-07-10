FROM debian:10

MAINTAINER choury zhouwei400@gmail.com

COPY . /root/sproxy
RUN apt-get  update && \
    apt-get install -y --no-install-recommends  gcc g++ cmake make libssl-dev libz-dev && \
    cd /root/sproxy && \
    cmake . && \
    make sproxy VERBOSE=1 && \
    make install && \
    apt-get autoremove -y --purge gcc g++ cmake make && \
    apt-get clean && \
    true

EXPOSE 80
WORKDIR /var/lib/sproxy
CMD ["/usr/local/bin/sproxy"]
