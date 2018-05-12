# Base image to use, this must be set as the first line
FROM alpine

# Maintainer: docker_user <docker_user at email.com> (@docker_user)
MAINTAINER choury zhouwei400@gmail.com

# Commands to update the image
COPY . /root/sproxy

RUN apk update && \
    apk add gcc g++ binutils-gold cmake make wget libexecinfo-dev openssl-dev libgcc libstdc++ ca-certificates && \
    cd /root/sproxy && \
    cmake . && \
    make sproxy VERBOSE=1 && \
    wget https://gist.githubusercontent.com/choury/c42dd14f1f1bfb9401b5f2b4986cb9a9/raw/sites.list && \
    apk del gcc g++ binutils-gold cmake make wget
#COPY keys /root/keys/

# Commands when creating a new container
EXPOSE 80
WORKDIR /root/sproxy
ENTRYPOINT ["./sproxy"]
