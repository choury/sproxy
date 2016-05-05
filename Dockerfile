# This dockerfile uses the debian:sid image

# Base image to use, this must be set as the first line
FROM debian:sid

# Maintainer: docker_user <docker_user at email.com> (@docker_user)
MAINTAINER choury zhouwei400@gmail.com

# Commands to update the image
RUN apt-get update && apt-get -y install gcc g++ cmake make git libssl-dev
WORKDIR /root
RUN git clone https://github.com/choury/sproxy
WORKDIR /root/sproxy
RUN  git checkout dtls && cmake . && make sproxy_server
#COPY keys /root/keys/

# Commands when creating a new container
EXPOSE 443
#CMD  ./sproxy_server -k ../keys/ca.pem ../keys/ssl.crt /root/keys/ssl.key
CMD  ./sproxy_server -h

