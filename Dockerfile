# This dockerfile uses the debian:sid image

# Base image to use, this must be set as the first line
FROM debian:sid

# Maintainer: docker_user <docker_user at email.com> (@docker_user)
MAINTAINER choury zhouwei400@gmail.com

# Commands to update the image
RUN apt-get update && apt-get -y install gcc g++ cmake make unzip libssl-dev libjson-c-dev wget
WORKDIR /root
RUN wget "https://github.com/choury/sproxy/archive/master.zip" && unzip master.zip && rm master.zip
WORKDIR /root/sproxy-master
RUN cmake . && make
#COPY keys /root/keys/

ENV SPROXY_USER choury
ENV SPROXY_PASS choury
# Commands when creating a new container
EXPOSE 80
RUN wget https://gist.githubusercontent.com/choury/c42dd14f1f1bfb9401b5f2b4986cb9a9/raw/sites.list
CMD  ./sproxy -s "${SPROXY_USER}:${SPROXY_PASS}" ssl://l.choury.com

