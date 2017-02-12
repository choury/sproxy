#Cmake file for library prot.a
#Author:   choury
#Created:  2017/2/11


INCLUDE_DIRECTORIES(${PROJECT_SOURCE_DIR})

ADD_LIBRARY(prot ip_packet.c hpack.cpp http.cpp http2.cpp parse.cpp)

