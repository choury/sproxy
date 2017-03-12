#Cmake file for library misc.a
#Author:   choury
#Created:  2017/2/11


INCLUDE_DIRECTORIES(${PROJECT_SOURCE_DIR})

ADD_LIBRARY(misc dns.cpp dtls.cpp job.cpp net.c tls.c util.c strategy.cpp)

