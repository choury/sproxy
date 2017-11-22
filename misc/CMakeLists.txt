#Cmake file for library misc.a
#Author:   choury
#Created:  2017/2/11


include_directories(${PROJECT_SOURCE_DIR})

add_library(misc dtls.cpp job.cpp net.c tls.c util.c strategy.cpp rudp.cpp)

