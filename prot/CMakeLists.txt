#Cmake file for library prot.a
#Author:   choury
#Created:  2017/2/11


include_directories(${PROJECT_SOURCE_DIR})

add_library(prot ip_pack.cpp dns.cpp hpack.cpp http.cpp http2.cpp http_pack.cpp)

