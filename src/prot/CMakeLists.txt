#Cmake file for library prot.a
#Author:   choury
#Created:  2017/2/11

set(prot_src ep.cpp rwer.cpp netio.cpp sslio.cpp ip_pack.cpp dns.cpp resolver.cpp hpack.cpp http.cpp http2.cpp http_pack.cpp)

if(BUILD_RPC)
    set(prot_src ${prot_src} rpc.cpp)
endif()

add_library(prot ${prot_src})
