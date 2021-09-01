#Cmake file for library prot.a
#Author:   choury
#Created:  2017/2/11

set(prot_src
        ep.cpp
        rwer.cpp
        netio.cpp
        sslio.cpp
        ip_pack.cpp
        tls.c)

if(BUILD_RPC)
    set(prot_src ${prot_src} rpc.cpp)
endif()

add_library(prot_base ${prot_src})


add_subdirectory(dns)
add_subdirectory(http)
add_subdirectory(http2)
add_subdirectory(quic)
add_subdirectory(http3)

add_library(prot INTERFACE)
target_link_libraries(prot INTERFACE prot_base http3 quic http2 http dns)
