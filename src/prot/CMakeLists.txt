#Cmake file for library prot.a
#Author:   choury
#Created:  2017/2/11

set(prot_src
        ep.cpp
        rwer.cpp
        netio.cpp
        sslio.cpp
        memio.cpp
        tls.c
        multimsg.c
        rpc.cpp)

add_library(prot ${prot_src})


add_subdirectory(dns)
add_subdirectory(http)
add_subdirectory(http2)
add_subdirectory(socks5)
add_subdirectory(tcpip)
if(HAVE_QUIC)
    add_subdirectory(quic)
    add_subdirectory(http3)
endif()

#add_library(prot INTERFACE)
#target_link_libraries(prot INTERFACE prot_base http3 quic http2 http dns)
