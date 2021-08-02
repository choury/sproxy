#Cmake file for library prot.a
#Author:   choury
#Created:  2017/2/11

set(prot_src
        ep.cpp
        rwer.cpp
        netio.cpp
        sslio.cpp
        ip_pack.cpp)

if(BUILD_RPC)
    set(prot_src ${prot_src} rpc.cpp)
endif()

add_library(prot_base ${prot_src})


add_subdirectory(dns)
add_subdirectory(http)
add_subdirectory(http2)

add_library(prot INTERFACE)
target_link_libraries(prot INTERFACE prot_base dns http http2)
