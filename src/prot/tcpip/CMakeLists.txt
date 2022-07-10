#Cmake file for library tcpip.a
#Author:   choury
#Created:  2022/7/8

set(tcpip_src
        ip_pack.cpp
        ipbase.cpp
        tcp.cpp
        udp.cpp
        icmp.cpp
        tunio.cpp
        )

target_sources(prot PRIVATE ${tcpip_src})
