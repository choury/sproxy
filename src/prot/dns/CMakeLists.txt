#Cmake file for library prot.a
#Author:   choury
#Created:  2017/2/11

set(dns_src
        dns.cpp
        resolver.cpp
        )

add_library(dns ${dns_src})

add_executable(dns_test dns_test.cpp dns.cpp)
