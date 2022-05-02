#Cmake file for library prot.a
#Author:   choury
#Created:  2017/2/11

set(http3_src
        http3.cpp
        qpack.cpp
        )

target_sources(prot PRIVATE ${http3_src})
