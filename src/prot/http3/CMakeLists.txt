#Cmake file for library prot.a
#Author:   choury
#Created:  2017/2/11

set(http3_src
        http3.cpp
        qpack.cpp
        )

add_library(http3 ${http3_src})
