#Cmake file for library prot.a
#Author:   choury
#Created:  2017/2/11

set(http_src
        http.cpp
        http_pack.cpp
        )

add_library(http ${http_src})
