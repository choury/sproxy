#Cmake file for library prot.a
#Author:   choury
#Created:  2017/2/11

set(http_src
        http.cpp
        http_header.cpp
        http_def.cpp
        http_code.c
        )

add_library(http ${http_src})
