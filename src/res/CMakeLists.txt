#Cmake file for library res.a
#Author:   choury
#Created:  2017/2/11

set(res_src
        responser.cpp
        host.cpp
        proxy2.cpp
        fdns.cpp
        ping.cpp
        uhost.cpp
        file.cpp
        cgi.cpp
        status.cpp
        rproxy2.cpp
        doh.cpp
)

if(HAVE_QUIC)
    set(res_src ${res_src} proxy3.cpp rproxy3.cpp)
endif()

add_library(res ${res_src})
