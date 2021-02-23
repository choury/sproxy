#Cmake file for library req.a
#Author:   choury
#Created:  2017/2/11


set(req_src requester.cpp  guest.cpp guest_sni.cpp guest2.cpp)

if(LINUX OR ANDROID)
    set(req_src ${req_src} guest_vpn.cpp)
endif()

if(NOT ANDROID)
    set(req_src ${req_src} cli.cpp)
endif()

add_library(req  ${req_src})

