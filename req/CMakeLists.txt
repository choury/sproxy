#Cmake file for library req.a
#Author:   choury
#Created:  2017/2/11


include_directories(${PROJECT_SOURCE_DIR})

add_library(req requester.cpp  guest.cpp guest_s.cpp guest_sni.cpp guest_s2.cpp guest_vpn.cpp)

