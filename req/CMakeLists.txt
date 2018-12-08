#Cmake file for library req.a
#Author:   choury
#Created:  2017/2/11


include_directories(${PROJECT_SOURCE_DIR})

if(NOT APPLE)
    add_library(req requester.cpp  guest.cpp guest_sni.cpp guest2.cpp guest_vpn.cpp)
else()
    add_library(req requester.cpp  guest.cpp guest_sni.cpp guest2.cpp)
endif()

