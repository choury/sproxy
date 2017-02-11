#Cmake file for library req.a
#Author:   choury
#Created:  2017/2/11


INCLUDE_DIRECTORIES(${PROJECT_SOURCE_DIR})

ADD_LIBRARY(req requester.cpp  guest.cpp guest_s.cpp guest_sni.cpp guest_s2.cpp)

