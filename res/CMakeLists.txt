#Cmake file for library res.a
#Author:   choury
#Created:  2017/2/11


INCLUDE_DIRECTORIES(${PROJECT_SOURCE_DIR})

ADD_LIBRARY(res responser.cpp host.cpp proxy.cpp proxy2.cpp file.cpp cgi.cpp fdns.cpp)

