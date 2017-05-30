#Cmake file for library res.a
#Author:   choury
#Created:  2017/2/11


include_directories(${PROJECT_SOURCE_DIR})

add_library(res responser.cpp host.cpp proxy.cpp proxy2.cpp file.cpp cgi.cpp fdns.cpp)

