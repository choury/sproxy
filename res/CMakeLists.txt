#Cmake file for library res.a
#Author:   choury
#Created:  2017/2/11


include_directories(${PROJECT_SOURCE_DIR})


if(ENABLE_GZIP_TEST)
    add_library(res responser.cpp host.cpp proxy2.cpp fdns.cpp ping.cpp file.cpp cgi.cpp status.cpp gzip_test.cpp)
else()
    add_library(res responser.cpp host.cpp proxy2.cpp fdns.cpp ping.cpp file.cpp cgi.cpp status.cpp)
endif()
