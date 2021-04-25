#Cmake file for library res.a
#Author:   choury
#Created:  2017/2/11


if(ZLIB_FOUND)
    add_library(res responser.cpp host.cpp proxy2.cpp fdns.cpp ping.cpp file.cpp cgi.cpp status.cpp gzip_test.cpp)
else()
    add_library(res responser.cpp host.cpp proxy2.cpp fdns.cpp ping.cpp file.cpp cgi.cpp status.cpp)
endif()
