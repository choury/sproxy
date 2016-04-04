project(sproxy)
cmake_minimum_required(VERSION 2.8)

find_package(OpenSSL)

set(CMAKE_C_FLAGS "-Wall -ggdb -O0")
set(CMAKE_CXX_FLAGS "-std=c++11 -Wall -ggdb -O0")

add_executable(sproxy_server cgi.cpp file.cpp http.cpp http2.cpp 
hpack.cpp host.cpp guest.cpp peer.cpp guest_s.cpp guest_s2.cpp
lib.c parse.cpp server.cpp net.c dns.cpp)



add_executable(sproxy_client http.cpp http2.cpp hpack.cpp
peer.cpp guest.cpp guest_sni.cpp host.cpp proxy.cpp proxy2.cpp
lib.c parse.cpp client.cpp net.c dns.cpp tls.c)


#target_compile_definitions(sproxy_client PUBLIC CLIENT)
set_target_properties(sproxy_client PROPERTIES COMPILE_FLAGS "-DCLIENT")
target_link_libraries(sproxy_client ssl crypto)
target_link_libraries(sproxy_server ssl crypto dl)

install(TARGETS sproxy_client RUNTIME DESTINATION bin)


add_library(demo SHARED cgidemo.cpp)
set_target_properties(demo PROPERTIES OUTPUT_NAME "demo") 
