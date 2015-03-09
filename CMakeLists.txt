project(sproxy)

set(CMAKE_C_FLAGS "-Wall -ggdb")
set(CMAKE_CXX_FLAGS "-std=c++11 -Wall -ggdb")

add_executable(sproxy_server cgi.cpp file.cpp http.cpp 
spdy.cpp guest_spdy.cpp spdy_zlib.c
host.cpp guest.cpp peer.cpp guest_s.cpp 
lib.c parse.cpp server.cpp net.c dns.cpp)



add_executable(sproxy_client spdy_zlib.c http.cpp 
peer.cpp guest.cpp host.cpp proxy.cpp 
lib.c parse.cpp client.cpp net.c dns.cpp)


#target_compile_definitions(sproxy_client PUBLIC CLIENT)
set_target_properties(sproxy_client PROPERTIES COMPILE_FLAGS "-DCLIENT")
target_link_libraries(sproxy_client ssl crypto z)
target_link_libraries(sproxy_server ssl crypto z dl)

install(TARGETS sproxy_client RUNTIME DESTINATION bin)
