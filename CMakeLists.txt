project(sproxy)

set(CMAKE_C_FLAGS "-Wall -ggdb")
set(CMAKE_CXX_FLAGS "-std=c++11 -Wall -ggdb")

add_executable(sproxy_server http.cpp 
spdy.cpp guest_spdy.cpp spdy_zlib.c
host.cpp guest.cpp peer.cpp guest_s.cpp 
lib.c parse.cpp server.cpp net.c dns.cpp)



add_executable(sproxy_client http.cpp 
spdy.cpp proxy_spdy.cpp spdy_zlib.c
peer.cpp guest.cpp host.cpp proxy.cpp 
lib.c parse.cpp client.cpp net.c dns.cpp)

#target_compile_definitions(sproxy_client PUBLIC CLIENT)
SET_TARGET_PROPERTIES(sproxy_client PROPERTIES COMPILE_FLAGS "-DCLIENT")
TARGET_LINK_LIBRARIES(sproxy_client ssl crypto z)
TARGET_LINK_LIBRARIES(sproxy_server ssl crypto z)

install(TARGETS sproxy_client RUNTIME DESTINATION bin)