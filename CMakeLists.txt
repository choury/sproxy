project(sproxy)

set(CMAKE_C_FLAGS "-Wall -ggdb")
set(CMAKE_CXX_FLAGS "-std=c++11 -Wall -ggdb")
set(CMAKE_EXE_LINKER_FLAGS "-lssl -lcrypto -lz")

add_executable(sproxy_server 
spdy.cpp guest_spdy.cpp spdy_zlib.c
host.cpp guest.cpp peer.cpp guest_s.cpp 
lib.c parse.cpp server.cpp net.c dns.cpp)



add_executable(sproxy_client 
spdy.cpp proxy_spdy.cpp spdy_zlib.c
peer.cpp guest.cpp host.cpp proxy.cpp 
lib.c parse.cpp client.cpp net.c dns.cpp)

SET_TARGET_PROPERTIES(sproxy_client PROPERTIES COMPILE_FLAGS "-DCLIENAT")

install(TARGETS sproxy_client RUNTIME DESTINATION bin)