project(sproxy)

add_executable(sproxy_client spdy.c peer.cpp guest.cpp host.cpp proxy.cpp lib.c parse.cpp client.cpp net.c dns.cpp)
add_executable(sproxy_server spdy.c host.cpp guest.cpp proxy.cpp peer.cpp guest_s.cpp lib.c parse.cpp server.cpp net.c dns.cpp)

set(CMAKE_C_FLAGS "-Wall -ggdb")
set(CMAKE_CXX_FLAGS "-std=c++11 -Wall -ggdb")
set(CMAKE_EXE_LINKER_FLAGS "-lssl -lcrypto -lz")

install(TARGETS sproxy_client RUNTIME DESTINATION bin)
