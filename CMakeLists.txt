project(sproxy)

add_executable(sproxy_client peer.cpp guest.cpp host.cpp proxy.cpp lib.c parse.cpp threadpool.cpp client.cpp net.c dns.cpp)
add_executable(sproxy_server host.cpp guest.cpp proxy.cpp peer.cpp guest_s.cpp lib.c parse.cpp threadpool.cpp server.cpp net.c dns.cpp)

set(CMAKE_C_FLAGS "-Wall -g")
set(CMAKE_CXX_FLAGS "-std=c++11 -Wall -g")
set(CMAKE_EXE_LINKER_FLAGS "-lpthread -lssl -lcrypto")

install(TARGETS sproxy_client RUNTIME DESTINATION bin)
