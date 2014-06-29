project(sproxy)

add_executable(sproxy_client peer.cpp lib.c parse.cpp threadpool.cpp client.cpp net.c)
add_executable(sproxy_server peer.cpp lib.c parse.cpp threadpool.cpp server.cpp net.c)

set(CMAKE_C_FLAGS "-Wall -g")
set(CMAKE_CXX_FLAGS "-std=c++11 -Wall -g")
set(CMAKE_EXE_LINKER_FLAGS "-lpthread -lssl -lcrypto")

install(TARGETS sproxy_server RUNTIME DESTINATION bin)
