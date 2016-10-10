cmake_minimum_required(VERSION 2.8)
project(sproxy)

INCLUDE(CheckCXXCompilerFlag)

CHECK_CXX_COMPILER_FLAG("-std=c++11" HAVE_CXX11)
CHECK_CXX_COMPILER_FLAG("-fsanitize=undefined" HAVE_SAN_UNDEF)

set(CMAKE_REQUIRED_FLAGS "-fsanitize=address")
CHECK_CXX_COMPILER_FLAG("-fsanitize=address" HAVE_SAN_ADDR)
unset(CMAKE_REQUIRED_FLAGS)

if(NOT HAVE_CXX11)
    message(FATAL_ERROR "this project need c++11")
endif()


find_package(OpenSSL 1.0.2 REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})

set(CMAKE_C_FLAGS "-Wall")
set(CMAKE_CXX_FLAGS "-std=c++11 -Wall")

set(CMAKE_C_FLAGS_RELEASE "-O3")
set(CMAKE_CXX_FLAGS_RELEASE "-O3")

set(CMAKE_C_FLAGS_RELWITHDEBINFO "-ggdb")
set(CMAKE_CXX_FLAGS_RELWITHDEBINFO "-ggdb")

set(CMAKE_C_FLAGS_DEBUG "-ggdb -O0")
set(CMAKE_CXX_FLAGS_DEBUG "-ggdb -O0")

if (HAVE_SAN_ADDR)
    set(CMAKE_C_FLAGS_DEBUG "-fsanitize=address ${CMAKE_C_FLAGS_DEBUG}")
    set(CMAKE_CXX_FLAGS_DEBUG "-fsanitize=address ${CMAKE_CXX_FLAGS_DEBUG}")
endif()

if (HAVE_SAN_UNDEF)
    set(CMAKE_C_FLAGS_DEBUG "-fsanitize=undefined ${CMAKE_C_FLAGS_DEBUG}")
    set(CMAKE_CXX_FLAGS_DEBUG "-fsanitize=undefined ${CMAKE_CXX_FLAGS_DEBUG}")
endif()


add_executable(server cgi.cpp file.cpp http.cpp http2.cpp 
hpack.cpp host.cpp guest.cpp peer.cpp guest_s.cpp guest_s2.cpp dtls.cpp
lib.c parse.cpp server.cpp net.c dns.cpp responser.cpp requester.cpp)

set_target_properties(server PROPERTIES OUTPUT_NAME "sproxy_server") 
target_link_libraries(server ${OPENSSL_LIBRARIES} dl)


add_executable(client http.cpp http2.cpp hpack.cpp
peer.cpp guest.cpp guest_sni.cpp host.cpp proxy.cpp proxy2.cpp dtls.cpp
lib.c parse.cpp client.cpp net.c dns.cpp tls.c responser.cpp requester.cpp)

#target_compile_definitions(sproxy_client PUBLIC CLIENT)
set_target_properties(client PROPERTIES COMPILE_FLAGS "-DCLIENT")
set_target_properties(client PROPERTIES OUTPUT_NAME "sproxy_client") 

target_link_libraries(client ${OPENSSL_LIBRARIES} dl)

install(TARGETS client RUNTIME DESTINATION bin)


add_library(demo SHARED cgidemo.cpp)
set_target_properties(demo PROPERTIES OUTPUT_NAME "demo") 
