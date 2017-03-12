cmake_minimum_required(VERSION 2.8)
project(sproxy)

INCLUDE(CheckCXXCompilerFlag)

#SET(CMAKE_FIND_LIBRARY_SUFFIXES ".a")
#SET(BUILD_SHARED_LIBRARIES OFF)
#SET(CMAKE_EXE_LINKER_FLAGS "-static")

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

set(CMAKE_C_FLAGS "-Wall -fPIC")
set(CMAKE_CXX_FLAGS "-std=c++11 -Wall -fPIC")

set(CMAKE_C_FLAGS_RELEASE "-O3 -DNDEBUG")
set(CMAKE_CXX_FLAGS_RELEASE "-O3 -DNDEBUG")

set(CMAKE_C_FLAGS_RELWITHDEBINFO "-ggdb -DNDEBUG")
set(CMAKE_CXX_FLAGS_RELWITHDEBINFO "-ggdb -DNDEBUG")

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



ADD_SUBDIRECTORY(misc)
ADD_SUBDIRECTORY(prot)
ADD_SUBDIRECTORY(req)
ADD_SUBDIRECTORY(res)

INCLUDE_DIRECTORIES(${PROJECT_SOURCE_DIR})

add_executable(sproxy main.cpp peer.cpp)
set_target_properties(sproxy PROPERTIES OUTPUT_NAME "sproxy")
target_link_libraries(sproxy ${OPENSSL_LIBRARIES} dl req res prot misc)


install(TARGETS sproxy RUNTIME DESTINATION bin)

add_library(sproxy_vpn SHARED vpn.cpp peer.cpp)
set_target_properties(sproxy_vpn PROPERTIES OUTPUT_NAME "sproxy_vpn") 
target_link_libraries(sproxy_vpn req res prot misc)

add_library(demo SHARED cgidemo.cpp)
set_target_properties(demo PROPERTIES OUTPUT_NAME "demo") 

add_executable(vpn vpndemo.c)
set_target_properties(vpn PROPERTIES OUTPUT_NAME "vpndemo")
target_link_libraries(vpn asan ${OPENSSL_LIBRARIES} sproxy_vpn)
