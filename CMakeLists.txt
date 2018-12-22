cmake_minimum_required(VERSION 2.8)
project(sproxy)

INCLUDE(CheckCXXCompilerFlag)
set(CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake")

#SET(CMAKE_FIND_LIBRARY_SUFFIXES ".a")
#SET(BUILD_SHARED_LIBRARIES OFF)
#SET(CMAKE_EXE_LINKER_FLAGS "-static")

CHECK_CXX_COMPILER_FLAG("-std=c++11" HAVE_CXX11)
CHECK_CXX_COMPILER_FLAG("-std=c++14" HAVE_CXX14)
CHECK_CXX_COMPILER_FLAG("-std=c++17" HAVE_CXX17)
CHECK_CXX_COMPILER_FLAG("-std=c++2a" HAVE_CXX2a)

if(NOT HAVE_CXX11)
    message(FATAL_ERROR "this project need c++11")
endif()

CHECK_CXX_SOURCE_COMPILES("
#include <list>
using namespace std; 
int main(){
    list<int> a;
    a.insert(list<int>::const_iterator(a.begin()), 0);
    return 0;
}" NO_CONST_ITERATOR_BUG)



if(ANDROID_NDK)
    set(OPENSSL_ROOT_DIR ${OPENSSL_ROOT}/${ANDROID_ABI})
    set(OPENSSL_INCLUDE_DIR ${OPENSSL_ROOT_DIR}/include)
    set(OPENSSL_LIBRARIES ${OPENSSL_ROOT_DIR}/lib)
    set(OPENSSL_CRYPTO_LIBRARY ${OPENSSL_LIBRARIES}/libcrypto.a)
    set(OPENSSL_SSL_LIBRARY ${OPENSSL_LIBRARIES}/libssl.a)

    find_library(log-lib log)
    find_package(OpenSSL REQUIRED IMPORTED)

    string(REGEX REPLACE "-[^-]+$" ""  ANDROID_TARGET ${ANDROID_TOOLCHAIN_NAME})
    set(CMAKE_C_FLAGS "-isystem ${ANDROID_NDK}/sysroot/usr/include/${ANDROID_TARGET}")
    set(CMAKE_CXX_FLAGS "-isystem ${ANDROID_NDK}/sysroot/usr/include/${ANDROID_TARGET}")
else()
    CHECK_CXX_COMPILER_FLAG("-fsanitize=undefined" HAVE_SAN_UNDEF)
    set(CMAKE_REQUIRED_FLAGS "-fsanitize=address")
    CHECK_CXX_COMPILER_FLAG("-fsanitize=address" HAVE_SAN_ADDR)
    unset(CMAKE_REQUIRED_FLAGS)

    find_package(OpenSSL 1.0.2 REQUIRED)

    If("${CMAKE_SYSTEM}" MATCHES "Linux")
        set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fuse-ld=gold")
        set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -fuse-ld=gold")
    endif()
endif()

include_directories(${OPENSSL_INCLUDE_DIR})

if(NOT APPLE)
    find_package(JSON-C)
    if(JSON-C_FOUND)
        set(BUILD_CGI TRUE)
    else()
        message(WARNING "json-c not found, disable webui")
    endif()
endif()



set(CMAKE_C_FLAGS "-Wall -Wextra -fPIC ${CMAKE_C_FLAGS}")
set(CMAKE_CXX_FLAGS "-std=c++11 -Wall -Wextra -fPIC ${CMAKE_CXX_FLAGS}")

execute_process(COMMAND uname -r
    OUTPUT_VARIABLE KERNEL_NAME
    OUTPUT_STRIP_TRAILING_WHITESPACE
)

if(KERNEL_NAME MATCHES ".*-Microsoft")
    message("wsl kernel: ${KERNEL_NAME}")
    set(CMAKE_CXX_FLAGS "-DWSL ${CMAKE_CXX_FLAGS}")
endif()

if(NOT NO_CONST_ITERATOR_BUG)
    message(WARNING "have const_iterator insert bug, see https://gcc.gnu.org/bugzilla/show_bug.cgi?id=55817")
    set(CMAKE_CXX_FLAGS "-DHAVE_CONST_ITERATOR_BUG ${CMAKE_CXX_FLAGS}")
endif()

find_package(ZLIB)
if(NOT ZLIB_FOUND)
    message(WARNING "zlib not found, disable gzip test")
else()
    set(CMAKE_CXX_FLAGS "-DENABLE_GZIP_TEST ${CMAKE_CXX_FLAGS}")
    set(ENABLE_GZIP_TEST TRUE)
endif()

find_package(Backtrace)
configure_file(common.h.in ${PROJECT_SOURCE_DIR}/common.h ESCAPE_QUOTES)

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

if(BUILD_CGI)
    set(CMAKE_CXX_FLAGS "-DENABLE_CGI ${CMAKE_CXX_FLAGS}")
    add_subdirectory(cgi)
endif()
add_subdirectory(misc)
add_subdirectory(prot)
add_subdirectory(req)
add_subdirectory(res)

set(SPROXY_LIBS  req res prot misc ${OPENSSL_LIBRARIES} dl)
if(Backtrace_FOUND)
    include_directories(${Backtrace_INCLUDE_DIRS})
    set(SPROXY_LIBS ${SPROXY_LIBS} ${Backtrace_LIBRARIES})
endif()

if(ZLIB_FOUND)
    set(SPROXY_LIBS ${SPROXY_LIBS} z)
endif()

include_directories(${PROJECT_SOURCE_DIR})

if(NOT ANDROID_NDK)
    add_executable(sproxy main.cpp base.cpp)
    set_target_properties(sproxy PROPERTIES OUTPUT_NAME "sproxy")
    target_link_libraries(sproxy ${SPROXY_LIBS})

    if(NOT APPLE)
        add_library(sproxy_vpn SHARED vpn.cpp base.cpp)
        set_target_properties(sproxy_vpn PROPERTIES OUTPUT_NAME "sproxy_vpn")
        target_link_libraries(sproxy_vpn ${SPROXY_LIBS})

        add_executable(vpn vpndemo.c)
        set_target_properties(vpn PROPERTIES OUTPUT_NAME "vpndemo")
        target_link_libraries(vpn sproxy_vpn)

        install(TARGETS sproxy_vpn LIBRARY DESTINATION lib)
        install(TARGETS vpn RUNTIME DESTINATION bin)
    endif()
    install(TARGETS sproxy RUNTIME DESTINATION bin)
else()
    add_library(sproxy_vpn SHARED vpn.cpp base.cpp com_choury_sproxy_Service.cpp)
    set_target_properties(sproxy_vpn PROPERTIES OUTPUT_NAME "sproxy_vpn")
    target_link_libraries(sproxy_vpn ${SPROXY_LIBS} ${log-lib})
endif()
