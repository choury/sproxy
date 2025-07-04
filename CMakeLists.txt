cmake_minimum_required(VERSION 3.13)
cmake_policy(VERSION 3.13)
project(sproxy)

message(STATUS "Building for ${CMAKE_SYSTEM_PROCESSOR}")
set(CMAKE_MACOSX_RPATH TRUE)
set(CMAKE_SKIP_INSTALL_ALL_DEPENDENCY TRUE)

if(${CMAKE_SYSTEM_NAME} MATCHES "Linux")
    set(LINUX TRUE)
endif()

INCLUDE(CheckCCompilerFlag)
INCLUDE(CheckCXXCompilerFlag)
INCLUDE(CheckSymbolExists)
INCLUDE(CheckCXXSymbolExists)
INCLUDE(CheckFunctionExists)
INCLUDE(CMakePushCheckState)
set(CMAKE_EXPORT_COMPILE_COMMANDS TRUE)
set(CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake")


if(ANDROID)
    if(NOT DEFINED ENV{TERMUX_VERSION})
        set(ANDROID_APP TRUE CACHE BOOL "Build for android app")
    else()
        set(TERMUX TRUE CACHE BOOL "Build in termux")
    endif()
endif()

if(STATIC_BUILD)
    SET(CMAKE_FIND_LIBRARY_SUFFIXES ".a")
    SET(BUILD_SHARED_LIBRARIES OFF)
    SET(CMAKE_EXE_LINKER_FLAGS "-static")
endif()

CHECK_C_COMPILER_FLAG("-std=gnu99" HAVE_C99)
CHECK_CXX_COMPILER_FLAG("-std=c++17" HAVE_CXX17)
CHECK_CXX_COMPILER_FLAG("-std=c++20" HAVE_CXX20)

if(NOT HAVE_CXX17 OR NOT HAVE_C99)
    message(FATAL_ERROR "this project need c++17 and c99")
endif()

set(VERSION "v0.0.0")
find_package(Git)
if(Git_FOUND)
    execute_process(COMMAND ${GIT_EXECUTABLE} describe --tag --dirty --long --always
        WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
        OUTPUT_VARIABLE VERSION
        ERROR_VARIABLE GITERROR
        RESULT_VARIABLE GITRET
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )
    if(GITRET)
        message(FATAL_ERROR "Git Return: ${GITRET}, Error: ${GITERROR}")
    endif()
endif()
#parse the version information into pieces.
string(REGEX REPLACE "^v([0-9]+)\\..*" "\\1" PROJECT_VERSION_MAJOR "${VERSION}")
string(REGEX REPLACE "^v[0-9]+\\.([0-9]+).*" "\\1" PROJECT_VERSION_MINOR "${VERSION}")
string(REGEX REPLACE "^v[0-9]+\\.[0-9]+\\-([0-9]+).*" "\\1" PROJECT_VERSION_PATCH "${VERSION}")
message(STATUS "Set VERSION: ${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR}.${PROJECT_VERSION_PATCH}")

set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)

if(${CMAKE_BUILD_TYPE} MATCHES "Debug" AND NOT ANDROID_APP AND NOT STATIC_BUILD)
    CHECK_CXX_COMPILER_FLAG("-fsanitize=undefined" HAVE_SAN_UNDEF)
    set(CMAKE_REQUIRED_FLAGS "-fsanitize=address")
    CHECK_CXX_COMPILER_FLAG("-fsanitize=address" HAVE_SAN_ADDR)
    unset(CMAKE_REQUIRED_FLAGS)
endif()

CHECK_CXX_SOURCE_COMPILES("
#include <list>
using namespace std;
int main(){
    list<int> a;
    a.insert(list<int>::const_iterator(a.begin()), 0);
    return 0;
}" NO_CONST_ITERATOR_BUG)

CHECK_CXX_SOURCE_COMPILES("
#define _BSD_SOURCE
#include <netinet/tcp.h>
#include <netinet/udp.h>
int main(){
    struct tcphdr t1 = {.th_sport = 0};
    struct udphdr t2 = {.uh_sport = 0};
    return 0;
}" NO_GNU_SOURCE_BUG)

CHECK_CXX_SOURCE_COMPILES("
#include <atomic>
int main() {
    std::atomic<int64_t> i(0);
    i++;
    return 0;
}" HAVE_BUILTIN_ATOMIC)

if (NOT HAVE_BUILTIN_ATOMIC)
    message(STATUS "No built-in atomic, using libatomic.")
    set(CMAKE_EXE_LINKER_FLAGS "-latomic ${CMAKE_EXE_LINKER_FLAGS}")
endif()

set(HAVE_VPN TRUE CACHE BOOL "Have VPN")
set(HAVE_RPC TRUE CACHE BOOL "Have RPC")
if(ANDROID_APP)
    set(THIRDPATY_ROOT_DIR ${THIRDPATY_ROOT}/${ANDROID_ABI})
    set(JSON-C_INCLUDE_DIRS ${THIRDPATY_ROOT_DIR}/include/json-c)
    set(JSON-C_LIBRARIES ${THIRDPATY_ROOT_DIR}/lib/libjson-c.a)

    set(OPENSSL_INCLUDE_DIR ${THIRDPATY_ROOT_DIR}/include)
    set(OPENSSL_LIBRARIES ${THIRDPATY_ROOT_DIR}/lib)
    set(OPENSSL_CRYPTO_LIBRARY ${OPENSSL_LIBRARIES}/libcrypto.a)
    set(OPENSSL_SSL_LIBRARY ${OPENSSL_LIBRARIES}/libssl.a)

    find_library(log-lib log)
    # download ca-bundle.crt from https://curl.se/ca/cacert.pem
    set(SPROXY_CA_BUNDLE "/cacert.pem" CACHE STRING "CA bundle")
else()
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(JSON-C REQUIRED json-c)
    link_directories(${JSON-C_LIBRARY_DIRS})
    find_package(Readline)
    pkg_check_modules(LIBBPF libbpf>=1.0.0)
    pkg_check_modules(LIBURING liburing>=2.4)
    if(READLINE_FOUND)
        if(STATIC_BUILD)
            message(WARNING "disable client with static build")
        else()
            set(HAVE_CLIENT TRUE CACHE BOOL "Have Client")
            include_directories(${Readline_INCLUDE_DIR})
        endif()
    else()
        message(WARNING "readline not found, disable client")
    endif()
    pkg_check_modules(LIBELF libelf)
    set(SEARCH_CA_BUNDLE_PATHS
            /etc/ssl/certs/ca-certificates.crt
            /etc/pki/tls/certs/ca-bundle.crt
            /etc/ssl/ca-bundle.pem
            /etc/ssl/cert.pem
            /etc/pki/tls/cacert.pem
            /etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem
            /etc/pki/tls/cacert.pem
            /usr/share/ssl/certs/ca-bundle.crt
            /usr/local/etc/openssl/cert.pem
            /usr/local/share/certs/ca-root-nss.crt
            /data/data/com.termux/files/usr/etc/tls/cert.pem
    )

    foreach(SEARCH_CA_BUNDLE_PATH ${SEARCH_CA_BUNDLE_PATHS})
        if(EXISTS "${SEARCH_CA_BUNDLE_PATH}")
            message(STATUS "Found CA bundle: ${SEARCH_CA_BUNDLE_PATH}")
            set(SPROXY_CA_BUNDLE "${SEARCH_CA_BUNDLE_PATH}" CACHE STRING "CA bundle")
            break()
        endif()
    endforeach()
endif()

if(APPLE)
    set(HAVE_VPN FALSE CACHE BOOL "Have VPN" FORCE)
    find_library(CORE_LIBRARY CoreFoundation)
    find_library(SYSCONF_LIBRARY SystemConfiguration)
endif()

include_directories(${JSON-C_INCLUDE_DIRS})
if(USE_BORINGSSL)
    find_package(OpenSSL REQUIRED)
else()
    find_package(OpenSSL 1.1.1 REQUIRED)
endif()
include_directories(${OPENSSL_INCLUDE_DIR})

cmake_push_check_state()
set(CMAKE_REQUIRED_INCLUDES   "${OPENSSL_INCLUDE_DIR}")
set(CMAKE_REQUIRED_LIBRARIES  "${OPENSSL_LIBRARIES}" ${CMAKE_THREAD_LIBS_INIT} dl)
CHECK_CXX_SYMBOL_EXISTS(SSL_set_quic_method "openssl/ssl.h" HAVE_QUIC)
cmake_pop_check_state()

if(USE_BORINGSSL AND NOT HAVE_QUIC)
    message(FATAL_ERROR "wrong boringssl version, need quic support")
endif()

set(CMAKE_C_FLAGS "-std=gnu99 -Wall -Wextra -fPIC -fno-omit-frame-pointer ${CMAKE_C_FLAGS}")
if (HAVE_CXX20)
    set(CMAKE_CXX_FLAGS "-std=c++20 -Wall -Wextra -fPIC -fno-omit-frame-pointer ${CMAKE_CXX_FLAGS}")
else()
    set(CMAKE_CXX_FLAGS "-std=c++17 -Wall -Wextra -fPIC -fno-omit-frame-pointer ${CMAKE_CXX_FLAGS}")
endif()

if(APPLE)
    set(CMAKE_EXE_LINKER_FLAGS "-Wl,-export_dynamic ${CMAKE_EXE_LINKER_FLAGS}")
    set(CMAKE_SHARED_LINKER_FLAGS "-undefined dynamic_lookup ${CMAKE_SHARED_LINKER_FLAGS}")
else()
    set(CMAKE_EXE_LINKER_FLAGS "-rdynamic ${CMAKE_EXE_LINKER_FLAGS}")
endif()

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

if(NOT NO_GNU_SOURCE_BUG)
    message(WARNING "have libstdc++ gnu_source bug, see https://gcc.gnu.org/bugzilla/show_bug.cgi?id=11196")
    set(CMAKE_CXX_FLAGS "-DHAVE_GUN_SOURCE_BUG ${CMAKE_CXX_FLAGS}")
endif()

find_package(ZLIB)
if(ZLIB_FOUND)
    set(HAVE_ZLIB TRUE CACHE BOOL "Have ZLIB")
else()
    message(WARNING "zlib not found, disable gzip test")
endif()

if(LIBELF_FOUND)
    set(HAVE_ELF TRUE CACHE BOOL "Have ELF")
endif()

find_package(Backtrace)

set(CMAKE_C_FLAGS_RELEASE "-O2 -g -DNDEBUG")
set(CMAKE_CXX_FLAGS_RELEASE "-O2 -g -DNDEBUG")

set(CMAKE_C_FLAGS_DEBUG "-O0 -ggdb3")
set(CMAKE_CXX_FLAGS_DEBUG "-O0 -ggdb3")

if (HAVE_SAN_ADDR AND NOT ANDROID_APP)
    set(CMAKE_C_FLAGS_DEBUG "-fsanitize=address ${CMAKE_C_FLAGS_DEBUG}")
    set(CMAKE_CXX_FLAGS_DEBUG "-fsanitize=address ${CMAKE_CXX_FLAGS_DEBUG}")

    set(CMAKE_EXE_LINKER_FLAGS_DEBUG "${CMAKE_EXE_LINKER_FLAGS_DEBUG} -fsanitize=address")
    set(CMAKE_SHARED_LINKER_FLAGS_DEBUG "${CMAKE_SHARED_LINKER_FLAGS_DEBUG} -fsanitize=address")
endif()

if (HAVE_SAN_UNDEF AND APPLE) #we meet some issue about member function point with ubsan of gcc
    set(CMAKE_C_FLAGS_DEBUG "-fsanitize=undefined ${CMAKE_C_FLAGS_DEBUG}")
    set(CMAKE_CXX_FLAGS_DEBUG "-fsanitize=undefined ${CMAKE_CXX_FLAGS_DEBUG}")

    set(CMAKE_EXE_LINKER_FLAGS_DEBUG "${CMAKE_EXE_LINKER_FLAGS_DEBUG} -fsanitize=undefined")
    set(CMAKE_SHARED_LINKER_FLAGS_DEBUG "${CMAKE_SHARED_LINKER_FLAGS_DEBUG} -fsanitize=address")
endif()

if (CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fuse-ld=gold -Wl,--rosegment")
    set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -fuse-ld=gold -Wl,--rosegment")
endif()

find_program(CARGO_EXECUTABLE cargo)
find_program(RUSTC_EXECUTABLE rustc)

if(CARGO_EXECUTABLE AND RUSTC_EXECUTABLE)
    message(STATUS "Found cargo: ${CARGO_EXECUTABLE}")
    message(STATUS "Found rustc: ${RUSTC_EXECUTABLE}")
    set(HAVE_RUST TRUE CACHE BOOL "Have Rust")
else()
    message(STATUS "Rust not found, disable rust cgi")
endif()

find_program(BPFTOOL_EXECUTABLE bpftool /sbin/bpftool /user/sbin/bpftool)
find_program(CLANG_EXECUTABLE clang)
if(BPFTOOL_EXECUTABLE AND CLANG_EXECUTABLE AND LIBBPF_FOUND AND NOT STATIC_BUILD)
    message(STATUS "Found bpftool: ${BPFTOOL_EXECUTABLE}")
    message(STATUS "Found clang: ${CLANG_EXECUTABLE}")
    set(HAVE_BPF TRUE CACHE BOOL "Have Bpf")
else()
    message(STATUS "libbpf not found, disable bpf build")
endif()

if(HAVE_RPC)
    install(DIRECTORY webui DESTINATION /var/lib/sproxy)
else()
    install(DIRECTORY DESTINATION /var/lib/sproxy)
endif()

if(NOT HAVE_QUIC)
    message(WARNING "QUIC support not found, disable http3")
endif()

add_subdirectory(src)
add_subdirectory(systemd)
add_subdirectory(test)

SET(CPACK_SET_DESTDIR "ON")
set(CPACK_RPM_EXCLUDE_FROM_AUTO_FILELIST_ADDITION "/usr/bin;/var;/var/lib;/lib;/lib/systemd;/lib/systemd/system")
set(CPACK_PACKAGE_NAME "${PROJECT_NAME}")
set(CPACK_PACKAGE_VENDOR "choury")
set(CPACK_PACKAGE_DESCRIPTION_FILE "${PROJECT_SOURCE_DIR}/README.md")
set(CPACK_PACKAGE_VERSION_MAJOR "${PROJECT_VERSION_MAJOR}")
set(CPACK_PACKAGE_VERSION_MINOR "${PROJECT_VERSION_MINOR}")
set(CPACK_PACKAGE_VERSION_PATCH "${PROJECT_VERSION_PATCH}")
set(CPACK_PACKAGE_CONTACT "choury zhouwei400@gmail.com")
set(CPACK_SOURCE_GENERATOR "TGZ")
set(CPACK_SOURCE_IGNORE_FILES "${PROJECT_BINARY_DIR};/.git/;.gitignore")

set(CPACK_GENERATOR "ZIP;TGZ")
if(CMAKE_SYSTEM_NAME MATCHES Linux)
    list(APPEND CPACK_GENERATOR "DEB")
    set(CPACK_DEBIAN_PACKAGE_SECTION "application")
    set(CPACK_DEBIAN_PACKAGE_DEPENDS "openssl(>=1.1.1),libjson-c5,zlib1g,libelf1,libreadline8")

    list(APPEND CPACK_GENERATOR "RPM")
    set(CPACK_RPM_PACKAGE_RELEASE "1")
    set(CPACK_RPM_PACKAGE_LICENSE "GPL")
    set(CPACK_RPM_PACKAGE_REQUIRES "openssl >= 1.1.1, json-c, zlib, elfutils-libelf, readline")
endif()

message(STATUS "CPack generators: ${CPACK_GENERATOR}")
include(CPack)
