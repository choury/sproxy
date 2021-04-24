cmake_minimum_required(VERSION 3.5)
project(sproxy)

message(STATUS "Building for ${CMAKE_SYSTEM_PROCESSOR}")
set(CMAKE_MACOSX_RPATH 1)

if(${CMAKE_SYSTEM_NAME} MATCHES "Linux")
    set(LINUX TRUE)
endif()

INCLUDE(CheckCCompilerFlag)
INCLUDE(CheckCXXCompilerFlag)
set(CMAKE_EXPORT_COMPILE_COMMANDS TRUE)
set(CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake")

#SET(CMAKE_FIND_LIBRARY_SUFFIXES ".a")
#SET(BUILD_SHARED_LIBRARIES OFF)
#SET(CMAKE_EXE_LINKER_FLAGS "-static")

CHECK_C_COMPILER_FLAG("-std=gnu99" HAVE_C99)
CHECK_CXX_COMPILER_FLAG("-std=c++11" HAVE_CXX11)
CHECK_CXX_COMPILER_FLAG("-std=c++14" HAVE_CXX14)
CHECK_CXX_COMPILER_FLAG("-std=c++17" HAVE_CXX17)
CHECK_CXX_COMPILER_FLAG("-std=c++2a" HAVE_CXX2a)

if(NOT HAVE_CXX11 OR NOT HAVE_C99)
    message(FATAL_ERROR "this project need c++11 and c99")
endif()

set(VERSION "v0.0.0")
string(TIMESTAMP NOW UTC)
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
message(STATUS "Set VERSION: ${VERSION}")
#parse the version information into pieces.
string(REGEX REPLACE "^v([0-9]+)\\..*" "\\1" PROJECT_VERSION_MAJOR "${VERSION}")
string(REGEX REPLACE "^v[0-9]+\\.([0-9]+).*" "\\1" PROJECT_VERSION_MINOR "${VERSION}")
string(REGEX REPLACE "^v[0-9]+\\.[0-9]+\\.([0-9]+).*" "\\1" PROJECT_VERSION_PATCH "${VERSION}")

set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)

CHECK_CXX_COMPILER_FLAG("-fsanitize=undefined" HAVE_SAN_UNDEF)
set(CMAKE_REQUIRED_FLAGS "-fsanitize=address")
CHECK_CXX_COMPILER_FLAG("-fsanitize=address" HAVE_SAN_ADDR)
unset(CMAKE_REQUIRED_FLAGS)

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

if(ANDROID)
    set(OPENSSL_ROOT_DIR ${OPENSSL_ROOT}/${ANDROID_ABI})
    set(OPENSSL_INCLUDE_DIR ${OPENSSL_ROOT_DIR}/include)
    set(OPENSSL_LIBRARIES ${OPENSSL_ROOT_DIR}/lib)
    set(OPENSSL_CRYPTO_LIBRARY ${OPENSSL_LIBRARIES}/libcrypto.a)
    set(OPENSSL_SSL_LIBRARY ${OPENSSL_LIBRARIES}/libssl.a)
    find_package(OpenSSL REQUIRED IMPORTED)

    find_library(log-lib log)
else()
    set(BUILD_RPC TRUE)
    find_package(JSON-C REQUIRED)
    include_directories(${JSON-C_INCLUDE_DIR})

    find_package(OpenSSL 1.0.2 REQUIRED)

    find_package(Readline)
    if(READLINE_FOUND)
        set(BUILD_CLIENT TRUE)
        include_directories(${Readline_INCLUDE_DIR})
    else()
        message(WARNING "readline not found, disable client")
    endif()
endif()

if(APPLE)
    find_library(CORE_LIBRARY CoreFoundation)
    find_library(SYSCONF_LIBRARY SystemConfiguration)
endif()

include_directories(${OPENSSL_INCLUDE_DIR})

set(CMAKE_C_FLAGS "-std=gnu99 -Wall -Wextra -fPIC -fno-omit-frame-pointer ${CMAKE_C_FLAGS}")
set(CMAKE_CXX_FLAGS "-std=c++11 -Wall -Wextra -fPIC -fno-omit-frame-pointer ${CMAKE_CXX_FLAGS}")
set(CMAKE_EXE_LINKER_FLAGS "-rdynamic ${CMAKE_EXE_LINKER_FLAGS}")

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
    set(CMAKE_CXX_FLAGS "-DENABLE_GZIP_TEST ${CMAKE_CXX_FLAGS}")
    set(BUILD_GZIP_TEST TRUE)
else()
    message(WARNING "zlib not found, disable gzip test")
endif()


find_package(Backtrace)

set(CMAKE_C_FLAGS_RELEASE "-O3 -DNDEBUG")
set(CMAKE_CXX_FLAGS_RELEASE "-O3 -DNDEBUG")

set(CMAKE_C_FLAGS_RELWITHDEBINFO "-ggdb -DNDEBUG")
set(CMAKE_CXX_FLAGS_RELWITHDEBINFO "-ggdb -DNDEBUG")

set(CMAKE_C_FLAGS_DEBUG "-ggdb -O0")
set(CMAKE_CXX_FLAGS_DEBUG "-ggdb -O0")

if (HAVE_SAN_ADDR AND NOT ANDROID)
    set(CMAKE_C_FLAGS_DEBUG "-fsanitize=address ${CMAKE_C_FLAGS_DEBUG}")
    set(CMAKE_CXX_FLAGS_DEBUG "-fsanitize=address ${CMAKE_CXX_FLAGS_DEBUG}")
endif()

if (HAVE_SAN_UNDEF)
    set(CMAKE_C_FLAGS_DEBUG "-fsanitize=undefined ${CMAKE_C_FLAGS_DEBUG}")
    set(CMAKE_CXX_FLAGS_DEBUG "-fsanitize=undefined ${CMAKE_CXX_FLAGS_DEBUG}")
endif()

if (CMAKE_CXX_COMPILER_ID STREQUAL "GNU" OR ANDROID)
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fuse-ld=gold -Wl,--rosegment")
    set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -fuse-ld=gold -Wl,--rosegment")
endif()

add_subdirectory(src)
add_subdirectory(systemd)

if(BUILD_RPC)
    add_compile_definitions(WITH_RPC)
    install(DIRECTORY webui DESTINATION /var/lib/sproxy)
else()
    install(DIRECTORY DESTINATION /var/lib/sproxy)
endif()

#SET(CPACK_SET_DESTDIR "ON")
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
    set(CPACK_DEBIAN_PACKAGE_DEPENDS "openssl(>=1.0.2),libjson-c3,zlib1g")

    list(APPEND CPACK_GENERATOR "RPM")
    set(CPACK_RPM_PACKAGE_RELEASE "1")
    set(CPACK_RPM_PACKAGE_LICENSE "GPL")
    set(CPACK_RPM_PACKAGE_REQUIRES "openssl json-c zlib")
endif()

message(STATUS "CPack generators: ${CPACK_GENERATOR}")
include(CPack)
