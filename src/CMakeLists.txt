configure_file(${PROJECT_SOURCE_DIR}/src/common/common.h.in ${PROJECT_BINARY_DIR}/src/common/common.h ESCAPE_QUOTES)
configure_file(${PROJECT_SOURCE_DIR}/src/common/version.h.in ${PROJECT_BINARY_DIR}/src/common/version.h ESCAPE_QUOTES)

include_directories(${PROJECT_BINARY_DIR}/src)
include_directories(${PROJECT_SOURCE_DIR}/src)

if(NOT ANDROID)
    add_subdirectory(cgi)
endif()

if(HAVE_BPF)
    add_subdirectory(bpf)
endif()

add_subdirectory(prot)
add_subdirectory(misc)
add_subdirectory(req)
add_subdirectory(res)

if(APPLE)
    set(SPROXY_LIBS prot req res misc ${OPENSSL_LIBRARIES} dl Threads::Threads)
else()
    set(SPROXY_LIBS
        -Wl,--start-group
        prot req res misc
        -Wl,--end-group
        ${OPENSSL_LIBRARIES} dl Threads::Threads)
endif()
if(Backtrace_FOUND)
    include_directories(${Backtrace_INCLUDE_DIRS})
    set(SPROXY_LIBS ${SPROXY_LIBS} ${Backtrace_LIBRARIES})
endif()

if(APPLE)
    set(SPROXY_LIBS ${SPROXY_LIBS} ${CORE_LIBRARY} ${SYSCONF_LIBRARY})
endif()

if(HAVE_BPF)
    link_directories(${LIBBPF_LIBRARY_DIRS})
    set(SPROXY_LIBS ${SPROXY_LIBS} bpf_loader ${LIBBPF_LIBRARIES})
endif()

if(HAVE_ELF)
    include_directories(${LIBELF_INCLUDE_DIRS})
    set(SPROXY_LIBS ${SPROXY_LIBS} ${LIBELF_LIBRARIES})
endif()

if(LIBURING_FOUND)
    include_directories(${LIBURING_INCLUDE_DIRS})
    link_directories(${LIBURING_LIBRARY_DIRS})
    set(SPROXY_LIBS ${SPROXY_LIBS} ${LIBURING_LIBRARIES})
    set(HAVE_URING TRUE CACHE BOOL "Have io_uring")
else()
    message(STATUS "liburing not found, io_uring support disabled")
endif()

set(SPROXY_LIBS ${SPROXY_LIBS} ${JSON-C_LIBRARIES})
if(LINUX OR APPLE)
    add_executable(sproxy server/server.cpp common/base.cpp)
    set_target_properties(sproxy PROPERTIES OUTPUT_NAME "sproxy")
    target_link_libraries(sproxy ${SPROXY_LIBS})
    install(TARGETS sproxy RUNTIME DESTINATION bin)
endif()

if(HAVE_CLIENT)
    add_executable(scli client/client.cpp prot/rpc.cpp)
    set_target_properties(scli PROPERTIES OUTPUT_NAME "scli")
    target_link_libraries(scli ${JSON-C_LIBRARIES} ${Readline_LIBRARY} Threads::Threads)
    install(TARGETS scli RUNTIME DESTINATION bin)
endif()


if(ANDROID)
    add_library(sproxy_lib SHARED common/base.cpp android/com_choury_sproxy_Service.cpp)
    set_target_properties(sproxy_lib PROPERTIES OUTPUT_NAME "sproxy")
    target_link_libraries(sproxy_lib ${SPROXY_LIBS} ${log-lib})
endif()
