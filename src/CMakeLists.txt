configure_file(${PROJECT_SOURCE_DIR}/src/common/common.h.in ${PROJECT_BINARY_DIR}/src/common/common.h ESCAPE_QUOTES)
configure_file(${PROJECT_SOURCE_DIR}/src/common/version.h.in ${PROJECT_BINARY_DIR}/src/common/version.h ESCAPE_QUOTES)

macro(sproxy_append_paths incs libs)
    if(incs)
        list(APPEND SPROXY_INCLUDE_DIRS ${incs})
    endif()
    if(libs)
        list(APPEND SPROXY_LIBRARY_DIRS ${libs})
    endif()
endmacro()

set(SPROXY_INCLUDE_DIRS
        ${PROJECT_SOURCE_DIR}/src
        ${PROJECT_BINARY_DIR}/src
        ${JSON-C_INCLUDE_DIRS}
        ${OPENSSL_INCLUDE_DIR})
set(SPROXY_LIBRARY_DIRS ${JSON-C_LIBRARY_DIRS})
set(SPROXY_OPTIONAL_LIBS "")

if(Backtrace_FOUND)
    sproxy_append_paths("${Backtrace_INCLUDE_DIRS}" "")
    list(APPEND SPROXY_OPTIONAL_LIBS ${Backtrace_LIBRARIES})
endif()

if(HAVE_ELF)
    sproxy_append_paths("${LIBELF_INCLUDE_DIRS}" "${LIBELF_LIBRARY_DIRS}")
    list(APPEND SPROXY_OPTIONAL_LIBS ${LIBELF_LIBRARIES})
endif()

if(HAVE_URING)
    sproxy_append_paths("${LIBURING_INCLUDE_DIRS}" "${LIBURING_LIBRARY_DIRS}")
    list(APPEND SPROXY_OPTIONAL_LIBS ${LIBURING_LIBRARIES})
endif()

if(HAVE_BPF)
    sproxy_append_paths("" "${LIBBPF_LIBRARY_DIRS}")
    list(APPEND SPROXY_OPTIONAL_LIBS bpf_loader ${LIBBPF_LIBRARIES})
endif()

if(HAVE_JEMALLOC)
    list(APPEND SPROXY_OPTIONAL_LIBS ${JEMALLOC_LIB})
endif()

if(APPLE)
    list(APPEND SPROXY_OPTIONAL_LIBS ${CORE_LIBRARY} ${SYSCONF_LIBRARY})
endif()

list(REMOVE_DUPLICATES SPROXY_INCLUDE_DIRS)
list(FILTER SPROXY_INCLUDE_DIRS EXCLUDE REGEX "^$")

list(REMOVE_DUPLICATES SPROXY_LIBRARY_DIRS)
list(FILTER SPROXY_LIBRARY_DIRS EXCLUDE REGEX "^$")

add_library(sproxy_headers INTERFACE)
target_include_directories(sproxy_headers INTERFACE ${SPROXY_INCLUDE_DIRS})
if(SPROXY_LIBRARY_DIRS)
    target_link_directories(sproxy_headers INTERFACE ${SPROXY_LIBRARY_DIRS})
endif()

if(NOT ANDROID_APP)
    add_subdirectory(cgi)
endif()

if(HAVE_BPF)
    add_subdirectory(bpf)
endif()

add_subdirectory(prot)
add_subdirectory(misc)
add_subdirectory(req)
add_subdirectory(res)

set(SPROXY_CORE_TARGETS prot req res misc)
foreach(target ${SPROXY_CORE_TARGETS})
    target_link_libraries(${target} PUBLIC sproxy_headers)
endforeach()

if(HAVE_BPF)
    target_link_libraries(bpf_loader PUBLIC sproxy_headers)
endif()

if(APPLE)
    set(SPROXY_LIBS prot req res misc ${OPENSSL_LIBRARIES} dl Threads::Threads)
else()
    set(SPROXY_LIBS
        -Wl,--start-group
        prot req res misc
        -Wl,--end-group
        ${OPENSSL_LIBRARIES} dl Threads::Threads)
endif()

set(SPROXY_LIBS ${SPROXY_LIBS} ${JSON-C_LIBRARIES} ${SPROXY_OPTIONAL_LIBS})
if(LINUX OR APPLE OR TERMUX)
    add_executable(sproxy server/server.cpp common/base.cpp)
    set_target_properties(sproxy PROPERTIES OUTPUT_NAME "sproxy")
    target_link_libraries(sproxy PRIVATE sproxy_headers)
    target_link_libraries(sproxy PRIVATE ${SPROXY_LIBS})
    install(TARGETS sproxy RUNTIME DESTINATION bin)
endif()

if(HAVE_CLIENT)
    add_executable(scli client/client.cpp prot/rpc.cpp)
    set_target_properties(scli PROPERTIES OUTPUT_NAME "scli")
    target_link_libraries(scli PRIVATE sproxy_headers)
    target_include_directories(scli PRIVATE ${Readline_INCLUDE_DIR})
    target_link_libraries(scli PRIVATE ${JSON-C_LIBRARIES} ${Readline_LIBRARY} Threads::Threads)
    install(TARGETS scli RUNTIME DESTINATION bin)
endif()

if(ANDROID_APP)
    add_library(sproxy_lib SHARED common/base.cpp android/com_choury_sproxy_Service.cpp)
    set_target_properties(sproxy_lib PROPERTIES OUTPUT_NAME "sproxy")
    target_link_libraries(sproxy_lib PRIVATE sproxy_headers)
    target_link_libraries(sproxy_lib PRIVATE ${SPROXY_LIBS} ${log-lib})
endif()
