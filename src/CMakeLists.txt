cmake_minimum_required(VERSION 2.8)

add_custom_target(version COMMAND ${CMAKE_COMMAND} -E touch_nocreate ${PROJECT_SOURCE_DIR}/src/version.h.in)

configure_file(${PROJECT_SOURCE_DIR}/src/common.h.in ${PROJECT_BINARY_DIR}/src/common.h ESCAPE_QUOTES)
configure_file(${PROJECT_SOURCE_DIR}/src/version.h.in ${PROJECT_BINARY_DIR}/src/version.h ESCAPE_QUOTES)

include_directories(${PROJECT_BINARY_DIR}/src)
include_directories(${PROJECT_SOURCE_DIR}/src)

if(BUILD_WEBUI)
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

if(LINUX OR APPLE)
    add_executable(sproxy main.cpp base.cpp)
    set_target_properties(sproxy PROPERTIES OUTPUT_NAME "sproxy")
    target_link_libraries(sproxy ${SPROXY_LIBS})
    add_dependencies(sproxy version)
    install(TARGETS sproxy RUNTIME DESTINATION bin)
endif()

if(LINUX)
    add_library(vpn_share SHARED vpn.cpp base.cpp)
    set_target_properties(vpn_share PROPERTIES OUTPUT_NAME "sproxy_vpn")
    target_link_libraries(vpn_share ${SPROXY_LIBS})

    add_executable(vpn vpndemo.c)
    set_target_properties(vpn PROPERTIES OUTPUT_NAME "vpndemo")
    add_dependencies(vpn version)
    target_link_libraries(vpn vpn_share)

    install(TARGETS vpn_share LIBRARY DESTINATION lib${LIBSUFFIX})
    install(TARGETS vpn RUNTIME DESTINATION sbin)
endif()

if(ANDROID)
    add_library(vpn_share SHARED vpn.cpp base.cpp com_choury_sproxy_Service.cpp)
    set_target_properties(vpn_share PROPERTIES OUTPUT_NAME "sproxy_vpn")
    target_link_libraries(vpn_share ${SPROXY_LIBS} ${log-lib})
endif()
