cmake_minimum_required(VERSION 2.8)

include_directories(${PROJECT_SOURCE_DIR}/src)

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
        install(TARGETS vpn RUNTIME DESTINATION sbin)
    endif()
    install(TARGETS sproxy RUNTIME DESTINATION bin)
else()
    add_library(sproxy_vpn SHARED vpn.cpp base.cpp com_choury_sproxy_Service.cpp)
    set_target_properties(sproxy_vpn PROPERTIES OUTPUT_NAME "sproxy_vpn")
    target_link_libraries(sproxy_vpn ${SPROXY_LIBS} ${log-lib})
endif()
