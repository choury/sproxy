#Cmake file for cgi
#Author:   choury
#Created:  2017/4/2

add_library(demo SHARED demo.cpp)
target_link_libraries(demo PUBLIC sproxy_headers)
set_target_properties(demo PROPERTIES OUTPUT_NAME "demo")

add_library(login SHARED login.cpp)
target_link_libraries(login PUBLIC sproxy_headers)
set_target_properties(login PROPERTIES OUTPUT_NAME "login")

add_library(sites SHARED sites.cpp)
target_link_libraries(sites PUBLIC sproxy_headers)
set_target_properties(sites PROPERTIES OUTPUT_NAME "sites")

add_library(proxy SHARED proxy.cpp)
target_link_libraries(proxy PUBLIC sproxy_headers)
set_target_properties(proxy PROPERTIES OUTPUT_NAME "proxy")

set(INSTALL_LIBRARIES login sites proxy)

if (HAVE_RUST)
    set(RUST_BUILD_DIR ${CMAKE_CURRENT_BINARY_DIR}/rs_build)
    set(RUST_BUILD_LIBRARY ${RUST_BUILD_DIR}/release/libsproxy_cgi.a)
    add_custom_target(
            rust_static_library
            BYPRODUCTS ${RUST_BUILD_LIBRARY}
            COMMAND ${CMAKE_COMMAND} -E env
                    ${CARGO_EXECUTABLE} build --release --target-dir ${RUST_BUILD_DIR}
            WORKING_DIRECTORY  ${CMAKE_CURRENT_SOURCE_DIR}/rs
    )

    # 为 Rust 静态库创建一个 CMake 目标
    add_library(cgi_rust STATIC IMPORTED GLOBAL)
    set_target_properties(cgi_rust PROPERTIES IMPORTED_LOCATION ${RUST_BUILD_LIBRARY})
    add_dependencies(cgi_rust rust_static_library)

    add_library(alarm SHARED alarm.cpp)
    target_link_libraries(alarm PUBLIC sproxy_headers cgi_rust)
    set_target_properties(alarm PROPERTIES OUTPUT_NAME "alarm")
    set(INSTALL_LIBRARIES ${INSTALL_LIBRARIES} alarm)

    add_library(acme SHARED acme.cpp)
    target_link_libraries(acme PUBLIC sproxy_headers cgi_rust)
    set_target_properties(acme PROPERTIES OUTPUT_NAME "acme")
    set(INSTALL_LIBRARIES ${INSTALL_LIBRARIES} acme)
endif()

if(ZLIB_FOUND)
    add_library(gzip_test SHARED gzip_test.cpp)
    target_link_libraries(gzip_test PUBLIC sproxy_headers z)
    set_target_properties(gzip_test PROPERTIES OUTPUT_NAME "test")
    set(INSTALL_LIBRARIES ${INSTALL_LIBRARIES} gzip_test)
endif()

if(LIBXML2_FOUND)
    add_library(webdav SHARED webdav.cpp)
    target_link_libraries(webdav PUBLIC sproxy_headers ${LIBXML2_LIBRARIES})
    target_include_directories(webdav PUBLIC ${LIBXML2_INCLUDE_DIRS})
    set_target_properties(webdav PROPERTIES OUTPUT_NAME "webdav")
    set(INSTALL_LIBRARIES ${INSTALL_LIBRARIES} webdav)
endif()

install(TARGETS ${INSTALL_LIBRARIES} LIBRARY DESTINATION /var/lib/sproxy/cgi)
