#Cmake file for cgi
#Author:   choury
#Created:  2017/4/2

add_library(demo SHARED demo.cpp)
set_target_properties(demo PROPERTIES OUTPUT_NAME "demo")

add_library(login SHARED login.cpp)
set_target_properties(login PROPERTIES OUTPUT_NAME "login")

add_library(sites SHARED sites.cpp)
set_target_properties(sites PROPERTIES OUTPUT_NAME "sites")

add_library(proxy SHARED proxy.cpp)
set_target_properties(proxy PROPERTIES OUTPUT_NAME "proxy")

set(INSTALL_LIBRARIES login sites proxy)

if (HAVE_RUST)
    set(RUST_BUILD_DIR ${CMAKE_CURRENT_BINARY_DIR}/rs_build)
    set(RUST_BUILD_LIBRARY ${RUST_BUILD_DIR}/release/libfcm.a)
    add_custom_target(
            rust_static_library
            BYPRODUCTS ${RUST_BUILD_LIBRARY}
            COMMAND ${CARGO_EXECUTABLE} build --release --target-dir ${RUST_BUILD_DIR}
            WORKING_DIRECTORY  ${CMAKE_CURRENT_SOURCE_DIR}/rs
    )

    # 为 Rust 静态库创建一个 CMake 目标
    add_library(fcm_lib STATIC IMPORTED GLOBAL)
    set_target_properties(fcm_lib PROPERTIES IMPORTED_LOCATION ${RUST_BUILD_LIBRARY})
    add_dependencies(fcm_lib rust_static_library)

    add_library(alarm SHARED alarm.cpp)
    target_link_libraries(alarm PUBLIC fcm_lib)
    set_target_properties(alarm PROPERTIES OUTPUT_NAME "alarm")
    set(INSTALL_LIBRARIES ${INSTALL_LIBRARIES} alarm)
endif()

if(ZLIB_FOUND)
    add_library(gzip_test SHARED gzip_test.cpp)
    target_link_libraries(gzip_test PUBLIC z)
    set_target_properties(gzip_test PROPERTIES OUTPUT_NAME "test")
    install(TARGETS login sites proxy gzip_test LIBRARY DESTINATION /var/lib/sproxy/cgi)
    set(INSTALL_LIBRARIES ${INSTALL_LIBRARIES} gzip_test)
endif()

install(TARGETS ${INSTALL_LIBRARIES} LIBRARY DESTINATION /var/lib/sproxy/cgi)
