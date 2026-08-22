#Cmake file for library prot.a
#Author:   choury
#Created:  2017/2/11

set(http2_src
        http2.cpp
        hpack.cpp
        )

target_sources(prot PRIVATE ${http2_src})

add_executable(hpack_test hpack_test.cpp hpack.cpp ../http/http_code.cpp)
target_link_libraries(hpack_test PRIVATE sproxy_headers)
