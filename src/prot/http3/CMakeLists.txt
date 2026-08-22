#Cmake file for library prot.a
#Author:   choury
#Created:  2017/2/11

set(http3_src
        http3.cpp
        qpack.cpp
        )

target_sources(prot PRIVATE ${http3_src})

add_executable(qpack_test qpack_test.cpp qpack.cpp ../http/http_code.cpp)
target_link_libraries(qpack_test PRIVATE sproxy_headers)
