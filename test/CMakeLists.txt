#hpack.cpp/http_code.cpp复用工程HPACK实现，misc/util.c复用base64编解码
#(与src/prot/http2/hpack_test同款闭包+桩)，h2帧头/常量直接include prot/http2/http2.h
add_executable(sproxy_test sproxy_test.cpp tls_chan.cpp h2_chan.cpp
        ${PROJECT_SOURCE_DIR}/src/prot/http2/hpack.cpp
        ${PROJECT_SOURCE_DIR}/src/prot/http/http_code.cpp
        ${PROJECT_SOURCE_DIR}/src/misc/util.c)
target_link_libraries(sproxy_test PRIVATE sproxy_headers ${OPENSSL_LIBRARIES})
