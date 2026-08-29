#Cmake file for library prot.a
#Author:   choury
#Created:  2017/2/11

set(quic_src
        quicio.cpp
        quic_server.cpp
        quic_pack.cpp
        pn_namespace.cpp
        quic_qos.cpp
        quic_bbr.cpp
        quic_cubic.cpp
        quic_reno.cpp
)

target_sources(prot PRIVATE ${quic_src})

add_executable(quic_frame_test quic_frame_test.cpp quic_pack.cpp ../../misc/buffer.cpp)
target_link_libraries(quic_frame_test PRIVATE sproxy_headers ${OPENSSL_LIBRARIES})


if(false)
    add_executable(crypto_test crypto-test.c quic_pack.cpp)
    target_link_libraries(crypto_test ${OPENSSL_LIBRARIES})
endif()
