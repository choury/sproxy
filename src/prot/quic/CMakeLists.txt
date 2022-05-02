#Cmake file for library prot.a
#Author:   choury
#Created:  2017/2/11

set(quic_src
        quicio.cpp
        quic_mgr.cpp
        quic_pack.cpp
        quic_qos.cpp)

target_sources(prot PRIVATE ${quic_src})


if(NOT ANDROID AND false)
    add_executable(crypto_test crypto-test.c quic_pack.cpp)
    target_link_libraries(crypto_test ${OPENSSL_LIBRARIES})
endif()
