add_library(mesh_lib
    manager.cpp
    gossip.cpp
    local.cpp
    route.cpp)

add_executable(gossip_test gossip_test.cpp gossip.cpp)
target_link_libraries(gossip_test PRIVATE sproxy_headers
    ${JSON-C_LIBRARIES} ${OPENSSL_LIBRARIES})

add_executable(route_test route_test.cpp route.cpp)
target_link_libraries(route_test PRIVATE sproxy_headers)
