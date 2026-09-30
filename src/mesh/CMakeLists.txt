add_library(mesh_lib
    mesh_manager.cpp
    mesh_gossip.cpp
    mesh_local.cpp)

add_executable(mesh_gossip_test mesh_gossip_test.cpp mesh_gossip.cpp)
target_link_libraries(mesh_gossip_test PRIVATE sproxy_headers
    ${JSON-C_LIBRARIES} ${OPENSSL_LIBRARIES})
