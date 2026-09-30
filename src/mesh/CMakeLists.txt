add_library(mesh_lib
    mesh_manager.cpp
    mesh_gossip.cpp
    mesh_local.cpp
    mesh_route.cpp)

add_executable(mesh_gossip_test mesh_gossip_test.cpp mesh_gossip.cpp)
target_link_libraries(mesh_gossip_test PRIVATE sproxy_headers
    ${JSON-C_LIBRARIES} ${OPENSSL_LIBRARIES})

add_executable(mesh_route_test mesh_route_test.cpp mesh_route.cpp)
target_link_libraries(mesh_route_test PRIVATE sproxy_headers)
