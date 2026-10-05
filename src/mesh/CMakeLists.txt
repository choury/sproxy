#Cmake file for library mesh.a
#Author:   choury

add_library(mesh_lib manager.cpp route.cpp)
add_executable(route_test route_test.cpp route.cpp)
target_link_libraries(route_test PRIVATE sproxy_headers)
