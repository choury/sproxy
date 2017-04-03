#Cmake file for cgi
#Author:   choury
#Created:  2017/4/2


include_directories(${PROJECT_SOURCE_DIR})
include_directories(${JSON-C_INCLUDE_DIR})

add_library(sites SHARED sites.cpp)
target_link_libraries(sites ${JSON-C_LIBRARIES})
set_target_properties(sites PROPERTIES OUTPUT_NAME "sites")

add_library(proxy SHARED proxy.cpp)
target_link_libraries(proxy ${JSON-C_LIBRARIES})
set_target_properties(proxy PROPERTIES OUTPUT_NAME "proxy")
