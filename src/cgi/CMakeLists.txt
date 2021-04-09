#Cmake file for cgi
#Author:   choury
#Created:  2017/4/2


if(APPLE)
    set(CMAKE_SHARED_LINKER_FLAGS "-undefined dynamic_lookup")
endif()

add_library(demo SHARED demo.cpp)
set_target_properties(demo PROPERTIES OUTPUT_NAME "demo")

add_library(login SHARED login.cpp)
set_target_properties(login PROPERTIES OUTPUT_NAME "login")

add_library(sites SHARED sites.cpp)
set_target_properties(sites PROPERTIES OUTPUT_NAME "sites")

add_library(proxy SHARED proxy.cpp)
set_target_properties(proxy PROPERTIES OUTPUT_NAME "proxy")

install(TARGETS login sites proxy LIBRARY DESTINATION /var/lib/sproxy/cgi)
