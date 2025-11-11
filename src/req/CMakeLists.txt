#Cmake file for library req.a
#Author:   choury
#Created:  2017/2/11


set(req_src requester.cpp  guest.cpp guest_sni.cpp guest2.cpp guest_vpn.cpp guest_tproxy.cpp rguest2.cpp cli.cpp rproxy_listener.cpp)

if(HAVE_QUIC)
    set(req_src ${req_src} guest3.cpp rguest3.cpp)
endif()

add_library(req  ${req_src})
