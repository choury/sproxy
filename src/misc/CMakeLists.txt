#Cmake file for library misc.a
#Author:   choury
#Created:  2017/2/11

set(misc_src job.cpp net.c util.c strategy.cpp config.c trie_helper.cpp network_notify.cpp pcap.c buffer.cpp cert_manager.cpp hook.cpp)

if(APPLE)
    set(misc_src ${misc_src} network_notify_osx.c)
elseif(LINUX OR TERMUX)
    set(misc_src ${misc_src} network_notify_linux.c tun.c)
elseif(ANDROID_APP)
    set(misc_src ${misc_src} network_notify_android.c execinfo.cpp)
endif()

add_library(misc ${misc_src})
add_executable(trie_test trie_test.cpp trie_helper.cpp)
target_link_libraries(trie_test PRIVATE sproxy_headers)
add_executable(buffer_test buffer_test.cpp buffer.cpp)
target_link_libraries(buffer_test PRIVATE sproxy_headers)


if((LINUX OR TERMUX) AND HAVE_ELF)
    add_library(hook SHARED hook_so.cpp)
    add_executable(hook_test hook_test.cpp hook.cpp)
    target_link_libraries(hook PRIVATE sproxy_headers)
    target_link_libraries(hook_test PRIVATE elf sproxy_headers)
endif()
