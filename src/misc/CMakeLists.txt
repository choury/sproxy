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
add_executable(buffer_test buffer_test.cpp buffer.cpp)


if((LINUX OR TERMUX) AND HAVE_ELF)
    add_library(hook SHARED hook_so.cpp)
    add_executable(hook_test hook_test.cpp hook.cpp)
    target_link_libraries(hook_test elf)
endif()
