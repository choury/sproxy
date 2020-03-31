#Cmake file for library misc.a
#Author:   choury
#Created:  2017/2/11

set(misc_src job.cpp net.c util.c strategy.cpp config.c trie_helper.cpp network_nofity.cpp)

if(ANDROID)
    set(misc_src ${misc_src} ifaddrs-android.c)
endif()

if(APPLE)
    set(misc_src ${misc_src} network_notify_osx.c)
elseif(LINUX)
    set(misc_src ${misc_src} network_notify_linux.c)
elseif(ANDROID)
    set(misc_src ${misc_src} network_notify_android.c)
endif()

add_library(misc ${misc_src})
add_executable(trie_test trie_test.cpp trie_helper.cpp)
