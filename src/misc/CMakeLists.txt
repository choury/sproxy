#Cmake file for library misc.a
#Author:   choury
#Created:  2017/2/11


add_library(misc job.cpp net.c tls.c util.c ifaddrs-android.c strategy.cpp config.c trie_helper.cpp)
add_executable(trie_test trie_test.cpp trie_helper.cpp)
