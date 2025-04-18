#include <assert.h>
#include <arpa/inet.h>
#include "trie.h"


int main(){
#ifndef NDEBUG
    std::cout<<"---------- t1 ----------"<<std::endl;
    Trie<std::string, void*> t1;
    t1.insert(split("sproxy.choury.com"), (void*)1);
    t1.insert(split("test.choury.com"), (void*)2);
    t1.insert(split("*.com"), (void*)3);
    t1.insert(split("test.choury.com"), (void*)4, "test.*");
    t1.insert(split("test.choury.com"), (void*)5, "*.html"); //wrong req expr
    t1.dump(0);

    assert(t1.find(split("abc.choury.com"))->value == (void*)3);
    assert(t1.find(split("test.choury.com"))->value == (void*)2);
    assert(t1.find(split("test.choury.com"), "test1")->value == (void*)4);
    assert(t1.find(split("abc.test.net")) == nullptr);
    assert(t1.find(split("choury.com"))->value == (void*)3);

    bool found;
    t1.remove(split("choury.com"), found);
    assert(found == false);
    t1.remove(split("abc.test.choury.com"), found);
    assert(found == false);
    t1.remove(split("test.choury.com"), found);
    assert(found == true);
    t1.remove(split("*.com"), found);
    assert(found == true);
    t1.remove(split("sproxy.choury.com"), found);
    assert(found == true);

    t1.dump(0);

    std::cout<<"---------- t2 ----------"<<std::endl;
    Trie<std::string, void*> t2;
    t2.insert(split("sproxy.choury.com"), (void*)1);
    t2.insert(split("test.choury.com"), (void*)2);
    t2.insert(split("*.choury.com"), (void*)3);
    t2.insert(split("test.choury.com"),(void*)4, "abc|xyz");
    t2.dump(0);

    assert(t2.find(split("choury.com")) == nullptr);
    assert(t2.findAll(split("choury.com")).empty());
    assert(t2.find(split("test.choury.com"))->value == (void*)2);
    assert(t2.find(split("test.choury.com"), "xyz")->value == (void*)4);
    assert(t2.findAll(split("test.choury.com")).size() == 2);

    assert(t2.find(split("t4.choury.com"))->value == (void*)3);
    assert(t2.find(split("t4.choury.com"), "abc")->value == (void*)3);
    assert(t2.find(split("ddd.test.choury.com"), "001")->value == (void*)3);
    assert(t2.findAll(split("ddd.test.choury.com")).size() == 1);
    assert(t2.find(split("test.com")) == nullptr);


    auto t2entrys = t2.dump(std::list<std::string>{});
    for(const auto& entry: t2entrys){
        std::cout<<join(entry.first)<<": "<<entry.second<<std::endl;
    }

    t2.clear();
    t2.dump(0);

    std::cout<<"---------- t3 ----------"<<std::endl;
    Trie<char, void*> t3;
    in_addr  t3addr;
    assert(inet_pton(AF_INET, "192.168.0.1", &t3addr) == 1);
    t3.insert(split(t3addr, 16), (void*)16);
    t3.insert(split(t3addr, 24), (void*)24);
    //t3.dump(0);
    in_addr  t3ip1; 
    assert(inet_pton(AF_INET, "10.10.10.10", &t3ip1) == 1);
    assert(t3.find(split(t3ip1)) == nullptr);

    in_addr  t3ip2; 
    assert(inet_pton(AF_INET, "192.168.10.10", &t3ip2) == 1);
    assert(t3.find(split(t3ip2))->value == (void*)16);

    in_addr  t3ip3; 
    assert(inet_pton(AF_INET, "192.168.0.10", &t3ip3) == 1);
    assert(t3.find(split(t3ip3))->value == (void*)24);


    auto t3entrys = t3.dump(std::list<char>{});
    for(const auto& entry: t3entrys){
        std::cout<<join(AF_INET, entry.first)<<": "<<entry.second<<std::endl;
    }
    
    in_addr t3ip4;
    assert(inet_pton(AF_INET, "192.168.0.10", &t3ip4) == 1);
    t3.remove(split(t3ip4), found);
    assert(found == false);
    t3.remove(split(t3ip4, 16), found);
    assert(found == true);
    t3entrys = t3.dump(std::list<char>{});
    for(const auto& entry: t3entrys){
        std::cout<<join(AF_INET, entry.first)<<": "<<entry.second<<std::endl;
    }
    t3.clear();

    std::cout<<"---------- t4 ----------"<<std::endl;
    Trie<char, void*> t4;
    in6_addr t4addr;
    assert(inet_pton(AF_INET6, "2001:da8:b000:6803:62eb:69ff:feb4:a6c2", &t4addr) == 1);
    t4.insert(split(t4addr, 64), (void*)64);
    //t4.dump(0);

    in6_addr t4ip1;
    assert(inet_pton(AF_INET6, "2001:da8:b000:6803::ffff", &t4ip1) == 1);
    assert(t4.find(split(t4ip1))->value == (void*)64);

    in6_addr t4ip2;
    assert(inet_pton(AF_INET6, "2002:da8:b000:6803::ffff", &t4ip2) == 1);
    assert(t4.find(split(t4ip2)) == nullptr);

    auto t4entrys = t4.dump(std::list<char>{});
    for(const auto& entry: t4entrys){
        std::cout<<join(AF_INET6, entry.first)<<": "<<entry.second<<std::endl;
    }
    t4.clear();

    std::cout<<"---------- t5 ----------"<<std::endl;
    Trie<char, void*> t5;
    in6_addr t5addr;
    assert(inet_pton(AF_INET6, "2001:da8:b000:6803:62eb:69ff:feb4:a6c2", &t5addr) == 1);
    t5.insert(split(t5addr), (void*)128);
    //t4.dump(0);

    assert(t5.find(split(t5addr))->value == (void*)128);

    in6_addr t5ip2;
    assert(inet_pton(AF_INET6, "2002:da8:b000:6803::ffff", &t5ip2) == 1);
    assert(t5.find(split(t5ip2)) == nullptr);

    auto t5entrys = t5.dump(std::list<char>{});
    for(const auto& entry: t5entrys){
        std::cout<<join(AF_INET6, entry.first)<<": "<<entry.second<<std::endl;
    }
    t5.clear();

    std::cout<<"---------- t6 ----------"<<std::endl;
    Trie<char, void*> t6;
    in6_addr t6addr;
    assert(inet_pton(AF_INET6, "2001::1", &t6addr) == 1);
    t6.insert(split(t6addr, 16), (void*)16);

    assert(t6.find(split(t6addr))->value == (void*)16);
    assert(t6.find(split(t6addr, 16))->value == (void*)16);

    auto t6entrys = t6.dump(std::list<char>{});
    for(const auto& entry: t6entrys){
        std::cout<<join(AF_INET6, entry.first)<<": "<<entry.second<<std::endl;
    }
    t6.clear();
#endif
}
