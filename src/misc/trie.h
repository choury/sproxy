#ifndef TRIE_H__
#define TRIE_H__

#include <map>
#include <string>
#include <iostream>
#include <list>
#include <netdb.h>
#include <string.h>

static inline std::string wildcard(std::string) {
    return "*";
}

static inline char wildcard(char) {
    return '*';
}

template<typename V>
class TrieType{
public:
    V value;
};

template<typename T, typename V>
class Trie: public TrieType<V> {
    bool isKey = false;
    std::map<T, Trie<T,V>*> children;
public:
    void insert(std::list<T>&& token, V v){
        if(token.empty()){
            isKey = true;
            this->value = v;
            return;
        }
        auto top = token.front();
        if(children.count(top) == 0){
            children[top] = new Trie<T, V>();
        }
        token.pop_front();
        children[top]->insert(std::move(token), v);
    }
    const Trie<T,V>* find(std::list<T>&& token) const{
        if(token.empty()){
            if(isKey){
                return this;
            }else{
                return nullptr;
            }
        }
        auto top = token.front();
        if(children.count(top)){
            token.pop_front();
            auto found = children.at(top)->find(std::move(token));
            if(found){
                return found;
            }
        }
        if(children.count(wildcard(top))){
            return children.at(wildcard(top));
        }
        return nullptr;
    }
    bool remove(std::list<T>&& token, bool& found) {
        if(token.empty()){
            found = this->isKey;
            return children.empty() && found;
        }
        auto top = token.front();
        if(children.count(top)){
            token.pop_front();
            if(children[top]->remove(std::move(token), found)){
                delete children[top];
                children.erase(top);
            }
        }else{
            found = false;
        }
        return children.empty() && found;
    }
    void clear() {
        for(auto child : children){
            child.second->clear();
            delete child.second;
        }
        children.clear();
    }
#ifndef NDEBUG
    void dump(int tab) const{
        if(isKey){
            std::cout<<this->value<<std::endl;
        }else if(tab){
            std::cout<<std::endl;
        }
        for(auto& i: children){
            for(int i=0; i < tab; i++){
                std::cout<<"  ";
            }
            std::cout<<i.first<<": ";
            i.second->dump(tab+1);
        }
    }
#endif
    std::list<std::pair<std::list<T>, V>> dump(std::list<T> tokens) {
        std::list<std::pair<std::list<T>, V>> result;
        if(isKey){
            result.emplace_back(tokens, this->value);
        }
        for(auto child: children){
            auto tokens_ = tokens;
            tokens_.emplace_back(child.first);
            result.splice(result.end(), child.second->dump(tokens_));
        }
        return result;
    }
};


std::list<std::string> split(std::string s);
std::list<char> split(in_addr ip, int prefix = -1);
std::list<char> split(in6_addr ip6, int prefix = -1);
std::list<char> split(const sockaddr_storage* ip, int prefix = -1);
std::string join(std::list<std::string> tokens);
std::string join(int type, std::list<char> tokens);

#endif