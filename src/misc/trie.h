#ifndef TRIE_H__
#define TRIE_H__

#include <map>
#include <string>
#include <iostream>
#include <list>
#include <netdb.h>
#include <regex>

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
    bool isEndpoint = false;
    std::map<T, Trie<T,V>*> children;
    std::map<std::string, Trie<T, V>*> regexChildren;
public:
    ~Trie(){
        clear();
    }
    void insert(std::list<T>&& token, V v, std::string reg = ""){
        if(token.empty()){
            if(reg.empty()) {
                isEndpoint = true;
                this->value = v;
                return;
            }
            regexChildren[reg] = new Trie<T, V>();
            regexChildren[reg]->insert({}, v, "");
            return;
        }
        auto top = token.front();
        if(children.count(top) == 0){
            children[top] = new Trie<T, V>();
        }
        token.pop_front();
        children[top]->insert(std::move(token), v, reg);
    }
    const TrieType<V>* find(std::list<T>&& token, std::string ext = "") const{
        if(token.empty()) {
            for (auto i: regexChildren) {
                try{
                    std::regex reg(i.first);
                    if (std::regex_match(ext, reg)) {
                        return i.second->find({}, "");
                    }
                }catch(std::regex_error&) {
                    continue;
                }
            }
            if (isEndpoint) {
                return this;
            }
            return nullptr;
        }
        auto top = token.front();
        if(children.count(top)){
            token.pop_front();
            auto found = children.at(top)->find(std::move(token), ext);
            if(found){
                return found;
            }
        }
        if(children.count(wildcard(top))){
            return children.at(wildcard(top))->find({}, ext);
        }
        return nullptr;
    }
    std::vector<TrieType<V>*> findAll(std::list<T>&& token) {
        std::vector<TrieType<V>*> result;
        if(token.empty()){
            if(isEndpoint){
                result.push_back(this);
            }
            for(auto i: regexChildren){
                result.push_back(i.second);
            }
            return result;
        }
        auto top = token.front();
        if(children.count(top)){
            token.pop_front();
            auto found = children.at(top)->findAll(std::move(token));
            result.insert(result.end(), found.begin(), found.end());
        }
        if(!result.empty()) {
            return result;
        }
        if(children.count(wildcard(top))){
            auto found = children.at(wildcard(top))->findAll({});
            result.insert(result.end(), found.begin(), found.end());
        }
        return result;
    }
    bool remove(std::list<T>&& token, bool& found) {
        if(token.empty()){
            found = this->isEndpoint || regexChildren.size();
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
            delete child.second;
        }
        children.clear();
        for(auto regexChild: regexChildren) {
            delete regexChild.second;
        }
        this->isEndpoint = false;
        regexChildren.clear();
    }
#ifndef NDEBUG
    void dump(int tab) const{
        if(isEndpoint){
            std::cout<<this->value<<std::endl;
        }else if(tab){
            std::cout<<std::endl;
        }
        for(auto& i: children){
            for(int j=0; j < tab; j++){
                std::cout<<"  ";
            }
            std::cout<<i.first<<": ";
            i.second->dump(tab+1);
        }
        for(auto& i: regexChildren){
            for(int j=0; j < tab; j++){
                std::cout<<"  ";
            }
            std::cout<<"reg:"<<i.first<<": ";
            i.second->dump(tab+1);
        }
    }
#endif
    std::list<std::pair<std::list<T>, V>> dump(std::list<T> tokens) {
        std::list<std::pair<std::list<T>, V>> result;
        if(isEndpoint){
            result.emplace_back(tokens, this->value);
        }
        for(auto child: children){
            auto tokens_ = tokens;
            tokens_.emplace_back(child.first);
            result.splice(result.end(), child.second->dump(tokens_));
        }
        for(auto regexChild: regexChildren){
            auto tokens_ = tokens;
            result.splice(result.end(), regexChild.second->dump(tokens_));
        }
        return result;
    }
};


std::list<std::string> split(std::string s);
std::list<char> split(in_addr ip, int prefix = -1);
std::list<char> split(in6_addr ip6, int prefix = -1);
std::list<char> split(const sockaddr_storage* ip, int prefix = -1);
std::string join(const std::list<std::string>& tokens);
std::string join(int type, const std::list<char>& tokens);

#endif