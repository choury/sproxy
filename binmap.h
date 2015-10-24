#ifndef BINMAP_H__
#define BINMAP_H__
#include <map>
#include <set>
#include <typeinfo>

#include <assert.h>

template<class T1, class T2>
class mulmap{
    std::map<T1, std::set<T2>> data;
public:
    typedef class mulmap_iterator{
        std::pair<T1, T2> temp_pair;
        const mulmap<T1, T2> *map;
    public:
        typename std::map<T1, std::set<T2>>::iterator mi;
        typename std::set<T2>::iterator si;
        mulmap_iterator(const mulmap<T1, T2> *map):map(map){}
        bool operator!=(const mulmap_iterator &cmp){
            if(mi == map->data.end() || cmp.mi == map->data.end()){
               return mi != cmp.mi; 
            }
            return mi != cmp.mi || si != cmp.si;
        }
        mulmap_iterator operator++(int){
            mulmap_iterator tmp = *this;
            si++;
            if(si == mi->second.end()){
                mi++;
                si = mi->second.begin();
            }
            return tmp;
        }
        mulmap_iterator& operator++(){
            si++;
            if(si == mi->second.end()){
                mi++;
                si = mi->second.begin();
            }
            return *this;
        }
        std::pair<const T1, const T2> operator*(){
            return std::make_pair(mi->first, *si);
        }
        const std::pair<T1, T2>* operator->(){
            temp_pair = std::make_pair(mi->first, *si);
            return &temp_pair;
        }
    } iterator;
    typedef class mulmap_const_iterator{
        std::pair<T1, T2> temp_pair;
        const mulmap<T1, T2> *map;
    public:
        typename std::map<T1, std::set<T2>>::const_iterator mi;
        typename std::set<T2>::const_iterator si;
        mulmap_const_iterator(const mulmap<T1, T2> *map):map(map){}
        bool operator!=(const mulmap_const_iterator &cmp){
            if(mi == map->data.end() || cmp.mi == map->data.end()){
               return mi != cmp.mi; 
            }
            return mi != cmp.mi || si != cmp.si;
        }
        mulmap_const_iterator operator++(int){
            mulmap_const_iterator tmp = *this;
            si++;
            if(si == mi->second.end()){
                mi++;
                si = mi->second.begin();
            }
            return tmp;
        }
        mulmap_const_iterator& operator++(){
            si++;
            if(si == mi->second.end()){
                mi++;
                si = mi->second.begin();
            }
            return *this;
        }
        std::pair<const T1, const T2> operator*(){
            return std::make_pair(mi->first, *si);
        }
        const std::pair<T1, T2>* operator->(){
            temp_pair = std::make_pair(mi->first, si->c_str());
            return &temp_pair;
        }
    } const_iterator;
    size_t count(const T1 key) const{
        if(data.count(key)){
            return data.at(key).size();
        }
        return 0;
    }
    void insert(const T1 t1, const T2 t2){
        if(data.count(t1)){
            data[t1].insert(t2);
        }else{
            std::set<T2> set;
            set.insert(t2);
            data.insert(std::make_pair(t1, set));
        }
    }
    auto operator[](const T1 key) -> decltype(data[key])
    {
        return data[key];
    }
    auto at(const T1 key) const -> decltype(data.at(key))
    {
        return data.at(key);
    }
    auto erase(const T1 key) -> decltype(data.erase(key))
    {
        return data.erase(key);
    }
    void erase(const T1 t1, const T2 t2){
        if(data.count(t1)){
            data[t1].erase(t2);
            if(data[t1].empty()){
                data.erase(t1);
            }
        }
    }
    void erase(iterator i){
        i.mi->second.erase(i.si);
        if(i.mi->second.size() == 0){
            data.erase(i.mi);
        }
    }
    iterator begin() {
        iterator i(this);
        i.mi = data.begin();
        if(i.mi != data.end())
            i.si = i.mi->second.begin();
        return i;
    }
    const_iterator begin() const{
        const_iterator i(this);
        i.mi = data.begin();
        if(i.mi != data.end())
            i.si = i.mi->second.begin();
        return i;
    }
    iterator end() {
        iterator i(this);
        i.mi = data.end();
        return i;
    }
    const_iterator end() const {
        const_iterator i(this);
        i.mi = data.end();
        return i;
    }
};

template<class T1, class T2>
class binmap{
    mulmap<T1, T2> left;
    mulmap<T2, T1> right;
public:
    void insert(const T1, const T2);
    void erase(const T1, const T2);
    void erase(const T1);
    void erase(const T2);
    T1 at(const T2 key);
    T2 at(const T1 key);
    const std::set<T1> operator[](const T2 key);
    const std::set<T2> operator[](const T1 key);
    size_t count(T1 t1);
    size_t count(T2 t2);
    const std::set<std::pair<T1, T2>> pairs();
};


template<class T1, class T2>
void binmap<T1, T2>::insert(const T1 t1, const T2 t2) {
    assert(typeid(t1) != typeid(t2));
    left.insert(t1, t2);
    right.insert(t2, t1);
}

template<class T1, class T2>
void binmap<T1, T2>::erase(const T1 key) {
    if(left.count(key)){
        auto set = left[key];
        left.erase(key);
        for(auto i: set){
            right.erase(i, key);
        }
    }
}

template<class T1, class T2>
void binmap<T1, T2>::erase(const T2 key) {
    if(right.count(key)){
        auto set = right[key];
        right.erase(key);
        for(auto i: set){
            left.erase(i, key);
        }
    }
}

template<class T1, class T2>
void binmap<T1, T2>::erase(const T1 t1, const T2 t2) {
    left.erase(t1, t2);
    right.erase(t2, t1);
}


template<class T1, class T2>
T2 binmap<T1, T2>::at(const T1 key) {
    return *left.at(key).begin();
}

template<class T1, class T2>
T1 binmap<T1, T2>::at(const T2 key) {
    return *right.at(key).begin();
}

template<class T1, class T2>
const std::set<T2> binmap<T1, T2>::operator[](const T1 key)
{
    std::set<T2> set;
    if(left.count(key)){
        set = left[key];
    }
    return set;
}

template<class T1, class T2>
const std::set<T1> binmap<T1, T2>::operator[](const T2 key)
{
    std::set<T1> set;
    if(right.count(key)){
        set =  right[key];
    }
    return set;
}

template<class T1, class T2>
size_t binmap<T1, T2>::count(T1 t1) {
    return left.count(t1);
}


template<class T1, class T2>
size_t binmap<T1, T2>::count(T2 t2) {
    return right.count(t2);
}

template<class T1, class T2>
const std::set<std::pair<T1, T2 >> binmap<T1, T2>::pairs() { 
    std::set<std::pair<T1, T2>> pairs;
    for(auto i: left){
        pairs.insert(i);
    }
    return pairs;
}


#endif