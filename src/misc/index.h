#ifndef INDEX_H__
#define INDEX_H__

#include <map>
#include <assert.h>

template <class T1, class T2, class D>
class Index2{
    std::map<std::pair<T1, T2>, D> containers;
    using iterator = typename decltype(containers)::iterator;
    std::multimap<T1, iterator> idx1;
    std::multimap<T2, iterator> idx2;
public:
    using const_iterator = typename decltype(containers)::const_iterator;
    void Add(const T1 t1, const T2 t2, const D data);
    const_iterator GetOne(const T1 t1) const;
    const_iterator GetOne(const T2 t2) const;
    bool Has(const T1 t1) const;
    bool Has(const T2 t1) const;
    void Delete(const T1 t1);
    void Delete(const T2 t2);
    void Delete(const T1 t1,const T2 t2);
    const decltype(containers)& data(){
        return containers;
    }
    size_t size() const;
    void clear();
};

template<class T1, class T2, class D>
void Index2<T1, T2, D>::Add(const T1 t1, const T2 t2, const D data) {
    auto p = containers.emplace(std::make_pair(t1, t2), data);
    assert(p.second);
    idx1.emplace(t1, p.first);
    idx2.emplace(t2, p.first);
}

template<class T1, class T2, class D>
typename Index2<T1, T2, D>::const_iterator Index2<T1, T2, D>::GetOne(const T1 t1) const {
    if(idx1.count(t1) == 0){
        return containers.end();
    }
    return idx1.find(t1)->second;
}

template<class T1, class T2, class D>
typename Index2<T1, T2, D>::const_iterator Index2<T1, T2, D>::GetOne(const T2 t2) const{
    if(idx2.count(t2) == 0){
        return containers.end();
    }
    return idx2.find(t2)->second;
}


template<class T1, class T2, class D>
bool Index2<T1, T2, D>::Has(const T1 t1) const {
    return idx1.count(t1);
}

template<class T1, class T2, class D>
bool Index2<T1, T2, D>::Has(const T2 t2) const {
    return idx2.count(t2);
}

template<class T1, class T2, class D>
void Index2<T1, T2, D>::Delete(const T1 t1) {
    if(idx1.count(t1) == 0){
        return;
    }
    auto range1 = idx1.equal_range(t1);
    for(auto i = range1.first; i != range1.second; i = idx1.erase(i)){
        iterator d = i->second;
        auto range2 = idx2.equal_range(d->first.second);
        for(auto j = range2.first; j != range2.second;){
            if(j->second == d){
                j = idx2.erase(j);
            }else{
                j++;
            }
        }
        containers.erase(d);
    }
}

template<class T1, class T2, class D>
void Index2<T1, T2, D>::Delete(const T2 t2) {
    if(idx2.count(t2) == 0){
        return;
    }
    auto range2 = idx2.equal_range(t2);
    for(auto i = range2.first; i != range2.second; i = idx2.erase(i)){
        iterator d = i->second;
        auto range1 = idx1.equal_range(d->first.first);
        for(auto j = range1.first; j != range1.second;){
            if(j->second == d){
                j = idx1.erase(j);
            }else{
                j++;
            }
        }
        containers.erase(d);
    }
}


template<class T1, class T2, class D>
void Index2<T1, T2, D>::Delete(const T1 t1, const T2 t2) {
    auto d = containers.find(std::make_pair(t1, t2));
    if(d == containers.end()){
        return;
    }
    auto range1 = idx1.equal_range(t1);
    for(auto i = range1.first; i != range1.second;){
        if(i->second == d){
            i = idx1.erase(i);
        }else{
            i++;
        }
    }
    auto range2 = idx2.equal_range(t2);
    for(auto i = range2.first; i != range2.second;){
        if(i->second == d){
            i = idx2.erase(i);
        }else{
            i++;
        }
    }
    containers.erase(d);
}

template<class T1, class T2, class D>
size_t Index2<T1, T2, D>::size() const {
    assert(idx1.size() == idx2.size());
    return containers.size();
}

template<class T1, class T2, class D>
void Index2<T1, T2, D>::clear(){
    assert(idx1.size() == idx2.size());
    idx1.clear();
    idx2.clear();
    containers.clear();
}

template <class T1, class T2>
class bimap{
    std::map<T1, T2> map1;
    std::map<T2, T1> map2;
public:
    void add(const T1& t1, const T2& t2) {
        map1.emplace(t1, t2);
        map2.emplace(t2, t1);
        assert(map1.size() == map2.size());
    }
    T2& at(const T1& t1) {
        assert(map1.size() == map2.size());
        if(map1.count(t1) == 0) {
            abort();
        }
        return map1[t1];
    }
    T1& at(const T2& t2) {
        assert(map2.size() == map2.size());
        if(map2.count(t2) == 0) {
            abort();
        }
        return map2[t2];
    }
    bool has(const T1 t1) const {
        assert(map1.size() == map2.size());
        return map1.count(t1);
    }
    bool has(const T2 t2) const {
        assert(map1.size() == map2.size());
        return map2.count(t2);
    }
    void erase(const T1 t1) {
        if(map1.count(t1) == 0){
            return;
        }
        map2.erase(map1[t1]);
        map1.erase(t1);
        assert(map1.size() == map2.size());
    }
    void erase(const T2 t2) {
        if(map2.count(t2) == 0){
            return;
        }
        map1.erase(map2[t2]);
        map2.erase(t2);
        assert(map1.size() == map2.size());
    }
    size_t size() const {
        assert(map1.size() == map2.size());
        return map1.size();
    }
    void clear() {
        assert(map1.size() == map2.size());
        map1.clear();
        map2.clear();
    }
};

#endif
