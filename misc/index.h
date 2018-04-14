#ifndef INDEX_H__
#define INDEX_H__

#include <map>
#include <assert.h>

template <class T1, class T2, class D>
class Index2{
    struct Container{
        const T1 t1;
        const T2 t2;
        D  data;
    };
    std::map<T1, Container*> idx1;
    std::map<T2, Container*> idx2;
public:
    void Add(const T1 t1, const T2 t2, const D data);
    Container* Get(const T1 t1) const;
    Container* Get(const T2 t2) const;
    void Delete(const T1 t1);
    void Delete(const T2 t2);
    const std::map<T1, Container*>& index1(){
        return idx1;
    }
    const std::map<T2, Container*>& index2(){
        return idx2;
    }
    void clear();
};

template<class T1, class T2, class D>
void Index2<T1, T2, D>::Add(const T1 t1, const T2 t2, const D data) {
    assert(idx1.count(t1) == 0 && idx2.count(t2) == 0);
    Container* c = new Container{t1, t2, data};
    idx1.insert(std::make_pair(t1, c));
    idx2.insert(std::make_pair(t2, c));
}

template<class T1, class T2, class D>
typename Index2<T1, T2, D>::Container* Index2<T1, T2, D>::Get(const T1 t1) const{
    if(idx1.count(t1) == 0){
        return nullptr;
    }
    return idx1.at(t1);
}

template<class T1, class T2, class D>
typename Index2<T1, T2, D>::Container* Index2<T1, T2, D>::Get(const T2 t2) const{
    if(idx2.count(t2) == 0){
        return nullptr;
    }
    return idx2.at(t2);
}

template<class T1, class T2, class D>
void Index2<T1, T2, D>::Delete(const T1 t1) {
    Container* c = idx1.at(t1);
    assert(c->t1 == t1);
    idx2.erase(c->t2);
    idx1.erase(t1);
    delete c;
}

template<class T1, class T2, class D>
void Index2<T1, T2, D>::Delete(const T2 t2) {
    Container* c = idx2.at(t2);
    assert(c->t2 == t2);
    idx1.erase(c->t1);
    idx2.erase(t2);
    delete c;
}

template<class T1, class T2, class D>
void Index2<T1, T2, D>::clear(){
    for(auto i: idx2){
        delete i.second;
    }
    assert(idx1.size() == idx2.size());
    idx1.clear();
    idx2.clear();
}

#endif
