#ifndef INDEX_H__
#define INDEX_H__

#include <map>

template <class T1, class T2, class D>
class Index2{
    struct Container{
        const T1 t1;
        const T2 t2;
        D        data;
    };
    std::map<T1, Container> idx1;
    std::map<T2, Container> idx2;
public:
    void Add(T1 t1, T2 t2, D data);
    Container* Get(T1 t1);
    Container* Get(T2 t2);
    void Delete(T1 t1);
    void Delete(T2 t2);
};

template<class T1, class T2, class D>
void Index2<T1, T2, D>::Add(T1 t1, T2 t2, D data) {
    idx1.insert(std::make_pair(t1, Container{t1, t2, data}));
    idx2.insert(std::make_pair(t2, Container{t1, t2, data}));
}

template<class T1, class T2, class D>
typename Index2<T1, T2, D>::Container* Index2<T1, T2, D>::Get(T1 t1){
    if(idx1.count(t1) == 0){
        return nullptr;
    }
    return &idx1.at(t1);
}

template<class T1, class T2, class D>
typename Index2<T1, T2, D>::Container* Index2<T1, T2, D>::Get(T2 t2) {
    if(idx2.count(t2) == 0){
        return nullptr;
    }
    return &idx2.at(t2);
}

template<class T1, class T2, class D>
void Index2<T1, T2, D>::Delete(T1 t1) {
    idx2.erase(idx1.at(t1).t2);
    idx1.erase(t1);
}

template<class T1, class T2, class D>
void Index2<T1, T2, D>::Delete(T2 t2) {
    idx1.erase(idx2.at(t2).t1);
    idx2.erase(t2);
}

#endif
