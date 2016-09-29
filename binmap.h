#ifndef BINMAP_H__
#define BINMAP_H__
#include <map>
#include <set>
#include <typeinfo>

#include <assert.h>

template<class T1, class T2>
class binmap{
    std::map<T1, T2> left;
    std::map<T2, T1> right;
public:
    void insert(const T1&, const T2&);
    void erase(const T1&, const T2&);
    void erase(const T1&);
    void erase(const T2&);
    T1 at(const T2& key);
    T2 at(const T1& key);
    T1& operator[](const T2& key);
    T1 operator[](const T2& key)const;
    T2& operator[](const T1& key);
    T2 operator[](const T1& key)const;
    size_t count(T1 t1);
    size_t count(T2 t2);
    const std::map<T1, T2>& Left();
    const std::map<T2, T1>& Right();
    bool empty() const;
    void clear();
};


template<class T1, class T2>
void binmap<T1, T2>::insert(const T1& t1, const T2& t2) {
    assert(typeid(t1) != typeid(t2));
    left.insert(std::make_pair(t1, t2));
    right.insert(std::make_pair(t2, t1));
}

template<class T1, class T2>
void binmap<T1, T2>::erase(const T1& key) {
    if(left.count(key)){
        right.erase(left[key]);
        left.erase(key);
    }
}

template<class T1, class T2>
void binmap<T1, T2>::erase(const T2& key) {
    if(right.count(key)){
        left.erase(right[key]);
        right.erase(key);
    }
}

template<class T1, class T2>
void binmap<T1, T2>::erase(const T1& t1, const T2& t2) {
    left.erase(t1);
    right.erase(t2);
}


template<class T1, class T2>
T2 binmap<T1, T2>::at(const T1& key) {
    return left.at(key);
}

template<class T1, class T2>
T1 binmap<T1, T2>::at(const T2& key) {
    return right.at(key);
}

template<class T1, class T2>
T2& binmap<T1, T2>::operator[](const T1& key)
{
    return left[key];
}

template<class T1, class T2>
T2 binmap<T1, T2>::operator[](const T1& key) const
{
    return left[key];
}

template<class T1, class T2>
T1& binmap<T1, T2>::operator[](const T2& key)
{
    return  right[key];
}

template<class T1, class T2>
T1 binmap<T1, T2>::operator[](const T2& key) const
{
    return  right[key];
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
const std::map<T1, T2>& binmap<T1, T2>::Left(){
    return left;
}

template<class T1, class T2>
const std::map<T2, T1>& binmap<T1, T2>::Right(){
    return right;
}

template<class T1, class T2>
bool binmap<T1, T2>::empty() const {
    return left.empty() && right.empty();
}

template<class T1, class T2>
void binmap<T1, T2>::clear() {
    left.clear();
    right.clear();
}


#endif

