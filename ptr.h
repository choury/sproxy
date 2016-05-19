#ifndef PTR_H__
#define PTR_H__

#include <stddef.h>
#include <vector>

class Ptr_for_this;

struct Ptr_data{
    Ptr_for_this *data;
    int  count;
    bool deffer(){
        count--;
        if(count <= 0){
            delete this;
            return true;
        }
        return false;
    }
};



class Ptr{
    Ptr_data *d = nullptr;
public:
    Ptr(){}
    Ptr(Ptr_data *d):d(d){
        d->count++;
    }
    Ptr(const Ptr &ptr){
        d = ptr.d;
        if(d)
            d->count++;
    }
    Ptr& operator=(const Ptr &ptr){
        this->~Ptr();
        d = ptr.d;
        if(d)
            d->count++;
        return *this;
    }
    Ptr_for_this* get(){
        if(expired())
            return nullptr;
        return d->data;
    }
    bool expired(){
        return !d || !d->data ||  d->count <= 0;
    }
    ~Ptr(){
        if(!d)
            return;
        d->deffer();
    }
};

class Ptr_for_this{
    std::vector<Ptr_data *> ps;
public:
    explicit Ptr_for_this(){
        ps.push_back(new Ptr_data{this, 1});
    }
    ~Ptr_for_this(){
        for(auto i:ps){
            i->data = nullptr;
            i->deffer();
        }
    }
    void reset_this_ptr(Ptr_for_this *to = nullptr){
        for(auto i:ps){
            i->data = to;
            if(to)
                to->ps.push_back(i);
        }
        ps.clear();
        ps.push_back(new Ptr_data{this, 1});
    }
    virtual Ptr shared_from_this(){
        return ps[0];
    }
};

#endif
