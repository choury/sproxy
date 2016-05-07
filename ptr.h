#ifndef PTR_H__
#define PTR_H__

#include <stddef.h>

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
    Ptr_data *d;
public:
    explicit Ptr_for_this(){
        d = new Ptr_data{this, 1};
    }
    ~Ptr_for_this(){
        d->data = nullptr;
        d->deffer();
    }
    void reset_this_ptr(){
        this->~Ptr_for_this();
        d = new Ptr_data{this, 1};
    }
    virtual Ptr shared_from_this(){
        return d;
    }
};

#endif
