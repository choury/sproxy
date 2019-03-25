#include "job.h"
#include "util.h"
#include "common.h"
#include <map>
#include <vector>

using std::function;

struct job_n{
    std::function<int ()> func;
    const void *index;
};

struct job_v{
    const char* func_name;
    uint32_t delay_ms;
    uint32_t last_done_ms;
};


class job_n_cmp{
public:
    bool operator()(const struct job_n& a, const struct job_n& b) const{
        auto afunc = a.func.target<int()>();
        auto bfunc = a.func.target<int()>();
        if(afunc == bfunc){
            return a.index < b.index;
        }else{
            return afunc < bfunc;
        }
    }
};

std::map<job_n, job_v, job_n_cmp> delayjobs;
std::map<job_n, const char*, job_n_cmp> prejobs;
std::map<job_n, const char*, job_n_cmp> postjobs;

void add_delayjob_real(function<int()> func, const char *func_name, const void *index, uint32_t interval_ms){
    assert(index);
#ifndef NDEBUG
    if(delayjobs.count(job_n{func, index})){
        LOGD(DJOB, "update a delay job %s for %p by %d\n", func_name, index, interval_ms);
    }else{
        LOGD(DJOB, "add a delay job %s for %p by %d\n", func_name, index, interval_ms);
    }
#endif
    delayjobs[job_n{func, index}] = job_v{func_name, interval_ms, getmtime()};
}

void add_prejob_real(function<int()> func, const char *func_name, const void *index){
    assert(index);
#ifndef NDEBUG
    LOGD(DJOB, "add a pre job %s for %p\n", func_name, index);
#endif
    prejobs[job_n{std::move(func), index}] = func_name;
}

void add_postjob_real(function<int()> func, const char *func_name, const void *index){
    assert(index);
#ifndef NDEBUG
    LOGD(DJOB, "add a post job %s for %p\n", func_name, index);
#endif
    postjobs[job_n{std::move(func), index}] = func_name;
}

void del_delayjob_real(function<int()> func, __attribute__ ((unused)) const char *func_name, const void *index){
    assert(index);
#ifndef NDEBUG
    if(delayjobs.count(job_n{func, index})){
        LOGD(DJOB, "del a delay job %s of %p\n", func_name, index);
    }else{
        LOGD(DJOB, "del a delay job %s of %p not found\n", func_name, index);
    }
#endif
    delayjobs.erase(job_n{func, index});
}

void del_prejob_real(function<int()> func, __attribute__ ((unused)) const char *func_name, const void *index){
    assert(index);
#ifndef NDEBUG
    if(prejobs.count(job_n{func, index})){
        LOGD(DJOB, "del a prejob %s of %p\n", func_name, index);
    }else{
        LOGD(DJOB, "del a prejob %s of %p not found\n", func_name, index);
    }
#endif
    prejobs.erase(job_n{func, index});
}

void del_postjob_real(function<int()> func, __attribute__ ((unused)) const char *func_name, const void *index){
    assert(index);
#ifndef NDEBUG
    if(postjobs.count(job_n{func, index})){
        LOGD(DJOB, "del a postjob %s of %p\n", func_name, index);
    }else{
        LOGD(DJOB, "del a postjob %s of %p not found\n", func_name, index);
    }
#endif
    postjobs.erase(job_n{func, index});
}

uint32_t do_delayjob(){
    uint32_t now = getmtime();
    std::map<job_n, job_v, job_n_cmp> job_todo;
    for(auto i=delayjobs.begin(); i!= delayjobs.end();){
        uint32_t diff = now - i->second.last_done_ms;
        if(diff >= i->second.delay_ms){
            LOGD(DJOB, "start delay job %s for %p diff %u\n",
                 i->second.func_name, i->first.index, diff );
            job_todo[i->first] = i->second;
            i = delayjobs.erase(i);
        }else{
            i++ ;
        }
    }
    for(auto i : job_todo){
        if(i.first.func()){
            i.second.last_done_ms = now;
            delayjobs[i.first] = i.second;
            LOGD(DJOB, "delay job %s readded\n", i.second.func_name);
        }
    }
    uint32_t min_interval = 0xffffff7f;
    for(const auto& i : delayjobs){
        uint32_t left = i.second.delay_ms + i.second.last_done_ms - now;
        if(left < min_interval){
            min_interval = left;
        }
    }
    return min_interval;
}

void do_prejob(){
    for(auto i = prejobs.begin(); i!= prejobs.end();){
        if(i->first.func() == 0){
            LOGD(DJOB, "done prejob %s for %p\n", i->second, i->first.index);
            i = prejobs.erase(i);
        }else{
            LOGD(DJOB, "done prejob %s for %p [R]\n", i->second, i->first.index);
            i++;
        }
    }
}

void do_postjob(){
    for(auto i = postjobs.begin(); i!= postjobs.end();){
        if(i->first.func() == 0){
            LOGD(DJOB, "done postjob %s for %p\n", i->second, i->first.index);
            i = postjobs.erase(i);
        }else{
            LOGD(DJOB, "done postjob %s for %p [R]\n", i->second, i->first.index);
            i++;
        }
    }
}

int check_delayjob(function<int()> func, const void* index){
    assert(index);
    return delayjobs.count(job_n{std::move(func), index});
}

void dump_job(Dumper dp, void* param){
    dp(param, "delay job queue:\n");
    uint32_t now = getmtime();
    for(const auto& i : delayjobs){
        uint32_t left = i.second.delay_ms + i.second.last_done_ms - now;
        dp(param, "\t%s(%p): %d/%d\n", i.second.func_name, i.first.index, left, i.second.delay_ms);
    }
    dp(param, "pre job queue:\n");
    for(const auto& i: prejobs){
        dp(param, "\t%s(%p)\n", i.second, i.first.index);
    }
    dp(param, "post job queue:\n");
    for(const auto& i: postjobs){
        dp(param, "\t%s(%p)\n", i.second, i.first.index);
    }
}

void job_clear(){
    LOGD(DJOB, "clear all jobs\n");
    delayjobs.clear();
    prejobs.clear();
    postjobs.clear();
}
