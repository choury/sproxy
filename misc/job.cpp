#include "job.h"
#include "common.h"
#include <map>
#include <vector>

struct job_n{
    int (* func)(void *);
    void *arg;
};

struct job_v{
    const char *func_name;
    uint32_t delay;
    uint32_t last_done;
};


class job_n_cmp{
public:
    bool operator()(const struct job_n& a, const struct job_n& b) const{
        if(a.func == b.func){
            return a.arg < b.arg;
        }else{
            return a.func < b.func;
        }
    }
};

std::map<job_n, job_v, job_n_cmp> delayjobs;
std::map<job_n, const char*, job_n_cmp> prejobs;
std::map<job_n, const char*, job_n_cmp> postjobs;

void add_delayjob_real(job_func func, const char *func_name, void *arg, uint32_t interval){
#ifndef NDEBUG
    if(delayjobs.count(job_n{func, arg})){
        LOGD(DJOB, "update a delay job %s for %p by %d\n", func_name, arg, interval);
    }else{
        LOGD(DJOB, "add a delay job %s for %p by %d\n", func_name, arg, interval);
    }
#endif
    delayjobs[job_n{func, arg}] = job_v{func_name, interval, getmtime()};
}

void add_prejob_real(job_func func, const char *func_name, void *arg){
#ifndef NDEBUG
    LOGD(DJOB, "add a pre job %s for %p\n", func_name, arg);
#endif
    prejobs[job_n{func, arg}] = func_name;
}

void add_postjob_real(job_func func, const char *func_name, void *arg){
#ifndef NDEBUG
    LOGD(DJOB, "add a post job %s for %p\n", func_name, arg);
#endif
    postjobs[job_n{func, arg}] = func_name;
}

void del_delayjob_real(job_func func, const char *func_name, void *arg){
#ifndef NDEBUG
    if(delayjobs.count(job_n{func, arg})){
        LOGD(DJOB, "del a delay job %s of %p\n", func_name, arg);
    }else{
        LOGD(DJOB, "del a delay job %s of %p not found\n", func_name, arg);
    }
#endif
    delayjobs.erase(job_n{func, arg});
}

void del_prejob_real(job_func func, const char *func_name, void *arg){
#ifndef NDEBUG
    if(prejobs.count(job_n{func, arg})){
        LOGD(DJOB, "del a prejob %s of %p\n", func_name, arg);
    }else{
        LOGD(DJOB, "del a prejob %s of %p not found\n", func_name, arg);
    }
#endif
    prejobs.erase(job_n{func, arg});
}

void del_postjob_real(job_func func, const char *func_name, void *arg){
#ifndef NDEBUG
    if(postjobs.count(job_n{func, arg})){
        LOGD(DJOB, "del a postjob %s of %p\n", func_name, arg);
    }else{
        LOGD(DJOB, "del a postjob %s of %p not found\n", func_name, arg);
    }
#endif
    postjobs.erase(job_n{func, arg});
}

uint32_t do_delayjob(){
    uint32_t now = getmtime();
    std::map<job_n, job_v, job_n_cmp> job_todo;
    for(auto i=delayjobs.begin(); i!= delayjobs.end();){
        uint32_t diff = now - i->second.last_done;
        if(diff >= i->second.delay){
            LOGD(DJOB, "start delay job %s for %p diff %u\n",
                 i->second.func_name, i->first.arg, diff );
            job_todo[i->first] = i->second;
            i = delayjobs.erase(i);
        }else{
            i++ ;
        }
    }
    for(auto i : job_todo){
        if(i.first.func(i.first.arg)){
            i.second.last_done = now;
            delayjobs[i.first] = i.second;
            LOGD(DJOB, "delay job %s readded\n", i.second.func_name);
        }
    }
    uint32_t min_interval = 0xffffffff;
    for(auto i : delayjobs){
        uint32_t left = i.second.delay + i.second.last_done - now;
        if(left < min_interval){
            min_interval = left;
        }
    }
    return min_interval;
}

void do_prejob(){
    for(auto i = prejobs.begin(); i!= prejobs.end();){
        if(i->first.func(i->first.arg) == 0){
            LOGD(DJOB, "done prejob %s for %p\n", i->second, i->first.arg);
            i = prejobs.erase(i);
        }else{
            LOGD(DJOB, "done prejob %s for %p [R]\n", i->second, i->first.arg);
            i++;
        }
    }
}

void do_postjob(){
    for(auto i = postjobs.begin(); i!= postjobs.end();){
        if(i->first.func(i->first.arg) == 0){
            LOGD(DJOB, "done postjob %s for %p\n", i->second, i->first.arg);
            i = postjobs.erase(i);
        }else{
            LOGD(DJOB, "done postjob %s for %p [R]\n", i->second, i->first.arg);
            i++;
        }
    }
}

int check_delayjob(job_func func, void* arg){
    return delayjobs.count(job_n{func, arg});
}

void dump_job(){
    LOG("delay job queue:\n");
    uint32_t now = getmtime();
    for(auto i : delayjobs){
        uint32_t left = i.second.delay + i.second.last_done - now;
        LOG("\t%s(%p): %d/%d\n", i.second.func_name, i.first.arg, left, i.second.delay);
    }
    LOG("pre job queue:\n");
    for(auto i: prejobs){
        LOG("\t%s(%p)\n", i.second, i.first.arg);
    }
    LOG("post job queue:\n");
    for(auto i: postjobs){
        LOG("\t%s(%p)\n", i.second, i.first.arg);
    }
}

void job_clear(){
    LOGD(DJOB, "clear all jobs\n");
    delayjobs.clear();
    prejobs.clear();
    postjobs.clear();
}
