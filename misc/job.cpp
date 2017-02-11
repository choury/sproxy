#include "job.h"
#include "common.h"
#include <map>
#include <vector>

struct job_n{
    void (* func)(void *);
    void *arg;
};

struct job_v{
    const char *func_name;
    uint32_t interval;
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

std::map<job_n, job_v, job_n_cmp> callfunc_map;

void add_job_real(job_func func, const char *func_name, void *arg, uint32_t interval){
#ifndef NDEBUG
    if(callfunc_map.count(job_n{func, arg})){
        LOGD(DJOB, "update a function %s for %p by %d\n", func_name, arg, interval);
    }else{
        LOGD(DJOB, "add a function %s for %p by %d\n", func_name, arg, interval);
    }
#endif
    callfunc_map[job_n{func, arg}] = job_v{func_name, interval, getmtime()};
}

void del_job_real(job_func func, const char *func_name, void *arg){
#ifndef NDEBUG
    if(callfunc_map.count(job_n{func, arg})){
        LOGD(DJOB, "del a function %s of %p\n", func_name, arg);
    }else{
        LOGD(DJOB, "del a function %s of %p not found\n", func_name, arg);
    }
#endif
    callfunc_map.erase(job_n{func, arg});
}

uint32_t do_job(){
    uint32_t now = getmtime();
    uint32_t min_interval = 0xffffffff;
    std::vector<job_n> job_set;
    for(auto i=callfunc_map.begin(); i!= callfunc_map.end(); i++){
        uint32_t diff = now - i->second.last_done;
        if(diff >= i->second.interval){
#ifndef NDEBUG
            LOGD(DJOB, "start job %s for %p diff %u\n",
                 i->second.func_name, i->first.arg, diff );
#endif
            i->second.last_done = now;
            job_set.push_back(i->first);
        }
        uint32_t left = i->second.interval + i->second.last_done - now;
        if(left < min_interval){
            min_interval = left;
        }
    }
    for(auto i:job_set){
        i.func(i.arg);
    }
    return min_interval;
}
