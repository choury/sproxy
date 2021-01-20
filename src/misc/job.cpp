#include "job.h"
#include "util.h"
#include "common.h"
#include <assert.h>
#include <set>

using std::function;
job_handler static_job_handler;

#define JOB_DESTROIED (1u<<16u)

struct Job{
    const char* func_name;
    std::function<void()> func;
    uint32_t flags;
    uint32_t delay_ms;
    uint32_t last_done_ms;
    job_handler* handler;
    ~Job(){}
};

std::set<Job*> gjobs;

Job* job_handler::addjob_with_name(std::function<void()> func, const char *func_name, uint32_t interval_ms, uint32_t flags) {
    Job* job = new Job{
            func_name,
            std::move(func),
            flags,
            interval_ms,
            getmtime(),
            this,
    };
    LOGD(DJOB, "add a Job %p %s by %d\n", job, func_name, interval_ms);
    gjobs.insert(job);
    jobs.push_back(job);
    if(flags & JOB_FLAGS_AUTORELEASE){
        return nullptr;
    }
    return job;
}

Job* job_handler::updatejob_with_name(Job *job, std::function<void()> func, const char *func_name, uint32_t interval_ms) {
    if(job == nullptr){
        return addjob_with_name(func, func_name, interval_ms, 0);
    }
    assert((job->flags & JOB_DESTROIED) == 0);
    LOGD(DJOB, "update a Job %p %s by %d\n", job, func_name, interval_ms);
    job->delay_ms = interval_ms;
    job->last_done_ms = getmtime();
    job->func_name = func_name;
    gjobs.insert(job);
    return job;
}

void job_handler::deljob(Job **job) {
    if(*job == nullptr){
        return;
    }
    LOGD(DJOB, "del a Job %p %s\n", *job, (*job)->func_name);
    (*job)->flags |= JOB_DESTROIED;
    gjobs.erase(*job);
    for(auto j = jobs.begin(); j != jobs.end(); j++ ){
        if(*j == *job){
            jobs.erase(j);
            break;
        }
    }
    delete *job;
    *job = nullptr;
}

job_handler::~job_handler() {
    for(auto j: jobs){
        assert((j->flags & JOB_DESTROIED) == 0);
        gjobs.erase(j);
        j->flags |= JOB_DESTROIED;
        LOGD(DJOB, "destroy a Job %p %s\n", j, j->func_name);
        delete j;
    }
}

uint32_t do_delayjob(){
    uint32_t now = getmtime();
    std::list<Job*> jobs_todo;
    for(auto j = gjobs.begin(); j != gjobs.end();){
        uint32_t diff = now - (*j)->last_done_ms;
        assert(((*j)->flags & JOB_DESTROIED) == 0);
        if(diff < (*j)->delay_ms){
            j++;
            continue;
        }
        LOGD(DJOB, "start Job %p %s diff %u\n", (*j), (*j)->func_name, diff);
        jobs_todo.push_back(*j);
        j = gjobs.erase(j);
    }
    for(auto j: jobs_todo){
        if(j->flags & JOB_FLAGS_AUTORELEASE){
            j->func();
            j->handler->deljob(&j);
        }else{
            j->func();
        }
    }
    uint32_t min_interval = 0xffffff7f;
    for(auto j: gjobs){
        uint32_t left = j->delay_ms + j->last_done_ms - now;
        if(left < min_interval){
            min_interval = left;
        }
    }
    return min_interval;
}

void dump_job(Dumper dp, void* param){
    dp(param, "Job queue:\n");
    uint32_t now = getmtime();
    for(auto j: gjobs){
        uint32_t left = j->delay_ms + j->last_done_ms - now;
        dp(param, "\t%p %s: %d/%d\n", j, j->func_name, left, j->delay_ms);
    }
}

