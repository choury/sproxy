#include "job.h"
#include "util.h"
#include "common/common.h"
#include <assert.h>
#include <set>

std::set<Job*> gjobs;
job_handler static_job_handler;

#define JOB_RUNNING   (1u<<15u)
#define JOB_DESTROIED (1u<<16u)

struct Job{
    const char* func_name;
    std::function<void()> func;
    uint32_t flags;
    uint32_t delay_ms;
    uint32_t last_done_ms;
    job_handler* handler;
};


uint32_t JobPending(const Job* job) {
    if(job == nullptr || gjobs.count(const_cast<Job*>(job)) == 0) {
        return 0;
    }
    uint32_t next_do = job->delay_ms + job->last_done_ms;
    uint32_t now = getmtime();
    return  next_do > now ? next_do - now : 1;
}

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
    job->func = std::move(func);
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
    (*job)->flags |= JOB_DESTROIED;
    gjobs.erase(*job);
    for(auto j = jobs.begin(); j != jobs.end(); j++ ){
        if(*j == *job){
            jobs.erase(j);
            break;
        }
    }
    if(((*job)->flags & JOB_RUNNING) == 0){
        LOGD(DJOB, "del a Job %p %s\n", *job, (*job)->func_name);
        delete *job;
    }else{
        LOGD(DJOB, "delay to del a Job %p %s\n", *job, (*job)->func_name);
    }
    *job = nullptr;
}

job_handler::~job_handler() {
    for(auto j: jobs){
        assert((j->flags & JOB_DESTROIED) == 0);
        gjobs.erase(j);
        j->flags |= JOB_DESTROIED;
        if((j->flags & JOB_RUNNING) == 0) {
            LOGD(DJOB, "destroy a Job %p %s\n", j, j->func_name);
            delete j;
        }else{
            LOGD(DJOB, "delay to destroy a Job %p %s\n", j, j->func_name);
        }
    }
}

uint32_t do_delayjob(){
    uint32_t now = getmtime();
    std::list<Job*> jobs_todo;
    for(auto j = gjobs.begin(); j != gjobs.end();) {
        uint32_t diff = now - (*j)->last_done_ms;
        assert(((*j)->flags & JOB_DESTROIED) == 0);
        if(diff < (*j)->delay_ms) {
            j++;
            continue;
        }
        LOGD(DJOB, "will do Job %p %s diff %u\n", (*j), (*j)->func_name, diff);
        (*j)->flags |= JOB_RUNNING;
        jobs_todo.push_back(*j);
        j = gjobs.erase(j);
    }
    for(auto j: jobs_todo){
        if(j->flags & JOB_DESTROIED){
            LOGD(DJOB, "destroy a Job %p %s before do it\n", j, j->func_name);
            delete j;
            continue;
        }
        j->func();
        if(j->flags & JOB_DESTROIED){
            LOGD(DJOB, "destroy a Job %p %s after done\n", j, j->func_name);
            delete j;
            continue;
        }
        j->flags &= ~JOB_RUNNING;
        if (j->flags & JOB_FLAGS_AUTORELEASE) {
            j->handler->deljob(&j);
        }
    }
    uint32_t min_interval = 0xffffffff;
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
        dp(param, "  %p %s: %d/%d\n", j, j->func_name, left, j->delay_ms);
    }
}

