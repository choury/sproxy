#include "job.h"
#include "util.h"
#include "common.h"
#include <assert.h>
#include <cxxabi.h>
#include <string>

using std::function;
job_handler static_job_handler;

struct Job{
    const char* func_name;
    std::function<void()> func;
    uint32_t flags;
    uint32_t delay_ms;
    uint32_t last_done_ms;
    std::list<Job*>::iterator i;
    job_handler* handler;
};

std::string demangle(const char* name) {
    int status = -4; // some arbitrary value to eliminate the compiler warning
    char* output = abi::__cxa_demangle(name, NULL, NULL, &status);
    if(status == 0){
        std::string  out = output;
        free(output);
        return out;
    }else{
        return name;
    }
}

std::list<Job*> delayjobs;

Job* job_handler::addjob_with_name(std::function<void()> func, const char *func_name, uint32_t interval_ms, uint32_t flags) {
    LOGD(DJOB, "add a Job %s by %d\n", func_name, interval_ms);
    Job* job = new Job{
        func_name,
        std::move(func),
        flags,
        interval_ms,
        getmtime(),
        delayjobs.end(),
        this,
    };
    job->i = delayjobs.insert(delayjobs.end(), job);
    jobs.push_back(job);
    if(flags & JOB_FLAGS_AUTORELEASE){
        return nullptr;
    }
    return job;
}

Job * job_handler::updatejob_with_name(Job *job, std::function<void()> func, const char *func_name, uint32_t interval_ms) {
    if(job == nullptr){
        return addjob_with_name(func, func_name, interval_ms, 0);
    }
    LOGD(DJOB, "update a Job %s by %d\n", func_name, interval_ms);
    job->delay_ms = interval_ms;
    job->last_done_ms = getmtime();
    job->func_name = func_name;
    if(job->i == delayjobs.end()){
        job->i = delayjobs.insert(delayjobs.end(), job);
    }
    return job;
}

void job_handler::deljob(Job **job) {
    if(*job == nullptr){
        return;
    }
    LOGD(DJOB, "del a Job %s\n", (*job)->func_name);
    if((*job)->i != delayjobs.end()) {
        delayjobs.erase((*job)->i);
    }
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
        if(j->i != delayjobs.end()) {
            delayjobs.erase(j->i);
        }
        LOGD(DJOB, "destroy a Job %s\n", j->func_name);
        delete j;
    }
}

uint32_t do_delayjob(){
    uint32_t now = getmtime();
    std::list<Job*> jobs_todo;
    for(auto j=delayjobs.begin(); j!= delayjobs.end();){
        uint32_t diff = now - (*j)->last_done_ms;
        if(diff >= (*j)->delay_ms){
            LOGD(DJOB, "start Job %s diff %u\n", (*j)->func_name, diff);
            (*j)->i = delayjobs.end();
            jobs_todo.push_back(*j);
            j = delayjobs.erase(j);
        }else{
            j++ ;
        }
    }
    for(auto j: jobs_todo){
        j->func();
        if(j->flags & JOB_FLAGS_AUTORELEASE){
            j->handler->deljob(&j);
        }
    }
    uint32_t min_interval = 0xffffff7f;
    for(auto j: delayjobs){
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
    for(auto j: delayjobs){
        uint32_t left = j->delay_ms + j->last_done_ms - now;
        dp(param, "\t%s: %d/%d\n", j->func_name, left, j->delay_ms);
    }
}

