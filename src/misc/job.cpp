#include "job.h"
#include "common/common.h"
#include <assert.h>

#include <list>

#define JOB_RUNNING   (1u<<15u)
#define JOB_DESTROIED (1u<<16u)


struct job{
    const char* func_name;
    std::function<void()> func;
    uint32_t flags;
    uint64_t delay_ms;
    uint32_t last_done_ms;
    job* pre;
    job* next;
};

job root = {"root", [](){}, 0, 0, 0, nullptr, nullptr};

void static insert_job(job* j){
    job* pre = &root;
    job* next = root.next;
    while(next && next->last_done_ms + next->delay_ms < j->last_done_ms + j->delay_ms){
        pre = next;
        next = next->next;
    }
    j->pre = pre;
    j->next = next;
    pre->next = j;
    if(next) next->pre = j;
}

void static remove_job(job* j) {
    if(j->pre == nullptr) {
        return;
    }
    j->pre->next = j->next;
    if(j->next) j->next->pre = j->pre;
    j->pre = nullptr;
}


void jobDeleter::operator()(job *job) {
    if (job == nullptr) {
        return;
    }
    remove_job(job);
    job->flags |= JOB_DESTROIED;
    if ((job->flags & JOB_RUNNING) == 0) {
        LOGD(DJOB, "destory a Job %p %s\n", job, job->func_name);
        delete job;
    } else {
        LOGD(DJOB, "delay to destory a Job %p %s\n", job, job->func_name);
    }
}

uint32_t JobPending(Job& job) {
    if(job == nullptr || job->pre == nullptr) {
        return UINT32_MAX;
    }
    uint64_t next_do = job->delay_ms + job->last_done_ms;
    uint32_t now = getmtime();
    return  next_do > now ? next_do - now : 1;
}


Job addjob_with_name(std::function<void()> func, const char *func_name, uint32_t interval_ms, uint32_t flags) {
    auto now = getmtime();
    job* j = new job{
            func_name,
            std::move(func),
            flags,
            interval_ms,
            now,
            nullptr,
            nullptr,
    };
    LOGD(DJOB, "add a Job %p %s by %d\n", j, func_name, interval_ms);
    insert_job(j);

    if(flags & JOB_FLAGS_AUTORELEASE){
        return nullptr;
    }
    return Job(j);
}

Job updatejob_with_name(Job job, std::function<void()> func, const char *func_name, uint32_t interval_ms) {
    if(job == nullptr){
        return addjob_with_name(func, func_name, interval_ms, 0);
    }
    assert((job->flags & JOB_DESTROIED) == 0);
    LOGD(DJOB, "update a Job %p %s by %d\n", job.get(), func_name, interval_ms);
    job->func = std::move(func);
    job->delay_ms = interval_ms;
    job->last_done_ms = getmtime();
    job->func_name = func_name;
    remove_job(job.get());
    insert_job(job.get());
    return job;
}


uint32_t do_delayjob(){
    uint32_t now = getmtime();
    std::list<job*> jobs_todo;
    job* j = root.next;
    while(j) {
        uint32_t diff = now - j->last_done_ms;
        assert((j->flags & JOB_DESTROIED) == 0);
        if(diff < j->delay_ms){
            break;
        }

        LOGD(DJOB, "will do Job %p %s diff %u\n", j, j->func_name, diff);
        j->flags |= JOB_RUNNING;
        jobs_todo.push_back(j);
        remove_job(j);
        j = j->next;
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
            jobDeleter()(j);
        }
    }
#if __ANDROID__
    uint32_t min_interval = 0x7fffffff; //max
#else
    uint32_t min_interval = 60000; //1min
#endif
    now = getmtime();
    if(root.next){
        job* j = root.next;
        uint64_t next_do = j->delay_ms + j->last_done_ms;
        min_interval = next_do > now ? next_do-now : 0;
    }
    return min_interval;
}

void dump_job(Dumper dp, void* param){
    dp(param, "Job queue:\n");
    uint32_t now = getmtime();
    job* j = root.next;
    while(j) {
        uint32_t left = j->delay_ms + j->last_done_ms - now;
        dp(param, "  %p %s: %d/%d\n", j, j->func_name, left, (int)j->delay_ms);
        j = j->next;
    }
}
