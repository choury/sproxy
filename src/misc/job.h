#ifndef JOB_H__
#define JOB_H__

#include <stdint.h>
#include <functional>
#include <list>

struct Job;
class job_handler{
    std::list<Job*> jobs;
public:
#define JOB_FLAGS_AUTORELEASE (1u<<0u)
    Job* addjob_with_name(std::function<void()> func, const char* func_name, uint32_t interval_ms, uint32_t flags);
    Job* updatejob_with_name(Job* job, std::function<void()> func, const char* func_name, uint32_t interval_ms);
#define addjob(func, interval_ms, flags) addjob_with_name(func, #func, interval_ms, flags)
#define updatejob(job, func, interval_ms) updatejob_with_name(job, func, #func, interval_ms)
    void deljob(Job** job);
    ~job_handler();
};

uint32_t do_delayjob();
extern job_handler static_job_handler;
#define AddJob(func, interval_ms, flags) static_job_handler.addjob_with_name(func, #func, interval_ms, flags)
#define DelJob(job) static_job_handler.deljob(job)
#define UpdateJob(job, func, interval_ms) satic_job_handler.updatejob_with_name(job, func, #func, interval_ms)
#endif
