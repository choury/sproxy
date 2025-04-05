#ifndef JOB_H__
#define JOB_H__

#include <stdint.h>
#include <functional>
#include <memory>

struct job;
class jobDeleter {
public:
    void operator()(job *job);
};

typedef std::unique_ptr<job, jobDeleter> Job;
#define JOB_FLAGS_AUTORELEASE (1u<<0u)

uint32_t JobPending(Job& job);
uint32_t do_delayjob();
Job addjob_with_name(std::function<void()> func, const char *func_name, uint32_t interval_ms, uint32_t flags);
#define AddJob(func, interval_ms, flags) addjob_with_name(func, #func "#" STRINGIZE(__LINE__), interval_ms, flags)
Job updatejob_with_name(Job job, std::function<void()> func, const char *func_name, uint32_t interval_ms);
#define UpdateJob(job, func, interval_ms) updatejob_with_name(job, func, #func "#" STRINGIZE(__LINE__), interval_ms)
#endif
