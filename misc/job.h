#ifndef JOB_H__
#define JOB_H__

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*job_func)(void *);
void add_job_real(job_func func, const char *func_name, void *arg, uint32_t interval);
#define add_job(a, b, c) add_job_real(a, #a, b, c)
void del_job_real(job_func func, const char *func_name, void *arg);
#define del_job(a, b) del_job_real(a, #a, b)
uint32_t do_job();

void job_clear();

#ifdef  __cplusplus
}
#endif

#endif
