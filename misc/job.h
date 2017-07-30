#ifndef JOB_H__
#define JOB_H__

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef int (*job_func)(void *);
void add_delayjob_real(job_func func, const char *func_name, void *arg, uint32_t interval);
//if return no zero, the job will be repeated
#define add_delayjob(a, b, c) add_delayjob_real(a, #a, b, c)
void del_delayjob_real(job_func func, const char *func_name, void *arg);
#define del_delayjob(a, b) del_delayjob_real(a, #a, b)

//if return no zero, the job will be repeated
void add_prejob_real(job_func func, const char *func_name, void *arg);
#define add_prejob(a, b) add_prejob_real(a, #a, b);
void del_prejob_real(job_func func, const char *func_name, void *arg);
#define del_prejob(a, b) del_prejob_real(a, #a, b);

//if return no zero, the job will be repeated
void add_postjob_real(job_func func, const char *func_name, void *arg);
#define add_postjob(a, b) add_postjob_real(a, #a, b);
void del_postjob_real(job_func func, const char *func_name, void *arg);
#define del_postjob(a, b) del_postjob_real(a, #a, b);

uint32_t do_delayjob();
void do_prejob();
void do_postjob();
int check_delayjob(job_func func, void* arg);


#ifdef  __cplusplus
}
#endif

#endif
