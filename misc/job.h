#ifndef JOB_H__
#define JOB_H__

#include <stdint.h>
#include <functional>

void add_delayjob_real(std::function<int()> func, const char *func_name, const void *index, uint32_t interval_ms);
//if return no zero, the job will be repeated
#define add_delayjob(a, b, c) add_delayjob_real(a, #a, b, c)
void del_delayjob_real(std::function<int()> func, const char *func_name, const void *index);
#define del_delayjob(a, b) del_delayjob_real(a, #a, b)

#if 0
//if return no zero, the job will be repeated
void add_prejob_real(std::function<int()> func, const char *func_name, const void *index);
#define add_prejob(a, b) add_prejob_real(a, #a, b);
void del_prejob_real(std::function<int()> func, const char *func_name, const void *index);
#define del_prejob(a, b) del_prejob_real(a, #a, b);

//if return no zero, the job will be repeated
void add_postjob_real(std::function<int()> func, const char *func_name, const void *index);
#define add_postjob(a, b) add_postjob_real(a, #a, b);
void del_postjob_real(std::function<int()> func, const char *func_name, const void *index);
#define del_postjob(a, b) del_postjob_real(a, #a, b);
void do_prejob();
void do_postjob();
#endif

uint32_t do_delayjob();
int check_delayjob(std::function<int()> func, const void* index);

#endif
