#ifndef _UTIL_H
#define _UTIL_H

#include <linux/sched/task.h>
#include <linux/time.h>
#include <linux/types.h>

struct task_struct* find_task_from_pid(pid_t pid);

/**
 *  Returns the nanosecond count. Used to compute time taken to execute
 *  functions. Cannot be used to determine the actual time, only used for
 *  deltas.
 */
u64 sus_time_nanos(void);

#endif
