#ifndef _UTIL_H
#define _UTIL_H

#include <linux/sched/task.h>
#include <linux/time.h>
#include <linux/types.h>

struct task_struct* find_task_from_pid(pid_t pid);

/**
 *  Returns the jiffy count. Used to compute time taken to execute
 *  functions.
 */
u64 sus_time_jiffies(void);

/**
 * Computes the difference between the two jiffy counts.
 *
 * difference = large_jiffies - small_jiffies
 *
 * @return timespec64 containing the difference.
 */
struct timespec64 sus_micro_difference(u64 large_jiffers, u64 small_jiffies);

#endif
