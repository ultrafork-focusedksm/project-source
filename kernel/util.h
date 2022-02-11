#ifndef _UTIL_H
#define _UTIL_H

#include <linux/sched/task.h>
#include <linux/time.h>
#include <linux/types.h>

/**
 * Looks up the task_struct for the process with the given pid in the main
 * namespace. This function cannot be used to lookup the task_struct for
 * a process running in another namespace.
 *
 * @param pid Process ID to lookup
 *
 * @return Task structure associated with the process. NULL if the process
 * could not be found.
 */
struct task_struct* find_task_from_pid(pid_t pid);

/**
 *  Returns the nanosecond count. Used to compute time taken to execute
 *  functions. Cannot be used to determine the actual time, only used for
 *  deltas.
 *
 *  @return nanosecond uptime counter
 */
u64 sus_time_nanos(void);

#endif
