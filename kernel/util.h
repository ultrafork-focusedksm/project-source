#ifndef _UTIL_H
#define _UTIL_H

#include <linux/sched/task.h>
#include <linux/types.h>

struct task_struct* find_task_from_pid(pid_t pid);

#endif
