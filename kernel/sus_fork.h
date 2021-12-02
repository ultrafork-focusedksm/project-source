#ifndef _SUS_FORK_H
#define _SUS_FORK_H

#include <linux/sched.h>
#include <linux/sched/task.h>

struct task_struct* sus_kernel_clone(struct task_struct* target,
                                     struct kernel_clone_args* args);

#endif
