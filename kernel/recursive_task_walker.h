/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _RECURSIVE_TASK_WALKER_H
#define _RECURSIVE_TASK_WALKER_H

#include <linux/sched/task.h>

#define RECURSIVE_TASK_WALKER_CONTINUE 0
#define RECURSIVE_TASK_WALKER_STOP 1

struct recursive_task_walker
{
    /**
     * Define a visitor for each task.
     *
     * @param task The task being visited
     * @param data Private data passed into the walker for use in these
     * functions.
     * @return RECURSIVE_TASK_WALKER_CONTINUE to keep traversing,
     * RECURSIVE_TASK_WALKER_STOP to stop traversing.
     */
    int (*task_handler)(struct task_struct* task, void* data);
};

/**
 * Recursive task walker. Given a task, visit it, and all its
 * decendants.
 * @param task The parent task structure
 * @param data Private data pointer for the handlers to use.
 * @param walker The walker context
 */
void walk_task(struct task_struct* task, void* data,
               struct recursive_task_walker* walker);

#endif
