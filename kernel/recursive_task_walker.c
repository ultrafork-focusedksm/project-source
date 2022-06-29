// SPDX-License-Identifier: GPL-2.0
#include "recursive_task_walker.h"

/**
 * Recursive task walker. Given a task, visit it, and all its
 * decendants.
 * @param task The parent task structure
 * @param data Private data pointer for the handlers to use.
 * @param walker The walker context
 */
void walk_task(struct task_struct* task, void* data,
               struct recursive_task_walker* walker)
{
    struct list_head* list;

    int status = walker->task_handler(task, data);
    if (status == RECURSIVE_TASK_WALKER_CONTINUE)
    {
        list_for_each(list, &task->children)
        {
            struct task_struct* child =
                list_entry(list, struct task_struct, sibling);
            if (unlikely(NULL == child))
            {
                pr_err("rtask_walker: unexpected NULL child\n");
            }
            else
            {
                walk_task(child, data, walker);
            }
        }
    }
}
