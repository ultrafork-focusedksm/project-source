#include "ultrafork.h"
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>

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

static int recursive_task_traverse(struct task_struct* task, void* data);

static struct recursive_task_walker rtask_logger = {
    .task_handler = recursive_task_traverse,
};

/**
 * Recursive task walker. Given a task, visit it, and all its decendants.
 * @param task The parent task structure
 * @param data Private data pointer for the handlers to use.
 * @param walker The walker context
 */
static void walk_task(struct task_struct* task, void* data,
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

            status = walker->task_handler(child, data);
            if (status == RECURSIVE_TASK_WALKER_STOP)
            {
                return;
            }

            walk_task(child, data, walker);
        }
    }
}

static int recursive_task_traverse(struct task_struct* task, void* data)
{
    pr_info("%s, pid=%d, tgid=%d\n", task->comm, task->pid, task->tgid);
    return RECURSIVE_TASK_WALKER_CONTINUE;
}

static void suspend_task(struct task_struct* task)
{
    // TODO: Does this actually work, its a bit hacky. also look at
    // activate_task and deactivate_task
    // TODO: Block CONT signals until we are ready to resume.
    kill_pid(task_pid(task), SIGSTOP, 1);
}

static void resume_task(struct task_struct* task)
{
    // TODO: see nots on suspend_task
    kill_pid(task_pid(task), SIGCONT, 1);
}

static struct task_struct* find_task_from_pid(unsigned long pid)
{
    struct pid* pid_struct = find_get_pid(pid);
    return get_pid_task(pid_struct, PIDTYPE_PID);
}

int sus_mod_fork(unsigned long pid, unsigned char flags)
{
    struct task_struct* parent;

    if (pid < 1)
    {
        return -EINVAL;
    }

    parent = find_task_from_pid(pid);

    if (IS_ERR(parent))
    {
        return -EINVAL;
    }

    walk_task(parent, NULL, &rtask_logger);
    return 0;
}
