#include "ultrafork.h"
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/sched.h>

#define RECURSIVE_TASK_WALKER_CONTINUE 0
#define RECURSIVE_TASK_WALKER_STOP 1

struct recursive_task_walker
{
    int (*task_handler)(struct task_struct*, void*)
};

static int recursive_task_traverse(struct task_struct* task, void* data);

static struct recursive_task_walker rtask_logger = {
    .task_handler = recursive_task_traverse,
};

static struct task_struct* find_task_from_pid(unsigned long pid)
{
    struct pid* pid_struct = find_get_pid(pid);
    return get_pid_task(pid_struct, PIDTYPE_PID);
}

static void walk_task(struct task_struct* task, void* data,
                      struct recursive_task_walker* walker)
{
    struct list_head* list;

    walker->task_handler(task, data, walker);
    list_for_each(list, &task->children)
    {
        struct task_struct* child =
            list_entry(list, struct task_struct, sibling);
        int status = walker->task_handler(child, data);
        if (status == RECURSIVE_TASK_WALKER_STOP)
        {
            return;
        }
        walk_task(child, data, walker);
    }
}

static int recursive_task_traverse(struct task_struct* task, void* data)
{
    pr_info("%s, pid=%d, tgid=%d\n", task->comm, task->pid, task->tgid);
    return RECURSIVE_TASK_WALKER_CONTINUE;
}

int sus_mod_fork(unsigned long pid, unsigned char flags)
{
    struct list_head* list;
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

    walk_task(parent, NULL, rtask_logger);
    return 0;
}
