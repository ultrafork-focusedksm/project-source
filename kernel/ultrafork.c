#include "ultrafork.h"
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/sched.h>

static struct task_struct* find_task_from_pid(unsigned long pid)
{
    struct pid* pid_struct = find_get_pid(pid);
    return get_pid_task(pid_struct, PIDTYPE_PID);
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

    if (PTR_ERR(parent))
    {
        return -EINVAL;
    }

    pr_info(UFRK_LOG_PREFIX " %s pid=%d, tgid=%d\n", parent->comm, parent->pid,
            parent->tgid);
    list_for_each(list, &parent->children)
    {
        struct task_struct* task =
            list_entry(list, struct task_struct, sibling);
        pr_info("%s, pid=%d, tgid=%d\n", task->comm, task->pid, task->tgid);
    }
    return 0;
}
