#include "focused_ksm.h"
#include "sus.h"
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/module.h>

static struct task_struct* find_task_from_pid(unsigned long pid)
{
    struct pid* pid_struct = find_get_pid(pid);
    return get_pid_task(pid_struct, PIDTYPE_PID);
}

int sus_mod_merge(unsigned long pid1, unsigned long pid2)
{
    return -EINVAL;
}

