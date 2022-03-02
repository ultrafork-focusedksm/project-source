#include "util.h"
#include <linux/sched/clock.h>

struct task_struct* find_task_from_pid(pid_t pid)
{
    struct pid* pid_struct = find_get_pid(pid);
    return get_pid_task(pid_struct, PIDTYPE_PID);
}

u64 sus_time_nanos(void)
{
    return sched_clock();
}
