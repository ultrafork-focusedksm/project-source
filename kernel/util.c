#include "util.h"

struct task_struct* find_task_from_pid(pid_t pid)
{
    struct pid* pid_struct = find_get_pid(pid);
    return get_pid_task(pid_struct, PIDTYPE_PID);
}

u64 sus_time_jiffies(void)
{
    return get_jiffies_64();
}

struct timespec64 sus_micro_difference(u64 large_jiffers, u64 small_jiffies)
{
    struct timespec64 ts;
    jiffies_to_timespec64(large_jiffers - small_jiffies, &ts);
    return ts;
}
