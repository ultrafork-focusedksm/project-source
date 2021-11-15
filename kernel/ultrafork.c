#include "ultrafork.h"
#include <linux/cgroup.h>
#include <linux/completion.h>
#include <linux/errno.h>
#include <linux/freezer.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/ptrace.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/sched/task.h>
#include <linux/types.h>

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
 * A fork involves two processes, the parent and the child. A recursive
 * fork involves two groups of processes, the original group and the forked
 * group.
 */
struct rfork_context
{
    /** The parent process of the original parent process. The process that
     * spawned the parent process in the original fork group. */
    struct task_struct* original_grandparent;
    /** The top level forked process. All other forked processes are
     * descendants of this process. */
    struct task_struct* forked_parent;
    /** Process group counter. Used to track how many processes we have already
     * forked. */
    u32 counter;
};

static int recursive_task_traverse(struct task_struct* task, void* data);
static int recursive_fork(struct task_struct* task, void* data);
static int recursive_task_resume(struct task_struct* task, void* data);
static void suspend_task(struct task_struct* task);
static void resume_task(struct task_struct* task);

static struct recursive_task_walker rtask_logger = {
    .task_handler = recursive_task_traverse,
};

static struct recursive_task_walker rfork_walker = {
    .task_handler = recursive_fork,
};

static struct recursive_task_walker rfork_resume_walker = {
    .task_handler = recursive_task_resume,
};

/**
 * Recursive task walker. Given a task, visit it, and all its
 * decendants.
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

static int recursive_task_traverse(struct task_struct* task, void* data)
{
    pr_info("%s, pid=%d, tgid=%d\n", task->comm, task->pid, task->tgid);
    suspend_task(task);
    return RECURSIVE_TASK_WALKER_CONTINUE;
}

static int recursive_task_resume(struct task_struct* task, void* data)
{
    pr_info("rfork: resume: pid=%d, tgid=%d\n", task->pid, task->tgid);
    resume_task(task);
    return RECURSIVE_TASK_WALKER_CONTINUE;
}

static inline void sus_freezer_do_not_count(struct task_struct* task)
{
    task->flags |= PF_FREEZER_SKIP;
}

static inline void sus_freezer_count(struct task_struct* task)
{
    task->flags &= ~PF_FREEZER_SKIP;
    // TODO: check this
    smp_mb();
    // TODO: examine return
    freeze_task(task);
}

static int wait_for_vfork_done(struct task_struct* child,
                               struct completion* vfork)
{
    int killed;

    sus_freezer_do_not_count(child);

    task_cgroup_enter_frozen(child);
    killed = wait_for_completion_killable(vfork);
    task_cgroup_leave_frozen(false, child);

    sus_freezer_count(child);

    if (killed)
    {
        task_lock(child);
        child->vfork_done = NULL;
        task_unlock(child);
    }

    put_task_struct(child);
    return killed;
}

static pid_t sus_kernel_clone(struct task_struct* target,
                              struct kernel_clone_args* args)
{
    u64 clone_flags = args->flags;
    struct completion vfork;
    struct pid* pid;
    struct task_struct* p;
    int trace = 0;
    pid_t nr;

    if ((args->flags & CLONE_PIDFD) && (args->flags & CLONE_PARENT_SETTID) &&
        (args->pidfd == args->parent_tid))
    {
        return -EINVAL;
    }

    if (!(clone_flags & CLONE_UNTRACED))
    {
        if (clone_flags & CLONE_VFORK)
        {
            trace = PTRACE_EVENT_VFORK;
        }
        else if (args->exit_signal != SIGCHLD)
        {
            trace = PTRACE_EVENT_CLONE;
        }
        else
        {
            trace = PTRACE_EVENT_FORK;
        }

        if (likely(!ptrace_event_enabled(target, trace)))
        {
            trace = 0;
        }
    }

    p = copy_process(target, trace, NUMA_NO_NODE, args);

    if (IS_ERR(p))
    {
        return PTR_ERR(p);
    }

    trace_sched_process_fork(target, p);

    pid = get_task_pid(p, PIDTYPE_PID);
    nr = pid_vnr(pid);

    if (clone_flags & CLONE_PARENT_SETTID)
    {
        put_user(nr, args->parent_tid);
    }

    if (clone_flags & CLONE_VFORK)
    {
        p->vfork_done = &vfork;
        init_completion(&vfork);
        get_task_struct(p);
    }

    wake_up_new_task(p);

    if (unlikely(trace))
    {
        ptrace_event_pid(trace, pid);
    }

    if (clone_flags & CLONE_VFORK)
    {
        if (!wait_for_vfork_done(p, &vfork))
        {
            ptrace_event_pid(PTRACE_EVENT_VFORK_DONE, pid);
        }
    }

    put_pid(pid);

    return nr;
}

static int recursive_fork(struct task_struct* task, void* data)
{
    struct rfork_context* ctx = (struct rfork_context*)data;
    struct kernel_clone_args args = {.exit_signal = SIGCHLD};
    struct task_struct* forked_task =
        copy_process(task_pid(task), 0, NUMA_NO_NODE, &args);

    pr_info("rfork orig  : %s, pid=%d, tgid=%d\n", task->comm, task->pid,
            task->tgid);
    pr_info("rfork forked: %s, pid=%d, tgid=%d\n", forked_task->comm,
            forked_task->pid, forked_task->tgid);

    if (0 == ctx->counter)
    {
        pr_info("rfork: adjusting pointers of lead process\n");
        struct task_struct* previous_parent = forked_task->parent;
        struct task_struct* iter;
        struct list_head* pos;
        struct list_head* q;
        // This means we are the parent process of the group
        // we need to adjust this process (meaning the forked_task) to have
        // the same parent has task. Eventually we will also have namespacing
        // and like to consider as well.
        forked_task->parent = ctx->original_grandparent;

        // remove forked_task its previous parent's child list.
        list_for_each_safe(pos, q, &previous_parent->children)
        {
            iter = list_entry(pos, struct task_struct, children);
            if (iter->pid == forked_task->pid &&
                iter->tgid == forked_task->tgid)
            {
                list_del(pos);
            }
        }

        // Add to the new parent's child list
        INIT_LIST_HEAD(&forked_task->sibling);
        list_add(&forked_task->sibling, &forked_task->parent->children);
        pr_info("rfork: lead process pointers adjusted\n");
    }

    // increment the counter
    ctx->counter++;
    return RECURSIVE_TASK_WALKER_CONTINUE;
}

static void suspend_task(struct task_struct* task)
{
    // TODO: This does work, but its sort of gross. We shouldn't allow userspace
    // to override us. Look into:
    // activate_task and deactivate_task
    // TODO: Block CONT signals until we are ready to resume.
    kill_pid(task_pid(task), SIGSTOP, 1);
}

static void resume_task(struct task_struct* task)
{
    // TODO: see nots on suspend_task
    kill_pid(task_pid(task), SIGCONT, 1);
}

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

    struct rfork_context ctx = {
        .forked_parent = NULL,
        .original_grandparent = parent->parent,
        .counter = 0,
    };
    walk_task(parent, &ctx, &rfork_walker);

    walk_task(parent, NULL, &rfork_resume_walker);
    return 0;
}
