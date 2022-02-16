/*
 * Main implementation file for Ultrafork.
 * author: Adrian Curless <awcurless@wpi.edu>
 *
 *
 */
#include "ultrafork.h"
#include "recursive_task_walker.h"
#include "sus_fork.h"
#include "util.h"
#include <linux/anon_inodes.h>
#include <linux/cgroup.h>
#include <linux/completion.h>
#include <linux/errno.h>
#include <linux/freezer.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/types.h>

// mnemonic macros to clarify the possible valus for
// task_walk_context->is_process.
#define TOPMOST_UNINITIALIZED 0
#define TOPMOST_TASK 1
#define NON_TOPMOST_TASK 2

/**
 * Thread or process, kept in task_walk_context for each task being cloned.
 */
enum task_type
{
    // thread = 0, process = 1, this is important for logic using this value
    TASK_THREAD = 0,
    TASK_PROCESS = 1
};

/**
 * Single entry mapping between original and forked process IDs.
 */
struct pid_translation
{
    pid_t old_pid;
    pid_t new_pid;
};

/**
 * Translation table for original and forked IDs.
 */
struct pid_translation_table
{
    size_t length;
    size_t cursor;
    // variable size, must be last
    struct pid_translation translations[];
};

/**
 * Data available for each task during Ultrafork.
 */
struct task_walk_context
{
    struct task_struct* task;
    /** Pointer to the single translation table instance. */
    struct pid_translation_table* tt;
    struct list_head list;
    /** Counter for the number of processes being cloned. Used to allocate the
     * translation table */
    size_t task_count;
    /** Flag indicating this processes status as the 'root' process in the
     * Ultrafork group.*/
    u8 is_topmost;
    /** Indicates if the task is a process or thread. See task_type enum. */
    u8 is_process;
};

static int recursive_task_traverse(struct task_struct* task, void* data);
static int recursive_fork(struct task_struct* task, u32 task_id,
                          struct task_walk_context*);
static int recursive_task_resume(struct task_struct* task, void* data);
static void suspend_task(struct task_struct* task);
static void resume_task(struct task_struct* task);

static struct recursive_task_walker rtask_logger = {
    .task_handler = recursive_task_traverse,
};

static struct recursive_task_walker rfork_resume_walker = {
    .task_handler = recursive_task_resume,
};

static struct kernel_clone_args process_clone_args = {.exit_signal = SIGCHLD};

/*
 * Flags used to start a thread. These are taken from the pthread_create
 * implementation in glibc.
 */
static struct kernel_clone_args thread_clone_args = {
    .flags = CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SYSVSEM | CLONE_SIGHAND |
             CLONE_THREAD | CLONE_SETTLS | CLONE_PARENT_SETTID |
             CLONE_CHILD_CLEARTID | 0};

/**
 * Simple method of determining if a task is a thread or process in most cases.
 * This function may not work on strangely configured free-form constructs
 * created with clone().
 */
static inline bool is_thread(struct task_struct* t)
{
    return t->pid != t->tgid;
}

static void make_new_task_node(struct task_struct* task,
                               struct task_walk_context* metadata,
                               u8 is_process)
{
    struct task_walk_context* node =
        kmalloc(sizeof(struct task_walk_context), GFP_KERNEL);

    node->task = task;
    INIT_LIST_HEAD(&node->list);

    if (metadata->is_topmost == TOPMOST_UNINITIALIZED)
    {
        pr_info("ufrk: topmost\n");
        node->is_topmost = TOPMOST_TASK;
        metadata->is_topmost = NON_TOPMOST_TASK;
    }
    metadata->task_count++;
    node->is_process = is_process;

    pr_debug("ufrk: fork_list_add: %p\n", node);
    list_add_tail(&node->list, &metadata->list);
}

static int recursive_task_traverse(struct task_struct* task, void* data)
{
    struct task_struct* thread = NULL;
    struct task_walk_context* ctx = (struct task_walk_context*)data;

    pr_info("%s, pid=%d, tid=%d\n", task->comm, task->pid, task_pid_vnr(task));
    suspend_task(task);

    make_new_task_node(task, ctx, TASK_PROCESS);

    for_each_thread(task, thread)
    {
        if (task->pid != task_pid_vnr(thread))
        {
            make_new_task_node(thread, ctx, TASK_THREAD);

            pr_info(
                "thread %d has pid %d, parent %d and real_parent %d, tgid=%d\n",
                task_pid_vnr(thread), thread->pid, thread->parent->pid,
                thread->real_parent->pid, thread->tgid);
        }
    }

    return RECURSIVE_TASK_WALKER_CONTINUE;
}

/**
 * Task walker for resuming sleeping processes after Ultrafork has run.
 * @param task The task being visited currently.
 * @param data Context data for traversing the tasks.
 */
static int recursive_task_resume(struct task_struct* task, void* data)
{
    resume_task(task);
    return RECURSIVE_TASK_WALKER_CONTINUE;
}

static int run_rfork(struct task_walk_context* ctx)
{
    struct task_walk_context* next;
    int err_count = 0;
    u32 task_id = 0;
    struct pid_translation_table* tt = ctx->tt;

    list_for_each_entry(next, &ctx->list, list)
    {
        if (likely(NULL != next->task))
        {
            int ret_code;
            pr_info("ufrk[%d]: visiting task pid=%d, tgid=%d\n", task_id,
                    next->task->pid, next->task->tgid);
            next->tt = tt;
            ret_code = recursive_fork(next->task, task_id, next);
            pr_info("ufrk[%d]: fork result %d\n", task_id, ret_code);
            if (ret_code != RECURSIVE_TASK_WALKER_CONTINUE)
            {
                err_count++;
            }
        }
        task_id++;
    }
    return err_count;
}

/**
 * Performs a translation from the original process ID to its forked process.
 *
 * @param tt  Translation table for process IDs.
 * @param old_pid Process ID to translate
 * @return the newly created process ID matching old_pid
 */
static pid_t translate_pid(struct pid_translation_table* tt, pid_t old_pid)
{
    size_t i;
    for (i = 0; i < tt->cursor; i++)
    {
        if (old_pid == tt->translations[i].old_pid)
        {
            return tt->translations[i].new_pid;
        }
    }
    return 0;
}

static void wake_cloned_processes(struct pid_translation_table* tt)
{
    pid_t cloned_task_pid;
    struct task_struct* cloned_task;
    struct task_struct* iter;
    size_t cursor;

    // wake up new processes
    for (cursor = 0; cursor < tt->cursor; cursor++)
    {
        cloned_task_pid = tt->translations[cursor].new_pid;
        cloned_task = find_task_from_pid(cloned_task_pid);

        pr_info("ufrk: wake_cloned_processes: waking process %d,%d. Parent=%d, "
                "RealParent=%d, tgid=%d\n",
                cloned_task->pid, task_pid_vnr(cloned_task),
                cloned_task->parent->pid, cloned_task->real_parent->pid,
                cloned_task->tgid);

        list_for_each_entry(iter, &cloned_task->children, sibling)
        {
            pr_info(
                "ufrk: wake_cloned_processes: cloned task %d has child %d\n",
                cloned_task->pid, iter->pid);
        }

        /*
         * NOTE: Here we explicitly set the frozen flag to false. This is done
         * for no good reason at all. Without this, sometimes (< 1/4), we will
         * get a warning about a negative reference count in the cgroup freezer.
         * Due to the checking logical in the freezer, this turns out to be
         * benign, but this flag avoids the warning altogether. If the reason
         * for the warning is found, remove this line.
         */
        cloned_task->frozen = false;

        wake_up_new_task(cloned_task);
        /* if (!is_thread(cloned_task)) */
        /* { */
        resume_task(cloned_task);
        /* } */
    }
}

/**
 * Pass over all processes decending from the original target process
 * (excluding the newly cloned processes). Use the pid_translation_table to
 * lookup the corresponding cloned PIDs and update the siblings and children
 * lists for consistency.
 *
 * @param task Task currently being visited
 * @param data Context.
 * @return return code, used to control visiting.
 */
static int rebuild_siblings(struct pid_translation_table* tt)
{
    pid_t cloned_task_pid;
    pid_t cloned_iter_pid;
    struct list_head* pos;
    struct list_head* q;
    struct task_struct* iter;
    struct task_struct* task;
    struct task_struct* cloned_task;
    struct task_struct* cloned_iter_task;
    size_t cursor;

    for (cursor = 0; cursor < tt->cursor; cursor++)
    {
        // iterate through each entry of the now-complete translation table.

        task = find_task_from_pid(tt->translations[cursor].old_pid);
        cloned_task_pid = tt->translations[cursor].new_pid;
        cloned_task = find_task_from_pid(cloned_task_pid);
        pr_info("iterating on pid %d\n", cloned_task->pid);

        if (!is_thread(cloned_task))
        {
            if (0 == cursor)
            {
                pr_info("ufrk: rebuild_siblings: topmost adding %d as child of "
                        "%d\n",
                        cloned_task->pid, cloned_task->parent->pid);
                INIT_LIST_HEAD(&cloned_task->sibling);
                list_add(&cloned_task->sibling, &cloned_task->parent->children);
            }

            list_for_each_safe(pos, q, &task->children)
            {
                iter = list_entry(pos, struct task_struct, sibling);
                BUG_ON(NULL == iter);

                pr_info("ufrk: rechild: [%d] visiting pid %d\n", task->pid,
                        iter->pid);

                cloned_iter_pid = translate_pid(tt, iter->pid);
                BUG_ON(0 == cloned_iter_pid);

                cloned_iter_task = find_task_from_pid(cloned_iter_pid);
                if (likely(NULL != cloned_iter_task))
                {
                    pr_info("ufrk: resibling: [%d] adding pid %d to "
                            "children\n",
                            cloned_task->pid, cloned_iter_pid);
                    INIT_LIST_HEAD(&cloned_iter_task->sibling);
                    list_add(&cloned_iter_task->sibling,
                             &cloned_task->children);
                }
            }
        }

        list_for_each_safe(pos, q, &cloned_task->children)
        {
            iter = list_entry(pos, struct task_struct, sibling);
            BUG_ON(NULL == iter);

            if (0 == iter->pid || 0 != translate_pid(tt, iter->pid))
            {
                pr_info("ufkr: resibling: removing child %d from %d\n",
                        iter->pid, cloned_task->pid);
                list_del_init(pos);
            }
        }

        list_for_each_safe(pos, q, &cloned_task->children)
        {
            iter = list_entry(pos, struct task_struct, sibling);
            BUG_ON(NULL == iter);

            pr_info("ufrk: process %d has child %d\n", cloned_task->pid,
                    iter->pid);
        }
    }
    return 0;
}

/**
 * Attempts to look up the given PID in the translation table, if the PID is
 * not present in the table, it is returned, otherwise the mapped PID is
 * returned.
 */
static pid_t try_translate_pid(struct pid_translation_table* tt, pid_t pid)
{
    pid_t new_pid = translate_pid(tt, pid);
    if (0 == new_pid)
    {
        new_pid = pid;
    }
    return new_pid;
}

static int recursive_fork(struct task_struct* task, u32 task_id,
                          struct task_walk_context* ctx)
{
    struct task_struct* iter;
    struct task_struct* forked_task;
    struct list_head* pos;
    struct list_head* q;
    struct kernel_clone_args* args;

    if (ctx->is_process)
    {
        args = &process_clone_args;
    }
    else
    {
        args = &thread_clone_args;
    }

    list_for_each_entry(iter, &task->children, sibling)
    {
        pr_info("ufrk: %d is child of %d\n", iter->pid, task->pid);
    }

    forked_task = sus_kernel_clone(task, args);

    if (unlikely(forked_task == NULL))
    {
        pr_err("ufrk: failed to fork task, counter: %d\n", task_id);
        return -EACCES;
    }

    // TODO: race condition
    //    suspend_task(forked_task);

    pr_info("rfork orig  : %s, pid=%d, tgid=%d\n", task->comm, task->pid,
            task->tgid);
    pr_info("rfork forked: %s, pid=%d, tgid=%d\n", forked_task->comm,
            forked_task->pid, forked_task->tgid);

    ctx->tt->translations[ctx->tt->cursor].old_pid = task->pid;
    ctx->tt->translations[ctx->tt->cursor].new_pid = forked_task->pid;
    pr_info("rfork: storting mapping %d -> %d in tt slot %ld\n", task->pid,
            forked_task->pid, ctx->tt->cursor);
    ctx->tt->cursor++;

    list_for_each_entry(iter, &task->children, sibling)
    {
        pr_info("ufrk: %d is child of %d\n", iter->pid, task->pid);
    }

    if (ctx->is_topmost == TOPMOST_TASK)
    {
        pr_info("rfork: topmost process, %d reparented to %d\n",
                forked_task->pid, task->parent->pid);
        forked_task->parent = task->parent;
        forked_task->real_parent = task->real_parent;
        forked_task->parent_exec_id = task->parent_exec_id;
        forked_task->exit_signal = task->exit_signal;

        forked_task->signal->has_child_subreaper =
            task->real_parent->signal->has_child_subreaper ||
            task->real_parent->signal->is_child_subreaper;
    }
    else
    {

        if (ctx->is_process == TASK_THREAD)
        {
            // we are forking a thread
            pid_t new_pid = try_translate_pid(ctx->tt, task->parent->pid);
            pr_info("rfork: not-topmost, %d reparented to %d\n",
                    forked_task->pid, new_pid);

            pr_info("rfork: a thread %d\n", forked_task->pid);
            forked_task->real_parent = find_task_from_pid(new_pid);
            BUG_ON(NULL == forked_task->real_parent);

            forked_task->parent = forked_task->real_parent;

            forked_task->tgid = try_translate_pid(ctx->tt, task->tgid);

            forked_task->parent_exec_id = forked_task->parent->parent_exec_id;

            new_pid = try_translate_pid(ctx->tt, task->group_leader->pid);
            forked_task->group_leader = find_task_from_pid(new_pid);

            forked_task->signal = forked_task->parent->signal;
            /* refcount_dec(&forked_task->parent->sighand->count); */
            forked_task->parent->signal->nr_threads++;
            atomic_inc(&forked_task->parent->signal->live);
            refcount_inc(&forked_task->parent->signal->sigcnt);

            sus_task_join_group_stop(forked_task, forked_task->parent);

            forked_task->sighand = forked_task->parent->sighand;
            refcount_inc(&forked_task->parent->sighand->count);

            BUG_ON(NULL == forked_task->group_leader);

            list_add_tail_rcu(&forked_task->thread_group,
                              &forked_task->group_leader->thread_group);
            list_add_tail_rcu(&forked_task->thread_node,
                              &forked_task->signal->thread_head);

            pr_info("rfork_thread: %d preparing to replace mm\n",
                    forked_task->pid);
            sus_copy_mm(args->flags, forked_task, forked_task->parent);
            pr_info("rfork_thread: %d replaced mm\n", forked_task->pid);

            pr_info("rfork_thread %d: original real_parent=%d, parent=%d, "
                    "tgid=%d, group_leader=%d",
                    task->pid, task->real_parent->pid, task->parent->pid,
                    task->tgid, task->group_leader->pid);
            pr_info("rfork_thread %d: cloned real_parent=%d, parent=%d, "
                    "tgid=%d, group_leader=%d",
                    forked_task->pid, forked_task->real_parent->pid,
                    forked_task->parent->pid, forked_task->tgid,
                    forked_task->group_leader->pid);
        }
        else
        {
            // we are forking a process

            pid_t new_pid = translate_pid(ctx->tt, task->parent->pid);
            pr_info("rfork: not-topmost, %d reparented to %d\n",
                    forked_task->pid, new_pid);
            pr_info("rfork: a process %d\n", forked_task->pid);
            forked_task->parent = find_task_from_pid(new_pid);
            BUG_ON(NULL == forked_task->parent);
            forked_task->real_parent = forked_task->parent;

            // we only edit the4 signal struct if we are a process
            forked_task->signal->has_child_subreaper =
                forked_task->real_parent->signal->has_child_subreaper ||
                forked_task->real_parent->signal->is_child_subreaper;
        }
    }

    // remove forked process from children
    list_for_each_safe(pos, q, &task->children)
    {
        iter = list_entry(pos, struct task_struct, sibling);
        if (likely(NULL != iter))
        {
            if (forked_task->pid == iter->pid)
            {
                pr_info("ufrk: removing forked pid %d from children of %d\n",
                        forked_task->pid, task->pid);
                list_del_init(pos);
            }
        }
    }

    return RECURSIVE_TASK_WALKER_CONTINUE;
}

/**
 * Suspend the given task by sending SIGSTOP. This is a somewhat foolish method,
 * as it can be reversed by SIGCONT sent by userspace, which would cause a nasty
 * race condition if delivered while ultrafork is working on the process.
 *
 * TODO: This does work, but its sort of gross. We shouldn't allow
 * userspace to override us. Look into: activate_task and deactivate_task
 *
 * TODO: Block CONT signals until we are ready to resume.
 *
 * @param task The process to stop.
 */
static void suspend_task(struct task_struct* task)
{
    /* if (!is_thread(task)) */
    /* { */
    kill_pid(task_pid(task), SIGSTOP, 1);
    /* } */
}

/**
 * Resumes the given task using SIGCONT. See notes on suspend_task.
 *
 * @param task The process to resume.
 */
static void resume_task(struct task_struct* task)
{
    kill_pid(task_pid(task), SIGCONT, 1);
    pr_info("ufrk: resume: %d, %d awake\n", task->pid, task->tgid);
}

static void task_list_cleanup(struct task_walk_context* ctx)
{
    struct list_head* next;
    struct list_head* pos;

    list_for_each_safe(pos, next, &ctx->list)
    {
        struct task_walk_context* entry =
            list_entry(pos, struct task_walk_context, list);
        BUG_ON(NULL == entry);

        pr_info("ufrk: cleanup: visiting %d,%d\n", entry->task->pid,
                entry->task->tgid);
        list_del_init(pos);
        kfree(entry);
    }
}

static void clean_parent_children(struct task_struct* parent)
{
    struct task_struct* iter;
    struct list_head* pos;
    struct list_head* next;

    list_for_each_safe(pos, next, &parent->children)
    {
        iter = list_entry(pos, struct task_struct, sibling);
        if (likely(NULL != iter))
        {
            if (0 == iter->pid)
            {
                pr_info(
                    "clean_parent_children: removing %d from children of %d\n",
                    iter->pid, parent->pid);
                list_del_init(pos);
            }
        }
    }
}

int sus_mod_fork(unsigned long pid, unsigned char flags)
{
    u64 start;
    struct task_struct* parent;
    struct pid_translation_table* tt;
    struct task_walk_context wctx = {
        .task = NULL, .is_topmost = TOPMOST_UNINITIALIZED, .task_count = 0};
    INIT_LIST_HEAD(&wctx.list);

    if (pid < 1)
    {
        return -EINVAL;
    }

    parent = find_task_from_pid(pid);

    if (IS_ERR(parent))
    {
        return -EINVAL;
    }

    start = sus_time_nanos();
    pr_info("ufrk: locking process group\n");
    walk_task(parent, &wctx, &rtask_logger);

    tt = kmalloc(sizeof(struct pid_translation_table) +
                     sizeof(struct pid_translation) * wctx.task_count,
                 GFP_KERNEL);
    tt->length = wctx.task_count;
    tt->cursor = 0;
    wctx.tt = tt;

    pr_info("ufrk: tasks locked, preparing fork\n");
    run_rfork(&wctx);

    pr_info("ufrk: releasing target process list from pid,tgid: %d,%d\n",
            current->pid, current->tgid);
    task_list_cleanup(&wctx);

    pr_info("ufrk: sibling rebuilder\n");
    rebuild_siblings(tt);

    clean_parent_children(parent->parent);

    pr_info("ufrk: resuming process group from pid,tgid: %d,%d\n", current->pid,
            current->tgid);
    walk_task(parent, NULL, &rfork_resume_walker);
    wake_cloned_processes(tt);

    pr_info("ufrk: releasing translation table memory\n");
    kfree(tt);

    pr_info("ufrk: return to caller, took %lldns\n", sus_time_nanos() - start);
    return 0;
}
