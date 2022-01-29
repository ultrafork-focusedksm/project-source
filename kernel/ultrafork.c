#include "ultrafork.h"
#include "recursive_task_walker.h"
#include "sus_fork.h"
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
#include <linux/types.h>

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
    struct pid_translation translations[];
};

/**
 * Data available for each task during Ultrafork.
 */
struct task_walk_context
{
    struct task_struct* task;
    struct list_head list;
    size_t task_count;
    /** Pointer to the single translation table instance. */
    struct pid_translation_table* tt;
    pid_t parent;
    pid_t forked_pid;
    /** Flag indicating this processes status as the 'root' process in the
     * Ultrafork group.*/
    u8 is_topmost;
};

static int recursive_task_traverse(struct task_struct* task, void* data);
static int recursive_fork(struct task_struct* task, u32 task_id,
                          struct task_walk_context*);
static int recursive_task_resume(struct task_struct* task, void* data);
static void suspend_task(struct task_struct* task);
static void resume_task(struct task_struct* task);
static int rebuild_sibling_callback(struct task_struct* task, void* data);

static struct recursive_task_walker rtask_logger = {
    .task_handler = recursive_task_traverse,
};

static struct recursive_task_walker rfork_resume_walker = {
    .task_handler = recursive_task_resume,
};

static struct recursive_task_walker rtask_sibling_rebuilder = {
    .task_handler = rebuild_sibling_callback,
};

static int recursive_task_traverse(struct task_struct* task, void* data)
{
    struct task_walk_context* ctx = (struct task_walk_context*)data;

    struct task_walk_context* node =
        kmalloc(sizeof(struct task_walk_context), GFP_KERNEL);

    pr_info("%s, pid=%d, tgid=%d\n", task->comm, task->pid, task->tgid);
    suspend_task(task);

    node->parent = task->real_parent->pid; // or parent
    node->task = task;
    INIT_LIST_HEAD(&node->list);

    if (ctx->is_topmost == 0)
    {
        pr_info("ufrk: topmost\n");
        node->is_topmost = 1;
        ctx->is_topmost = 2;
    }
    ctx->task_count++;

    pr_info("ufrk: fork_list_add: %p\n", node);
    list_add_tail(&node->list, &ctx->list);

    return RECURSIVE_TASK_WALKER_CONTINUE;
}

/**
 * Task walker for resuming sleeping processes after Ultrafork has run.
 * @param task The task being visited currently.
 * @param data Context data for traversing the tasks.
 */
static int recursive_task_resume(struct task_struct* task, void* data)
{
    pr_info("rfork: resume: pid=%d, tgid=%d\n", task->pid, task->tgid);
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

static struct task_struct* find_task_from_pid(unsigned long pid)
{
    struct pid* pid_struct = find_get_pid(pid);
    return get_pid_task(pid_struct, PIDTYPE_PID);
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
static int rebuild_sibling_callback(struct task_struct* task, void* data)
{
    pid_t cloned_task_pid;
    pid_t cloned_iter_pid;
    struct list_head* pos;
    struct list_head* q;
    struct task_struct* iter;
    struct task_struct* cloned_task;
    struct task_struct* cloned_iter_task;
    struct pid_translation_table* tt = (struct pid_translation_table*)data;

    cloned_task_pid = translate_pid(tt, task->pid);
    cloned_task = find_task_from_pid(cloned_task_pid);

    list_for_each_safe(pos, q, &task->children)
    {
        iter = list_entry(pos, struct task_struct, sibling);
        if (likely(NULL != iter))
        {
            pr_info("ufrk: rechild: [%d] visiting pid %d\n", task->pid,
                    iter->pid);

            cloned_iter_pid = translate_pid(tt, iter->pid);
            if (likely(0 != cloned_iter_pid))
            {
                cloned_iter_task = find_task_from_pid(cloned_iter_pid);
                if (likely(NULL != cloned_iter_task))
                {
                    pr_info("ufrk: resibling: [%d] adding pid %d to children\n",
                            cloned_task->pid, cloned_iter_pid);
                    INIT_LIST_HEAD(&cloned_iter_task->children);
                    list_add(&cloned_iter_task->children,
                             &cloned_task->children);
                    pr_info("ufrk: resibling: child added\n");
                }
            }
        }
    }

    list_for_each_safe(pos, q, &cloned_task->children)
    {
        iter = list_entry(pos, struct task_struct, sibling);
        if (likely(NULL != iter))
        {
            if (0 == iter->pid || 0 != translate_pid(tt, iter->pid))
            {
                pr_info("ufkr: resibling: removing child %d from %d\n",
                        iter->pid, cloned_task->pid);
                list_del_init(pos);
            }
        }
    }

    wake_up_new_task(cloned_task);
    return RECURSIVE_TASK_WALKER_STOP;
}

static int recursive_fork(struct task_struct* task, u32 task_id,
                          struct task_walk_context* ctx)
{
    struct task_struct* iter;
    struct task_struct* forked_task;
    struct list_head* pos;
    struct list_head* q;
    struct kernel_clone_args args = {.exit_signal = SIGCHLD};

    list_for_each_entry(iter, &task->children, sibling)
    {

        pr_info("ufrk: %d is child of %d\n", iter->pid, task->pid);
    }

    forked_task = sus_kernel_clone(task, &args);

    if (forked_task == NULL)
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

    // TODO: unused:
    ctx->forked_pid = forked_task->pid;

    ctx->tt->translations[ctx->tt->cursor].old_pid = task->pid;
    ctx->tt->translations[ctx->tt->cursor].new_pid = forked_task->pid;
    pr_info("rfork: storting mapping %d -> %d in tt slot %ld\n", task->pid,
            forked_task->pid, ctx->tt->cursor);
    ctx->tt->cursor++;

    list_for_each_entry(iter, &task->children, sibling)
    {

        pr_info("ufrk: %d is child of %d\n", iter->pid, task->pid);
    }

    if (ctx->is_topmost == 1)
    {
        pr_info("rfork: topmost process, %d reparented to %d\n",
                forked_task->pid, task->parent->pid);
        forked_task->parent = task->parent;
        forked_task->real_parent = task->real_parent;

        forked_task->signal->has_child_subreaper =
            task->real_parent->signal->has_child_subreaper ||
            task->real_parent->signal->is_child_subreaper;
        pr_info("rfork: task %d subreaper %d\n", forked_task->pid,
                forked_task->signal->has_child_subreaper);
        /* forked_task->group_leader = task->group_leader; */

        INIT_LIST_HEAD(&forked_task->children);
        list_add(&forked_task->children, &task->parent->children);
    }
    else
    {
        pid_t new_pid = translate_pid(ctx->tt, task->parent->pid);
        pr_info("rfork: not-topmost, %d reparented to %d\n",
                forked_task->parent->pid, new_pid);

        forked_task->parent = find_task_from_pid(new_pid);
        forked_task->real_parent = forked_task->parent;

        forked_task->signal->has_child_subreaper =
            forked_task->real_parent->signal->has_child_subreaper ||
            forked_task->real_parent->signal->is_child_subreaper;
        pr_info("rfork: task %d subreaper %d\n", forked_task->pid,
                forked_task->signal->has_child_subreaper);

        //   remove_from_siblings(task, forked_task);
    }

    // remove forked process from children
    list_for_each_safe(pos, q, &task->children)
    {
        iter = list_entry(pos, struct task_struct, sibling);
        if (likely(NULL != iter))
        {
            pr_info("rfork: del_child[%d]: checking %d\n", task->pid,
                    iter->pid);
            if (forked_task->pid == iter->pid)
            {
                pr_info("ufrk: removing forked pid %d from children of %d\n",
                        forked_task->pid, task->pid);
                list_del_init(pos);
            }
        }
    }

    /* wake_up_new_task(forked_task); */

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
    kill_pid(task_pid(task), SIGSTOP, 1);
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
        if (likely(NULL != entry))
        {
            pr_info("ufrk: cleanup: visiting %d,%d, %p\n", entry->task->pid,
                    entry->task->tgid, entry);
            list_del_init(pos);
            kfree(entry);
        }
        else
        {
            pr_err("ufrk: cleanup: ignoring NULL entry\n");
        }
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
    struct task_struct* parent;
    struct pid_translation_table* tt;
    struct task_walk_context wctx = {
        .task = NULL, .parent = 0, .is_topmost = 0, .task_count = 0};
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
    walk_task(parent, tt, &rtask_sibling_rebuilder);

    clean_parent_children(parent->parent);

    pr_info("ufrk: resuming process group from pid,tgid: %d,%d\n", current->pid,
            current->tgid);
    walk_task(parent, NULL, &rfork_resume_walker);

    pr_info("ufrk: releasing translation table memory\n");
    kfree(tt);

    pr_info("ufrk: return to caller\n");
    return 0;
}
