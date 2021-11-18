#include "ultrafork.h"
#include <linux/audit.h>
#include <linux/cgroup.h>
#include <linux/cn_proc.h>
#include <linux/completion.h>
#include <linux/delayacct.h>
#include <linux/errno.h>
#include <linux/freezer.h>
#include <linux/fs.h>
#include <linux/fs_struct.h>
#include <linux/futex.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/livepatch.h>
#include <linux/module.h>
#include <linux/perf_event.h>
#include <linux/ptrace.h>
#include <linux/sched.h>
#include <linux/sched/autogroup.h>
#include <linux/sched/cputime.h>
#include <linux/sched/signal.h>
#include <linux/sched/task.h>
#include <linux/sched/task_stack.h>
#include <linux/security.h>
#include <linux/stackleak.h>
#include <linux/task_io_accounting_ops.h>
#include <linux/taskstats_kern.h>
#include <linux/tsacct_kern.h>
#include <linux/tty.h>
#include <linux/types.h>

#define RECURSIVE_TASK_WALKER_CONTINUE 0
#define RECURSIVE_TASK_WALKER_STOP 1

/*
 * Yes, this is a nasty macro. It ensures we don't make any mistakes using the
 * current process in fork related calls instead of the target process. The goal
 * is to catch any incorrect usages at compile time.
 *
 * DO NOT include any headers _after_ this line, or all hell will break loose.
 */
#define current ERROR

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

static inline void rcu_copy_process(struct task_struct* p)
{
#ifdef CONFIG_PREEMPT_RCU
    p->rcu_read_lock_nesting = 0;
    p->rcu_read_unlock_special.s = 0;
    p->rcu_blocked_node = NULL;
    INIT_LIST_HEAD(&p->rcu_node_entry);
#endif /* #ifdef CONFIG_PREEMPT_RCU */
#ifdef CONFIG_TASKS_RCU
    p->rcu_tasks_holdout = false;
    INIT_LIST_HEAD(&p->rcu_tasks_holdout_list);
    p->rcu_tasks_idle_cpu = -1;
#endif /* #ifdef CONFIG_TASKS_RCU */
#ifdef CONFIG_TASKS_TRACE_RCU
    p->trc_reader_nesting = 0;
    p->trc_reader_special.s = 0;
    INIT_LIST_HEAD(&p->trc_holdout_list);
#endif /* #ifdef CONFIG_TASKS_TRACE_RCU */
}

static inline void init_task_pid_links(struct task_struct* task)
{
    enum pid_type type;

    for (type = PIDTYPE_PID; type < PIDTYPE_MAX; ++type)
        INIT_HLIST_NODE(&task->pid_links[type]);
}

static void rt_mutex_init_task(struct task_struct* p)
{
    raw_spin_lock_init(&p->pi_lock);
#ifdef CONFIG_RT_MUTEXES
    p->pi_waiters = RB_ROOT_CACHED;
    p->pi_top_task = NULL;
    p->pi_blocked_on = NULL;
#endif
}

static inline void init_task_pid(struct task_struct* task, enum pid_type type,
                                 struct pid* pid)
{
    if (type == PIDTYPE_PID)
        task->thread_pid = pid;
    else
        task->signal->pids[type] = pid;
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

static __always_inline void mm_clear_owner(struct mm_struct* mm,
                                           struct task_struct* p)
{
#ifdef CONFIG_MEMCG
    if (mm->owner == p)
        WRITE_ONCE(mm->owner, NULL);
#endif
}

static void mmdrop_async_fn(struct work_struct* work)
{
    struct mm_struct* mm;

    mm = container_of(work, struct mm_struct, async_put_work);
    __mmdrop(mm);
}

static void mmdrop_async(struct mm_struct* mm)
{
    if (unlikely(atomic_dec_and_test(&mm->mm_count)))
    {
        INIT_WORK(&mm->async_put_work, mmdrop_async_fn);
        schedule_work(&mm->async_put_work);
    }
}

static void __delayed_free_task(struct rcu_head* rhp)
{
    struct task_struct* tsk = container_of(rhp, struct task_struct, rcu);

    free_task(tsk);
}

static __always_inline void delayed_free_task(struct task_struct* tsk)
{
    if (IS_ENABLED(CONFIG_MEMCG))
        call_rcu(&tsk->rcu, __delayed_free_task);
    else
        free_task(tsk);
}

static struct task_struct* sus_copy_process(struct task_struct* target,
                                            int trace, int node,
                                            struct kernel_clone_args* args)
{

    int pidfd = -1;
    int retval;
    struct task_struct* p;
    struct multiprocess_signals delayed;
    u64 clone_flags = args->flags;
    struct nsproxy* nsp = target->nsproxy;
    struct pid* pid = task_pid(target);

    /*
     * Don't allow sharing the root directory with processes in a different
     * namespace
     */
    if ((clone_flags & (CLONE_NEWNS | CLONE_FS)) == (CLONE_NEWNS | CLONE_FS))
        return ERR_PTR(-EINVAL);

    if ((clone_flags & (CLONE_NEWUSER | CLONE_FS)) ==
        (CLONE_NEWUSER | CLONE_FS))
        return ERR_PTR(-EINVAL);
    /*
     * Thread groups must share signals as well, and detached threads
     * can only be started up within the thread group.
     */
    if ((clone_flags & CLONE_THREAD) && !(clone_flags & CLONE_SIGHAND))
        return ERR_PTR(-EINVAL);

    /*
     * Shared signal handlers imply shared VM. By way of the above,
     * thread groups also imply shared VM. Blocking this case allows
     * for various simplifications in other code.
     */
    if ((clone_flags & CLONE_SIGHAND) && !(clone_flags & CLONE_VM))
        return ERR_PTR(-EINVAL);

    /*
     * Siblings of global init remain as zombies on exit since they are
     * not reaped by their parent (swapper). To solve this and to avoid
     * multi-rooted process trees, prevent global and container-inits
     * from creating siblings.
     */
    if ((clone_flags & CLONE_PARENT) &&
        target->signal->flags & SIGNAL_UNKILLABLE)
        return ERR_PTR(-EINVAL);

    /*
     * If the new process will be in a different pid or user namespace
     * do not allow it to share a thread group with the forking task.
     */
    if (clone_flags & CLONE_THREAD)
    {
        if ((clone_flags & (CLONE_NEWUSER | CLONE_NEWPID)) ||
            (task_active_pid_ns(target) != nsp->pid_ns_for_children))
            return ERR_PTR(-EINVAL);
    }

    /*
     * If the new process will be in a different time namespace
     * do not allow it to share VM or a thread group with the forking task.
     */
    if (clone_flags & (CLONE_THREAD | CLONE_VM))
    {
        if (nsp->time_ns != nsp->time_ns_for_children)
            return ERR_PTR(-EINVAL);
    }

    if (clone_flags & CLONE_PIDFD)
    {
        /*
         * - CLONE_DETACHED is blocked so that we can potentially
         *   reuse it later for CLONE_PIDFD.
         * - CLONE_THREAD is blocked until someone really needs it.
         */
        if (clone_flags & (CLONE_DETACHED | CLONE_THREAD))
            return ERR_PTR(-EINVAL);
    }
    /*
     * Force any signals received before this point to be delivered
     * before the fork happens.  Collect up signals sent to multiple
     * processes that happen during the fork and delay them so that
     * they appear to happen after the fork.
     */
    sigemptyset(&delayed.signal);
    INIT_HLIST_NODE(&delayed.node);

    spin_lock_irq(&target->sighand->siglock);
    if (!(clone_flags & CLONE_THREAD))
        hlist_add_head(&delayed.node, &target->signal->multiprocess);
    recalc_sigpending();
    spin_unlock_irq(&target->sighand->siglock);
    retval = -ERESTARTNOINTR;
    if (task_sigpending(target))
        goto fork_out;

    retval = -ENOMEM;
    p = dup_task_struct(target, node);
    if (!p)
        goto fork_out;
    if (args->io_thread)
    {
        /*
         * Mark us an IO worker, and block any signal that isn't
         * fatal or STOP
         */
        p->flags |= PF_IO_WORKER;
        siginitsetinv(&p->blocked, sigmask(SIGKILL) | sigmask(SIGSTOP));
    }

    /*
     * This _must_ happen before we call free_task(), i.e. before we jump
     * to any of the bad_fork_* labels. This is to avoid freeing
     * p->set_child_tid which is (ab)used as a kthread's data pointer for
     * kernel threads (PF_KTHREAD).
     */
    p->set_child_tid =
        (clone_flags & CLONE_CHILD_SETTID) ? args->child_tid : NULL;
    /*
     * Clear TID on mm_release()?
     */
    p->clear_child_tid =
        (clone_flags & CLONE_CHILD_CLEARTID) ? args->child_tid : NULL;

    ftrace_graph_init_task(p);

    rt_mutex_init_task(p);
    lockdep_assert_irqs_enabled();

#ifdef CONFIG_PROVE_LOCKING
    DEBUG_LOCKS_WARN_ON(!p->softirqs_enabled);
#endif

    retval = -EAGAIN;
    if (is_ucounts_overlimit(task_ucounts(p), UCOUNT_RLIMIT_NPROC,
                             rlimit(RLIMIT_NPROC)))
    {
        if (p->real_cred->user != INIT_USER && !capable(CAP_SYS_RESOURCE) &&
            !capable(CAP_SYS_ADMIN))
            goto bad_fork_free;
    }
    target->flags &= ~PF_NPROC_EXCEEDED;

    retval = copy_creds(p, clone_flags);
    if (retval < 0)
        goto bad_fork_free;

    /*
     * If multiple threads are within copy_process(), then this check
     * triggers too late. This doesn't hurt, the check is only there
     * to stop root fork bombs.
     */
    retval = -EAGAIN;
    if (data_race(nr_threads >= max_threads))
        goto bad_fork_cleanup_count;

    retval = copy_creds(p, clone_flags);
    if (retval < 0)
        goto bad_fork_free;

    /*
     * If multiple threads are within copy_process(), then this check
     * triggers too late. This doesn't hurt, the check is only there
     * to stop root fork bombs.
     */
    retval = -EAGAIN;
    if (data_race(nr_threads >= max_threads))
        goto bad_fork_cleanup_count;

    delayacct_tsk_init(p); /* Must remain after dup_task_struct() */
    p->flags &= ~(PF_SUPERPRIV | PF_WQ_WORKER | PF_IDLE | PF_NO_SETAFFINITY);
    p->flags |= PF_FORKNOEXEC;
    INIT_LIST_HEAD(&p->children);
    INIT_LIST_HEAD(&p->sibling);
    rcu_copy_process(p);
    p->vfork_done = NULL;
    spin_lock_init(&p->alloc_lock);

    init_sigpending(&p->pending);

    p->utime = p->stime = p->gtime = 0;
#ifdef CONFIG_ARCH_HAS_SCALED_CPUTIME
    p->utimescaled = p->stimescaled = 0;
#endif
    prev_cputime_init(&p->prev_cputime);

#ifdef CONFIG_VIRT_CPU_ACCOUNTING_GEN
    seqcount_init(&p->vtime.seqcount);
    p->vtime.starttime = 0;
    p->vtime.state = VTIME_INACTIVE;
#endif

#ifdef CONFIG_IO_URING
    p->io_uring = NULL;
#endif

#if defined(SPLIT_RSS_COUNTING)
    memset(&p->rss_stat, 0, sizeof(p->rss_stat));
#endif

    p->default_timer_slack_ns = target->timer_slack_ns;

#ifdef CONFIG_PSI
    p->psi_flags = 0;
#endif

    task_io_accounting_init(&p->ioac);
    acct_clear_integrals(p);

    posix_cputimers_init(&p->posix_cputimers);

    p->io_context = NULL;
    audit_set_context(p, NULL);
    cgroup_fork(p);
#ifdef CONFIG_NUMA
    p->mempolicy = mpol_dup(p->mempolicy);
    if (IS_ERR(p->mempolicy))
    {
        retval = PTR_ERR(p->mempolicy);
        p->mempolicy = NULL;
        goto bad_fork_cleanup_threadgroup_lock;
    }
#endif
#ifdef CONFIG_CPUSETS
    p->cpuset_mem_spread_rotor = NUMA_NO_NODE;
    p->cpuset_slab_spread_rotor = NUMA_NO_NODE;
    seqcount_spinlock_init(&p->mems_allowed_seq, &p->alloc_lock);
#endif
#ifdef CONFIG_TRACE_IRQFLAGS
    memset(&p->irqtrace, 0, sizeof(p->irqtrace));
    p->irqtrace.hardirq_disable_ip = _THIS_IP_;
    p->irqtrace.softirq_enable_ip = _THIS_IP_;
    p->softirqs_enabled = 1;
    p->softirq_context = 0;
#endif

    p->pagefault_disabled = 0;

#ifdef CONFIG_LOCKDEP
    lockdep_init_task(p);
#endif

#ifdef CONFIG_DEBUG_MUTEXES
    p->blocked_on = NULL; /* not blocked yet */
#endif
#ifdef CONFIG_BCACHE
    p->sequential_io = 0;
    p->sequential_io_avg = 0;
#endif
#ifdef CONFIG_BPF_SYSCALL
    RCU_INIT_POINTER(p->bpf_storage, NULL);
#endif

    /* Perform scheduler related setup. Assign this task to a CPU. */
    retval = sched_fork(clone_flags, p);
    if (retval)
        goto bad_fork_cleanup_policy;

    retval = perf_event_init_task(p, clone_flags);
    if (retval)
        goto bad_fork_cleanup_policy;
    retval = audit_alloc(p);
    if (retval)
        goto bad_fork_cleanup_perf;

    /* copy all the process information */
    shm_init_task(p);
    retval = security_task_alloc(p, clone_flags);
    if (retval)
        goto bad_fork_cleanup_audit;
    retval = copy_semundo(clone_flags, p);
    if (retval)
        goto bad_fork_cleanup_security;
    retval = copy_files(clone_flags, p);
    if (retval)
        goto bad_fork_cleanup_semundo;
    retval = copy_fs(clone_flags, p);
    if (retval)
        goto bad_fork_cleanup_files;
    retval = copy_sighand(clone_flags, p);
    if (retval)
        goto bad_fork_cleanup_fs;
    retval = copy_signal(clone_flags, p);
    if (retval)
        goto bad_fork_cleanup_sighand;
    retval = copy_mm(clone_flags, p);
    if (retval)
        goto bad_fork_cleanup_signal;
    retval = copy_namespaces(clone_flags, p);
    if (retval)
        goto bad_fork_cleanup_mm;
    retval = copy_io(clone_flags, p);
    if (retval)
        goto bad_fork_cleanup_namespaces;
    retval =
        copy_thread(clone_flags, args->stack, args->stack_size, p, args->tls);
    if (retval)
        goto bad_fork_cleanup_io;

    stackleak_task_init(p);

    if (pid != &init_struct_pid)
    {
        pid = alloc_pid(p->nsproxy->pid_ns_for_children, args->set_tid,
                        args->set_tid_size);
        if (IS_ERR(pid))
        {
            retval = PTR_ERR(pid);
            goto bad_fork_cleanup_thread;
        }
    }

    /*
     * This has to happen after we've potentially unshared the file
     * descriptor table (so that the pidfd doesn't leak into the child
     * if the fd table isn't shared).
     */
    if (clone_flags & CLONE_PIDFD)
    {
        retval = get_unused_fd_flags(O_RDWR | O_CLOEXEC);
        if (retval < 0)
            goto bad_fork_free_pid;

        pidfd = retval;

        pidfile =
            anon_inode_getfile("[pidfd]", &pidfd_fops, pid, O_RDWR | O_CLOEXEC);
        if (IS_ERR(pidfile))
        {
            put_unused_fd(pidfd);
            retval = PTR_ERR(pidfile);
            goto bad_fork_free_pid;
        }
        get_pid(pid); /* held by pidfile now */

        retval = put_user(pidfd, args->pidfd);
        if (retval)
            goto bad_fork_put_pidfd;
    }

#ifdef CONFIG_BLOCK
    p->plug = NULL;
#endif
    futex_init_task(p);

    /*
     * sigaltstack should be cleared when sharing the same VM
     */
    if ((clone_flags & (CLONE_VM | CLONE_VFORK)) == CLONE_VM)
        sas_ss_reset(p);

    /*
     * Syscall tracing and stepping should be turned off in the
     * child regardless of CLONE_PTRACE.
     */
    user_disable_single_step(p);
    clear_task_syscall_work(p, SYSCALL_TRACE);
#if defined(CONFIG_GENERIC_ENTRY) || defined(TIF_SYSCALL_EMU)
    clear_task_syscall_work(p, SYSCALL_EMU);
#endif
    clear_tsk_latency_tracing(p);

    /* ok, now we should be set up.. */
    p->pid = pid_nr(pid);
    if (clone_flags & CLONE_THREAD)
    {
        p->group_leader = target->group_leader;
        p->tgid = target->tgid;
    }
    else
    {
        p->group_leader = p;
        p->tgid = p->pid;
    }

    p->nr_dirtied = 0;
    p->nr_dirtied_pause = 128 >> (PAGE_SHIFT - 10);
    p->dirty_paused_when = 0;

    p->pdeath_signal = 0;
    INIT_LIST_HEAD(&p->thread_group);
    p->task_works = NULL;

#ifdef CONFIG_KRETPROBES
    p->kretprobe_instances.first = NULL;
#endif

    /*
     * Ensure that the cgroup subsystem policies allow the new process to be
     * forked. It should be noted that the new process's css_set can be changed
     * between here and cgroup_post_fork() if an organisation operation is in
     * progress.
     */
    retval = cgroup_can_fork(p, args);
    if (retval)
        goto bad_fork_put_pidfd;

    /*
     * From this point on we must avoid any synchronous user-space
     * communication until we take the tasklist-lock. In particular, we do
     * not want user-space to be able to predict the process start-time by
     * stalling fork(2) after we recorded the start_time but before it is
     * visible to the system.
     */

    p->start_time = ktime_get_ns();
    p->start_boottime = ktime_get_boottime_ns();

    /*
     * Make it visible to the rest of the system, but dont wake it up yet.
     * Need tasklist lock for parent etc handling!
     */
    write_lock_irq(&tasklist_lock);

    /* CLONE_PARENT re-uses the old parent */
    if (clone_flags & (CLONE_PARENT | CLONE_THREAD))
    {
        p->real_parent = target->real_parent;
        p->parent_exec_id = target->parent_exec_id;
        if (clone_flags & CLONE_THREAD)
            p->exit_signal = -1;
        else
            p->exit_signal = target->group_leader->exit_signal;
    }
    else
    {
        p->real_parent = target;
        p->parent_exec_id = target->self_exec_id;
        p->exit_signal = args->exit_signal;
    }

    klp_copy_process(p);

    sched_core_fork(p);

    spin_lock(&target->sighand->siglock);

    /*
     * Copy seccomp details explicitly here, in case they were changed
     * before holding sighand lock.
     */
    copy_seccomp(p);

    rseq_fork(p, clone_flags);

    /* Don't start children in a dying pid namespace */
    if (unlikely(!(ns_of_pid(pid)->pid_allocated & PIDNS_ADDING)))
    {
        retval = -ENOMEM;
        goto bad_fork_cancel_cgroup;
    }

    /* Let kill terminate clone/fork in the middle */
    if (fatal_signal_pending(target))
    {
        retval = -EINTR;
        goto bad_fork_cancel_cgroup;
    }

    /* past the last point of failure */
    if (pidfile)
        fd_install(pidfd, pidfile);

    init_task_pid_links(p);
    if (likely(p->pid))
    {
        ptrace_init_task(p, (clone_flags & CLONE_PTRACE) || trace);

        init_task_pid(p, PIDTYPE_PID, pid);
        if (thread_group_leader(p))
        {
            init_task_pid(p, PIDTYPE_TGID, pid);
            init_task_pid(p, PIDTYPE_PGID, task_pgrp(target));
            init_task_pid(p, PIDTYPE_SID, task_session(target));

            if (is_child_reaper(pid))
            {
                ns_of_pid(pid)->child_reaper = p;
                p->signal->flags |= SIGNAL_UNKILLABLE;
            }
            p->signal->shared_pending.signal = delayed.signal;
            p->signal->tty = tty_kref_get(target->signal->tty);
            /*
             * Inherit has_child_subreaper flag under the same
             * tasklist_lock with adding child to the process tree
             * for propagate_has_child_subreaper optimization.
             */
            p->signal->has_child_subreaper =
                p->real_parent->signal->has_child_subreaper ||
                p->real_parent->signal->is_child_subreaper;
            list_add_tail(&p->sibling, &p->real_parent->children);
            list_add_tail_rcu(&p->tasks, &init_task.tasks);
            attach_pid(p, PIDTYPE_TGID);
            attach_pid(p, PIDTYPE_PGID);
            attach_pid(p, PIDTYPE_SID);
            __this_cpu_inc(process_counts);
        }
        else
        {
            target->signal->nr_threads++;
            atomic_inc(&target->signal->live);
            refcount_inc(&target->signal->sigcnt);
            task_join_group_stop(p);
            list_add_tail_rcu(&p->thread_group, &p->group_leader->thread_group);
            list_add_tail_rcu(&p->thread_node, &p->signal->thread_head);
        }
        attach_pid(p, PIDTYPE_PID);
        nr_threads++;
    }
    /* total_forks++; */
    hlist_del_init(&delayed.node);
    spin_unlock(&target->sighand->siglock);
    syscall_tracepoint_update(p);
    write_unlock_irq(&tasklist_lock);

    proc_fork_connector(p);
    sched_post_fork(p);
    cgroup_post_fork(p, args);
    perf_event_fork(p);

    trace_task_newtask(p, clone_flags);
    uprobe_copy_process(p, clone_flags);

    copy_oom_score_adj(clone_flags, p);

    return p;
bad_fork_cancel_cgroup:
    sched_core_free(p);
    spin_unlock(&target->sighand->siglock);
    write_unlock_irq(&tasklist_lock);
    cgroup_cancel_fork(p, args);
bad_fork_put_pidfd:
    if (clone_flags & CLONE_PIDFD)
    {
        fput(pidfile);
        put_unused_fd(pidfd);
    }
bad_fork_free_pid:
    if (pid != &init_struct_pid)
        free_pid(pid);
bad_fork_cleanup_thread:
    exit_thread(p);
bad_fork_cleanup_io:
    if (p->io_context)
        exit_io_context(p);
bad_fork_cleanup_namespaces:
    exit_task_namespaces(p);
bad_fork_cleanup_mm:
    if (p->mm)
    {
        mm_clear_owner(p->mm, p);
        mmput(p->mm);
    }
bad_fork_cleanup_signal:
    if (!(clone_flags & CLONE_THREAD))
        free_signal_struct(p->signal);
bad_fork_cleanup_sighand:
    __cleanup_sighand(p->sighand);
bad_fork_cleanup_fs:
    exit_fs(p); /* blocking */
bad_fork_cleanup_files:
    exit_files(p); /* blocking */
bad_fork_cleanup_semundo:
    exit_sem(p);
bad_fork_cleanup_security:
    security_task_free(p);
bad_fork_cleanup_audit:
    audit_free(p);
bad_fork_cleanup_perf:
    perf_event_free_task(p);
bad_fork_cleanup_policy:
    lockdep_free_task(p);
#ifdef CONFIG_NUMA
    mpol_put(p->mempolicy);
bad_fork_cleanup_threadgroup_lock:
#endif
    delayacct_tsk_free(p);
bad_fork_cleanup_count:
    dec_rlimit_ucounts(task_ucounts(p), UCOUNT_RLIMIT_NPROC, 1);
    exit_creds(p);
bad_fork_free:
    WRITE_ONCE(p->__state, TASK_DEAD);
    put_task_stack(p);
    delayed_free_task(p);
fork_out:
    spin_lock_irq(&target->sighand->siglock);
    hlist_del_init(&delayed.node);
    spin_unlock_irq(&target->sighand->siglock);
    return ERR_PTR(retval);
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
        /* return -EINVAL; */
        return NULL;
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

    p = sus_copy_process(target, trace, NUMA_NO_NODE, args);

    if (IS_ERR(p))
    {
        pr_err("ufrk: sus_kernel_clone: copy_process reported error\n");
        //    return PTR_ERR(p);
        return NULL;
    }

    // TODO:
    // trace_sched_process_fork(target, p);

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

    return p;
}

static int recursive_fork(struct task_struct* task, void* data)
{
    struct rfork_context* ctx = (struct rfork_context*)data;
    struct kernel_clone_args args = {.exit_signal = SIGCHLD};

    struct task_struct* forked_task = sus_kernel_clone(task, &args);

    if (forked_task == NULL)
    {
        pr_err("ufrk: failed to fork task, counter: %d\n", ctx->counter);
        return -EACCES;
    }

    pr_info("rfork orig  : %s, pid=%d, tgid=%d\n", task->comm, task->pid,
            task->tgid);
    pr_info("rfork forked: %s, pid=%d, tgid=%d\n", forked_task->comm,
            forked_task->pid, forked_task->tgid);

    if (0 == ctx->counter)
    {

        struct task_struct* previous_parent = forked_task->parent;
        struct task_struct* iter;
        struct list_head* pos;
        struct list_head* q;

        pr_info("rfork: adjusting pointers of lead process\n");

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

    pr_info("Tasks locked, preparing fork\n");
    struct rfork_context ctx = {
        .forked_parent = NULL,
        .original_grandparent = parent->parent,
        .counter = 0,
    };
    walk_task(parent, &ctx, &rfork_walker);

    walk_task(parent, NULL, &rfork_resume_walker);
    return 0;
}
