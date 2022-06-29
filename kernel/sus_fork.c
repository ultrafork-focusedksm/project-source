// SPDX-License-Identifier: GPL-2.0
/*
 * sus_fork.c: The functions in this file make up the clone implementation for
 * Ultrafork that could be extracted from the kernel easily. Part of the
 * implementation exists as patches to the kernel source. The implementation is
 * split like this because it is much easier to develop in a module than by
 * directly patching the kernel. The bulk of the code is in this file, so
 * hopefully future modifications will be made easier by this design decision.
 *
 * Limitations:
 *
 * - The kernel/fork.c implementation has fork bomb protection, which does
 *   not exist here. That is not really an issue, because in order to create
 *   a fork bomb, the attacker would need to have shell access to a user
 *   with permissions to access the docker daemon (i.e. start and stop
 *   containers), which is equivalent to root access anyway.
 */
#include <linux/anon_inodes.h>
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
#include <linux/mempolicy.h>
#include <linux/module.h>
#include <linux/perf_event.h>
#include <linux/ptrace.h>
#include <linux/sched.h>
#include <linux/sched/autogroup.h>
#include <linux/sched/cputime.h>
#include <linux/sched/mm.h>
#include <linux/sched/signal.h>
#include <linux/sched/task.h>
#include <linux/sched/task_stack.h>
#include <linux/security.h>
#include <linux/stackleak.h>
#include <linux/task_io_accounting_ops.h>
#include <linux/tsacct_kern.h>
#include <linux/tty.h>
#include <linux/types.h>

static void rcu_copy_process(struct task_struct* p)
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

static void init_task_pid_links(struct task_struct* task)
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

static void sus_freezer_do_not_count(struct task_struct* task)
{
    task->flags |= PF_FREEZER_SKIP;
}

static void sus_freezer_count(struct task_struct* task)
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

static void __sus_mmdrop(struct mm_struct* mm)
{
    mm_free_pgd(mm);
    sus_destroy_context(mm);
    sus_mmu_notifier_subscriptions_destroy(mm);
    check_mm(mm);
    put_user_ns(mm->user_ns);
    free_mm(mm);
}

static void mmdrop_async_fn(struct work_struct* work)
{
    struct mm_struct* mm;

    mm = container_of(work, struct mm_struct, async_put_work);
    __sus_mmdrop(mm);
}

static void mmdrop_async(struct mm_struct* mm)
{
    if (unlikely(atomic_dec_and_test(&mm->mm_count)))
    {
        INIT_WORK(&mm->async_put_work, mmdrop_async_fn);
        schedule_work(&mm->async_put_work);
    }
}

static void free_signal_struct(struct signal_struct* sig)
{
    sus_taskstats_tgid_free(sig);
    sched_autogroup_exit(sig);

    if (sig->oom_mm)
    {
        mmdrop_async(sig->oom_mm);
    }
    signal_cache_free(sig);
}

static void __delayed_free_task(struct rcu_head* rhp)
{
    struct task_struct* tsk = container_of(rhp, struct task_struct, rcu);

    free_task(tsk);
}

static void delayed_free_task(struct task_struct* tsk)
{
    if (IS_ENABLED(CONFIG_MEMCG))
        call_rcu(&tsk->rcu, __delayed_free_task);
    else
        free_task(tsk);
}

/**
 * SuS implementation of copy_process. The main difference between the
 * copy_process routine and this routine is that this function takes
 * a target process. In the kernel/fork.c copy_process, this target process
 * is implicitly 'current'. This function is extracted to the module for ease
 * of modification, since it needs to be kept in sync with the kernel's
 * implementation.
 */
static struct task_struct* sus_copy_process(struct task_struct* target,
                                            int trace, int node,
                                            struct kernel_clone_args* args)
{

    int pidfd = -1;
    int retval;
    struct task_struct* p;
    struct multiprocess_signals delayed;
    struct file* pidfile = NULL;
    u64 clone_flags = args->flags;
    struct nsproxy* nsp = target->nsproxy;
    struct pid* pid = task_pid(target);

    /*
     * Don't allow sharing the root directory with processes in a different
     * namespace
     */
    if ((clone_flags & (CLONE_NEWNS | CLONE_FS)) == (CLONE_NEWNS | CLONE_FS))
    {
        pr_err("sus_copy_process: root directory cannot be shared across "
               "namespaces\n");
        return ERR_PTR(-EINVAL);
    }

    if ((clone_flags & (CLONE_NEWUSER | CLONE_FS)) ==
        (CLONE_NEWUSER | CLONE_FS))
    {
        pr_err("sus_copy_process: can't clone the filesystem and be a in a "
               "user ns\n");
        return ERR_PTR(-EINVAL);
    }
    /*
     * Thread groups must share signals as well, and detached threads
     * can only be started up within the thread group.
     */
    if ((clone_flags & CLONE_THREAD) && !(clone_flags & CLONE_SIGHAND))
    {
        pr_err("sus_copy_process: thread groups must share signal handlers\n");
        return ERR_PTR(-EINVAL);
    }

    /*
     * Shared signal handlers imply shared VM. By way of the above,
     * thread groups also imply shared VM. Blocking this case allows
     * for various simplifications in other code.
     */
    if ((clone_flags & CLONE_SIGHAND) && !(clone_flags & CLONE_VM))
    {
        pr_err(
            "sus_copy_process: shared signal handlers imply sharing memory\n");
        return ERR_PTR(-EINVAL);
    }

    /*
     * Siblings of global init remain as zombies on exit since they are
     * not reaped by their parent (swapper). To solve this and to avoid
     * multi-rooted process trees, prevent global and container-inits
     * from creating siblings.
     */
    if ((clone_flags & CLONE_PARENT) &&
        target->signal->flags & SIGNAL_UNKILLABLE)
    {
        pr_err("sus_copy_process: global inits cannot spawn siblings\n");
        return ERR_PTR(-EINVAL);
    }

    /*
     * If the new process will be in a different pid or user namespace
     * do not allow it to share a thread group with the forking task.
     */
    if (clone_flags & CLONE_THREAD)
    {
        if ((clone_flags & (CLONE_NEWUSER | CLONE_NEWPID)) ||
            (task_active_pid_ns(target) != nsp->pid_ns_for_children))
        {
            pr_err("sus_copy_process: thread groups cannot exist across pid "
                   "and user namespaces\n");
            return ERR_PTR(-EINVAL);
        }
    }

    /*
     * If the new process will be in a different time namespace
     * do not allow it to share VM or a thread group with the forking task.
     */
    if (clone_flags & (CLONE_THREAD | CLONE_VM))
    {
        if (nsp->time_ns != nsp->time_ns_for_children)
        {
            pr_err("sus_copy_process: time namespaces imply non-shared VM\n");
            return ERR_PTR(-EINVAL);
        }
    }

    if (clone_flags & CLONE_PIDFD)
    {
        /*
         * - CLONE_DETACHED is blocked so that we can potentially
         *   reuse it later for CLONE_PIDFD.
         * - CLONE_THREAD is blocked until someone really needs it.
         */
        if (clone_flags & (CLONE_DETACHED | CLONE_THREAD))
        {
            pr_err(
                "sus_copy_process: block clone pidfd and thead until needed\n");
            return ERR_PTR(-EINVAL);
        }
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
    sus_recalc_sigpending(target);
    spin_unlock_irq(&target->sighand->siglock);
    retval = -ERESTARTNOINTR;

    /*
     * In normal fork, this is an error test, but since we are using SIGSTOP
     * to suspend the processes, we can't fail on this check.
     */
    if (task_sigpending(target))
    {
        pr_info("sus_copy_process: target is SIGPENDING\n");
    }

    retval = -ENOMEM;
    p = dup_task_struct(target, node);
    if (!p)
    {
        pr_err("sus_copy_process: dup_task_struct failed\n");
        goto fork_out;
    }
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
        {
            pr_err("sus_copy_process: overlimit or not capable\n");
            goto bad_fork_free;
        }
    }
    target->flags &= ~PF_NPROC_EXCEEDED;

    retval = sus_copy_creds(p, clone_flags, target);
    if (retval < 0)
    {
        pr_err("sus_copy_process: copy_creds failed\n");
        goto bad_fork_free;
    }

    /*
     * If multiple threads are within copy_process(), then this check
     * triggers too late. This doesn't hurt, the check is only there
     * to stop root fork bombs.
     */
    retval = -EAGAIN;
    //   if (data_race(nr_threads >= max_threads))
    //        goto bad_fork_cleanup_count;

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
        pr_err("sus_copy_process: failed to duplicate mem policy\n");
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
    retval = sus_sched_fork(clone_flags, p, target);
    if (retval)
    {
        pr_err("sus_copy_process: failed to setup scheduler\n");
        goto bad_fork_cleanup_policy;
    }

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
    {
        pr_err("sus_copy_process: %d security_task_alloc failed", p->pid);
        goto bad_fork_cleanup_audit;
    }
    retval = sus_copy_semundo(clone_flags, p, target);
    if (retval)
    {
        pr_err("sus_copy_process: %d copy_semundo failed", p->pid);
        goto bad_fork_cleanup_security;
    }
    retval = sus_copy_files(clone_flags, p, target);
    if (retval)
    {
        pr_err("sus_copy_process: %d copy_files failed", p->pid);
        goto bad_fork_cleanup_semundo;
    }
    retval = sus_copy_fs(clone_flags, p, target);
    if (retval)
    {
        pr_err("sus_copy_process: %d copy_fs failed", p->pid);
        goto bad_fork_cleanup_files;
    }
    retval = sus_copy_sighand(clone_flags, p, target);
    if (retval)
    {
        pr_err("sus_copy_process: %d copy_sighand failed", p->pid);
        goto bad_fork_cleanup_fs;
    }
    retval = sus_copy_signal(clone_flags, p, target);
    if (retval)
    {
        pr_err("sus_copy_process: %d copy_signal failed", p->pid);
        goto bad_fork_cleanup_sighand;
    }
    retval = sus_copy_mm(clone_flags, p, target);
    if (retval)
    {
        pr_err("sus_copy_process: %d copy_mm failed", p->pid);
        goto bad_fork_cleanup_signal;
    }
    retval = copy_namespaces(clone_flags, p);
    if (retval)
    {
        pr_err("sus_copy_process: %d copy_namespaces failed", p->pid);
        goto bad_fork_cleanup_mm;
    }
    retval = sus_copy_io(clone_flags, p);
    if (retval)
    {
        pr_err("sus_copy_process: %d copy_io failed", p->pid);
        goto bad_fork_cleanup_namespaces;
    }
    retval = sus_copy_thread(clone_flags, args->stack, args->stack_size, p,
                             target, args->tls);
    if (retval)
    {
        pr_err("sus_copy_process: %d copy_thread failed", p->pid);
        goto bad_fork_cleanup_io;
    }

    stackleak_task_init(p);

    if (pid != &init_struct_pid)
    {
        pid = alloc_pid(p->nsproxy->pid_ns_for_children, args->set_tid,
                        args->set_tid_size);
        if (IS_ERR(pid))
        {
            pr_err("sus_copy_process: %d alloc_pid failed", p->pid);
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
        {
            pr_err("sus_copy_process: %d get_unused_fd_flags failed", p->pid);
            goto bad_fork_free_pid;
        }

        pidfd = retval;

        pidfile = fork_get_pidfile(pid);
        if (IS_ERR(pidfile))
        {
            put_unused_fd(pidfd);
            retval = PTR_ERR(pidfile);
            pr_err("sus_copy_process: %d fork_get_pidfile failed", p->pid);
            goto bad_fork_free_pid;
        }
        get_pid(pid); /* held by pidfile now */

        retval = put_user(pidfd, args->pidfd);
        if (retval)
        {
            pr_err("sus_copy_process: %d put_user failed", p->pid);
            goto bad_fork_put_pidfd;
        }
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
    retval = sus_cgroup_can_fork(target, p, args);
    if (retval)
    {
        pr_err("sus_copy_process: %d cgroup_can_fork failed", p->pid);
        goto bad_fork_put_pidfd;
    }

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
    fork_write_lock_irq();

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

    sus_sched_core_fork(p, target);

    spin_lock(&target->sighand->siglock);

    /*
     * Copy seccomp details explicitly here, in case they were changed
     * before holding sighand lock.
     */
    sus_copy_seccomp(p, target);

    sus_rseq_fork(p, clone_flags, target);

    /* Don't start children in a dying pid namespace */
    if (unlikely(!(ns_of_pid(pid)->pid_allocated & PIDNS_ADDING)))
    {
        retval = -ENOMEM;
        pr_err("sus_copy_process: %d dying namespace, aborting", p->pid);
        goto bad_fork_cancel_cgroup;
    }

    /* Let kill terminate clone/fork in the middle */

    /*
    if (fatal_signal_pending(target))
    {
        retval = -EINTR;
        goto bad_fork_cancel_cgroup;
    }
    */

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
            pr_info("sus_copy_process: %d is thread_group_leader", p->pid);
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
            increment_process_count();
        }
        else
        {
            pr_info("sus_copy_process: %d is NOT thread_group_leader", p->pid);
            /* target->signal->nr_threads++; */
            /* atomic_inc(&target->signal->live); */
            /* refcount_inc(&target->signal->sigcnt); */

            /* sus_task_join_group_stop(p, target); */
            /* list_add_tail_rcu(&p->thread_group,
             * &p->group_leader->thread_group); */
            /* list_add_tail_rcu(&p->thread_node, &p->signal->thread_head); */
        }
        attach_pid(p, PIDTYPE_PID);
        //        nr_threads++;
    }
    /* total_forks++; */
    hlist_del_init(&delayed.node);
    spin_unlock(&target->sighand->siglock);
    // syscall_tracepoint_update(p);
    fork_write_unlock_irq();

    proc_fork_connector(p);
    sched_post_fork(p);
    cgroup_post_fork(p, args);
    perf_event_fork(p);

    // trace_task_newtask(p, clone_flags);
    sus_uprobe_copy_process(p, clone_flags, target);

    sus_copy_oom_score_adj(clone_flags, p, target);

    return p;
bad_fork_cancel_cgroup:
    sched_core_free(p);
    spin_unlock(&target->sighand->siglock);
    fork_write_unlock_irq();
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
    // bad_fork_cleanup_count:
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

struct task_struct* sus_kernel_clone(struct task_struct* target,
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
        pr_err("ufrk: sus_kernel_clone: invalid clone flags passed\n");
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

    // wake_up_new_task(p);

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
