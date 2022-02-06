#include "cow_counter.h"
#include "util.h"
#include <linux/limits.h>
#include <linux/list.h>
#include <linux/rmap.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>

/**
 * The COW counter is a function that determines the size of any memory
 * COW shared with a given process. This function was created for testing the
 * SuS memory system, particularly Ultrafork.
 *
 * This function only totals COW memory shared by the parent with this process.
 * It makes no effort to determine how much (if any) is shared with any
 * child processes.
 *
 * @param proc Process ID to scan
 * @return -errno in the event of error, otherwise the number of bytes COW
 * shared with this process.
 */
ssize_t cow_count(pid_t proc)
{
    struct mm_struct* mm;
    struct vm_area_struct* vma;
    struct list_head* pos;
    struct anon_vma_chain* chain;
    struct task_struct* task = find_task_from_pid(proc);
    ssize_t cow_memory = 0;

    if (NULL == task)
    {
        pr_err("Task not found with PID %d\n", proc);
        return -EINVAL;
    }

    // get_task_mm does not require the caller to lock.
    mm = get_task_mm(task);

    // mm is NULL for kernel threads
    if (NULL != mm && NULL != mm->mmap)
    {
        down_read(&mm->mmap_lock);

        /*
         * This may look like a double loop over vm_area_structs. This is
         * correct. In order to determine if memory is COW shared with this
         * process, we must iterate though all the processes's vm_area_structs
         * and for each, access the anon_vma_chain. If the chain contains this
         * vm_area_struct, then it is COW shared with this process, so total its
         * size.
         */
        for (vma = mm->mmap; NULL != vma; vma = vma->vm_next)
        {
            list_for_each(pos, &vma->anon_vma_chain)
            {
                chain = list_entry(pos, struct anon_vma_chain, same_vma);
                cow_memory += chain->vma->vm_end - chain->vma->vm_start;
            }
        }
        up_read(&mm->mmap_lock);
        pr_debug("%d total COW memory bytes %ld\n", task->pid, cow_memory);
    }

    return cow_memory;
}
