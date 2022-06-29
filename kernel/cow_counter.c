// SPDX-License-Identifier: GPL-2.0
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
 * @param proc Process ID to examine.
 * @param cow_bytes Pointer to write copy-on-write byte count to.
 * @param vm_bytes Pointer to write virtual memory byte count to.
 *
 * @return 0 for success, -1 otherwise.
 */
int cow_count(pid_t proc, size_t* cow_bytes, size_t* vm_bytes)
{
    struct mm_struct* mm;
    struct vm_area_struct* vma;
    struct list_head* pos;
    struct anon_vma_chain* chain;
    struct task_struct* task = find_task_from_pid(proc);

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

        *cow_bytes = 0;
        *vm_bytes = 0;
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
                *cow_bytes += (chain->vma->vm_end - chain->vma->vm_start);

                // if there are multiple entries on a chain for a single VM
                // area, it means the memory area has been passed down though
                // multiple processes (more than just the parent). We only
                // want to count such regions once, to avoid over-calculating
                // the size of the COW regions.
                break;
            }

            *vm_bytes += vma->vm_end - vma->vm_start;
        }
        up_read(&mm->mmap_lock);
        pr_info("%d total COW memory bytes %ld, VM bytes %ld\n", task->pid,
                *cow_bytes, *vm_bytes);
    }

    return 0;
}
