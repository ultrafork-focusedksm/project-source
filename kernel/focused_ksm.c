#include "focused_ksm.h"
#include "hash_tree.h"
#include "sus.h"
#include <asm/types.h>
#include <crypto/blake2b.h>
#include <crypto/internal/hash.h>
#include <linux/crypto.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/ksm.h>
#include <linux/list.h>
#include <linux/mm.h>
#include <linux/mm_types.h>
#include <linux/mmu_notifier.h>
#include <linux/module.h>
#include <linux/page-flags.h>
#include <linux/pagemap.h>
#include <linux/pagewalk.h>
#include <linux/pgtable.h>
#include <linux/rmap.h>
#include <linux/sched/mm.h>
#include <linux/types.h>

// Helper to print bytes during debugging of hashing functions
void kprint_bytes(u8* input, size_t size)
{
    size_t i;
    size_t j;
    for (i = 0; i < size; i = i + 32)
    {
        for (j = 0; j < 32; j++)
        {
            pr_cont(KERN_INFO "%02X", input[i + j]);
        }
        pr_cont(KERN_INFO "\n");
    }
}

static struct task_struct* find_task_from_pid(unsigned long pid)
{
    struct pid* pid_struct = find_get_pid(pid);
    return get_pid_task(pid_struct, PIDTYPE_PID);
}

/**
 * Helper function that performs long and short hash on a page of size PAGE_SIZE
 * @page pointer to the page we want to hash
 * @out_short output for the short hash
 * @out_long output for the long hash
 */
static void fksm_hash_page(struct page* page, u64 *out_short, u8* out_long)
{
    int err;                  // hash output error code
    u8* addr;                 // page mapping address
    struct crypto_shash* tfm; // crypto transform object
    struct shash_desc* desc;  // crypto description object

    // init blake2b hash parameters
    tfm = crypto_alloc_shash("blake2b-512", 0, 0);
    BUG_ON(IS_ERR(tfm));
    desc = kmalloc(sizeof(*desc) + crypto_shash_descsize(tfm), GFP_KERNEL);
    BUG_ON(IS_ERR(desc));
    desc->tfm = tfm;

    // ATOMIC START
    addr = kmap_atomic(page);
    BUG_ON(IS_ERR(addr));

    // short hash operation
    *out_short = xxh64(addr, PAGE_SIZE, 0);

    // long hash operation
    err = crypto_shash_digest(desc, addr, PAGE_SIZE, out_long);

    kunmap_atomic(addr);
    // ATOMIC END

    kfree(tfm);
    kfree(desc);

    // problems if the hash isn't valid since we don't memcmp
    BUG_ON(err != 0);
}

/**
 * Callback function on each pte in the mm of the current process
 * @pte pte of the current page
 * @addr not used
 * @next not used
 * @walk context for the callback
 */
static int callback_pte_range(pte_t* pte, unsigned long addr,
                              unsigned long next, struct mm_walk* walk)
{
    /*
     * we want to walk the full range so unless something catastrophic occurs we
     * return 0 from the callback to keep going. if something bad happens return
     * negative value. do not return a positive value
     */
    struct page* current_page;            // current page in callback
    struct page_metadata* current_meta;   // metadata for current page
    struct page_metadata* existing_meta;  // metadata from hash_tree
    struct first_level_bucket* hash_tree; // stack ref to hash tree
    u64* out_short;                        // short hash output
    u8* out_long;                         // long hash output
    int code;                             // replace_page output code

    current_page = pte_page(*pte); // get the page from pte
    if (IS_ERR(current_page))
    {
        pr_err("FKSM_ERROR: pte_page lookup error");
    }

    // TODO: find out if THP will be walked through or only pointed to the head
    // TODO: compound pages walking through tails too? Locking the group?
    if (PageAnon(current_page))
    {
        // compatible page type, hash it
        out_short = kmalloc(sizeof(u64), GFP_KERNEL);
        out_long = kmalloc(BLAKE2B_512_HASH_SIZE, GFP_KERNEL);

        fksm_hash_page(current_page, out_short, out_long);

        current_meta = kmalloc(sizeof(struct page_metadata), GFP_KERNEL);

        // collect metadata
        current_meta->page = current_page;
        current_meta->pte = pte;
        current_meta->vma = walk->vma;
        current_meta->mm = walk->mm;

        // hold local ref to hash tree (only needed on compatible)
        hash_tree = (struct first_level_bucket*)walk->private;

        // add new_meta to hash_tree and check if return is not null (already
        // existing metadata)
        pr_info("%p | %llu | %p | %p", hash_tree, *out_short, out_long,
                current_meta);
        existing_meta = hash_tree_get_or_create(hash_tree, *out_short, out_long,
                                                current_meta);
        if (existing_meta != NULL)
        {
            // replace_page condition, we can merge this page into curr_meta
            code = replace_page(current_meta->vma, current_meta->page,
                                existing_meta->page, *current_meta->pte);
            if (code == -EFAULT)
            {
                pr_err("FKSM_MERGE: REPLACE_PAGE FAIL");
            }
            else
            {
                pr_info("FKSM_MERGE: REPLACE_PAGE SUCCESS");
            }

            // throw these out, they exist already
            kfree(current_meta);            
        }
        kfree(out_short);
        kfree(out_long);
    }
    
    return 0;
}

static struct mm_walk_ops task_walk_ops = {.pte_entry = callback_pte_range};

static int scan(unsigned long pid, struct first_level_bucket* hash_tree)
{
    struct task_struct* task;

    task = find_task_from_pid(pid); // get task struct
    pr_info("FKSM: FIND TASK FOR %lu", pid);

    if (IS_ERR(task))
    {
        pr_err("FKSM_ERROR: task struct not found");
    }

    pr_info("FKSM: READ LOCK FOR SCAN");
    mmap_read_lock(task->active_mm);

    pr_info("FKSM: WALK START");
    walk_page_range(task->active_mm, 0, TASK_SIZE, &task_walk_ops, hash_tree);

    pr_info("FKSM: WALK END, UNLOCKING");
    mmap_read_unlock(task->active_mm);

    return 0; // returning int in case we want to add return flags
}

int sus_mod_merge(unsigned long pid1, unsigned long pid2)
{
    struct first_level_bucket* hash_tree;
    hash_tree = first_level_init();

    pr_info("FKSM_MAIN: pid1 start");
    scan(pid1, hash_tree);
    pr_info("FKSM_MAIN: pid2 start");
    scan(pid2, hash_tree);
    pr_info("FKSM_MAIN: end");

    return 0;
}
