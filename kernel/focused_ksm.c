#include "focused_ksm.h"
#include "hash_tree.h"
#include "sus.h"
#include "util.h"
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

static size_t scanned; // counter for valid pages that are hashed and looked up
                       // on the hash tree
static size_t merge_success; // successful merges of pages
static size_t merge_fail;    // failed merges of pages

// static struct task_struct* find_task_from_pid(unsigned long pid)
// {
//     struct pid* pid_struct = find_get_pid(pid);
//     return get_pid_task(pid_struct, PIDTYPE_PID);
// }

/**
 * Helper function that performs long and short hash on a page of size PAGE_SIZE
 * @page pointer to the page we want to hash
 * @out_short output for the short hash
 * @out_long output for the long hash
 */
static void fksm_hash_page(struct page* page, u64* out_short, u8* out_long)
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
    struct page* current_page;           // current page in callback
    struct page_metadata* current_meta;  // metadata for current page
    struct page_metadata* existing_meta; // metadata from hash_tree
    struct walk_ctx* ctx;                // context object
    struct merge_node* new_node;         // new mergeable object
    u64* out_short;                      // short hash output object
    u8* out_long;                        // long hash output object

    current_page = pte_page(*pte); // get the page from pte
    if (IS_ERR(current_page))
    {
        pr_err("FKSM_ERROR: pte_page lookup error");
    }

    if (PageAnon(current_page))
    {
        // compatible page type, hash it
        scanned += 1;

        out_short = kmalloc(sizeof(u64), GFP_KERNEL);
        out_long = kmalloc(BLAKE2B_512_HASH_SIZE, GFP_KERNEL);

        fksm_hash_page(current_page, out_short, out_long);

        current_meta = kmalloc(sizeof(struct page_metadata), GFP_KERNEL);

        // TODO: remove metadata wrapper around page*
        // this used to have more uses but we've refactored it
        current_meta->page = current_page;

        // hold local ref to hash tree (only needed on compatible)
        ctx = (struct walk_ctx*)walk->private;

        // add new_meta to hash_tree and check if return is not null
        existing_meta = hash_tree_get_or_create(ctx->hash_tree, *out_short,
                                                out_long, current_meta);

        // todo: remove unneccesary data in meta
        if (existing_meta != NULL && current_meta->page != existing_meta->page)
        {
            // we want to replace page but cannot do it yet because of traversal
            // allocate merge object and replace_page later
            new_node = kmalloc(sizeof(struct merge_node), GFP_KERNEL);
            new_node->vma = walk->vma;
            new_node->page = current_page;
            new_node->existing_page = existing_meta->page;
            new_node->pte = *pte;
            // add new_node as next element, update tail position
            ctx->merge_tail->next = new_node;
            ctx->merge_tail = new_node;

            // throw this out, it exists already
            kfree(current_meta);
        }

        // clean up for our allocated hash output objects
        kfree(out_short);
        kfree(out_long);
    }

    return 0;
}

static struct mm_walk_ops task_walk_ops = {.pte_entry = callback_pte_range};

static int scan(unsigned long pid, struct first_level_bucket* hash_tree)
{
    struct task_struct* task;
    struct walk_ctx* ctx;
    struct merge_node *prev_node, *curr_node, *head, *tail;
    int code;

    task = find_task_from_pid(pid); // get task struct
    BUG_ON(IS_ERR(task));

    head = kmalloc(sizeof(struct merge_node), GFP_KERNEL);
    tail = head;
    ctx = kmalloc(sizeof(struct walk_ctx), GFP_KERNEL);
    ctx->hash_tree = hash_tree;
    ctx->merge_tail = tail;

    pr_debug("FKSM: SCAN START");
    mmap_read_lock(task->active_mm);

    walk_page_range(task->active_mm, 0, TASK_SIZE, &task_walk_ops, ctx);
    curr_node = head->next;
    while (curr_node)
    {
        // pr_info("FKSM_REPLACE: %p | %p | %p | %lu", curr_node->vma,
        //         curr_node->page, curr_node->existing_page,
        //         curr_node->pte.pte);

        // replace_page and result prints
        code = replace_page(curr_node->vma, curr_node->page,
                            curr_node->existing_page, curr_node->pte);
        if (code == -EFAULT)
        {
            pr_err("FKSM_MERGE: REPLACE_PAGE FAIL");
            merge_fail += 1;
        }
        else
        {
            pr_debug("FKSM_MERGE: REPLACE_PAGE SUCCESS");
            merge_success += 1;
        }

        // cursor iteration
        if (curr_node->next != NULL)
        {
            prev_node = curr_node;
            curr_node = curr_node->next;
            kfree(prev_node);
        }
        else
        {
            kfree(curr_node);
            break;
        }
    }
    kfree(head);

    mmap_read_unlock(task->active_mm);
    pr_debug("FKSM: SCAN END");

    return 0; // returning int in case we want to add return flags
}

int sus_mod_merge(unsigned long pid1, unsigned long pid2)
{
    struct first_level_bucket* hash_tree;
    u64 start, end;

    hash_tree = first_level_init();
    scanned = 0;
    merge_success = 0;
    merge_fail = 0;

    start = sus_time_nanos();

    pr_debug("FKSM_MAIN: scan for pid %lu start", pid1);
    scan(pid1, hash_tree);
    pr_debug("FKSM_MAIN: scan for pid %lu start", pid2);
    scan(pid2, hash_tree);
    pr_debug("FKSM_MAIN: end");

    end = sus_time_nanos();
    pr_info("FKSM_TESTS: dt %llu scan %ld m_s %ld m_f %ld\n", (end-start),scanned, merge_success,
            merge_fail);

    hash_tree_destroy(hash_tree);
    pr_debug("FKSM_MAIN: hash_tree destroyed");

    return 0;
}
