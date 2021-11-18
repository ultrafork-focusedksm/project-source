#include "focused_ksm.h"
#include "sus.h"
#include <asm/types.h>
#include <crypto/internal/hash.h>
#include <crypto/sha3.h>
#include <linux/crypto.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/page-flags.h>
#include <linux/pagemap.h>
#include <linux/pagewalk.h>
#include <linux/pgtable.h>
#include <linux/types.h>
#include <linux/list.h>
#include <linux/rmap.h>
#include <linux/ksm.h>
#include <linux/mm_types.h>
#include <linux/mmu_notifier.h>
#include <stdbool.h>

static int callback_pte_range(pte_t* pte, unsigned long addr,
                              unsigned long next, struct mm_walk* walk)
{
    /*
     * we want to walk the full range so unless something catastrophic occurs we
     * return 0 from the callback to keep going. if something bad happens return
     * negative value. do not return a positive value
     */

    struct page* current_page = pte_page(*pte); // page from page table entry

    // TODO: find out if THP will be walked through or only pointed to the head
    // TODO: compound pages walking through tails too?
    if (PageAnon(current_page) || PageCompound(current_page) ||
        PageTransHuge(current_page))
    {
        struct crypto_shash* tfm; // hash transform object
        struct shash_desc* desc;
        struct metadata_collection* new_meta;

        tfm = crypto_alloc_shash("sha3-512", 0, 0); // init transform object
        if (IS_ERR(tfm))
        {
            pr_err("FKSM_ERROR: in callback, crypto tfm object identified as "
                   "error pointer");
        }
        desc = kmalloc(sizeof(*desc) + crypto_shash_descsize(tfm),
                       GFP_KERNEL); // init descriptor object
        if (IS_ERR(desc))
        {
            pr_err("FKSM_ERROR: in callback, crypto desc object identified as "
                   "error pointer");
        }
        desc->tfm = tfm; // set descriptor transform object for our hashing call

        new_meta = kmalloc(sizeof(struct metadata_collection), GFP_KERNEL);
        if (IS_ERR(new_meta))
        {
            pr_err("FKSM_ERROR: in callback, new_meta not allocated");
        }
        INIT_LIST_HEAD(&new_meta->list); // initialize list

        if (fksm_hash(desc, current_page, PAGE_SIZE, new_meta->checksum) != 0)
        {
            pr_err(
                "FKSM_ERROR: in callback, fksm_hash() helper returned error");
        }
        kfree(tfm);
        kfree(desc);

        new_meta->page_metadata.page = current_page; // set page_metadata
        new_meta->page_metadata.pte = pte;
        new_meta->page_metadata.mm = walk->mm;
        list_add(&new_meta->list, (struct list_head*)walk->private);
    }
    return 0;
}

static struct mm_walk_ops task_walk_ops = {.pte_entry = callback_pte_range};

static sus_metadata_collection_t traverse(unsigned long pid)
{
    struct task_struct* task = find_task_from_pid(pid); // get task struct

    sus_metadata_collection_t metadata_list;
    metadata_list = kmalloc(sizeof(metadata_list), GFP_KERNEL);

    if (IS_ERR(metadata_list))
    {
        pr_err("FKSM_ERROR: metadata_list not allocated");
    }
    INIT_LIST_HEAD(metadata_list); // initialize list

    mmap_read_lock(task->active_mm);
    walk_page_range(task->active_mm, 0, TASK_SIZE, &task_walk_ops,
                    &metadata_list);
    mmap_read_unlock(task->active_mm);

    return metadata_list;
}

static void combine(sus_metadata_collection_t list1,
                    sus_metadata_collection_t list2)
{

    struct metadata_collection* curr_list1;
    struct metadata_collection* curr_list2;

    list_for_each_entry(curr_list1, list1, list)
    {
        list_for_each_entry(curr_list2, list2, list)
        {
            if (memcmp(curr_list1->checksum, curr_list2->checksum, sizeof(curr_list1->checksum))) {
                struct page *curr_page1 = curr_list1->page_metadata.page;
                struct page *curr_page2 = curr_list2->page_metadata.page;

                void* addr = kmap_atomic(curr_page1);
                struct vm_area_struct *curr_vma = find_vma(curr_list1->page_metadata.mm, (unsigned long int) addr);
                replace_page(curr_vma, curr_page1, curr_page2, *(curr_list1->page_metadata.pte));
                kunmap_atomic(addr);

            }
        }
    }
    kfree(list1);
    kfree(list2);
}

int sus_mod_merge(unsigned long pid1, unsigned long pid2)
{
    sus_metadata_collection_t list1 = traverse(pid1);
    sus_metadata_collection_t list2 = traverse(pid2);
    combine(list1, list2);
    return -EINVAL;
}
