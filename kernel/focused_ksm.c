#include "focused_ksm.h"
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

//Helper to print bytes during debugging of hashing functions
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

static int fksm_hash(struct shash_desc* desc, struct page* page,
                     unsigned int len, u8* out)
{
    int err;
    u8* addr;

    addr = kmap_atomic(page); // address to page
    if (IS_ERR(addr))
    {
        pr_err("FKSM_ERROR: in fksm_hash() helper, kmap_atomic returned error "
               "pointer");
        return -1;
    }

    err = crypto_shash_digest(desc, addr, len, out);
    kunmap_atomic(addr);

    if (err)
    {
        pr_err("FKSM_ERROR: in fksm_hash() helper, digest function returned "
               "error");
        return err;
    }
    return 0;
}

static int callback_pte_range(pte_t* pte, unsigned long addr,
                              unsigned long next, struct mm_walk* walk)
{
    /*
     * we want to walk the full range so unless something catastrophic occurs we
     * return 0 from the callback to keep going. if something bad happens return
     * negative value. do not return a positive value
     */

    struct metadata_collection* main_list;
    struct page* current_page;
    struct crypto_shash* tfm; // hash transform object
    struct shash_desc* desc;
    struct metadata_collection* new_meta;

    current_page = pte_page(*pte); // page from page table entry
    if (IS_ERR(current_page))
    {
        pr_err(
            "FKSM_ERROR: in callback, pte_page lookup returned error pointer");
    }

    // TODO: find out if THP will be walked through or only pointed to the head
    // TODO: compound pages walking through tails too? Locking the group?
    if (PageAnon(current_page) || PageCompound(current_page) ||
        PageTransHuge(current_page))
    {

        tfm = crypto_alloc_shash("blake2b-512", 0, 0); // init transform object
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
        new_meta->page_metadata.vma = walk->vma;
        new_meta->page_metadata.mm = walk->mm;
        main_list = (struct metadata_collection*)walk->private;
        list_add(&new_meta->list, &main_list->list);
    }
    return 0;
}

static struct mm_walk_ops task_walk_ops = {.pte_entry = callback_pte_range};

static struct metadata_collection* traverse(unsigned long pid)
{
    struct task_struct* task;
    struct metadata_collection* metadata_list;

    task = find_task_from_pid(pid); // get task struct
    pr_info("FKSM: FIND TASK FOR %lu", pid);

    if (IS_ERR(task))
    {
        pr_err("FKSM_ERROR: task struct not found");
    }

    metadata_list = kmalloc(sizeof(struct metadata_collection), GFP_KERNEL);

    if (IS_ERR(metadata_list))
    {
        pr_err("FKSM_ERROR: metadata_list not allocated");
    }
    INIT_LIST_HEAD(&metadata_list->list); // initialize list
    metadata_list->first = true;

    pr_info("FKSM: READ LOCK FOR TRAVERSE");
    mmap_read_lock(task->active_mm);

    pr_info("FKSM: WALK START");
    walk_page_range(task->active_mm, 0, TASK_SIZE, &task_walk_ops,
                    metadata_list);

    pr_info("FKSM: WALK END, UNLOCKING");
    mmap_read_unlock(task->active_mm);

    return metadata_list;
}

/*
static struct metadata_collection* traverse2(unsigned long pid)
{
    // crypto objects
    struct crypto_shash* tfm; // crypto transform object
    struct shash_desc* desc;  // crypto hash desc object

    // pid memory objects
    struct task_struct* task;   // task struct for pid
    struct mm_struct* mm;       // mm of task
    struct vm_area_struct* vma; // pointer to a vma in mm
    unsigned long address;      // virtual address cursor within vma bounds
    struct page* page;          // page struct for address

    // fksm objects
    struct metadata_collection* metadata_list; // main return object
    struct metadata_collection* new_meta;      // new list element pointer

    // page table lookup variables
    pgd_t* pgd;
    pmd_t* pmd;
    pte_t *ptep;

    metadata_list = kmalloc(sizeof(struct metadata_collection), GFP_KERNEL);

    INIT_LIST_HEAD(&metadata_list->list); // initialize list
    metadata_list->first = true;

    tfm = crypto_alloc_shash("blake2b-512", 0, 0); // init transform object
    if (IS_ERR(tfm))
    {
        pr_err("FKSM_ERROR: in callback, crypto tfm object identified as "
               "error pointer");
        goto traverse_exit;
    }

    desc = kmalloc(sizeof(*desc) + crypto_shash_descsize(tfm),
                   GFP_KERNEL); // init descriptor object
    if (IS_ERR(desc))
    {
        pr_err("FKSM_ERROR: in callback, crypto desc object identified as "
               "error pointer");
        goto traverse_exit;
    }

    desc->tfm = tfm; // set descriptor transform object for our hashing call

    task = find_task_from_pid(pid); // get task struct
    if (IS_ERR(task))
    {
        pr_err("FKSM_ERROR: task struct not found");
        goto traverse_exit;
    }

    mm = get_task_mm(task);
    if (IS_ERR(mm))
    {
        pr_err("FKSM_ERROR: mm struct not found for task");
    }

    address = 0;
    mmap_read_lock(mm);
    for (vma = mm->mmap; NULL != vma; vma = vma->vm_next)
    {
        // for each VMA in our task mm
        if (address < vma->vm_start)
            address = vma->vm_start; // move virtual address to start of vma
        if (!vma->anon_vma)
            address = vma->vm_end; // skip to end if anon_vma is null
        while (address < vma->vm_end)
        {
            // grab the page pointer for this virtual address in vma
            page = follow_page(
                vma, address,
                FOLL_GET); // fix: FOLL_PIN since we want to access memory
            if (IS_ERR_OR_NULL(page))
            {
                // page pointer is bogus, skip
                address += PAGE_SIZE;
                continue;
            }
            if (PageAnon(page))
            {
                // we have an anonymous page
                // todo: compatibility with other types

                new_meta = kmalloc(sizeof(struct metadata_collection),
                                   GFP_KERNEL); // new list item
                if (IS_ERR(new_meta))
                {
                    pr_err("FKSM_ERROR: in callback, new_meta not
                    allocated");
                }
                INIT_LIST_HEAD(&new_meta->list); // initialize list

                if (fksm_hash(desc, page, PAGE_SIZE, new_meta->checksum) !=
                0)
                {
                    pr_err("FKSM_ERROR: in callback, fksm_hash() helper "
                           "returned error");
                }

                //TODO: is there a macro for this?

                new_meta->page_metadata.page = page; // set page_metadata

                //THIS IS WHY I DID NOT CONTINUE HERE, how to get PTE
                //new_meta->page_metadata.pte = ;
                new_meta->page_metadata.mm = mm;
                new_meta->page_metadata.vma = vma;

                list_add(&new_meta->list, &metadata_list->list);
            }
            // put_page(*page);      // todo: what is this for?
            address += PAGE_SIZE; // jump to next address
        }
    }
    // clean up objects before return (avoid memory leaks)
traverse_exit:
    mmap_read_unlock(mm);
    kfree(tfm);
    kfree(desc);

    return metadata_list;
}
*/

static void combine(struct metadata_collection* list1,
                    struct metadata_collection* list2, unsigned long pid1)
{
    struct metadata_collection *curr_list1, *curr_list2, *entry;
    struct list_head q;
    struct page *curr_page1, *curr_page2;
    int code; // replace page output code
    int count;

    struct task_struct* task;

    task = find_task_from_pid(pid1); // get task struct
    if (IS_ERR(task))
    {
        pr_err("FKSM_ERROR: task struct not found");
    }

    count = 0;
    list_for_each_entry(curr_list1, &list1->list, list)
    {
        if (curr_list1->first)
            continue;

        list_for_each_entry(curr_list2, &list2->list, list)
        {
            if (curr_list2->merged || curr_list2->first)
                continue;

            if ((curr_list1->page_metadata.page !=
                 curr_list2->page_metadata.page) &&
                memcmp(curr_list1->checksum, curr_list2->checksum,
                       BLAKE2B_512_HASH_SIZE) == 0)
            {
                curr_page1 = curr_list1->page_metadata.page;
                curr_page2 = curr_list2->page_metadata.page;

                // todo: test this with swapped order in signature
                // todo: make sure we've got the right pte in this signature
                // todo: describe how signature works in the report?
                code =
                    replace_page(curr_list2->page_metadata.vma, curr_page2,
                                 curr_page1, *(curr_list2->page_metadata.pte));

                if (code == -EFAULT)
                {
                    pr_err("FKSM_MERGE: REPLACE_PAGE FAIL");
                }
                else
                {
                    pr_info("FKSM_MERGE: REPLACE_PAGE SUCCESS");
                    curr_list2->merged = true;
                    count++;
                }
            }
        }
    }
    pr_info("%d", count);

    // todo: there is a memory leak with the lists, free them properly
    // i could not get this code working before the hash tree was ready
    // switching to developing hash tree functionality

    /*
    list_for_each_safe(&(entry->list), q, &(list1->list))
    {
        list_del(&(entry->list));
        kfree(&(entry->page_metadata));
        kfree(entry);
    }
    list_del(&(list1->list));
    kfree(list1);
    */

}

int sus_mod_merge(unsigned long pid1, unsigned long pid2)
{
    struct metadata_collection *list1, *list2;

    pr_info("FKSM: TRAVERSE1 START");
    list1 = traverse(pid1);
    pr_info("FKSM: TRAVERSE1 END, TRAVERSE2 START");
    list2 = traverse(pid2);
    pr_info("FKSM: TRAVERSE2 END, TRAVERSE COMPLETE, MERGE START");
    combine(list1, list2, pid1);
    pr_info("FKSM: MERGE END");
    return 0;
}
