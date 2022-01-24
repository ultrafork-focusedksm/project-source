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
#include <linux/types.h>
#include <stdbool.h>

void kprint_bytes(u8* input, size_t size)
{
    size_t i;
    for (i = 0; i < size; i++)
    {
        printk(KERN_INFO "%02X", input[i]);
    }
    printk(KERN_INFO "\n");
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
    pr_info("FKSM_INFO: HASH FUNCTION MAP ATOMIC");
    void* addr = kmap_atomic(page); // address to page
    if (IS_ERR(addr))
    {
        kunmap_atomic(addr);
        pr_err("FKSM_ERROR: in fksm_hash() helper, kmap_atomic returned error "
               "pointer");
        return -1;
    }
    pr_info("FKSM_INFO: HASHING");

    // kmap atomic critical section, accessing page transparently? Need to
    // verify ignore huge pages
    err = crypto_shash_digest(desc, addr, len, out);
    pr_info("FKSM_INFO: HASHED");

    kunmap_atomic(addr);
    pr_info("FKSM_INFO: HASH END UNMAP ATOMIC");

    if (err)
    {
        pr_err("FKSM_ERROR: in fksm_hash() helper, digest function returned "
               "error");
        return err;
    }
    kprint_bytes(out, BLAKE2B_512_HASH_SIZE);
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

    struct page* current_page = pte_page(*pte); // page from page table entry
    if (IS_ERR(current_page))
    {
        pr_err(
            "FKSM_ERROR: in callback, pte_page lookup returned error pointer");
    }
    pr_info("FKSM_INFO: page* %p", current_page);
    pr_info("FKSM_INFO: page flags %ld", current_page->flags);
    pr_info("FKSM_INFO: pre-page check");

    // TODO: find out if THP will be walked through or only pointed to the head
    // TODO: compound pages walking through tails too?
    if (PageAnon(current_page) || PageCompound(current_page) ||
        PageTransHuge(current_page))
    {
        pr_info("FKSM_INFO: POST-PAGE CHECK");

        struct crypto_shash* tfm; // hash transform object
        struct shash_desc* desc;
        struct metadata_collection* new_meta;


        tfm = crypto_alloc_shash("blake2b-512", 0, 0); // init transform object
        if (IS_ERR(tfm))
        {
            pr_err("FKSM_ERROR: in callback, crypto tfm object identified as "
                   "error pointer");
        }
        pr_info("FKSM_INFO: TFM OBJECT MADE");

        desc = kmalloc(sizeof(*desc) + crypto_shash_descsize(tfm),
                       GFP_KERNEL); // init descriptor object
        if (IS_ERR(desc))
        {
            pr_err("FKSM_ERROR: in callback, crypto desc object identified as "
                   "error pointer");
        }
        pr_info("FKSM_INFO: DESC OBJECT MADE");

        desc->tfm = tfm; // set descriptor transform object for our hashing call

        pr_info("FKSM_INFO: DESC TFM SET");

        new_meta = kmalloc(sizeof(struct metadata_collection), GFP_KERNEL);
        if (IS_ERR(new_meta))
        {
            pr_err("FKSM_ERROR: in callback, new_meta not allocated");
        }
        pr_info("FKSM_INFO: PRE-LIST INIT");
        INIT_LIST_HEAD(&new_meta->list); // initialize list
        pr_info("FKSM_INFO: POST-LIST INIT");

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
            if (memcmp(curr_list1->checksum, curr_list2->checksum,
                       BLAKE2B_512_HASH_SIZE) == 0)
            {
                struct page* curr_page1 = curr_list1->page_metadata.page;
                struct page* curr_page2 = curr_list2->page_metadata.page;

                void* addr = kmap_atomic(curr_page1);
                if (IS_ERR(addr))
                {
                    kunmap_atomic(addr);
                    pr_err(
                        "FKSM_ERROR: In combine(), kmap_atomic returned error");
                    return;
                }
                struct vm_area_struct* curr_vma = find_vma(
                    curr_list1->page_metadata.mm, (unsigned long int)addr);
                replace_page(curr_vma, curr_page1, curr_page2,
                             *(curr_list1->page_metadata.pte));
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
