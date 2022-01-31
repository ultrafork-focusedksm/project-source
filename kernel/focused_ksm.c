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
#include <linux/list.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/page-flags.h>
#include <linux/pagemap.h>
#include <linux/pagewalk.h>
#include <linux/pgtable.h>
#include <linux/types.h>

void kprint_bytes(u8* input, size_t size)
{
    size_t i;
    size_t j;
    for (i = 0; i < size; i=i+32)
    {
        for (j=0;j<32;j++){
            pr_cont(KERN_DEBUG "%02X", input[i+j]);
        }
        pr_cont(KERN_DEBUG "\n");
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
    pr_info("FKSM_INFO: HASH FUNCTION MAP ATOMIC");
    u8* addr = kmap_atomic(page); // address to page
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
    pr_debug("START_PRINT_ADDR\n");
    // if (addr[0]==0xAA){
    //     kprint_bytes(addr, 4096);
    // }
    pr_debug("END_PRINT_ADDR\n");

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
    pr_debug("PRINT_HASH\n");
    // kprint_bytes(out, BLAKE2B_512_HASH_SIZE);
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
    pr_info("FKSM: page* %p", current_page);
    pr_info("FKSM: page flags %ld", current_page->flags);
    pr_info("FKSM: pre-page check");

    // TODO: find out if THP will be walked through or only pointed to the head
    // TODO: compound pages walking through tails too?
    if (PageAnon(current_page) || PageCompound(current_page) ||
        PageTransHuge(current_page))
    {
        pr_info("FKSM: POST-PAGE CHECK");

        struct crypto_shash* tfm; // hash transform object
        struct shash_desc* desc;
        struct metadata_collection* new_meta;


        tfm = crypto_alloc_shash("blake2b-512", 0, 0); // init transform object
        if (IS_ERR(tfm))
        {
            pr_err("FKSM_ERROR: in callback, crypto tfm object identified as "
                   "error pointer");
        }
        pr_info("FKSM: TFM OBJECT MADE");

        desc = kmalloc(sizeof(*desc) + crypto_shash_descsize(tfm),
                       GFP_KERNEL); // init descriptor object
        if (IS_ERR(desc))
        {
            pr_err("FKSM_ERROR: in callback, crypto desc object identified as "
                   "error pointer");
        }
        pr_info("FKSM: DESC OBJECT MADE");

        desc->tfm = tfm; // set descriptor transform object for our hashing call

        pr_info("FKSM: DESC TFM SET");

        new_meta = kmalloc(sizeof(struct metadata_collection), GFP_KERNEL);
        if (IS_ERR(new_meta))
        {
            pr_err("FKSM_ERROR: in callback, new_meta not allocated");
        }
        pr_info("FKSM: PRE-LIST INIT");
        INIT_LIST_HEAD(&new_meta->list); // initialize list
        pr_info("FKSM: POST-LIST INIT");

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
    pr_info("FKSM: FIND TASK");
    struct task_struct* task = find_task_from_pid(pid); // get task struct
    if (IS_ERR(task))
    {
        pr_err("FKSM_ERROR: task struct not found");
    }

    pr_info("FKSM: ALLOC STRUCTURE");
    sus_metadata_collection_t metadata_list;
    metadata_list = kmalloc(sizeof(metadata_list), GFP_KERNEL);

    if (IS_ERR(metadata_list))
    {
        pr_err("FKSM_ERROR: metadata_list not allocated");
    }
    pr_info("FKSM: INIT META LIST");
    INIT_LIST_HEAD(metadata_list); // initialize list

    pr_info("FKSM: READ LOCK FOR TRAVERSE");
    mmap_read_lock(task->active_mm);
    walk_page_range(task->active_mm, 0, TASK_SIZE, &task_walk_ops,
                    &metadata_list);
    mmap_read_unlock(task->active_mm);

    return metadata_list;
}

static void combine(sus_metadata_collection_t list1,
                    sus_metadata_collection_t list2)
{
    return;
}

int sus_mod_merge(unsigned long pid1, unsigned long pid2)
{
    pr_info("FKSM: TRAVERSE1 START");
    sus_metadata_collection_t list1 = traverse(pid1);
    pr_info("FKSM: TRAVERSE1 END, TRAVERSE2 START");
    sus_metadata_collection_t list2 = traverse(pid2);
    pr_info("FKSM: TRAVERSE2 END, TRAVERSE COMPLETE, MERGE START");
    combine(list1, list2);
    pr_info("FKSM: MERGE END");
    return -EINVAL;
}
