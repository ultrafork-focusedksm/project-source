#include "focused_ksm.h"
#include "sus.h"
#include <crypto/internal/hash.h>
#include <crypto/sha3.h>
#include <linux/crypto.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/pagemap.h>
#include <linux/pagewalk.h>
#include <linux/pgtable.h>

static struct task_struct* find_task_from_pid(unsigned long pid)
{
    struct pid* pid_struct = find_get_pid(pid);
    return get_pid_task(pid_struct, PIDTYPE_PID);
}

static int callback_pte_range(pte_t* pte, unsigned long addr,
                              unsigned long next, struct mm_walk* walk)
{
    struct page* current_page = pte_page(*pte); // page from page table entry

    // TODO: check page flags
    if (true)
    {
        struct crypto_shash* tfm; // hash transform object
        struct shash_desc* desc;

        // TODO: error check tfm
        tfm = crypto_alloc_shash("sha3-512", 0, 0); // init transform object
        desc = kmalloc(sizeof(*desc) + crypto_shash_descsize(tfm),
                       GFP_KERNEL); // init descriptor object
        desc->tfm = tfm; // set descriptor transform object for our hashing call

        struct metadata_collection* new_meta =
            kmalloc(sizeof(*new_meta), GFP_KERNEL);

        new_meta->page = current_page;

        void* addr = kmap_atomic(page); // address to page
        //ignore huge pages
        crypto_shash_digest(desc, addr, PAGE_SIZE, new_meta->checksum);
        kunmap_atomic(addr);

        // access metadata_list pointer via walk->private
        // https://stackoverflow.com/questions/33933344/adding-items-to-a-linux-kernel-linked-list
        // check robert love book for list API
        list_add(&new_meta->list, walk->private);
        kfree(tfm);
        kfree(desc);
        return 0; // TODO: add proper return
    }
    return -1;
}

static struct mm_walk_ops task_walk_ops = {.pte_entry = callback_pte_range};

static sus_metadata_collection_t traverse(unsigned long pid)
{
    struct task_struct* task = find_task_from_pid(pid); // get task struct

    sus_metadata_collection_t metadata_list =
        kmalloc(sizeof(metadata_list), GFP_KERNEL); // output list
    LIST_HEAD(metadata_list);                       // initialize list
    
    // TODO: hold @mm->mmap_lock?
    walk_page_range(task->mm, 0, TASK_SIZE, &task_walk_ops, &metadata_list);

    return metadata_list;
}

static void combine(sus_metadata_collection_t list1,
                    sus_metadata_collection_t list2)
{
    return;
}

int sus_mod_merge(unsigned long pid1, unsigned long pid2)
{
    sus_metadata_collection_t list1 = traverse(pid1);
    sus_metadata_collection_t list2 = traverse(pid2);
    combine(list1, list2);
    return -EINVAL;
}
