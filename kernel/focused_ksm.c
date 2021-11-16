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
#include <linux/list.h>
#include <linux/rmap.h>

static int replace_page(struct vm_area_struct *vma, struct page *page,
                        struct page *kpage, pte_t orig_pte)
{
    struct mm_struct *mm = vma->vm_mm;
    pmd_t *pmd;
    pte_t *ptep;
    pte_t newpte;
    spinlock_t *ptl;
    unsigned long addr;
    int err = -EFAULT;
    struct mmu_notifier_range range;

    addr = page_address_in_vma(page, vma);
    if (addr == -EFAULT)
        goto out;

    pmd = mm_find_pmd(mm, addr);
    if (!pmd)
        goto out;

    mmu_notifier_range_init(&range, MMU_NOTIFY_CLEAR, 0, vma, mm, addr,
                            addr + PAGE_SIZE);
    mmu_notifier_invalidate_range_start(&range);

    ptep = pte_offset_map_lock(mm, pmd, addr, &ptl);
    if (!pte_same(*ptep, orig_pte)) {
        pte_unmap_unlock(ptep, ptl);
        goto out_mn;
    }

    /*
     * No need to check ksm_use_zero_pages here: we can only have a
     * zero_page here if ksm_use_zero_pages was enabled already.
     */
    if (!is_zero_pfn(page_to_pfn(kpage))) {
        get_page(kpage);
        page_add_anon_rmap(kpage, vma, addr, false);
        newpte = mk_pte(kpage, vma->vm_page_prot);
    } else {
        newpte = pte_mkspecial(pfn_pte(page_to_pfn(kpage),
                                       vma->vm_page_prot));
        /*
         * We're replacing an anonymous page with a zero page, which is
         * not anonymous. We need to do proper accounting otherwise we
         * will get wrong values in /proc, and a BUG message in dmesg
         * when tearing down the mm.
         */
        dec_mm_counter(mm, MM_ANONPAGES);
    }

    flush_cache_page(vma, addr, pte_pfn(*ptep));
    /*
     * No need to notify as we are replacing a read only page with another
     * read only page with the same content.
     *
     * See Documentation/vm/mmu_notifier.rst
     */
    ptep_clear_flush(vma, addr, ptep);
    set_pte_at_notify(mm, addr, ptep, newpte);

    page_remove_rmap(page, false);
    if (!page_mapped(page))
        try_to_free_swap(page);
    put_page(page);

    pte_unmap_unlock(ptep, ptl);
    err = 0;
    out_mn:
    mmu_notifier_invalidate_range_end(&range);
    out:
    return err;
}

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
    // TODO: tag to identify which part of union. check documentation
    // TODO: restructure metadata_collection to have an internal struct that contains page*, pte_t*, and mm_struct*. checksum still part of the node
    // probably a macro to query page type. sched.h or mm_types
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
        //kmap atomic critical section, accessing page transparently? Need to verify
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
    //TODO: Use list_for_each_entry
    sus_metadata_collection_t* curr_list1;
    sus_metadata_collection_t* curr_list2;

    list_for_each_entry(curr_list1, &list1, list)
    {
        list_for_each_entry(curr_list2, &list2, list)
        {
            if (curr_list1->checksum == curr_list2->checksum) {
                struct page *curr_page1 = curr_list1->page;
                struct page *curr_page2 = curr_list2->page;
                vm_area_struct *curr_vma = find_vma(curr_page1->virtual, mm);

                //TODO: need a custom struct so we can have pte and mm_struct
                replace_page(curr_vma, curr_page1, curr_page2, orig_pte);
            }

        }

    }
    //TODO: free metadata_collections
    kfree(list1);
    kfree(list2);

    return;
}

int sus_mod_merge(unsigned long pid1, unsigned long pid2)
{
    sus_metadata_collection_t list1 = traverse(pid1);
    sus_metadata_collection_t list2 = traverse(pid2);
    combine(list1, list2);
    return -EINVAL;
}
