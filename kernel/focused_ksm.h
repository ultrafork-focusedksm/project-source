#ifndef _FOCUSED_KSM_H
#define _FOCUSED_KSM_H

#include <asm/types.h>
#include <crypto/blake2b.h>
#include <crypto/internal/hash.h>
#include <linux/pgtable.h>
#include <linux/types.h>

typedef struct list_head* sus_metadata_collection_t;
struct page_metadata
{
    struct page* page;
};

struct metadata_collection
{
    struct list_head list;
    struct page_metadata page_metadata;
    u8 checksum[BLAKE2B_512_HASH_SIZE];
    bool first;
    bool merged;
};

struct merge_node
{
    struct vm_area_struct* vma;
    struct page* page;
    struct page* existing_page;
    pte_t pte;
    struct merge_node* next; // next element as list
};

struct walk_ctx
{
    struct first_level_bucket* hash_tree;
    struct merge_node* merge_tail;
};

int sus_mod_merge(pid_t pid1, pid_t pid2);

#endif
