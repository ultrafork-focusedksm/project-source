#ifndef _FOCUSED_KSM_H
#define _FOCUSED_KSM_H

#include <asm/types.h>
#include <crypto/internal/hash.h>
#include <crypto/sha3.h>
#include <linux/pgtable.h>
#include <linux/types.h>

typedef struct list_head* sus_metadata_collection_t;

struct page_metadata
{
    struct page* page;
    pte_t* pte;
    struct mm_struct* mm;
};

struct metadata_collection
{
    struct page_metadata* page_metadata;
    struct list_head* list;
    u8 checksum[SHA3_512_DIGEST_SIZE];
};

int sus_mod_merge(unsigned long pid1, unsigned long pid2);
#endif
