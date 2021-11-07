#ifndef _FOCUSED_KSM_H
#define _FOCUSED_KSM_H

#include <crypto/sha3.h>
#include <linux/list.h>

typedef struct list_head* sus_metadata_collection_t;

struct metadata_collection
{
<<<<<<< HEAD
=======
    u8 checksum[SHA3_512_DIGEST_SIZE];
>>>>>>> b2ec342 (hashing using address from kmap_atomic)
    struct page* page;
    struct list_head list;
    u8 checksum[SHA3_512_DIGEST_SIZE];
};

int sus_mod_merge(unsigned long pid1, unsigned long pid2);
#endif
