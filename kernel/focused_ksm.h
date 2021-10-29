#ifndef _FOCUSED_KSM_H
#define _FOCUSED_KSM_H

#define SHA3_512_LEN (512 / 8)

#include <linux/list.h>

typedef struct list_head* sus_metadata_collection_t;

struct metadata_collection
{
    u8 checksum[SHA3_512_LEN];
    struct page* page;
};

int sus_mod_merge(unsigned long pid1, unsigned long pid2);
#endif
