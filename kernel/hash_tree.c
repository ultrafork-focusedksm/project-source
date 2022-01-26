#include "hash_tree.h"
#include <stdlib.h>

struct first_level_bucket* first_level_init() {
    struct first_level_bucket* new_hash_tree = kmalloc(256 * sizeof(struct first_level_bucket));

    for (int i = 0; i < 256; i++) {
        new_hash_tree[i].ptr = second_level_init();
    }

    return new_hash_tree;
}

struct second_level_container* second_level_init() {
    struct second_level_container* new_container = kmalloc(sizeof (struct second_level_container));
    new_container->buckets = kmalloc(32 * sizeof(struct second_level_bucket));
    new_container->next = NULL;
}

