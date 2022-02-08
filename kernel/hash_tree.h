#include "focused_ksm.h"
#include <linux/types.h>
#include <linux/rbtree.h>
#include <crypto/internal/hash.h>
#include <crypto/blake2b.h>
#include <linux/xxhash.h>

struct first_level_bucket {
    u64 byte;
    struct second_level_container* ptr;
};

struct second_level_container {
    struct second_level_bucket* buckets;
    struct second_level_container* next;
    struct second_level_container* prev;
};

struct second_level_bucket {
    u64 value;
    struct rb_root tree;
};

struct hash_tree_node {
    struct rb_node node;
    u8* value;
    struct page_metadata* metadata;
};

struct first_level_bucket* first_level_init(void);
struct second_level_container* second_level_init(second_level_container* previous);

int hash_tree_add(struct first_level_bucket* map, u64 xxhash, u8* blake2b, struct page_metadata* metadata);
struct page_metadata* hash_tree_lookup(struct first_level_bucket* map, u64 xxhash, u8* blake2b);
int hash_tree_delete(struct first_level_bucket* map, u64 xxhash, u8* blake2b);

struct hash_tree_node* rb_search(struct rb_root *root, u8* blake2b);
int rb_insert(struct rb_root *root, struct hash_tree_node* node_to_add);

int sus_mod_htree(int flags);
