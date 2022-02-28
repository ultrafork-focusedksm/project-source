#include "focused_ksm.h"
#include <linux/types.h>
#include <linux/rbtree.h>
#include <crypto/internal/hash.h>
#include <crypto/blake2b.h>
#include <linux/xxhash.h>
#define CONTAINER_SIZE 32
#define FIRST_LEVEL_SIZE 256

struct first_level_bucket {
    struct second_level_container* ptr;
    u8 byte;
};

struct second_level_container {
    struct second_level_bucket* buckets;
    struct second_level_container* next;
    struct second_level_container* prev;
    int counter;
};

struct second_level_bucket {
    u64 xxhash;
    bool in_use;
    struct rb_root tree;
};

struct hash_tree_node {
    struct rb_node node;
    struct page_metadata* metadata;
    u8 value[BLAKE2B_512_HASH_SIZE];
};

struct first_level_bucket* first_level_init(void);

int hash_tree_add(struct first_level_bucket* map, u64 xxhash, u8* blake2b, struct page_metadata* metadata);
struct page_metadata* hash_tree_lookup(struct first_level_bucket* map, u64 xxhash, u8* blake2b);
struct page_metadata* hash_tree_get_or_create(struct first_level_bucket* map, u64 xxhash, u8* blake2b, struct page_metadata* metadata);
int hash_tree_delete(struct first_level_bucket* map, u64 xxhash, u8* blake2b);
int hash_tree_destroy(struct first_level_bucket* map);

int sus_mod_htree(int flags);
