#include <stdlib.h>
#include <linux/types.h>
#include <linux/rbtree.h>
#include <crypto/internal/hash.h>
#include <crypto/blake2b.h>
#include <linux/xxhash.h>

struct first_level_bucket {
    u8 byte;
    struct second_level_container* ptr;
};

struct second_level_container {
    struct second_level_bucket* buckets;
    struct second_level_container* next;
};

struct second_level_bucket {
    int value;
    struct rb_root tree;
};

struct red_black_node {
    struct rb_node next_node;
    int value;
};

struct first_level_bucket* hash_tree_init();

void hash_tree_add(struct first_level_bucket* map, u8* xxhash, u8* blake2b);

int hash_tree_lookup(struct first_level_bucket* map, u8* xxhash, u8** blake2b);

struct red_black_node rb_search(struct rb_root *root, int value);

int rb_insert(struct rb_root *root, struct red_black_node* node_to_add);