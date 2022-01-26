#include <stdlib.h>
#include <linux/rbtree.h>
//#include <crypto/internal/hash.h>
//#include <crypto/blake2b.h>
//#include <crypto/sha3.h>

struct first_level_bucket {
    int byte;
    struct second_level_container* ptr;
};

struct second_level_container {
    struct second_level_bucket* buckets; //TODO: Ask if this is legal
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

void hash_tree_add(struct first_level_bucket* map, int xxHash, int blake2b);

int hash_tree_lookup(struct first_level_bucket* map, int xxHash, int blake2b);

struct red_black_node rb_search(struct rb_root *root, int value);

int red_black_insert(struct rb_root *root, struct red_black_node* node_to_add);