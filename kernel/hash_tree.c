#include "hash_tree.h"
#include <linux/types.h>
#include <linux/kernel.h>

/**
 * @brief Allocates space for a 256 element array of first_level_buckets
 * 
 * @return struct first_level_bucket* Pointer to the beginning of the array
 */
struct first_level_bucket* first_level_init(void) {
    struct first_level_bucket* new_hash_tree = kzalloc(256 * sizeof(struct first_level_bucket), GFP_KERNEL); //Allocate 256 element tree
    return new_hash_tree;
}

/**
 * @brief Creates and initializes a second_level_container, which contains a chunk of 32 second_level_buckets
 * 
 * @return struct second_level_container* The new container
 */
struct second_level_container* second_level_init(void) {
    struct second_level_container* new_container = kmalloc(sizeof (struct second_level_container), GFP_KERNEL); //Allocate second level container
    new_container->buckets = kzalloc(32 * sizeof(struct second_level_bucket), GFP_KERNEL); //Each container gets a 32-array of buckets
    int i = 0;
    for (i; i < 32; i++) {
        new_container->buckets[i].value = NULL;
        new_container->buckets[i].tree = RB_ROOT;
    }
    new_container->next = NULL; //Pointer to next container starts as null since there is no next container
    return new_container;
}

/**
 * @brief Adds a page to a given hash tree based on its xxhash and blake2b hash values
 * 
 * 
 * @param tree The tree the element to
 * @param xxhash The xxhash value of the page
 * @param blake2b The blake2b value of the page
 */
int hash_tree_add(struct first_level_bucket* tree, u8* xxhash, u8* blake2b) {
    //====FIRST LEVEL HASH====//
    u8 first_byte = *xxhash; //Get the first byte of the xxhash

    tree[first_byte].byte = first_byte; //Just put the first byte in the first level array 
    if (tree[first_byte].ptr == NULL) { //If the container in that slot isn't defined, define it
        tree[first_byte].ptr = second_level_init();
    }

    //====SECOND LEVEL HASH====//
    struct second_level_container* curr_container = tree[first_byte].ptr; //Get the first container from the current bucket on the tree
    bool add_success = false;
    while (add_success == false) { // We're going to keep going through each container in sequence and see if xxHash value is present
        int i = 0;
        for (i; i < 32; i++) {
            if (memcmp(curr_container->buckets[i].value, xxhash) == 0) {
                struct red_black_node* new_node = kmalloc(sizeof(struct red_black_node), GFP_KERNEL);
                new_node->value = *blake2b;
                if (rb_insert(&curr_container->buckets[i].tree, new_node) != 0) {
                    pr_err("FKSM_ERROR: failed to add node to red-black tree");
                    return 1;
                }
                else add_success = true;
            }
            else if (curr_container->buckets[i].value == NULL) {
                curr_container->buckets[i].value = *xxhash;
                struct red_black_node* new_node = kmalloc(sizeof(struct red_black_node), GFP_KERNEL);
                new_node->value = *blake2b;
                if (rb_insert(&curr_container->buckets[i].tree, new_node)!= 0) {
                    pr_err("FKSM_ERROR: failed to add node to red-black tree");
                    return 1;
                }
                else add_success = true;
            }
        }
        if (add_success == false) { //if we go through all 32 buckets and still don't successfully add the new item, go to the next container
            if (curr_container->next == NULL) {
                curr_container->next = second_level_init();
            }
            else curr_container = curr_container->next;
        }
    }
    return 0; //If we get here, that means we successfully added the new value
}

int rb_insert(struct rb_root *root, struct red_black_node* node_to_add) {


    return 0;
}