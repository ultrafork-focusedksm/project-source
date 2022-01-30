#include "hash_tree.h"
#include <stdlib.h>
#include <linux/types.h>
#include <linux/kernel.h>

/**
 * @brief Allocates space for a 256 element array of first_level_buckets
 * 
 * @return struct first_level_bucket* Pointer to the beginning of the array
 */
struct first_level_bucket* first_level_init() {
    struct first_level_bucket* new_hash_tree = kzalloc(256 * sizeof(struct first_level_bucket), GFP_KERNEL); //Allocate 256 element tree
    return new_hash_tree;
}

/**
 * @brief Creates and initializes a second_level_container, which contains a chunk of 32 second_level_buckets
 * 
 * @return struct second_level_container* The new container
 */
struct second_level_container* second_level_init() {
    struct second_level_container* new_container = kmalloc(sizeof (struct second_level_container), GFP_KERNEL); //Allocate second level container
    new_container->buckets = kzalloc(32 * sizeof(struct second_level_bucket), GFP_KERNEL); //Each container gets a 32-array of buckets
    for (int i = 0; i < 32; i++) {
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
void hash_tree_add(struct first_level_bucket* tree, u8* xxhash, u8* blake2b) {
    //====FIRST LEVEL HASH====//
    u8 first_byte = *xxhash; //Get the first byte of the xxhash

    tree[first_byte].byte = first_byte; //Just put the first byte in the first level array 
    if (tree[first_byte].ptr == NULL) { //If the container in that slot isn't defined, define it
        tree[first_byte].ptr = second_level_init();
    }

    //====SECOND LEVEL HASH====//
    struct second_level_container* curr_container = tree[first_byte].ptr; //Get the first container from the current bucket on the tree
    bool found_open_bucket = false;
    while (true) { // We're going to keep going through each container in sequence and see if xxHash value is present
        for (int i = 0; i < 32; i++) {
            if (memcmp(curr_container->buckets[i].value, xxhash) == 0) {
                
            }
        }
    }
}