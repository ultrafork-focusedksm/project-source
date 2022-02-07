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
    for (i; i < 32; i++) { //Initialize each bucket
        new_container->buckets[i].tree = RB_ROOT; //Initialize the red-black tree in each bucket
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
int hash_tree_add(struct first_level_bucket* tree, u64 xxhash, u8* blake2b, struct page_metadata* metadata) {
    //====FIRST LEVEL HASH====//
    u8 first_byte = ((u8*)xxhash)[0]; //Get the first byte of the xxhash

    tree[first_byte].byte = first_byte; //Just put the first byte in the first level array 
    if (tree[first_byte].ptr == NULL) { //If the container in that slot isn't defined, define it
        tree[first_byte].ptr = second_level_init();
    }

    //====SECOND LEVEL HASH====//
    if (tree[first_byte].ptr == NULL) tree[first_byte].ptr = second_level_init();
    struct second_level_container* curr_container = tree[first_byte].ptr; //Get the first container from the current bucket on the tree
    bool add_success = false;
    while (add_success == false) { // We're going to keep going through each container in sequence and see if the xxHash value is present
    	int i = 0;
        for (i = 0; i < 32; i++) { //Loop through all 32 buckets of the current container
        	if (curr_container->buckets[i].value == 0) { //If the current bucket has nothing in it, put our hash there
                curr_container->buckets[i].value = xxhash; 
                struct hash_tree_node* new_node = kmalloc(sizeof(struct hash_tree_node), GFP_KERNEL); //Create a new hash tree node to put into the rbtree
                new_node->value = blake2b;
                new_node->metadata = metadata;
                if (rb_insert(&curr_container->buckets[i].tree, new_node) != 0) {
                    pr_err("FKSM_ERROR: failed to add node to red-black tree");
                    return -1;
                }
                else add_success = true;
            }
            else if (xxhash == curr_container->buckets[i].value) { //If we did find our xxhash value, try to put the blake2b into the tree in that slot
                struct hash_tree_node* new_node = kmalloc(sizeof(struct hash_tree_node), GFP_KERNEL);
                new_node->value = blake2b;
                new_node->metadata = metadata;
                if (rb_insert(&curr_container->buckets[i].tree, new_node) != 0) {
                    pr_err("FKSM_ERROR: failed to add node to red-black tree");
                    return -1;
                }
                else add_success = true;
            }
            
        }
        if (add_success == false) { //if we go through all 32 buckets and still don't successfully add the new item, go to the next container
            if (curr_container->next == NULL) { //If there isn't another cotainer connected to this one just yet, add a new one
                curr_container->next = second_level_init();
            }
            curr_container = curr_container->next; //Go to the next container
        }
    }
    return 0; //If we get here, that means we successfully added the new value
}


/**
 * @brief Tests to see if a hash is in the hash tree
 * 
 * @param tree 
 * @param xxhash 
 * @param blake2b 
 * @return true 
 * @return false 
 */
struct page_metadata* hash_tree_lookup(struct first_level_bucket* tree, u64 xxhash, u8* blake2b) {
    //====FIRST LEVEL HASH====//
    u8 first_byte = ((u8*)xxhash)[0];
    
    if (tree[first_byte].ptr == NULL) { //Look at the bucket for the first byte in the first level hash -- if there's no pointer there return NULL
    	return NULL;
    }
    
    //If there actually is a pointer there, we'll go to the second level hash
    
    //====SECOND LEVEL HASH====///
    else {
    	struct second_level_container* curr_container = tree[first_byte].ptr; //Get the container pointed to by the bucket in the first level hash
    	bool find_success = false;
    	while(find_success == false) { //Keep looping until we hit a termination condition
    		int i = 0;
    		for (i = 0; i < 32; i++) { //Loop through all 32 buckets on the current container
    			if (xxhash == curr_container->buckets[i].value) { //If we do find the xxhash, search the rbtree for the blake2b
    				struct page_metadata* result = rb_search(&curr_container->buckets[i].tree, blake2b); //This will return NULL if the rb_search doesn't find what it's looking for
    				return result;
    			}
    		}
    		if (curr_container->next == NULL) return NULL;
    		else curr_container = curr_container->next; 
    	}
    }
    return NULL;
}

/**
 * @brief Adds a node to the red-black tree
 * 
 * @param root The root of the red-black tree
 * @param node_to_add The red-black node to add to the tree
 */
int rb_insert(struct rb_root *root, struct hash_tree_node* node_to_add) {
    //Credit for most of this code is the example for rbtree on kernel.org

    struct rb_node **new_node = &(root->rb_node); //Get the address of the node pointer stored in our root
    struct rb_node *parent = NULL;

    //Now here's the meat of the operation: figuring out where the new node goes
    while (*new_node) {
        struct hash_tree_node* curr_node = container_of(*new_node, struct hash_tree_node, node);
        int result = memcmp(node_to_add->value, curr_node->value, BLAKE2B_512_HASH_SIZE);

        parent = *new_node; //move down 1 node, so the current node ends up being the parent
        if (result < 0) { //If the hash we're adding is less than the current value, move to the left
            new_node = &((*new_node)->rb_left);
        }
        else if (result > 0) { //If the hash we're adding is greater than the current value, move to the right
            new_node = &((*new_node)->rb_right);
        }
        else { //Otherwise, return an error code
            return -1;
        }
    }

    //Now we add the new node, then tell the tree to rebalance
    rb_link_node(&node_to_add->node, parent, new_node);
    rb_insert_color(&node_to_add->node, root);

    return 0;
}

/**
 * @brief Searches a red-black tree for a given blake2b hash, and returns a pointer to the page_metadata struct associated with it if found
 *
 * @param rb_root The root of the red-black tree to search
 * @param blake2b The blake2b value to look for
 */
struct page_metadata* rb_search(struct rb_root *root, u8* blake2b) {

	struct rb_node* node = root->rb_node; //Start at the first node
	
	while(node) { //Loop through all the nodes
		struct hash_tree_node* data = container_of(node, struct hash_tree_node, node); //Get the data of the current node
		int result = memcmp(blake2b, data->value, BLAKE2B_512_HASH_SIZE); //Compare the desired blake2b with the value in the data
		
		if (result < 0) node = node->rb_left; //If our blake2b is less than the value in the current node, go left
		else if (result > 0) node = node->rb_right; //Else go right
		else return data->metadata; //If they're equal, return the metadata in the current node
	}
	
	return NULL; //If we get through all the nodes without finding what we want, return NULL
}


int sus_mod_htree(int flags) {
	return 0;
}
