#include "hash_tree.h"
#include <linux/types.h>
#include <linux/kernel.h>
#define CONTAINER_SIZE 32


/**
 * @brief Allocates space for a 256 element array of first_level_buckets
 * 
 * @return struct first_level_bucket* Pointer to the beginning of the array
 */
struct first_level_bucket* first_level_init(void) {
    struct first_level_bucket* new_hash_tree = vzalloc(256 * sizeof(struct first_level_bucket), GFP_KERNEL); //Allocate 256 element tree
    return new_hash_tree;
}

/**
 * @brief Creates and initializes a second_level_container, which contains a chunk of 32 second_level_buckets
 * 
 * @return struct second_level_container* The new container
 */
struct second_level_container* second_level_init(struct second_level_container* previous) {
    struct second_level_container* new_container = vmalloc(sizeof (struct second_level_container), GFP_KERNEL); //Allocate second level container
    new_container->buckets = vzalloc(CONTAINER_SIZE * sizeof(struct second_level_bucket), GFP_KERNEL); //Each container gets a 32-array of buckets
    new_container->counter = 0;
    int i = 0;
    for (; i < CONTAINER_SIZE; i++) { //Initialize each bucket
    	new_container->buckets[i].in_use = false;
        new_container->buckets[i].tree = RB_ROOT; //Initialize the red-black tree in each bucket
    }
    new_container->next = NULL; //Pointer to next container starts as null since there is no next container
    new_container->prev = previous; //Set up previous container
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
        tree[first_byte].ptr = second_level_init(NULL);
    }

    //====SECOND LEVEL HASH====//
    struct second_level_container* curr_container = tree[first_byte].ptr; //Get the first container from the current bucket on the tree
    
    while (curr_container->counter >= CONTAINER_SIZE) { //First, we need to skip over full containers
    	if (curr_container->next == NULL) {
    		curr_container->next = second_level_init(curr_container);
    	}
    	curr_container = curr_container->next;
    }
    
    bool add_success = false;
    while (add_success == false) { // We're going to keep going through each container in sequence and see if the xxHash value is present
    	int i = 0;
        for (i = 0; i < CONTAINER_SIZE; i++) { //Loop through all 32 buckets of the current container
        	if (curr_container->buckets[i].in_use == false) { //If the current bucket isn't in use, put our hash there
                curr_container->buckets[i].xxhash = xxhash; 
                curr_container->counter += 1; //Since we're adding a new value, increment the counter in the container
                struct hash_tree_node* new_node = vmalloc(sizeof(struct hash_tree_node), GFP_KERNEL); //Create a new hash tree node to put into the rbtree
                new_node->value = blake2b;
                new_node->metadata = metadata;
                if (rb_insert(&curr_container->buckets[i].tree, new_node) != 0) {
                    pr_err("HASH_TREE_ERROR: failed to add node to red-black tree");
                    return -1;
                }
                else add_success = true;
            }
            else if (xxhash == curr_container->buckets[i].xxhash) { //If we did find our xxhash value, try to put the blake2b into the tree in that slot
                struct hash_tree_node* new_node = vmalloc(sizeof(struct hash_tree_node), GFP_KERNEL);
                new_node->value = blake2b;
                new_node->metadata = metadata;
                if (rb_insert(&curr_container->buckets[i].tree, new_node) != 0) {
                    pr_err("HASH_TREE_ERROR: failed to add node to red-black tree");
                    return -1;
                }
                else add_success = true;
            }
            
        }
        if (!add_success) { //if we go through all 32 buckets and still don't successfully add the new item, go to the next container
            if (curr_container->next == NULL) { //If there isn't another cotainer connected to this one just yet, add a new one
                curr_container->next = second_level_init(curr_container);
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
    		for (; i < CONTAINER_SIZE; i++) { //Loop through all 32 buckets on the current container
    			if (xxhash == curr_container->buckets[i].xxhash && curr_container->buckets[i].in_use == true) { //If we do find the xxhash, search the rbtree for the blake2b
    				struct page_metadata* result = rb_search(&curr_container->buckets[i].tree, blake2b)->metadata; //This will return NULL if the rb_search doesn't find what it's looking for
    				return result;
    			}
    		}
    		if (curr_container->next == NULL) return NULL;
    		else curr_container = curr_container->next; 
    	}
    }
    return NULL;
}

int hash_tree_delete(struct first_level_bucket* tree, u64 xxhash, u8* blake2b) {
	//====FIRST LEVEL HASH====//
	u8 first_byte = ((u8*)xxhash)[0];
	
	if (tree[first_byte].ptr == NULL) {
		pr_err("HASH_TREE_ERROR: delete failed, could not find first byte of xxhash in first level hash");
	}
	
	//====SECOND LEVEL HASH====//
	else {
		struct second_level_container* curr_container = tree[first_byte].ptr; //Get the container pointed to by the bucket in the first level hash
    	bool find_success = false;
    	while(find_success == false) { //Keep looping until we hit a termination condition
    		int i = 0;
    		for (; i < CONTAINER_SIZE; i++) { //Loop through all 32 buckets on the current container
    			if (xxhash == curr_container->buckets[i].xxhash && curr_container->buckets[i].in_use == true) { //If we find the hash we want and the bucket is in use, we're in the right spot
    				struct hash_tree_node* curr_node = rb_search(&curr_container->buckets[i].tree, blake2b);
    				if (curr_node) {
    					rb_erase(&curr_node->node, &curr_container->buckets[i].tree); //Remove node from tree
    					vfree(curr_node); //Free node
    					
    					if (curr_container->buckets[i].tree.rb_node == NULL) { //if the root of the tree is now null, we can set its bucket to empty
							curr_container->buckets[i].in_use = false;
							curr_container->counter -= 1; //decrement the number of used buckets in the container
							
							if (curr_container->counter <= 0) { //If the counter hits 0, the container is empty, so we can pave it
								if (curr_container->prev != NULL) curr_container->prev->next = curr_container->next; //Link the adjacent containers
								if (curr_container->next != NULL) curr_container->next->prev = curr_container->prev;
								vfree(curr_container); //free current container
							}
    					}
    					return 0;
    				}
    				else {
    					pr_err("HASH_TREE_ERROR: delete failed, couldn't find blake2b hash in rbtree");
    					return -1;
    				}
    			}
    		}
    		if (curr_container->next == NULL) { //If we hit a NULL looping through each container, we've hit the end of the second level hash and thus haven't found what we want
    			pr_err("HASH_TREE_ERROR: delete failed, couldn't find xxhash in second level hash");
	    		return -1;
    		}
    		else curr_container = curr_container->next; 
    	}
	}
}

/**
 * @brief Adds a node to the red-black tree
 * 
 * @param root The root of the red-black tree
 * @param node_to_add The red-black node to add to the tree
 */
static int rb_insert(struct rb_root *root, struct hash_tree_node* node_to_add) {
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
        	pr_err("HASH_TREE_ERROR: blake2b collision in red-black tree");
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
static struct hash_tree_node* rb_search(struct rb_root *root, u8* blake2b) {

	struct rb_node* node = root->rb_node; //Start at the first node
	
	while(node) { //Loop through all the nodes
		struct hash_tree_node* data = container_of(node, struct hash_tree_node, node); //Get the data of the current node
		int result = memcmp(blake2b, data->value, BLAKE2B_512_HASH_SIZE); //Compare the desired blake2b with the value in the data
		
		if (result < 0) node = node->rb_left; //If our blake2b is less than the value in the current node, go left
		else if (result > 0) node = node->rb_right; //Else go right
		else return data; //If they're equal, return the current node
	}
	
	return NULL; //If we get through all the nodes without finding what we want, return NULL
}


int sus_mod_htree(int flags) {
	printk("Entering ioctl");
	//u64 test_xxhash = 346236456;
	//u8* test_blake = vmalloc(sizeof(u64), GFP_KERNEL);
	
	//struct first_level_bucket* test_first_level = first_level_init();
	//printk("Initialized first_level_bucket");

	return 0;
}






