#ifndef _LIB_SUS_H
#define _LIB_SUS_H

#include "../kernel/sus.h"
#include <stdint.h>
#include <sys/types.h>

int sus_open();

int sus_fksm_merge(int, pid_t, pid_t);

int sus_hash_tree_test(int fd, int flags);

int sus_ufrk_fork(int, pid_t);

int sus_cow_counter(int, pid_t, size_t* cow, size_t* vm);

int sus_close(int);

#endif
