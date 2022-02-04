#ifndef _COW_COUNTER_H
#define _COW_COUNTER_H

#include <linux/types.h>

ssize_t cow_count(pid_t proc);

#endif
