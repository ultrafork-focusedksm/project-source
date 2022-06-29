/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _COW_COUNTER_H
#define _COW_COUNTER_H

#include <linux/types.h>

int cow_count(pid_t proc, size_t*, size_t*);

#endif
