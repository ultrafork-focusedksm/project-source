#ifndef _LIB_SUS_H
#define _LIB_SUS_H

#include "../kernel/sus.h"
#include <sys/types.h>

int sus_open();

int sus_fksm_merge(int, pid_t, pid_t);

int sus_close(int);

#endif
