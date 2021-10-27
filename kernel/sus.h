#ifndef _SUS_H
#define _SUS_H

#ifdef SUS_USERSPACE
#include <sys/ioctl.h>
#else
#include <linux/ioctl.h>
#endif

#define SUS_MOD_IOCTL_MAGIC 0xFA
#define SUS_MODE_FKSM 1
#define SUS_MODE_UFRK 2

struct fksm_ctx
{
    unsigned long pid1;
    unsigned long pid2;
};

struct sus_ctx
{
    unsigned char mode;
    struct fksm_ctx ctx;
};

#define SUS_MOD_UFRK_MERGE _IOW(SUS_MOD_IOCTL_MAGIC, 1, void*)

#endif
