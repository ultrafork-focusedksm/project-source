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

struct ufrk_ctx
{
    unsigned long pid;
    unsigned char flags;
};

struct sus_ctx
{
    unsigned char mode;
    union
    {
        struct fksm_ctx fksm;
        struct ufrk_ctx ufrk;
    };
};

#define SUS_MOD_FKSM_MERGE _IOW(SUS_MOD_IOCTL_MAGIC, 1, void*)
#define SUS_MOD_UFRK_FORK _IOW(SUS_MOD_IOCTL_MAGIC, 2, void*)

#endif
