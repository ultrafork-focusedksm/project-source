#ifndef _SUS_H
#define _SUS_H

#ifdef SUS_USERSPACE
#include <sys/ioctl.h>
#include <stddef.h>
#else
#include <linux/ioctl.h>
#endif

#define SUS_MOD_IOCTL_MAGIC 0xFA
#define SUS_MODE_FKSM 1
#define SUS_MODE_UFRK 2
#define SUS_MODE_HTREE 3
#define SUS_MODE_COW 4

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

struct hash_tree_ctx
{
    int flags;
};

struct cow_ctx
{
    unsigned long pid;
    size_t cow_bytes;
    size_t vm_bytes;
};

struct sus_ctx
{
    unsigned char mode;
    union
    {
        struct fksm_ctx fksm;
        struct ufrk_ctx ufrk;
        struct hash_tree_ctx htree;
        struct cow_ctx cow;
    };
};

#define SUS_MOD_FKSM_MERGE _IOW(SUS_MOD_IOCTL_MAGIC, 1, struct sus_ctx*)
#define SUS_MOD_UFRK_FORK _IOW(SUS_MOD_IOCTL_MAGIC, 2, struct sus_ctx*)
#define SUS_MOD_HASH_TREE _IOW(SUS_MOD_IOCTL_MAGIC, 3, struct sus_ctx*)
#define SUS_MOD_COW_COUNTER _IOW(SUS_MOD_IOCTL_MAGIC, 4, struct sus_ctx*)

#endif
