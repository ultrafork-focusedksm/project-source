#include "libsus.h"
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>

int sus_open()
{
    return open("/dev/sus_ioctl", O_RDWR);
}

int sus_fksm_merge(int fd, pid_t pid1, pid_t pid2)
{
    if (pid1 <= 0 || pid2 <= 0)
    {
        return EINVAL;
    }
    struct sus_ctx ctx;
    ctx.mode = SUS_MODE_FKSM;
    ctx.fksm.pid1 = pid1;
    ctx.fksm.pid2 = pid2;
    if (ioctl(fd, SUS_MOD_FKSM_MERGE, &ctx) == -1)
    {
        return -errno;
    }
    else
    {
        return 0;
    }
}

int sus_hash_tree_test(int fd, int flags)
{
    struct sus_ctx ctx;
    ctx.mode = SUS_MODE_HTREE;
    ctx.htree.flags = flags;
    if (ioctl(fd, SUS_MOD_HASH_TREE, &ctx) == -1)
    {
    	printf("sus_hash_tree_test failed, ioctl returned -1\n");
    	printf("errno: %d\n", errno);
        return -errno;
    }
    else {
        return 0;
    }
}

int sus_ufrk_fork(int fd, pid_t pid, uint8_t flags)
{
    if (pid <= 0)
    {
        return EINVAL;
    }

    struct sus_ctx ctx;
    ctx.mode = SUS_MODE_UFRK;
    ctx.ufrk.pid = pid;
    ctx.ufrk.flags = flags;

    if (ioctl(fd, SUS_MOD_UFRK_FORK, &ctx) == -1)
    {
        return -errno;
    }
    else
    {
        return 0;
    }
}

int sus_close(int fd)
{
    return close(fd);
}
