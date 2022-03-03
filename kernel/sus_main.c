#include "cow_counter.h"
#include "focused_ksm.h"
#include "hash_tree.h"
#include "sus.h"
#include "ultrafork.h"
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/version.h>

#define SUS_IOCTL "sus_ioctl"
#define SUS_MOD_LOG SUS_IOCTL ": "
#define FIRST_MINOR 0
#define MINOR_CNT 1

static dev_t dev;
static struct cdev c_dev;
static struct class* cl;

static int sus_mod_open(struct inode*, struct file*);
static int sus_mod_close(struct inode*, struct file*);
static long sus_mod_ioctl(struct file*, unsigned int, unsigned long);

static struct file_operations sus_ioctl_fops = {.owner = THIS_MODULE,
                                                .open = sus_mod_open,
                                                .release = sus_mod_close,
                                                .unlocked_ioctl =
                                                    sus_mod_ioctl};

static int sus_mod_open(struct inode* i, struct file* f)
{
    pr_debug(SUS_MOD_LOG "open\n");
    return 0;
}

static int sus_mod_close(struct inode* i, struct file* f)
{
    pr_debug(SUS_MOD_LOG "close\n");
    return 0;
}

static long sus_mod_ioctl(struct file* f, unsigned int cmd, unsigned long arg)
{
    struct sus_ctx ctx;
    ssize_t ret = -EINVAL;
    if (copy_from_user(&ctx, (struct sus_ctx*)arg, sizeof(struct sus_ctx)))
    {
        ret = -EACCES;
    }
    switch (cmd)
    {
    case SUS_MOD_FKSM_MERGE:
        if (SUS_MODE_FKSM == ctx.mode)
        {
            ret = sus_mod_merge(ctx.fksm.pid1, ctx.fksm.pid2);
        }
        break;
    case SUS_MOD_UFRK_FORK:
        if (SUS_MODE_UFRK == ctx.mode)
        {
            ret = sus_mod_fork(ctx.ufrk.pid);
        }
        break;
    case SUS_MOD_HASH_TREE:
        if (SUS_MODE_HTREE == ctx.mode)
        {
            ret = sus_mod_htree(ctx.htree.flags);
        }
        break;
    case SUS_MOD_COW_COUNTER:
        if (SUS_MODE_COW == ctx.mode)
        {
            size_t cow_bytes;
            size_t vm_bytes;
            size_t error;
            ret = cow_count(ctx.cow.pid, &cow_bytes, &vm_bytes);
            ctx.cow.cow_bytes = cow_bytes;
            ctx.cow.vm_bytes = vm_bytes;

            error = copy_to_user((struct sus_ctx*)arg, &ctx,
                                 sizeof(struct sus_ctx));
            if (error != 0)
            {
                pr_err("Unable to copy cow counter result to userpsace");
            }
        }
        break;
    default:
        break;
    }
    return ret;
}

static int __init sus_mod_init(void)
{
    struct device* dev_ret;
    int ret = alloc_chrdev_region(&dev, FIRST_MINOR, MINOR_CNT, SUS_IOCTL);
    if (ret < 0)
    {
        return ret;
    }
    cdev_init(&c_dev, &sus_ioctl_fops);
    ret = cdev_add(&c_dev, dev, MINOR_CNT);
    if (ret < 0)
    {
        return ret;
    }
    if (IS_ERR(cl = class_create(THIS_MODULE, "char")))
    {
        cdev_del(&c_dev);
        unregister_chrdev_region(dev, MINOR_CNT);
        return PTR_ERR(cl);
    }
    if (IS_ERR(dev_ret = device_create(cl, NULL, dev, NULL, SUS_IOCTL)))
    {
        class_destroy(cl);
        cdev_del(&c_dev);
        unregister_chrdev_region(dev, MINOR_CNT);
        return PTR_ERR(dev_ret);
    }
    printk(KERN_INFO SUS_MOD_LOG "loaded\n");
    return 0;
}

static void __exit sus_mod_exit(void)
{
    device_destroy(cl, dev);
    class_destroy(cl);
    cdev_del(&c_dev);
    unregister_chrdev_region(dev, MINOR_CNT);
    printk(KERN_INFO SUS_MOD_LOG "unloaded\n");
}

module_init(sus_mod_init);
module_exit(sus_mod_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Adrian Curless <awcurless@wpi.edu>");
MODULE_AUTHOR("Alex Simoneau <afsimoneau@wpi.edu>");
MODULE_AUTHOR("Billy Cross <wmcross@wpi.edu>");
MODULE_DESCRIPTION("IOCTL for SSUS MQP");
