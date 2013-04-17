#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netdevice.h>

#include "vnic.h"

MODULE_AUTHOR("Eli Cohen");
MODULE_DESCRIPTION("container for mlx4_vnic stats function");
MODULE_LICENSE("Dual BSD/GPL");

DEFINE_SPINLOCK(spl);
static int busy;

static struct net_device_stats *(*stat_func)(struct net_device *n);

static	struct module_attribute dentry;
int ref_count = 1;

static ssize_t mlx4_vnic_reduce_ref_cnt(struct module_attribute *attr,
			   struct module *mod, const char *buf, size_t count)
{
	if (ref_count == 1) {
		module_put(THIS_MODULE);
		ref_count --;
		printk("reducing ref count on module");
	}
	return count;
}

static void mlx4_vnic_create_sysfs_entry(void)
{
	dentry.show = NULL;
	dentry.store = mlx4_vnic_reduce_ref_cnt;
	dentry.attr.name = "enable_unload";
	dentry.attr.mode = S_IWUGO;
#ifndef _BP_NO_ATT_OWNER
	dentry.attr.owner = THIS_MODULE;
#endif
	if (sysfs_create_file(&(THIS_MODULE)->mkobj.kobj, &dentry.attr)) {
		printk("failed to create %s\n", dentry.attr.name);
		dentry.store = NULL;
	}
}



int mlx4_vnic_set_stats_function(struct net_device_stats *(*func)(struct net_device *n))
{
	unsigned long flags;

	spin_lock_irqsave(&spl, flags);
	if (busy) {
		spin_unlock_irqrestore(&spl, flags);
		return -EBUSY;
	}
	stat_func = func;
	spin_unlock_irqrestore(&spl, flags);

	return 0;
}

static struct net_device_stats dummy_stats = {0};

struct net_device_stats *mlx4_vnic_stats_func_container(struct net_device *n)
{
	unsigned long flags;
	struct net_device_stats *ret_stats = &dummy_stats;

	spin_lock_irqsave(&spl, flags);
	busy = 1;
	spin_unlock_irqrestore(&spl, flags);
	if (stat_func)
		ret_stats = stat_func(n);
	//else
		//printk("WARNING stats requested after module unload for "
		//       "device %s\n", n->name);

	spin_lock_irqsave(&spl, flags);
	busy = 0;
	spin_unlock_irqrestore(&spl, flags);
	return ret_stats;
}

EXPORT_SYMBOL(mlx4_vnic_set_stats_function);
EXPORT_SYMBOL(mlx4_vnic_stats_func_container);

static int __init mlx4_vnic_helper_init(void)
{
	mlx4_vnic_create_sysfs_entry();

	if (!try_module_get(THIS_MODULE))
		return -1;

	return 0;
}

static void __exit mlx4_vnic_helper_cleanup(void)
{
	if (dentry.store != NULL)
		sysfs_remove_file(&(THIS_MODULE)->mkobj.kobj, &dentry.attr);
	printk("failed to create %s\n", dentry.attr.name);
}

module_init(mlx4_vnic_helper_init);
module_exit(mlx4_vnic_helper_cleanup);

