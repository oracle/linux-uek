// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2023, Oracle and/or its affiliates.
 */

#include <linux/dmi.h>
#include <linux/init.h>
#include <linux/kallsyms.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/sched.h>
#include <linux/sched/isolation.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <xen/xen.h>

#define UEK_MISC_VER	"0.1"
#define DRV_NAME	"uek"

MODULE_AUTHOR("Konrad Rzeszutek Wilk <konrad.wilk@oracle.com>");
MODULE_DESCRIPTION(DRV_NAME);
MODULE_LICENSE("GPL");
MODULE_VERSION(UEK_MISC_VER);

DEFINE_STATIC_KEY_FALSE(on_exadata);
EXPORT_SYMBOL_GPL(on_exadata);

#ifdef	CONFIG_HUGETLB_PAGE_OPTIMIZE_VMEMMAP
extern void __init hugetlb_enable_vmemmap(void);
#endif

static int force_noio;
static const char *wq_names[] = {"ib_cm", "rdma_cma", "rdma_cm_fr",
		"mlx5_ib_event_wq", "rds_frmr_clean_wq", "rds_fmr_flushd",
		"krdsd", "rds_tcp_accept"};

static void force_noio_on_wq(int force_flag)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(wq_names); i++) {
		if (force_flag)
			mod_workqueue_for(wq_names[i], __WQ_NOIO, 0);
		else
			mod_workqueue_for(wq_names[i], 0, __WQ_NOIO);
	}
}

static void force_noio_on_tasks(int force_flag)
{
	struct task_struct *p;
	char tcomm[64];
	unsigned int i;
	unsigned int old_flag;

	write_lock_irq(&tasklist_lock);
	for_each_process(p) {
		if (is_global_init(p))
			continue;
		if (p->flags & PF_WQ_WORKER)
			wq_worker_comm(tcomm, sizeof(tcomm), p);
		else
			continue;

		task_lock(p);
		for (i = 0; i < ARRAY_SIZE(wq_names); i++) {
			if (strcmp(tcomm, wq_names[i]))
				continue;
			old_flag = p->flags;
			if (force_flag)
				p->flags |= PF_MEMALLOC_NOIO;
			else
				p->flags &= ~(PF_MEMALLOC_NOIO);

			smp_wmb();

			pr_info("%s (%p): %x <- %x\n", tcomm, p, old_flag, p->flags);
			break;
		}
		task_unlock(p);
	}
	write_unlock_irq(&tasklist_lock);
}

static int force_noio_proc_show(struct seq_file *m, void *v)
{
	seq_printf(m, "%s\n", force_noio ? "enabled" : "disabled");
	return 0;
}

static int force_noio_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, force_noio_proc_show, NULL);
}

static ssize_t force_noio_proc_write(struct file *file,
				     const char __user *user_buf, size_t count, loff_t *pos)
{
	char buf[2];
	ssize_t len;
	unsigned int val;

	len = min(count, sizeof(buf) - 1);
	if (copy_from_user(buf, user_buf, len))
		return -EFAULT;

	buf[len] = '\0';
	if (kstrtouint(buf, 0, &val))
		return -EINVAL;

	/* We only do 0 or 1 */
	if (val > 1)
		return -EINVAL;

	if (force_noio != val) {
		force_noio = val;
		force_noio_on_tasks(val);
		force_noio_on_wq(val);
	}
	return count;
}

static const struct file_operations force_noio_proc_fops = {
	.owner		= THIS_MODULE,
	.open		= force_noio_proc_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
	.write		= force_noio_proc_write,
};

static int __init uek_proc_init(void)
{
	struct proc_dir_entry *uek_proc = NULL;
	struct proc_dir_entry *e;

	/* No Xen support for you! */
	if (xen_domain())
		return 0;

	uek_proc = proc_mkdir(DRV_NAME, NULL);
	if (!uek_proc) {
		pr_err("Unable to create %s proc directory\n", DRV_NAME);
		return -EIO;
	}
	e = proc_create("force_noio", 0600, uek_proc, &force_noio_proc_fops);
	if (!e) {
		remove_proc_entry(DRV_NAME, NULL);
		uek_proc = NULL;
		return -EIO;
	}
	return 0;
}

/* Override to disable optimizations on Exadata systems. */
static bool exadata_disable;

static int __init uek_params(char *str)
{
	if (!str)
		return 0;

	if (strncmp(str, "exadata", 7) == 0) {
		static_branch_enable(&on_exadata);
		return 1;
	} else if ((strncmp(str, "noexadata", 9) == 0)) {
		exadata_disable = true;
		return 1;
	}

	return 1;
}
__setup("uek=", uek_params);

int exadata_check_allowed(struct task_struct *p, const struct cpumask *new_mask)
{
	/* Both isolcpus and uek=exadata MUST be set. */
	if (!static_key_enabled(&housekeeping_overridden))
		return 0;

	if (!static_key_enabled(&on_exadata))
		return 0;

	/* Kernel threads are OK. */
	if (p->flags & PF_KTHREAD)
		return 0;

	/*
	 * User-space tasks cannot be on CPUs on the isolcpus=.
	 *
	 * N.B. The housekeeping_cpumask is the inverse of isolcpus=
	 */
	if (cpumask_intersects(new_mask, housekeeping_cpumask(HK_FLAG_DOMAIN)))
		return 0;

	return -EINVAL;
};
EXPORT_SYMBOL_GPL(exadata_check_allowed);

static int detect_exadata_dmi(char **reason)
{
	static const char * const oemstrs[] = {"SUNW-PRMS-1", "00010000"};
	static const struct dmi_system_id oracle_mbs[] = {
		{
			.matches = {
				DMI_MATCH(DMI_SYS_VENDOR, "Oracle Corporation"),
			},
		},
		{
			.matches = {
				DMI_MATCH(DMI_CHASSIS_ASSET_TAG, "OracleCloud.com"),
			},
		},
		{}
	};

	unsigned int i, ok = 0;

	/* Not Oracle system? .. Bye. */
	if (!dmi_check_system(oracle_mbs))
		goto err;

	/* Check for Type 11 and make sure it has the right markings. */
	for (i = 0; i < ARRAY_SIZE(oemstrs); i++)
		if (dmi_find_device(DMI_DEV_TYPE_OEM_STRING, oemstrs[i], NULL))
			ok++;

	if (ok == 2) {
		*reason = "via DMI";
		return 0;
	}

err:
	return -ENODEV;
}

static int detect_exadata_bootline(char **reason)
{
	if (static_key_enabled(&on_exadata)) {
		*reason = "via command line";
		return 0;
	}
	return -ENODEV;
}

static int __init uek_misc_init(void)
{
	int ret;
	char *reason = NULL;

	/* Boot time override engaged */
	if (exadata_disable)
		return -ENODEV;

	ret = detect_exadata_bootline(&reason);
	if (!ret)
		goto enable;

	ret = detect_exadata_dmi(&reason);
	if (ret)
		return ret;

enable:
	/* Go-Go Exadata goodness! */
	static_branch_enable(&on_exadata);

	ret = uek_proc_init();
	if (ret)
		pr_err("Failed to add /proc/%s", DRV_NAME);

#ifdef	CONFIG_HUGETLB_PAGE_OPTIMIZE_VMEMMAP
	hugetlb_enable_vmemmap();
#endif
	pr_info("Detected Exadata (%s)", reason);

	return 0;
}

core_initcall(uek_misc_init);
