/* SPDX-License-Identifier: GPL-2.0 */

#include <linux/mutex.h>
#include <linux/debugfs.h>
#include <linux/uaccess.h>

#include <asm/spec_ctrl.h>
#include <asm/cpufeature.h>
#include <linux/module.h>
#include <linux/cpu.h>
#include <asm/msr.h>

unsigned int dynamic_ibrs __read_mostly;
EXPORT_SYMBOL_GPL(dynamic_ibrs);

enum {
	IBRS_DISABLED,
	IBRS_ENABLED,
	IBRS_MAX = IBRS_ENABLED,
};
static unsigned int ibrs_enabled;
static bool ibrs_admin_disabled;

unsigned int dynamic_ibpb __read_mostly;
EXPORT_SYMBOL_GPL(dynamic_ibpb);

enum {
	IBPB_DISABLED,
	IBPB_ENABLED,
	IBPB_MAX=IBPB_ENABLED
};
static unsigned int ibpb_enabled;
static bool ibpb_admin_disabled;

/* mutex to serialize IBRS control changes */
DEFINE_MUTEX(spec_ctrl_mutex);

static inline void set_ibrs_feature(void)
{
	bool ignore = false;

	if (xen_pv_domain())
		ignore = true;

	printk(KERN_INFO "FEATURE SPEC_CTRL Present%s\n", ignore ? " but ignored (Xen)": "");

	if (!ibrs_admin_disabled && !ignore) {
		dynamic_ibrs |= SPEC_CTRL_IBRS_INUSE;
		ibrs_enabled = IBRS_ENABLED;
	} else {
		dynamic_ibrs &= ~SPEC_CTRL_IBRS_INUSE;
		ibrs_enabled = IBRS_DISABLED;
	}
	sysctl_ibrs_enabled = (dynamic_ibrs & SPEC_CTRL_IBRS_INUSE) ? 1 : 0;
}

static inline void set_ibpb_feature(void)
{
	if (!ibpb_admin_disabled) {
		dynamic_ibpb = 1;
		ibpb_enabled = IBPB_ENABLED;
	} else {
		dynamic_ibpb = 0;
		ibpb_enabled = IBPB_DISABLED;
	}
	sysctl_ibpb_enabled = dynamic_ibpb ? 1 : 0;
}

void set_ibrs_disabled(void)
{
	dynamic_ibrs &= ~SPEC_CTRL_IBRS_INUSE;
	ibrs_enabled = IBRS_DISABLED;
	ibrs_admin_disabled = true;
	sysctl_ibrs_enabled = dynamic_ibrs;
}

void set_ibpb_disabled(void)
{
	dynamic_ibpb = 0;
	ibpb_enabled = 0;
	ibpb_admin_disabled = true;
	sysctl_ibpb_enabled = dynamic_ibpb;
}

void scan_spec_ctrl_feature(struct cpuinfo_x86 *c)
{
	if (!c->cpu_index) {
		if (cpu_has(c, X86_FEATURE_IBRS)) {
			set_ibrs_feature();
			set_ibpb_feature();
		} else if (cpu_has(c, X86_FEATURE_IBPB)) {
			printk_once(KERN_INFO "FEATURE IBPB Present\n");
			set_ibpb_feature();
			if (ibpb_inuse)
				sysctl_ibpb_enabled = 1;
		}
	}
}
EXPORT_SYMBOL_GPL(scan_spec_ctrl_feature);

bool ibrs_inuse(void)
{
	return ibrs_enabled == IBRS_ENABLED;
}
EXPORT_SYMBOL_GPL(ibrs_inuse);

static int __init noibrs(char *str)
{
	ibrs_admin_disabled = true;
	ibrs_enabled = IBRS_DISABLED;

	return 0;
}
early_param("noibrs", noibrs);

bool ibpb_inuse(void)
{
	return ibpb_enabled == IBPB_ENABLED;
}
EXPORT_SYMBOL_GPL(ibpb_inuse);

static int __init noibpb(char *str)
{
	ibpb_admin_disabled = true;
	ibpb_enabled = IBPB_DISABLED;

	return 0;
}
early_param("noibpb", noibpb);

static ssize_t __enabled_read(struct file *file, char __user *user_buf,
			      size_t count, loff_t *ppos, unsigned int *field)
{
	char buf[32];
	unsigned int len;

	len = sprintf(buf, "%d\n", ACCESS_ONCE(*field));
	return simple_read_from_buffer(user_buf, count, ppos, buf, len);
}

static ssize_t ibrs_enabled_read(struct file *file, char __user *user_buf,
				 size_t count, loff_t *ppos)
{
	return __enabled_read(file, user_buf, count, ppos, &ibrs_enabled);
}

static void spec_ctrl_flush_all_cpus(u32 msr_nr, u64 val)
{
	int cpu;

	get_online_cpus();
	for_each_online_cpu(cpu)
		wrmsr_on_cpu(cpu, msr_nr, (u32) val, (u32) (val >> 32));
	put_online_cpus();
}

static ssize_t ibrs_enabled_write(struct file *file,
				  const char __user *user_buf,
				  size_t count, loff_t *ppos)
{
	char buf[32];
	ssize_t len;
	unsigned int enable;

	len = min(count, sizeof(buf) - 1);
	if (copy_from_user(buf, user_buf, len))
		return -EFAULT;

	buf[len] = '\0';
	if (kstrtouint(buf, 0, &enable))
		return -EINVAL;

	if (enable > IBRS_MAX)
		return -EINVAL;

	if (!boot_cpu_has(X86_FEATURE_IBRS)) {
		ibrs_enabled = IBRS_DISABLED;
		return -ENODEV;
	}

	mutex_lock(&spec_ctrl_mutex);

	if (enable == IBRS_DISABLED) {
		/* disable IBRS usage */
		ibrs_admin_disabled = true;
		dynamic_ibrs &= ~SPEC_CTRL_IBRS_INUSE;
		spec_ctrl_flush_all_cpus(MSR_IA32_SPEC_CTRL,
					 SPEC_CTRL_FEATURE_DISABLE_IBRS);

	} else if (enable == IBRS_ENABLED) {
		/* enable IBRS usage in kernel */
		ibrs_admin_disabled = false;
		dynamic_ibrs |= SPEC_CTRL_IBRS_INUSE;

	}

	ibrs_enabled = enable;

	mutex_unlock(&spec_ctrl_mutex);
	return count;
}

static const struct file_operations fops_ibrs_enabled = {
	.read = ibrs_enabled_read,
	.write = ibrs_enabled_write,
	.llseek = default_llseek,
};

static ssize_t ibpb_enabled_read(struct file *file, char __user *user_buf,
				 size_t count, loff_t *ppos)
{
	return __enabled_read(file, user_buf, count, ppos, &ibpb_enabled);
}

static ssize_t ibpb_enabled_write(struct file *file,
				  const char __user *user_buf,
				  size_t count, loff_t *ppos)
{
	char buf[32];
	ssize_t len;
	unsigned int enable;

	len = min(count, sizeof(buf) - 1);
	if (copy_from_user(buf, user_buf, len))
		return -EFAULT;

	buf[len] = '\0';
	if (kstrtouint(buf, 0, &enable))
		return -EINVAL;

	if (enable > IBPB_MAX)
		return -EINVAL;

	if (!boot_cpu_has(X86_FEATURE_IBRS)) {
		ibpb_enabled = IBPB_DISABLED;
		return -ENODEV;
	}

	mutex_lock(&spec_ctrl_mutex);

	if (enable == IBPB_DISABLED) {
		/* disable IBPB usage */
		ibpb_admin_disabled = true;
		dynamic_ibpb = 0;
	} else if (enable == IBPB_ENABLED) {
		/* enable IBPB */
		ibpb_admin_disabled = false;
		dynamic_ibpb = 1;
	}

	ibpb_enabled = enable;

	mutex_unlock(&spec_ctrl_mutex);
	return count;
}

static const struct file_operations fops_ibpb_enabled = {
	.read = ibpb_enabled_read,
	.write = ibpb_enabled_write,
	.llseek = default_llseek,
};

static int __init debugfs_spec_ctrl(void)
{
	debugfs_create_file("ibrs_enabled", S_IRUSR | S_IWUSR,
			    arch_debugfs_dir, NULL, &fops_ibrs_enabled);
	debugfs_create_file("ibpb_enabled", S_IRUSR | S_IWUSR,
			    arch_debugfs_dir, NULL, &fops_ibpb_enabled);
	return 0;
}
late_initcall(debugfs_spec_ctrl);

void unprotected_firmware_begin(void)
{
	/*
	 * rmb prevent unwanted speculation when we
	 * are setting IBRS
	 */
	rmb();
}
EXPORT_SYMBOL_GPL(unprotected_firmware_begin);

void unprotected_firmware_end(void)
{
}
EXPORT_SYMBOL_GPL(unprotected_firmware_end);
