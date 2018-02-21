/* SPDX-License-Identifier: GPL-2.0 */

#include <linux/mutex.h>
#include <linux/debugfs.h>
#include <linux/uaccess.h>

#include <asm/spec_ctrl.h>
#include <asm/cpufeature.h>
#include <linux/module.h>
#include <linux/cpu.h>
#include <asm/msr.h>

/*
 * dynamic_ibrs
 * bit 0 = indicate if ibrs/ibpb is currently in use
 * bit 1 = indicate if system supports ibrs/ibpb
 * bit 2 = indicate if admin disables ibrs/ibpb
 */

unsigned int dynamic_ibrs __read_mostly;
EXPORT_SYMBOL_GPL(dynamic_ibrs);

unsigned int dynamic_ibpb __read_mostly;
EXPORT_SYMBOL_GPL(dynamic_ibpb);

/* mutex to serialize IBRS control changes */
DEFINE_MUTEX(spec_ctrl_mutex);
EXPORT_SYMBOL(spec_ctrl_mutex);

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
	return __enabled_read(file, user_buf, count, ppos, &sysctl_ibrs_enabled);
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

	if (!ibrs_supported)
		return -ENODEV;

	len = min(count, sizeof(buf) - 1);
	if (copy_from_user(buf, user_buf, len))
		return -EFAULT;

	buf[len] = '\0';
	if (kstrtouint(buf, 0, &enable))
		return -EINVAL;

	if (enable > 1)
		return -EINVAL;

	if (!!enable != !!ibrs_disabled)
		return count;

	mutex_lock(&spec_ctrl_mutex);

	if (!enable) {
		set_ibrs_disabled();

		if (dynamic_ibrs & SPEC_CTRL_IBRS_SUPPORTED)
			spec_ctrl_flush_all_cpus(MSR_IA32_SPEC_CTRL,
					 SPEC_CTRL_FEATURE_DISABLE_IBRS);
	} else
		clear_ibrs_disabled();

	mutex_unlock(&spec_ctrl_mutex);
	return count;
}

static const struct file_operations fops_ibrs_enabled = {
	.read = ibrs_enabled_read,
	.write = ibrs_enabled_write,
	.llseek = default_llseek,
};

static ssize_t lfence_enabled_read(struct file *file, char __user *user_buf,
                                 size_t count, loff_t *ppos)
{
	uint32_t dummy = 0;

	if (ibrs_disabled)
		return __enabled_read(file, user_buf, count, ppos, &sysctl_lfence_enabled);

	return __enabled_read(file, user_buf, count, ppos, &dummy);
}

static ssize_t lfence_enabled_write(struct file *file,
				  const char __user *user_buf,
				  size_t count, loff_t *ppos)
{
	char buf[32];
	ssize_t len;
	unsigned int enable;

	/* You have to disable IBRS first. */
	if (ibrs_inuse) {
		pr_warn("IBRS is enabled. Ignoring request to change lfence_enabled state.");
		return -EINVAL;
	}

	len = min(count, sizeof(buf) - 1);
	if (copy_from_user(buf, user_buf, len))
		return -EFAULT;

	buf[len] = '\0';
	if (kstrtouint(buf, 0, &enable))
		return -EINVAL;

	/* Only 0 and 1 are allowed */
	if (enable > 1)
		return -EINVAL;

	mutex_lock(&spec_ctrl_mutex);

	if (!enable)
		set_lfence_disabled();
	else
		clear_lfence_disabled();

	mutex_unlock(&spec_ctrl_mutex);
	return count;
}

static const struct file_operations fops_lfence_enabled = {
	.read = lfence_enabled_read,
	.write = lfence_enabled_write,
	.llseek = default_llseek,
};

static ssize_t ibpb_enabled_read(struct file *file, char __user *user_buf,
				 size_t count, loff_t *ppos)
{
	return __enabled_read(file, user_buf, count, ppos, &sysctl_ibpb_enabled);
}

static ssize_t ibpb_enabled_write(struct file *file,
				  const char __user *user_buf,
				  size_t count, loff_t *ppos)
{
	char buf[32];
	ssize_t len;
	unsigned int enable;

	if (!ibpb_supported)
		return -ENODEV;

	len = min(count, sizeof(buf) - 1);
	if (copy_from_user(buf, user_buf, len))
		return -EFAULT;

	buf[len] = '\0';
	if (kstrtouint(buf, 0, &enable))
		return -EINVAL;

	if (enable > 1)
		return -EINVAL;

	if (!!enable != !!ibpb_disabled)
		return count;

	mutex_lock(&spec_ctrl_mutex);

	if (!enable)
		set_ibpb_disabled();
	else
		clear_ibpb_disabled();

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
	debugfs_create_file("lfence_enabled", S_IRUSR | S_IWUSR,
			    arch_debugfs_dir, NULL, &fops_lfence_enabled);
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
