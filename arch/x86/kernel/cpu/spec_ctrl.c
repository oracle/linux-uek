#include <linux/export.h>
#include <linux/init.h>
#include <linux/mutex.h>
#include <linux/debugfs.h>
#include <linux/uaccess.h>
#include <linux/cpu.h>
#include <asm/spec_ctrl.h>
#include <asm/cpufeature.h>
#include <asm/microcode.h>

u32 sysctl_ibrs_enabled;
EXPORT_SYMBOL(sysctl_ibrs_enabled);
u32 sysctl_ibpb_enabled;
EXPORT_SYMBOL(sysctl_ibpb_enabled);

static ssize_t __enabled_read(struct file *file, char __user *user_buf,
			      size_t count, loff_t *ppos, unsigned int *field)
{
	char buf[32];
	unsigned int len;

	len = sprintf(buf, "%d\n", READ_ONCE(*field));
	return simple_read_from_buffer(user_buf, count, ppos, buf, len);
}

static ssize_t ibrs_enabled_read(struct file *file, char __user *user_buf,
				 size_t count, loff_t *ppos)
{
	return __enabled_read(file, user_buf, count, ppos,
			      &sysctl_ibrs_enabled);
}

static void spec_ctrl_flush_all_cpus(u32 msr_nr, u64 val)
{
	int cpu;

	get_online_cpus();
	for_each_online_cpu(cpu)
		wrmsrl_on_cpu(cpu, msr_nr, val);
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

	if (retpoline_enabled()) {
		pr_warn("retpoline is enabled. Ignoring request to change ibrs state.\n");
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

	if (!!enable != !!ibrs_disabled)
		return count;

	mutex_lock(&spec_ctrl_mutex);

	if (!enable) {
		set_ibrs_disabled();
		disable_ibrs_firmware();
		if (use_ibrs & SPEC_CTRL_IBRS_SUPPORTED)
			spec_ctrl_flush_all_cpus(MSR_IA32_SPEC_CTRL,
						 x86_spec_ctrl_base);
	} else {
		clear_ibrs_disabled();
		set_ibrs_firmware();
	}
	refresh_set_spectre_v2_enabled();

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
	return __enabled_read(file, user_buf, count, ppos,
			      &sysctl_ibpb_enabled);
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

	/* Only 0 and 1 are allowed */
	if (enable > 1)
		return -EINVAL;

	if (!!enable != !!ibpb_disabled)
		return count;

	mutex_lock(&spec_ctrl_mutex);

	if (!enable)
		set_ibpb_disabled();
	else
		clear_ibpb_disabled();

	refresh_set_spectre_v2_enabled();

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
	debugfs_create_file("ibrs_enabled", S_IRUSR | S_IWUSR, arch_debugfs_dir, NULL,
			    &fops_ibrs_enabled);
	debugfs_create_file("ibpb_enabled", S_IRUSR | S_IWUSR, arch_debugfs_dir, NULL,
			    &fops_ibpb_enabled);
	return 0;
}
late_initcall(debugfs_spec_ctrl);
