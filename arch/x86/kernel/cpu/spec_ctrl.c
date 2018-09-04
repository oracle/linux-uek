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

enum mitigation_action {
	MITIGATION_DISABLE_IBRS,
	MITIGATION_ENABLE_IBRS,
	MITIGATION_DISABLE_RETPOLINE,
	MITIGATION_ENABLE_RETPOLINE
};

static void spec_ctrl_flush_all_cpus(u32 msr_nr, u64 val)
{
	int cpu;

	get_online_cpus();
	for_each_online_cpu(cpu)
		wrmsrl_on_cpu(cpu, msr_nr, val);
	put_online_cpus();
}

static void change_mitigation(enum mitigation_action action)
{
	bool ibrs_requested, ibrs_fw_requested, retpoline_requested;
	bool ibrs_used, ibrs_fw_used, retpoline_used;
	int changes = 0;

	mutex_lock(&spec_ctrl_mutex);

	/*
	 * Define the current state.
	 *
	 * IBRS firmware is enabled if either IBRS or retpoline is enabled.
	 * If both IBRS and retpoline are disabled, then IBRS firmware is
	 * disabled too.
	 */

	ibrs_used = !ibrs_disabled;
	retpoline_used = !!retpoline_enabled();
	ibrs_fw_used = (ibrs_used || retpoline_used);

	/*
	 * Define the requested state.
	 *
	 * Enabling IBRS will disable retpoline, and respectively enabling
	 * retpoline will disable IBRS. On the other hand, disabling a
	 * mitigation won't impact other mitigations.
	 *
	 */
	switch (action) {

	case MITIGATION_ENABLE_IBRS:
		ibrs_requested = true;
		ibrs_fw_requested = true;
		retpoline_requested = false;
		break;

	case MITIGATION_DISABLE_IBRS:
		ibrs_requested = false;
		ibrs_fw_requested = retpoline_used;
		retpoline_requested = retpoline_used;
		break;

	case MITIGATION_ENABLE_RETPOLINE:
		ibrs_requested = false;
		ibrs_fw_requested = true;
		retpoline_requested = true;
		break;

	case MITIGATION_DISABLE_RETPOLINE:
		ibrs_requested = ibrs_used;
		ibrs_fw_requested = ibrs_used;
		retpoline_requested = false;
		break;
	}

	/* Switch to the requested mitigation state. */

	if (ibrs_requested != ibrs_used) {
		if (ibrs_requested) {
			clear_ibrs_disabled();
		} else {
			set_ibrs_disabled();
			if (use_ibrs & SPEC_CTRL_IBRS_SUPPORTED) {
				spec_ctrl_flush_all_cpus(MSR_IA32_SPEC_CTRL,
							 x86_spec_ctrl_base);
			}
		}
		changes++;
	}

	if (retpoline_requested != retpoline_used) {
		if (retpoline_requested)
			retpoline_enable();
		else
			retpoline_disable();
		changes++;
	}

	if (ibrs_fw_requested != ibrs_fw_used) {
		if (ibrs_fw_requested)
			set_ibrs_firmware();
		else
			disable_ibrs_firmware();
		changes++;
	}

	if (changes > 0)
		refresh_set_spectre_v2_enabled();

	mutex_unlock(&spec_ctrl_mutex);
}

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

	/* Only 0 and 1 are allowed */
	if (enable > 1)
		return -EINVAL;

	if (enable)
		change_mitigation(MITIGATION_ENABLE_IBRS);
	else
		change_mitigation(MITIGATION_DISABLE_IBRS);

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

#ifdef CONFIG_RETPOLINE

static ssize_t retpoline_enabled_read(struct file *file, char __user *user_buf,
				 size_t count, loff_t *ppos)
{
	u32 sysctl_retpoline_enabled = retpoline_enabled() ? 1 : 0;

	return __enabled_read(file, user_buf, count, ppos,
			      &sysctl_retpoline_enabled);
}

static ssize_t retpoline_enabled_write(struct file *file,
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

	/* Only 0 and 1 are allowed */
	if (enable > 1)
		return -EINVAL;

	/*
	 * The retpoline feature is always present except on Skylake
	 * if the system wasn't explicitly booted with retpoline.
	 */
	if (enable && !boot_cpu_has(X86_FEATURE_RETPOLINE)) {
		pr_warn("Retpoline is disabled by default on Skylake-generation system.\n");
		pr_warn("Use the 'spectre_v2=retpoline' parameter to boot with retpoline.\n");
		return -EINVAL;
	}

	if (enable)
		change_mitigation(MITIGATION_ENABLE_RETPOLINE);
	else
		change_mitigation(MITIGATION_DISABLE_RETPOLINE);

	return count;
}

static const struct file_operations fops_retpoline_enabled = {
	.read = retpoline_enabled_read,
	.write = retpoline_enabled_write,
	.llseek = default_llseek,
};

#endif /* CONFIG_RETPOLINE */

static int __init debugfs_spec_ctrl(void)
{
	debugfs_create_file("ibrs_enabled", S_IRUSR | S_IWUSR, arch_debugfs_dir, NULL,
			    &fops_ibrs_enabled);
	debugfs_create_file("ibpb_enabled", S_IRUSR | S_IWUSR, arch_debugfs_dir, NULL,
			    &fops_ibpb_enabled);
	if (IS_ENABLED(CONFIG_RETPOLINE)) {
		debugfs_create_file("retpoline_enabled",
				    0600, arch_debugfs_dir, NULL,
				    &fops_retpoline_enabled);
	}
	return 0;
}
late_initcall(debugfs_spec_ctrl);
