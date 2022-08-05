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

enum mitigation_action {
	MITIGATION_DISABLE_IBRS,
	MITIGATION_ENABLE_IBRS,
	MITIGATION_DISABLE_RETPOLINE,
	MITIGATION_ENABLE_RETPOLINE,
	MITIGATION_DISABLE_EIBRS_RETPOLINE,
	MITIGATION_ENABLE_EIBRS_RETPOLINE,
};

static void change_mitigation(enum mitigation_action action)
{
	bool ibrs_requested, ibrs_fw_requested, retpoline_requested;
	bool ibrs_used, ibrs_fw_used, retpoline_used;
	int changes = 0;

	mutex_lock(&spec_ctrl_mutex);

	/*
	 * Define the current state.
	 *
	 * IBRS firmware is enabled if either basic IBRS or retpoline is
	 * enabled. If both basic IBRS and retpoline are disabled, then IBRS
	 * firmware is disabled too.
	 */

	ibrs_used = !ibrs_disabled;
	retpoline_used = !!retpoline_enabled();
	ibrs_fw_used = ((ibrs_used && !eibrs_supported) || (retpoline_used && !ibrs_used));

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
		ibrs_fw_requested = !eibrs_supported;
		retpoline_requested = false;
		break;

	case MITIGATION_DISABLE_IBRS:
		/*
		 * With the eibrs+retpoline modes, both ibrs and retpoline can
		 * be set at the same time, but is controlled with a separate
		 * knob. If we're in such a mode (`eibrs_retpoline_enabled` is
		 * 1) and a user writes a 0 to the `ibrs_enabled` knob, then
		 * should have no effect on the current ibrs state.
		 */
		ibrs_requested = ibrs_used && retpoline_used;
		ibrs_fw_requested = retpoline_used ? !ibrs_used : false;
		retpoline_requested = retpoline_used;
		break;

	case MITIGATION_ENABLE_RETPOLINE:
		ibrs_requested = false;
		ibrs_fw_requested = true;
		retpoline_requested = true;
		break;

	case MITIGATION_DISABLE_RETPOLINE:
		/*
		 * Similar to the `MITIGATION_DISABLE_IBRS` case above, if we're
		 * in eibrs+retpoline mode, then writing a 0 to the
		 * `retpoline_enabled` knob should have no effect on the current
		 * retpoline state.
		 */
		ibrs_requested = ibrs_used;
		ibrs_fw_requested = ibrs_used && !eibrs_supported;
		retpoline_requested = ibrs_used && retpoline_used;
		break;

	case MITIGATION_ENABLE_EIBRS_RETPOLINE:
		ibrs_requested = true;
		ibrs_fw_requested = false;
		retpoline_requested = true;
		break;

	case MITIGATION_DISABLE_EIBRS_RETPOLINE:
		ibrs_requested = !retpoline_used && ibrs_used;
		ibrs_fw_requested = retpoline_used && !ibrs_used;
		retpoline_requested = retpoline_used && !ibrs_used;
		break;
	}

	/* Switch to the requested mitigation state. */

	if (ibrs_requested != ibrs_used) {
		if (ibrs_requested) {
			clear_ibrs_disabled();
			/* If enhanced IBRS is available, turn it on now */
			if (eibrs_supported) {
				spec_ctrl_flush_all_cpus(MSR_IA32_SPEC_CTRL,
							 x86_spec_ctrl_priv);
			}
			if (!boot_cpu_has(X86_FEATURE_SMEP)) {
				/* IBRS without SMEP needs RSB overwrite */
				rsb_overwrite_enable();
			}
		} else {
			set_ibrs_disabled();
			if (use_ibrs & SPEC_CTRL_IBRS_SUPPORTED) {
				rsb_overwrite_disable();
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
			ibrs_firmware_enable();
		else
			ibrs_firmware_disable();
		changes++;
	}

	if (changes > 0) {
		refresh_set_spectre_v2_enabled();
		refresh_retbleed();
	}

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
	u32 ibrs_enabled = (sysctl_ibrs_enabled && !retpoline_enabled()) ? 1 : 0;
	return __enabled_read(file, user_buf, count, ppos, &ibrs_enabled);
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
	u32 sysctl_ibpb_enabled = ibpb_enabled();

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

	if (!boot_cpu_has(X86_FEATURE_IBPB))
		return -ENODEV;

	len = min(count, sizeof(buf) - 1);
	if (copy_from_user(buf, user_buf, len))
	return -EFAULT;

	buf[len] = '\0';
	if (kstrtouint(buf, 0, &enable))
	return -EINVAL;

	/* Only 0, 1 and 2 are allowed */
	if (enable > 2)
		return -EINVAL;

	if (enable == ibpb_enabled())
		return count;

	mutex_lock(&spec_ctrl_mutex);

	if (enable == 1)
		ibpb_always_enable();
	else if (enable == 2)
		ibpb_cond_enable();
	else
		ibpb_disable();

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
	u32 sysctl_retpoline_enabled = (retpoline_enabled() &&
				       !sysctl_ibrs_enabled) ? 1 : 0;

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

static ssize_t eibrs_retpoline_enabled_read(struct file *file,
					    char __user *user_buf, size_t count,
					    loff_t *ppos)
{
	u32 sysctl_eibrs_retpoline_enabled = (sysctl_ibrs_enabled &&
					     retpoline_enabled()) ? 1 : 0;
	return __enabled_read(file, user_buf, count, ppos,
			      &sysctl_eibrs_retpoline_enabled);
}

static ssize_t eibrs_retpoline_enabled_write(struct file *file,
					     const char __user *user_buf,
					     size_t count, loff_t *ppos)
{
	char buf[32];
	ssize_t len;
	unsigned int enable;

	if (!eibrs_supported)
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
		change_mitigation(MITIGATION_ENABLE_EIBRS_RETPOLINE);
	else
		change_mitigation(MITIGATION_DISABLE_EIBRS_RETPOLINE);

	return count;
}

static const struct file_operations fops_eibrs_retpoline_enabled = {
	.read = eibrs_retpoline_enabled_read,
	.write = eibrs_retpoline_enabled_write,
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
				    S_IRUSR | S_IWUSR, arch_debugfs_dir, NULL,
				    &fops_retpoline_enabled);
		debugfs_create_file("eibrs_retpoline_enabled",
				    S_IRUSR | S_IWUSR, arch_debugfs_dir, NULL,
				    &fops_eibrs_retpoline_enabled);
	}
	return 0;
}
late_initcall(debugfs_spec_ctrl);
