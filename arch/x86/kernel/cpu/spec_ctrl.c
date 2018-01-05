#include <linux/export.h>
#include <linux/init.h>
#include <linux/mutex.h>
#include <linux/debugfs.h>
#include <linux/uaccess.h>
#include <linux/cpu.h>
#include <asm/spec_ctrl.h>
#include <asm/cpufeature.h>

/*
 * use_ibrs
 * bit 0 = indicate if ibrs is currently in use
 * bit 1 = indicate if system supports ibrs
 * bit 2 = indicate if admin disables ibrs
 */

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
	return __enabled_read(file, user_buf, count, ppos, &sysctl_ibrs_enabled);
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

        len = min(count, sizeof(buf) - 1);
        if (copy_from_user(buf, user_buf, len))
                return -EFAULT;

        buf[len] = '\0';
        if (kstrtouint(buf, 0, &enable))
                return -EINVAL;

        if (enable > IBRS_MAX)
                return -EINVAL;

	mutex_lock(&spec_ctrl_mutex);

	if (enable == IBRS_DISABLED) {
		/* disable IBRS usage */
		set_ibrs_disabled();
		if (use_ibrs & SPEC_CTRL_IBRS_SUPPORTED)
			spec_ctrl_flush_all_cpus(MSR_IA32_SPEC_CTRL, SPEC_CTRL_FEATURE_DISABLE_IBRS);
	} else if (enable == IBRS_ENABLED) {
		/* enable IBRS usage in kernel */
		clear_ibrs_disabled();
		if (use_ibrs & SPEC_CTRL_IBRS_SUPPORTED)
			set_ibrs_inuse();
		else
			/* Platform don't support IBRS */
			enable = IBRS_DISABLED;
	} else if (enable == IBRS_ENABLED_USER) {
		/* enable IBRS usage in both userspace and kernel */
		clear_ibrs_disabled();
		/* don't change IBRS value once we set it to always on */
		clear_ibrs_inuse();
		if (use_ibrs & SPEC_CTRL_IBRS_SUPPORTED)
			spec_ctrl_flush_all_cpus(MSR_IA32_SPEC_CTRL, SPEC_CTRL_FEATURE_ENABLE_IBRS);
		else
			/* Platform don't support IBRS */
			enable = IBRS_DISABLED;
	}

	WRITE_ONCE(sysctl_ibrs_enabled, enable);

	mutex_unlock(&spec_ctrl_mutex);
	return count;
}

static const struct file_operations fops_ibrs_enabled = {
        .read = ibrs_enabled_read,
        .write = ibrs_enabled_write,
        .llseek = default_llseek,
};

static int __init debugfs_spec_ctrl(void)
{
        debugfs_create_file("ibrs_enabled", S_IRUSR | S_IWUSR,
                            arch_debugfs_dir, NULL, &fops_ibrs_enabled);
        return 0;
}
late_initcall(debugfs_spec_ctrl);
