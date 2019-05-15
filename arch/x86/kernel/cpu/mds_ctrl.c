#include <linux/export.h>
#include <linux/init.h>
#include <linux/debugfs.h>
#include <linux/uaccess.h>
#include <linux/cpu.h>
#include <asm/nospec-branch.h>
#include <asm/cpufeature.h>
#include <asm/microcode.h>

static ssize_t __enabled_read(struct file *file, char __user *user_buf,
                              size_t count, loff_t *ppos, unsigned int *field)
{
	char buf[2] = {'0', '\n'};;

	if (*field)
	        buf[0] = '1';

	return simple_read_from_buffer(user_buf, count, ppos, buf, 2);
}

static ssize_t mds_key_read(struct file *file,
				   char __user *user_buf,
				   size_t count, loff_t *ppos,
				   bool (*enabled_func) (void))
{
	u32 sysctl_mds_key = (*enabled_func)() ? 1 : 0;

	return __enabled_read(file, user_buf, count, ppos,
			      &sysctl_mds_key);
}

static ssize_t mds_key_write(struct file *file,
			     const char __user *user_buf,
			     size_t count, loff_t *ppos,
			     void (*enable_func) (void),
			     void (*disable_func) (void))
{
	char buf[2];
	ssize_t len = 1;
	unsigned int enable;

	if (copy_from_user(buf, user_buf, len))
		return -EFAULT;

	buf[len] = '\0';
	if (kstrtouint(buf, 0, &enable))
		return -EINVAL;

	/* Only 0 and 1 are allowed */
	if (enable > 1)
		return -EINVAL;

	if (enable)
		(*enable_func)();
	else
		(*disable_func)();

	return count;
}

static ssize_t mds_idle_clear_read(struct file *file,
				   char __user *user_buf,
				   size_t count, loff_t *ppos)
{
	return mds_key_read(file, user_buf, count, ppos,
			    mds_idle_clear_enabled);
}

static ssize_t mds_user_clear_read(struct file *file,
				   char __user *user_buf,
				   size_t count, loff_t *ppos)
{
	return mds_key_read(file, user_buf, count, ppos,
			    mds_user_clear_enabled);
}

static ssize_t mds_user_clear_write(struct file *file,
				    const char __user *user_buf,
				    size_t count, loff_t *ppos)
{
	return mds_key_write(file, user_buf, count, ppos,
			     mds_user_clear_enable,
			     mds_user_clear_disable);
}

static ssize_t mds_idle_clear_write(struct file *file,
				    const char __user *user_buf,
				    size_t count, loff_t *ppos)
{
	return mds_key_write(file, user_buf, count, ppos,
			     mds_idle_clear_enable,
			     mds_idle_clear_disable);
}

static const struct file_operations fops_mds_user_clear = {
	.read = mds_user_clear_read,
	.write = mds_user_clear_write,
	.llseek = default_llseek,
};

static const struct file_operations fops_mds_idle_clear = {
	.read = mds_idle_clear_read,
	.write = mds_idle_clear_write,
	.llseek = default_llseek,
};

static int __init debugfs_mds_ctrl(void)
{
	debugfs_create_file("mds_user_clear",
			   0600, arch_debugfs_dir, NULL,
			   &fops_mds_user_clear);
	debugfs_create_file("mds_idle_clear",
			   0600, arch_debugfs_dir, NULL,
			   &fops_mds_idle_clear);
        return 0;
}

late_initcall(debugfs_mds_ctrl);
