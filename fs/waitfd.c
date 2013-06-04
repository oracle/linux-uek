/*
 *  fs/waitfd.c
 *
 *  Copyright (C) 2008  Red Hat, Casey Dahlin <cdahlin@redhat.com>
 *
 *  Largely derived from fs/signalfd.c
 */

#include <linux/file.h>
#include <linux/poll.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/kernel.h>
#include <linux/signal.h>
#include <linux/list.h>
#include <linux/anon_inodes.h>
#include <linux/syscalls.h>

long do_waitid(int which, pid_t upid,
	       struct siginfo __user *infop, int options,
	       struct rusage __user *ru);

struct waitfd_ctx {
	int	options;
	int	which;
	pid_t	upid;
};

static int waitfd_release(struct inode *inode, struct file *file)
{
	kfree(file->private_data);
	return 0;
}

static unsigned int waitfd_poll(struct file *file, poll_table *wait)
{
	struct waitfd_ctx *ctx = file->private_data;
	long value;

	printk(KERN_INFO "DEBUG: %i: about to sleep on waitqueue at %p\n", current->pid, &current->signal->wait_chldexit);
	poll_wait(file, &current->signal->wait_chldexit, wait);
	printk(KERN_INFO "DEBUG: waitfd poll woken up and checking pid %i, options are %i\n", ctx->upid, ctx->options);

	value = do_waitid(ctx->which, ctx->upid, NULL,
			   ctx->options | WNOHANG | WNOWAIT, NULL);
	if (value > 0 || value == -ECHILD)
		return POLLIN | POLLRDNORM;

	printk(KERN_INFO "DEBUG: waitfd poll returning zilch\n");

	return 0;
}

/*
 * Returns a multiple of the size of a struct siginfo, or a negative
 * error code. The "count" parameter must be at least sizeof(struct siginfo)
 */
static ssize_t waitfd_read(struct file *file, char __user *buf, size_t count,
			     loff_t *ppos)
{
	struct waitfd_ctx *ctx = file->private_data;
	struct siginfo __user *info_addr = (struct siginfo *)buf;
	int flags = ctx->options;
	ssize_t ret, total = 0;

	count /= sizeof(struct siginfo);
	if (!count)
		return -EINVAL;

	if (file->f_flags & O_NONBLOCK)
		flags |= WNOHANG;

	do {
		ret = do_waitid(ctx->which, ctx->upid, info_addr, flags, NULL);
		if (ret == 0)
			ret = -EAGAIN;
		if (ret == -ECHILD)
			ret = 0;
		if (ret <= 0)
			break;

		info_addr++;
		total += sizeof(struct siginfo);
	} while (--count);

	return total ? total : ret;
}

static const struct file_operations waitfd_fops = {
	.release	= waitfd_release,
	.poll		= waitfd_poll,
	.read		= waitfd_read,
	.llseek		= noop_llseek,
};
 
SYSCALL_DEFINE4(waitfd, int, which, pid_t, upid, int, options, int, flags)
{
	int ufd;
	struct waitfd_ctx *ctx;

	/*
	 * Options validation from do_waitid()
	 */
	if (options & ~(WNOHANG|WNOWAIT|WEXITED|WSTOPPED|WCONTINUED))
		return -EINVAL;
	if (!(options & (WEXITED|WSTOPPED|WCONTINUED)))
		return -EINVAL;

	ctx = kmalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return -ENOMEM;

	ctx->options = options;
	ctx->upid = upid;
	ctx->which = which;

	ufd = anon_inode_getfd("[waitfd]", &waitfd_fops, ctx,
			       O_RDWR | flags | ((options & WNOHANG) ?
						 O_NONBLOCK | 0 : 0));
	/*
	 * Use the fd's nonblocking state from now on, since that can change.
	 */
	ctx->options &= ~WNOHANG;

	if (ufd < 0)
		kfree(ctx);

	return ufd;
}
