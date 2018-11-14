/* SPDX-License-Identifier: GPL-2.0 */
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

long kernel_wait4(pid_t upid, int __user *stat_addr,
	      int options, struct rusage __user *ru);

struct waitfd_ctx {
	int	options;
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

	poll_wait_fixed(file, &current->signal->wait_chldexit, wait,
		POLLIN);

	value = kernel_wait4(ctx->upid, NULL, ctx->options | WNOHANG | WNOWAIT,
			 NULL);
	if (value > 0 || value == -ECHILD)
		return POLLIN | POLLRDNORM;

	return 0;
}

/*
 * Returns a multiple of the size of a stat_addr, or a negative error code. The
 * "count" parameter must be at least sizeof(int).
 */
static ssize_t waitfd_read(struct file *file, char __user *buf, size_t count,
			     loff_t *ppos)
{
	struct waitfd_ctx *ctx = file->private_data;
	int __user *stat_addr = (int *)buf;
	int flags = ctx->options;
	ssize_t ret, total = 0;

	count /= sizeof(int);
	if (!count)
		return -EINVAL;

	if (file->f_flags & O_NONBLOCK)
		flags |= WNOHANG;

	do {
		ret = kernel_wait4(ctx->upid, stat_addr, flags, NULL);
		if (ret == 0)
			ret = -EAGAIN;
		if (ret == -ECHILD)
			ret = 0;
		if (ret <= 0)
			break;

		stat_addr++;
		total += sizeof(int);
	} while (--count);

	return total ? total : ret;
}

static const struct file_operations waitfd_fops = {
	.release	= waitfd_release,
	.poll		= waitfd_poll,
	.read		= waitfd_read,
	.llseek		= noop_llseek,
};

SYSCALL_DEFINE4(waitfd, int __maybe_unused, which, pid_t, upid, int, options,
		int __maybe_unused, flags)
{
	int ufd;
	struct waitfd_ctx *ctx;

	/*
	 * Options validation from kernel_wait4(), minus WNOWAIT, which is
	 * only used by our polling implementation.  If WEXITED or WSTOPPED
	 * are provided, silently remove them (for backward compatibility with
	 * older callers).
	 */
	options &= ~(WEXITED | WSTOPPED);
	if (options & ~(WNOHANG|WUNTRACED|WCONTINUED|
			__WNOTHREAD|__WCLONE|__WALL))
		return -EINVAL;

	ctx = kmalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return -ENOMEM;

	ctx->options = options;
	ctx->upid = upid;

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
