/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __LINUX_MEMFD_H
#define __LINUX_MEMFD_H

#include <linux/file.h>

#ifdef CONFIG_MEMFD_CREATE
extern long memfd_fcntl(struct file *file, unsigned int cmd, unsigned long arg);
unsigned int *memfd_file_seals_ptr(struct file *file);
#else
static inline long memfd_fcntl(struct file *f, unsigned int c, unsigned long a)
{
	return -EINVAL;
}

static inline unsigned int *memfd_file_seals_ptr(struct file *file)
{
	return NULL;
}
#endif

/* Retrieve memfd seals associated with the file, if any. */
static inline unsigned int memfd_file_seals(struct file *file)
{
	unsigned int *sealsp = memfd_file_seals_ptr(file);

	return sealsp ? *sealsp : 0;
}

#endif /* __LINUX_MEMFD_H */
