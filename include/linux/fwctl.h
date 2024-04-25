/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2024, NVIDIA CORPORATION & AFFILIATES
 */
#ifndef __LINUX_FWCTL_H
#define __LINUX_FWCTL_H
#include <linux/device.h>
#include <linux/cdev.h>
#include <linux/cleanup.h>
#include <uapi/fwctl/fwctl.h>

struct fwctl_device;
struct fwctl_uctx;

/**
 * struct fwctl_ops - Driver provided operations
 * @device_type: The drivers assigned device_type number. This is uABI
 * @uctx_size: The size of the fwctl_uctx struct to allocate. The first
 *	bytes of this memory will be a fwctl_uctx. The driver can use the
 *	remaining bytes as its private memory.
 * @open_uctx: Called when a file descriptor is opened before the uctx is ever
 *	used.
 * @close_uctx: Called when the uctx is destroyed, usually when the FD is
 *	closed.
 * @info: Implement FWCTL_INFO. Return a kmalloc() memory that is copied to
 *	out_device_data. On input length indicates the size of the user buffer
 *	on output it indicates the size of the memory. The driver can ignore
 *	length on input, the core code will handle everything.
 */
struct fwctl_ops {
	enum fwctl_device_type device_type;
	size_t uctx_size;
	int (*open_uctx)(struct fwctl_uctx *uctx);
	void (*close_uctx)(struct fwctl_uctx *uctx);
	void *(*info)(struct fwctl_uctx *uctx, size_t *length);
};

/**
 * struct fwctl_device - Per-driver registration struct
 * @dev: The sysfs (class/fwctl/fwctlXX) device
 *
 * Each driver instance will have one of these structs with the driver
 * private data following immeidately after. This struct is refcounted,
 * it is freed by calling fwctl_put().
 */
struct fwctl_device {
	struct device dev;
	/* private: */
	struct cdev cdev;

	struct rw_semaphore registration_lock;
	struct mutex uctx_list_lock;
	struct list_head uctx_list;
	const struct fwctl_ops *ops;
};

struct fwctl_device *_fwctl_alloc_device(struct device *parent,
					 const struct fwctl_ops *ops,
					 size_t size);
/**
 * fwctl_alloc_device - Allocate a fwctl
 * @parent: Physical device that provides the FW interface
 * @ops: Driver ops to register
 * @drv_struct: 'struct driver_fwctl' that holds the struct fwctl_device
 * @member: Name of the struct fwctl_device in @drv_struct
 *
 * This allocates and initializes the fwctl_device embedded in the drv_struct.
 * Upon success the pointer must be freed via fwctl_put(). Returns NULL on
 * failure. Returns a 'drv_struct *' on success, NULL on error.
 */
#define fwctl_alloc_device(parent, ops, drv_struct, member)                  \
	container_of(_fwctl_alloc_device(                                    \
			     parent, ops,                                    \
			     sizeof(drv_struct) +                            \
				     BUILD_BUG_ON_ZERO(                      \
					     offsetof(drv_struct, member))), \
		     drv_struct, member)

static inline struct fwctl_device *fwctl_get(struct fwctl_device *fwctl)
{
	get_device(&fwctl->dev);
	return fwctl;
}
static inline void fwctl_put(struct fwctl_device *fwctl)
{
	put_device(&fwctl->dev);
}
DEFINE_FREE(fwctl, struct fwctl_device *, if (_T) fwctl_put(_T));

int fwctl_register(struct fwctl_device *fwctl);
void fwctl_unregister(struct fwctl_device *fwctl);

/**
 * struct fwctl_uctx - Per user FD context
 * @fwctl: fwctl instance that owns the context
 *
 * Every FD opened by userspace will get a unique context allocation. Any driver
 * private data will follow immediately after.
 */
struct fwctl_uctx {
	struct fwctl_device *fwctl;
	/* private: */
	/* Head at fwctl_device::uctx_list */
	struct list_head uctx_list_entry;
};

#endif
