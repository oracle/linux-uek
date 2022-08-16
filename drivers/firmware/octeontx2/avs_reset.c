// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2021 - 2022 Marvell Technology Ltd.
 *
 * Driver allows to control AVS bus reset from Linux userspace level.
 * Userspace is able to signal some of the AVS devices about upcoming reboot.
 * This allows to set AVS bus devices into consistent state.
 */

#define pr_fmt(fmt)	"avs-reset: " fmt

#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/err.h>
#include <linux/firmware/octeontx2/mub.h>
#include <linux/spinlock.h>

/* SMC call responsible for AVS bus operations */
#define PLAT_OCTEONTX_SET_AVS_STATUS	0xc2000b08
/* Status value can be only 0 or 1 */
#define AVS_RESET_STATUS_MAX	2

struct mub_avs_reset {
	int avs_status; /* Keeps the AVS bus reset status */
	spinlock_t data_lock; /* Ensures the state is properly shared */

	struct mub_device *device;
};

/* Keep state globally, this is simple driver */
static struct mub_avs_reset avs_reset;

/* Use iterator approach to process data.
 * it's safer than simple branching with strncmp
 */
struct avs_status_desc {
	const char *name;
	int status;
	size_t sz;
};

/* Possible input values translated to valid states values */
static const struct avs_status_desc status_values[] = {
	{ "stop", 0, sizeof("stop") - 1 },
	{ "start", 1, sizeof("start") - 1 },
	{ NULL, 0, 0 } /* Sentinel */
};

/* Show AVS bus reset status */
static ssize_t status_show(struct mub_device *dev, char *buf)
{
	int status;
	struct mub_avs_reset *ar = (struct mub_avs_reset *)mub_get_data(dev);
	const char *name;

	spin_lock(&ar->data_lock);
	status = ar->avs_status;
	spin_unlock(&ar->data_lock);

	name = "unknown";
	if (status < AVS_RESET_STATUS_MAX)
		name = status_values[status].name;

	return sysfs_emit(buf, "%s\n", name);
}

/* Store new status of AVS bus reset */
static ssize_t status_store(struct mub_device *dev, const char *buf,
			    size_t count)
{
	struct mub_avs_reset *ar = (struct mub_avs_reset *)mub_get_data(dev);
	const struct avs_status_desc *desc;
	struct arm_smccc_res res;
	size_t sz;
	int ret;

	desc = &status_values[0];
	while (desc != &status_values[ARRAY_SIZE(status_values) - 1]) {
		sz = count > desc->sz ? desc->sz : count;

		if (!strncmp(buf, desc->name, sz))
			break;
		desc++;
	}

	/* Are we looking at sentinel? */
	if (!desc->name && !desc->sz)
		return -EINVAL;

	ret = mub_do_smc(dev, PLAT_OCTEONTX_SET_AVS_STATUS, desc->status,
			 0, 0, 0, 0, 0, 0, &res);
	if (ret)
		return ret;

	if (res.a0)
		return -EFAULT;

	spin_lock(&ar->data_lock);
	ar->avs_status = desc->status;
	spin_unlock(&ar->data_lock);

	return count;
}

MUB_ATTR_RW(reset, status_show, status_store);

static struct attribute *reset_attrs[] = {
	MUB_TO_ATTR(reset),
	NULL,
};

static const struct attribute_group reset_attr_group = {
	.attrs = reset_attrs,
};

static const struct attribute_group *reset_attr_groups[] = {
	&reset_attr_group,
	NULL,
};

static int __init avs_reset_init(void)
{
	struct mub_avs_reset *ar;

	ar = &avs_reset;
	ar->device = mub_device_register("avs-reset",
					 MUB_SOC_TYPE_9X | MUB_SOC_TYPE_10X,
					 reset_attr_groups);
	if (IS_ERR(ar->device))
		return PTR_ERR(ar->device);

	mub_set_data(ar->device, ar);
	ar->avs_status = 1; /* AVS bus is active by default */
	spin_lock_init(&ar->data_lock);

	return 0;
}
module_init(avs_reset_init);

static void __exit avs_reset_exit(void)
{
	struct mub_avs_reset *ar;

	ar = &avs_reset;
	mub_device_unregister(ar->device);

	pr_debug("Device unregistered!\n");
}
module_exit(avs_reset_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("AVS bus reset utility driver");
MODULE_AUTHOR("Wojciech Bartczak <wbartczak@marvell.com>");
