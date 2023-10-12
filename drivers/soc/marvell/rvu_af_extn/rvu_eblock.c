// SPDX-License-Identifier: GPL-2.0
/* Marvell RVU Admin Function driver - block extension interface
 *
 * This driver is loosely based on drivers/vfio/vfio.c
 *
 * Copyright (C) 2023 Marvell.
 *
 */

#include <linux/list.h>
#include <linux/mutex.h>
#include "rvu.h"
#include "rvu_eblock.h"

enum rvu_af_state {
	RVU_AF_INACTIVE, /* RVU AF device is in enabled state */
	RVU_AF_ACTIVE, /* RVU AF device is in disabled state */
};

/**
 * struct rvu_eb_bus - Extension block bus
 * @driver_list: list of registered drivers
 * @device_list:	list of enumerated devices
 * @state: reference state of RVU AF device
 * @lock: bus lock
 */
struct rvu_eb_bus {
	struct list_head	driver_list;
	struct list_head	device_list;
	int			state;
	/* TODO: Replace this with a RCU lock variant since this is mostly a read only
	 * list
	 */
	struct mutex		lock;
};

static struct rvu_eb_bus eb_bus = {
	.driver_list = LIST_HEAD_INIT(eb_bus.driver_list),
	.device_list = LIST_HEAD_INIT(eb_bus.device_list),
	.state = RVU_AF_INACTIVE,
	.lock = __MUTEX_INITIALIZER(eb_bus.lock),
};

/**
 * struct rvu_eb_device - Extension block device
 * @hw_block: RVU block hardware data
 * @driver: matching driver
 * @priv_data: private data for each instance
 * @node: node entry in the block list
 */
struct rvu_eb_device {
	struct rvu_block	*hw_block;
	struct rvu_eb_driver	*driver;
	void			*priv_data;
	struct list_head	node;
};

/**
 * struct rvu_eb_driver - Extension block driver
 * @ops: call back ops for the RVU blocks
 * @rcount: reference count for the driver ops
 * @node: node entry in the driver list
 */
struct rvu_eb_driver {
	const struct rvu_eblock_driver_ops	*ops;
	refcount_t				rcount;
	struct list_head			node;
};

#define for_each_eblock_dev(dev)		\
		list_for_each_entry(dev, &eb_bus.device_list, node)

#define for_each_eblock_dev_safe(dev, tmp)		\
		list_for_each_entry_safe(dev, tmp, &eb_bus.device_list, node)

#define for_each_eblock_drv(drv)		\
	list_for_each_entry(drv, &eb_bus.driver_list, node)

/* Gets the device to enabled mode */
static int rvu_eb_device_attach(struct rvu_eb_device *eblock,
			      struct rvu *rvu, int blkaddr)
{
	struct rvu_eb_driver *driver;
	bool match = false;
	void *data = NULL;
	int err = 0;

	for_each_eblock_drv(driver) {
		data = driver->ops->probe(rvu, blkaddr);
		if (!IS_ERR_OR_NULL(data)) {
			match = true;
			break;
		}
	}
	if (!match)
		return -EAGAIN;

	eblock->priv_data = data;

	/* Run all the init ops required to get the device active */
	err = driver->ops->setup(eblock->hw_block, eblock->priv_data);
	if (err)
		goto remove;
	err = driver->ops->init(eblock->hw_block, eblock->priv_data);
	if (err)
		goto free;

	err = driver->ops->register_interrupt(eblock->hw_block,
							eblock->priv_data);
	if (err)
		goto free;

	/* add a reference */
	refcount_inc(&driver->rcount);

	/*
	 * Ensure the device is initialized before we expose the run time ops
	 * like mailbox handling etc.
	 */
	smp_wmb();

	/* Bind the driver */
	eblock->driver = driver;
	return 0;

free:
	driver->ops->free(eblock->hw_block, eblock->priv_data);
remove:
	driver->ops->remove(eblock->hw_block, eblock->priv_data);

	return err;
}

/* Gets the device to disabled mode */
static int rvu_eb_device_detach(struct rvu_eb_device *eblock)
{
	struct rvu_eb_driver *driver = eblock->driver;

	if (!driver)
		goto out;

	eblock->driver = NULL;

	/* Ensure the driver unbinding happens before exit operations */
	smp_wmb();

	/* Run all the exit ops required to get the device inactive */
	driver->ops->unregister_interrupt(eblock->hw_block,
							eblock->priv_data);
	driver->ops->free(eblock->hw_block, eblock->priv_data);
	driver->ops->remove(eblock->hw_block, eblock->priv_data);

	eblock->priv_data = NULL;

	refcount_dec(&driver->rcount);
out:
	return 0;
}

static inline bool is_eblock(int blkaddr)
{
	switch (blkaddr) {
	/* List of extension blocks supported */
	case BLKADDR_REE0:
	case BLKADDR_REE1:
		return true;
	default:
		return false;
	};
}

/* API for block addition and removal from the extension bus */
void rvu_eblock_device_add(struct rvu *rvu, struct rvu_block *hwblock,
			  int blkaddr)
{
	struct rvu_eb_device *eblock;

	/* Add only the extension blocks */
	if (!is_eblock(blkaddr))
		goto out;

	/* Initialize few basic stuff that are generic */
	hwblock->addr = blkaddr;
	hwblock->rvu = rvu;

	eblock = kzalloc(sizeof(*eblock), GFP_KERNEL);
	if (!eblock)
		goto out;
	eblock->hw_block = hwblock;

	mutex_lock(&eb_bus.lock);
	list_add(&eblock->node, &eb_bus.device_list);
	mutex_unlock(&eb_bus.lock);
out:
	return;
}

static void rvu_eb_device_remove(struct rvu_eb_device *eblock)
{
	/* We dont expect a device to be removed from the bus that is in
	 * operation.
	 */
	WARN_ON(eblock->driver != NULL);

	/* Assumes necessary bus lock is taken by the caller */
	list_del(&eblock->node);
	kfree(eblock);
}

static void rvu_eb_bus_event(int state)
{
	mutex_lock(&eb_bus.lock);
	eb_bus.state = state;
	mutex_unlock(&eb_bus.lock);
}

static bool is_rvu_af_state_active(void)
{
	return (eb_bus.state == RVU_AF_ACTIVE);
}

static int rvu_eb_attach_all(void)
{
	struct rvu_eb_device *eblock;
	struct rvu_block *hwblock;

	mutex_lock(&eb_bus.lock);

	if (!is_rvu_af_state_active())
		goto out;

	for_each_eblock_dev(eblock) {
		hwblock = eblock->hw_block;
		/* Driver binded devices indicate initialized devices */
		if (eblock->driver)
			continue;
		rvu_eb_device_attach(eblock, hwblock->rvu, hwblock->addr);
	}

out:
	mutex_unlock(&eb_bus.lock);
	return 0;
}

static int rvu_eb_detach_all(void)
{
	struct rvu_eb_device *eblock;

	mutex_lock(&eb_bus.lock);

	for_each_eblock_dev(eblock) {
		rvu_eb_device_detach(eblock);
	}

	mutex_unlock(&eb_bus.lock);
	return 0;
}

static void rvu_eb_remove_all(void)
{
	struct rvu_eb_device *eblock;
	struct rvu_eb_device *tmp;

	mutex_lock(&eb_bus.lock);

	for_each_eblock_dev_safe(eblock, tmp) {
		rvu_eb_device_remove(eblock);
	}

	mutex_unlock(&eb_bus.lock);
}

int rvu_eblock_init(void)
{
	/* RVU probe is success */
	rvu_eb_bus_event(RVU_AF_ACTIVE);

	rvu_eb_attach_all();
	return 0;
}

void rvu_eblock_exit(void)
{
	/* RVU AF exit */
	rvu_eb_bus_event(RVU_AF_INACTIVE);

	rvu_eb_detach_all();
	rvu_eb_remove_all();
}

/* Mbox handler */
static void *rvu_eb_get_mbox_handler(int _id)
{
	struct rvu_eb_driver *driver;
	struct mbox_op *op;

	for_each_eblock_drv(driver) {
		op = driver->ops->mbox_op;
		if (_id >= op->start && _id <= op->end)
			return op->handler;
	}

	return NULL;
}

int rvu_eblock_mbox_handler(struct otx2_mbox *mbox, int devid,
			    struct mbox_msghdr *req)
{
	int (*mbox_handler)(struct otx2_mbox *mbox, int devid,
			    struct mbox_msghdr *req);
	int _id;

	/* check if valid, if not reply with a invalid msg */
	if (req->sig != OTX2_MBOX_REQ_SIG)
		goto bad_message;

	_id = req->id;

	mbox_handler = rvu_eb_get_mbox_handler(_id);
	if (!mbox_handler)
		goto bad_message;

	return mbox_handler(mbox, devid, req);

bad_message:
	return -EINVAL;
}

/* APIs for driver register / unregister */
int rvu_eblock_register_driver(const struct rvu_eblock_driver_ops *ops)
{
	struct rvu_eb_driver *driver;

	if (!ops->probe || !ops->init || !ops->setup ||
	    !ops->register_interrupt)
		return -EINVAL;

	if (!ops->remove || !ops->free ||
	    !ops->unregister_interrupt)
		return -EINVAL;

	driver = kzalloc(sizeof(*driver), GFP_KERNEL);
	if (!driver)
		return -ENOMEM;

	driver->ops = ops;
	refcount_set(&driver->rcount, 1);

	mutex_lock(&eb_bus.lock);
	list_add(&driver->node, &eb_bus.driver_list);
	mutex_unlock(&eb_bus.lock);

	/* See if we can attach any probed devices */
	rvu_eb_attach_all();

	return 0;
}
EXPORT_SYMBOL(rvu_eblock_register_driver);

void rvu_eblock_unregister_driver(struct rvu_eblock_driver_ops *ops)
{
	struct rvu_eb_driver *driver = NULL;
	struct rvu_eb_device *eblock;

	mutex_lock(&eb_bus.lock);

	/* Detach all eblock instances before we unregister */
	for_each_eblock_dev(eblock) {
		if (ops == eblock->driver->ops) {
			if (!driver)
				driver = eblock->driver;
			else
				WARN_ON(driver != eblock->driver);
			rvu_eb_device_detach(eblock);
		}
	}

	list_del(&driver->node);
	mutex_unlock(&eb_bus.lock);

	WARN_ON(!refcount_sub_and_test(1, &driver->rcount));
	kfree(driver);
}
EXPORT_SYMBOL(rvu_eblock_unregister_driver);

void rvu_eblock_module_init(void)
{
	/*
	 * Module init of all eblock drivers that are part of RVU AF
	 * module goes here.
	 */
	ree_eb_module_init();
}

void rvu_eblock_module_exit(void)
{
	/*
	 * Module exit of all eblock drivers that are part of RVU AF
	 * module goes here.
	 */
	ree_eb_module_exit();
}
