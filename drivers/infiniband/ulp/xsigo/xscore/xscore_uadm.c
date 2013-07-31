/*
 * Copyright (c) 2006-2012 Xsigo Systems Inc.  All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 */

/*
 * This file implements USPACE protocol
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/sched.h>
#include <linux/poll.h>

#include "xscore_priv.h"
#include "xscore.h"
#include "xsmp_common.h"
#include "xscore.h"

#define	PFX	"UADM"

static dev_t xscore_devt;
static struct cdev xscore_cdev;
static struct list_head read_list;
static int xscore_svc_id = -1;
struct mutex mut_lock;
static unsigned long xscore_uadm_flags;
static atomic_t list_count;
static struct class *uadm_class;
static DECLARE_WAIT_QUEUE_HEAD(read_wait);

#define	XSCORE_UADM_OPEN	0x1

#define	XSCORE_UADM_MAX_MSGS	256

struct xscore_uadm_hdr {
	u8 opcode;
	int flags;
	xsmp_cookie_t xsmp_hndl;
};

enum {
	XSCORE_UADM_CHASSIS_MSG = 1,
	XSCORE_UADM_REG_MSG,
};

struct xscore_uadm_msg {
	struct list_head list;
	struct xscore_uadm_hdr hdr;
	void *msg;
	int len;
};

/*
 * Called from thread context
 */
void xscore_uadm_receive(xsmp_cookie_t xsmp_hndl, u8 *data, int len)
{
	struct xscore_uadm_msg *msg;
	int err = 0;

	mutex_lock(&mut_lock);
	if (!xsigod_enable) {
		err++;
		goto out;
	}
	if (atomic_read(&list_count) > XSCORE_UADM_MAX_MSGS) {
		UADM_ERROR("%s: receive Q full, dropping packet\n",
			   __func__);
		err++;
		goto out;
	}
	msg = kmalloc(sizeof(*msg), GFP_KERNEL);
	if (!msg) {
		err++;
		goto out;
	}
	msg->msg = data;
	msg->hdr.xsmp_hndl = xsmp_hndl;
	msg->hdr.flags = 0;
	msg->hdr.opcode = XSCORE_UADM_CHASSIS_MSG;
	msg->len = len;
	list_add_tail(&msg->list, &read_list);
	atomic_inc(&list_count);
	wake_up_interruptible(&read_wait);
out:
	if (err)
		kfree(data);
	mutex_unlock(&mut_lock);
}

/*
 * Called from thread context
 */
static void xscore_event_handler(xsmp_cookie_t xsmp_hndl, int event)
{
	mutex_lock(&mut_lock);
	switch (event) {
	default:
		break;
	}
	mutex_unlock(&mut_lock);
}

static int xscore_uadm_register(void)
{
	struct xsmp_service_reg_info sinfo = {
		.receive_handler = xscore_uadm_receive,
		.event_handler = xscore_event_handler,
		.ctrl_message_type = XSMP_MESSAGE_TYPE_USPACE,
		.resource_flag_index = RESOURCE_FLAG_INDEX_USPACE
	};
	int ret = 0;

	UADM_FUNCTION("%s:\n", __func__);
	xscore_svc_id = xcpm_register_service(&sinfo);
	if (xscore_svc_id < 0) {
		UADM_ERROR("%s: xcpm_register_service failed %d\n",
			   __func__, xscore_svc_id);
		clear_bit(XSCORE_UADM_OPEN, &xscore_uadm_flags);
		ret = -ENODEV;
	}

	UADM_INFO("%s: Successful\n", __func__);
	return ret;
}

static int xscore_uadm_open(struct inode *inode, struct file *file)
{
	int ret = 0;

	if (test_and_set_bit(XSCORE_UADM_OPEN, &xscore_uadm_flags)) {
		UADM_ERROR("%s: Already open\n", __func__);
		ret = -EBUSY;
	}
	return ret;
}

static int xscore_uadm_release(struct inode *inode, struct file *file)
{
	struct xscore_uadm_msg *msg, *tmsg;

	mutex_lock(&mut_lock);
	/* unregister service */
	xcpm_unregister_service(xscore_svc_id);
	xscore_svc_id = -1;
	list_for_each_entry_safe(msg, tmsg, &read_list, list) {
		list_del(&msg->list);
		kfree(msg->msg);
		kfree(msg);
	}
	clear_bit(XSCORE_UADM_OPEN, &xscore_uadm_flags);
	mutex_unlock(&mut_lock);
	UADM_INFO("%s: Successful\n", __func__);
	return 0;
}

static unsigned int xscore_uadm_poll(struct file *file, poll_table *wait)
{
	unsigned int pollflags = 0;

	poll_wait(file, &read_wait, wait);
	mutex_lock(&mut_lock);
	if (!list_empty(&read_list))
		pollflags = POLLIN | POLLRDNORM;
	mutex_unlock(&mut_lock);
	return pollflags;
}

#define	HDR_LEN	(sizeof(struct xscore_uadm_hdr))

/*
 * Make it a blocking call later XXX
 */
static ssize_t xscore_uadm_read(struct file *file, char __user *buf,
				size_t count, loff_t *ppos)
{
	int ret;
	struct xscore_uadm_msg *msg;

	mutex_lock(&mut_lock);
	if (list_empty(&read_list)) {
		ret = -ENODATA;
		goto out;
	}
	msg = list_entry(read_list.next, struct xscore_uadm_msg, list);
	list_del(&msg->list);
	atomic_dec(&list_count);
	ret = msg->len > (count - HDR_LEN) ? (count - HDR_LEN) : msg->len;
	if (copy_to_user(buf, &msg->hdr, HDR_LEN) ||
	    copy_to_user(buf + HDR_LEN, msg->msg, ret))
		ret = -EFAULT;
	*ppos += (ret + HDR_LEN);
	kfree(msg->msg);
	kfree(msg);
out:
	mutex_unlock(&mut_lock);
	return ret;
}

static ssize_t xscore_uadm_write(struct file *file, const char __user *buf,
				 size_t count, loff_t *ppos)
{
	void *msg = NULL;
	int len;
	struct xscore_uadm_hdr hdr;
	int ret;

	len = count - HDR_LEN;
	if (len) {
		msg = kmalloc(len, GFP_KERNEL);
		if (!msg)
			return -ENOMEM;
	}
	mutex_lock(&mut_lock);
	if (copy_from_user(&hdr, buf, HDR_LEN) ||
	    (len && copy_from_user(msg, buf + HDR_LEN, len))) {
		UADM_ERROR("%s: copy_from_user error\n", __func__);
		ret = -EFAULT;
		if (msg != NULL)
			kfree(msg);
		goto out;
	}
	/*
	 * Check type of command and handle it accordingly
	 */
	switch (hdr.opcode) {
	case XSCORE_UADM_REG_MSG:
		if (xscore_uadm_register())
			ret = -EBUSY;
		else {
			ret = count;
			*ppos += count;
		}
		goto out;
	default:
		break;
	}

	ret = xcpm_send_message(hdr.xsmp_hndl, xscore_svc_id, msg, len);
	if (ret) {
		UADM_ERROR("%s: xcpm_send_message error  %d sess hndl: %p\n",
			   __func__, ret, hdr.xsmp_hndl);
		ret = -EINVAL;
		if (msg != NULL)
			kfree(msg);
		goto out;
	}
	ret = count;
	*ppos += count;
out:
	mutex_unlock(&mut_lock);
	return ret;
}

static const struct file_operations xscore_fops = {
	.open = xscore_uadm_open,
	.release = xscore_uadm_release,
	.read = xscore_uadm_read,
	.write = xscore_uadm_write,
	.poll = xscore_uadm_poll,
	.owner = THIS_MODULE,
};

void xscore_uadm_destroy(void)
{
	device_destroy(uadm_class,
		       MKDEV(MAJOR(xscore_devt), MINOR(xscore_devt)));
	class_destroy(uadm_class);
	cdev_del(&xscore_cdev);
	unregister_chrdev_region(xscore_devt, 1);
	mutex_destroy(&mut_lock);
}

int xscore_uadm_init(void)
{
	int result;

	INIT_LIST_HEAD(&read_list);
	mutex_init(&mut_lock);

	result = alloc_chrdev_region(&xscore_devt, 0, 1, "kxsigod");
	if (result) {
		UADM_ERROR("%s: alloc_chrdev_region error %d\n", __func__,
			   result);
		mutex_destroy(&mut_lock);
		return result;
	}

	cdev_init(&xscore_cdev, &xscore_fops);

	result = cdev_add(&xscore_cdev, xscore_devt, 1);
	if (result) {
		UADM_ERROR("%s: cdev_add error %d\n", __func__, result);
		unregister_chrdev_region(xscore_devt, 1);
		mutex_destroy(&mut_lock);
		return result;
	}
	uadm_class = class_create(THIS_MODULE, "kxsigod");
	if (IS_ERR(uadm_class)) {
		result = PTR_ERR(uadm_class);
		UADM_ERROR("%s: class_create  error %d\n", __func__,
			   result);
		cdev_del(&xscore_cdev);
		unregister_chrdev_region(xscore_devt, 1);
		mutex_destroy(&mut_lock);
		return result;
	}
	device_create(uadm_class, 0,
		      MKDEV(MAJOR(xscore_devt), MINOR(xscore_devt)), 0,
		      "kxsigod");
	return 0;
}
