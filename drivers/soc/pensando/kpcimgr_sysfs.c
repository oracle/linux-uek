// SPDX-License-Identifier: GPL-2.0
/*
 * Kernel PCIE Manager SYSFS functions
 *
 * Copyright (c) 2021, 2022, Oracle and/or its affiliates.
 */

#include "kpcimgr_api.h"

int kpcimgr_active_port;

/* 'valid' read returns value of valid field */
static ssize_t valid_show(struct device *dev,
			  struct device_attribute *attr,
			  char *buf)
{
	kstate_t *ks = get_kstate();

	return sprintf(buf, "%x\n", ks->valid);
}

/* 'valid' write causes invalidation, regardless of value written */
static ssize_t valid_store(struct device *dev,
			   struct device_attribute *attr,
			   const char *buf,
			   size_t count)
{
	kstate_t *ks = get_kstate();

	if (ks->running) {
		kpcimgr_stop_running();
		pr_info("%s: kpcimgr has stopped running\n", __func__);
	}
	ks->valid = 0;
	ks->debug = 0;
	if (ks->mod) {
		module_put(ks->mod);
		ks->mod = NULL;
		ks->code_base = NULL;
	}

	pr_info("%s: code unloaded\n", __func__);
	return count;
}

static ssize_t running_show(struct device *dev,
			    struct device_attribute *attr,
			    char *buf)
{
	kstate_t *ks = get_kstate();

	return sprintf(buf, "%x\n", ks->running | ks->debug);
}

static ssize_t running_store(struct device *dev,
			     struct device_attribute *attr,
			     const char *buf,
			     size_t count)
{
	kstate_t *ks = get_kstate();
	ssize_t rc;
	long val;

	rc = kstrtol(buf, 0, &val);
	if (rc)
		return rc;

	if (!ks->valid)
		return -EINVAL;

	if (val == 0) {
		if (ks->running) {
			kpcimgr_stop_running();
			pr_info("%s: kpcimgr has stopped polling\n", __func__);
		}
	} else {
		if (ks->running) {
			pr_info("%s: kpcimgr is already running\n", __func__);
		} else {
			ks->active_port = ffs(kpcimgr_active_port) - 1;
			pr_info("%s: kpcimgr will begin running on port %d\n",
				__func__, ks->active_port);
			kpcimgr_start_running();
		}
		ks->debug = val & 0xfff0;
	}

	return count;
}

static ssize_t cfgval_show(struct device *dev,
			   struct device_attribute *attr,
			   char *buf)
{
	kstate_t *ks = get_kstate();

	return sprintf(buf, "%x\n", ks->cfgval);
}

static ssize_t cfgval_store(struct device *dev,
			    struct device_attribute *attr,
			    const char *buf,
			    size_t count)
{
	kstate_t *ks = get_kstate();
	ssize_t rc;
	long val;

	rc = kstrtol(buf, 0, &val);
	if (rc)
		return rc;

	if (!ks->valid)
		return -EINVAL;

	ks->cfgval = val;
	return count;
}

static ssize_t lib_version_show(struct device *dev,
				struct device_attribute *attr,
				char *buf)
{
	kstate_t *ks = get_kstate();

	if (!ks->valid)
		return -ENODEV;

	return sprintf(buf, "%d.%d\n", ks->lib_version_major,
		       ks->lib_version_minor);
}

static ssize_t mgr_version_show(struct device *dev,
				struct device_attribute *attr,
				char *buf)
{
	return sprintf(buf, "%d\n", KPCIMGR_KERNEL_VERSION);
}

/* event queue peek */
static ssize_t event_queue_read(struct file *file, struct kobject *kobj,
				struct bin_attribute *attr, char *out,
				loff_t off, size_t count)
{
	kstate_t *ks = get_kstate();

	/* is queue empty? */
	if (ks->evq_head == ks->evq_tail)
		return 0;

	kpci_memcpy(out, (void *)ks->evq[ks->evq_tail], EVENT_SIZE);
	return EVENT_SIZE;
}

/*
 * This function is for testing. It injects an event onto the
 * event queue, simulating an event notification from h/w.
 */
static ssize_t event_queue_write(struct file *filp, struct kobject *kobj,
				 struct bin_attribute *bin_attr, char *buf,
				 loff_t off, size_t count)
{
	kstate_t *ks = get_kstate();

	if (count != EVENT_SIZE)
		return -EINVAL;

	if ((ks->evq_head + 1) % EVENT_QUEUE_LENGTH == ks->evq_tail)
		return -ENOSPC;

	kpci_memcpy((void *)ks->evq[ks->evq_head], buf, EVENT_SIZE);
	ks->evq_head = (ks->evq_head + 1) % EVENT_QUEUE_LENGTH;
	wake_up_event_queue();

	return EVENT_SIZE;
}

static ssize_t kstate_read(struct file *file, struct kobject *kobj,
			   struct bin_attribute *attr, char *out,
			   loff_t off, size_t count)
{
	kstate_t *ks = get_kstate();

	kpci_memcpy(out, (void *)ks + off, count);
	return count;
}

static DEVICE_ATTR_RW(valid);
static DEVICE_ATTR_RW(running);
static DEVICE_ATTR_RW(cfgval);
static DEVICE_ATTR_RO(lib_version);
static DEVICE_ATTR_RO(mgr_version);
static DEVICE_INT_ATTR(active_port, 0644, kpcimgr_active_port);
static BIN_ATTR_RO(kstate, sizeof(kstate_t));
static BIN_ATTR_RW(event_queue, EVENT_SIZE);

static struct attribute *dev_attrs[] = {
	&dev_attr_valid.attr,
	&dev_attr_running.attr,
	&dev_attr_cfgval.attr,
	&dev_attr_active_port.attr.attr,
	&dev_attr_lib_version.attr,
	&dev_attr_mgr_version.attr,
	NULL,
};

static struct bin_attribute *dev_bin_attrs[] = {
	&bin_attr_kstate,
	&bin_attr_event_queue,
	NULL,
};

const struct attribute_group kpci_attr_group = {
	.attrs = dev_attrs,
	.bin_attrs = dev_bin_attrs,
};

void kpcimgr_sysfs_setup(struct platform_device *pfdev)
{
	if (sysfs_create_group(&pfdev->dev.kobj, &kpci_attr_group)) {
		pr_err("KPCIMGR:sysfs_create_group failed\n");
		return;
	}

	if (sysfs_create_link(kernel_kobj, &pfdev->dev.kobj, "kpcimgr")) {
		pr_err("KPCIMGR: failed top create sysfs link\n");
		return;
	}
}
