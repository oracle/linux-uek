/*
 * Copyright (c) 2021, Pensando Systems Inc.
 */

#include <linux/kobject.h>
#include <linux/sysfs.h>
#include <linux/fs.h>
#include <linux/types.h>
#include <linux/device.h>
#include <linux/device.h>
#include <linux/types.h>
#include <linux/string.h>

#include "penfw_sysfs.h"
#include "penfw.h"

extern struct kobject *pensando_fw_kobj_get(void);

static struct kobject *pensando_kobj;
static struct kobject *penfw_kobject;
static struct kobject *pentrust_kobject;
static struct kobject *bl1_kobject;
static struct kobject *bl31_kobject;
static struct kobject *lifecycle_kobject;

static ssize_t pentrust_show(struct kobject *kobj, struct kobj_attribute *attr,
			     char *buf)
{
	struct penfw_call_args args = {0};

	args.a1 = PENFW_OP_GET_PENTRUST_STA;
	penfw_smc(&args);

	if (args.a0 < 0)
		return sprintf(buf, "Error\n");

	if (!strcmp(attr->attr.name, "version"))
		return sprintf(buf, "%llu\n", (args.a0 & 0xffffffff));
	else if (!strcmp(attr->attr.name, "upgrade"))
		return sprintf(buf, "%llu\n", (args.a1 >> 1) & 1);
	else if (!strcmp(attr->attr.name, "image_slot"))
		return sprintf(buf, "%llu\n", (args.a1 & 1));
	else
		return sprintf(buf, "\n");
}

static ssize_t pentrust_show_version(struct kobject *kobj, struct kobj_attribute *attr,
			     char *buf)
{
	struct penfw_call_args args = {0};
	int major, minor1, minor2;

	args.a1 = PENFW_OP_GET_PENTRUST_VERSION;
	penfw_smc(&args);

	if (args.a0 < 0)
		return sprintf(buf, "Error\n");

	if (!strcmp(attr->attr.name, "sw_version")) {
		major = args.a1 >> 32;
		minor1 = (args.a1 & 0xffff0000) >> 16;
		minor2 = args.a1 & 0xffff;
		return sprintf(buf, "%d.%d.%d\n", major, minor1, minor2);
	} else if (!strcmp(attr->attr.name, "crypto_version")) {
		major = args.a2 >> 32;
		minor1 = (args.a2 & 0xffff0000) >> 16;
		minor2 = args.a2 & 0xffff;
		return sprintf(buf, "%d.%d.%d\n", major, minor1, minor2);
	} else
		return sprintf(buf, "\n");
}

static ssize_t pentrust_store(struct kobject *kobj, struct kobj_attribute *attr,
			      const char *buf, size_t count)
{
	struct penfw_call_args args = {0};

	if (strcmp(attr->attr.name, "upgrade") != 0)
		return -1;
	args.a1 = PENFW_OP_SET_PENTRUST_UPG;
	penfw_smc(&args);
	if (args.a0 < 0)
		return -EIO;

	return count;
}

static ssize_t bl1_show(struct kobject *kobj, struct kobj_attribute *attr,
			char *buf)
{
	struct penfw_call_args args = {0};

	args.a1 = PENFW_OP_GET_BL1_STA;
	penfw_smc(&args);

	if (args.a0 < 0)
		return sprintf(buf, "Error\n");

	if (!strcmp(attr->attr.name, "version"))
		return sprintf(buf, "%llu\n", (args.a0 & 0xffffffff));
	else if (!strcmp(attr->attr.name, "ar_version"))
		return sprintf(buf, "%llu\n", ((args.a0 >> 32) & 0xff));
	else if (!strcmp(attr->attr.name, "upgrade"))
		return sprintf(buf, "%llu\n", (args.a1 >> 1) & 1);
	else if (!strcmp(attr->attr.name, "image_slot"))
		return sprintf(buf, "%llu\n", (args.a1 & 1));
	else
		return sprintf(buf, "\n");
}

static ssize_t bl1_ar_nvcntr_show(struct kobject *kobj,
				  struct kobj_attribute *attr, char *buf)
{
	struct penfw_call_args args = {0};

	args.a1 = PENFW_OP_GET_BL1_AR_NVCNTR;
	penfw_smc(&args);

	if (args.a0 < 0)
		return sprintf(buf, "Error\n");

	if (!strcmp(attr->attr.name, "ar_nv_cntr"))
		return sprintf(buf, "%llu\n", (args.a0 & 0xffffffff));
	else
		return sprintf(buf, "\n");
}

static ssize_t bl1_store(struct kobject *kobj, struct kobj_attribute *attr,
			 const char *buf, size_t count)
{
	struct penfw_call_args args = {0};

	if (strcmp(attr->attr.name, "upgrade") != 0)
		return -1;
	args.a1 = PENFW_OP_SET_BL1_UPG;
	penfw_smc(&args);
	if (args.a0 < 0)
		return -EIO;

	return count;
}

static ssize_t bl31_show(struct kobject *kobj, struct kobj_attribute *attr,
			 char *buf)
{
	struct penfw_call_args args = {0};
	char vers[256];
	uint64_t val;
	int byte, shift;

	args.a1 = PENFW_OP_GET_BL31_SW_VER;
	penfw_smc(&args);

	if (args.a0 < 0)
		return -EIO;

	for (byte = 0; byte < 256 - 1; byte++) {
		if ((byte / 8) == 0)
			val = args.a0;
		else if ((byte / 8) == 1)
			val = args.a1;
		else if ((byte / 8) == 2)
			val = args.a2;
		else
			val = args.a3;

		shift = (byte * 8) % 64;
		vers[byte] = (val >> (shift)) & 0x7f;
		if (vers[byte] == 0)
			break;
	}
	vers[255] = 0;

	return sprintf(buf, "%s\n", vers);
}

static const char *_lcs_to_str(int lcs_state)
{
	switch (lcs_state) {
	case 0:
		return "disabled";
	case 1:
		return "open";
	case 2:
		return "soft_prod";
	case 3:
		return "prod";
	case 4:
		return "rip";
	default:
		return "unknown";
	}
}

static ssize_t boot_lcs_show(struct kobject *kobj, struct kobj_attribute *attr,
			     char *buf)
{
	struct penfw_call_args args = {0};

	args.a1 = PENFW_OP_GET_BOOT_LCS;
	penfw_smc(&args);

	if (args.a0 < 0)
		return sprintf(buf, "Error\n");

	if (!strcmp(attr->attr.name, "boot_state"))
		return sprintf(buf, "%s\n", _lcs_to_str(args.a0));
	else
		return sprintf(buf, "\n");
}

static ssize_t next_lcs_show(struct kobject *kobj, struct kobj_attribute *attr,
			     char *buf)
{
	struct penfw_call_args args = {0};

	args.a1 = PENFW_OP_GET_NEXT_LCS;
	penfw_smc(&args);

	if (args.a0 < 0)
		return sprintf(buf, "Error\n");

	if (!strcmp(attr->attr.name, "next_state"))
		return sprintf(buf, "%s\n", _lcs_to_str(args.a0));
	else
		return sprintf(buf, "\n");
}

// pentrust attributes
static struct kobj_attribute pentrust_attr_ver = __ATTR(version, 0400,
							pentrust_show, NULL);
static struct kobj_attribute pentrust_attr_img_slot = __ATTR(image_slot, 0400,
							     pentrust_show,
							     NULL);
static struct kobj_attribute pentrust_attr_upg = __ATTR(upgrade, 0600,
							pentrust_show,
							pentrust_store);
static struct kobj_attribute pentrust_attr_sw_ver = __ATTR(sw_version, 0400,
							pentrust_show_version, NULL);

static struct kobj_attribute pentrust_attr_crypto_ver = __ATTR(crypto_version, 0400,
							pentrust_show_version, NULL);

static struct attribute *pentrust_attrs[] = {
	&pentrust_attr_ver.attr,
	&pentrust_attr_img_slot.attr,
	&pentrust_attr_upg.attr,
	&pentrust_attr_sw_ver.attr,
	&pentrust_attr_crypto_ver.attr,
	NULL
};

static struct attribute_group pentrust_attr_group = {
	.attrs = pentrust_attrs,
};

// bl1 attributes
static struct kobj_attribute bl1_attr_ver = __ATTR(version, 0400, bl1_show,
						   NULL);
static struct kobj_attribute bl1_attr_ar_version = __ATTR(ar_version, 0400,
							  bl1_show, NULL);
static struct kobj_attribute bl1_attr_img_slot = __ATTR(image_slot, 0400,
							bl1_show, NULL);
static struct kobj_attribute bl1_attr_upg = __ATTR(upgrade, 0600, bl1_show,
						   bl1_store);
static struct kobj_attribute bl1_attr_ar_nv_cntr = __ATTR(ar_nv_cntr, 0400,
							  bl1_ar_nvcntr_show,
							  NULL);

static struct attribute *bl1_attrs[] = {
	&bl1_attr_ver.attr,
	&bl1_attr_ar_version.attr,
	&bl1_attr_img_slot.attr,
	&bl1_attr_upg.attr,
	&bl1_attr_ar_nv_cntr.attr,
	NULL
};

static struct attribute_group bl1_attr_group = {
	.attrs = bl1_attrs,
};

// bl31 attributes
static struct kobj_attribute bl31_attr_sw_ver = __ATTR(sw_version, 0400,
						       bl31_show, NULL);

static struct attribute *bl31_attrs[] = {
	&bl31_attr_sw_ver.attr,
	NULL
};

static struct attribute_group bl31_attr_group = {
	.attrs = bl31_attrs,
};

// lifecycle attributes
static struct kobj_attribute lifecycle_attr_boot_state = __ATTR(boot_state,
								0400,
								boot_lcs_show,
								NULL);
static struct kobj_attribute lifecycle_attr_next_state = __ATTR(next_state,
								0400,
								next_lcs_show,
								NULL);

static struct attribute *lifecycle_attrs[] = {
	&lifecycle_attr_boot_state.attr,
	&lifecycle_attr_next_state.attr,
	NULL
};

static struct attribute_group lifecycle_attr_group = {
	.attrs = lifecycle_attrs,
};


int penfw_sysfs_init(struct device *penfwDevice)
{
	int ret = 0;

	// /sys/firmware/pensando
	pensando_kobj = pensando_fw_kobj_get();
	if (!pensando_kobj) {
		dev_err(penfwDevice, "Unable to create /sys/firmware/pensando"
				     " node\n");
		return -ENOMEM;
	}

	// /sys/firmware/pensando/penfw
	penfw_kobject = kobject_create_and_add("penfw", pensando_kobj);
	if (!penfw_kobject) {
		dev_err(penfwDevice, "Unable to create "
				     "/sys/firmware/pensando/penfw node\n");
		ret = -ENOMEM;
		goto penfw_err;
	}

	// /sys/firmware/pensando/penfw/pentrust
	pentrust_kobject = kobject_create_and_add("pentrust", penfw_kobject);
	if (!pentrust_kobject) {
		dev_err(penfwDevice, "Unable to create "
				     "/sys/firmware/pensando/penfw/pentrust "
				     "node\n");
		ret = -ENOMEM;
		goto pentrust_err;
	}

	if (sysfs_create_group(pentrust_kobject, &pentrust_attr_group)) {
		dev_err(penfwDevice, "Unable to create pentrust attributes "
				     "group\n");
		ret = -1;
		goto bl1_err;
	}

	// /sys/firmware/pensando/penfw/bl1
	bl1_kobject = kobject_create_and_add("bl1", penfw_kobject);
	if (!bl1_kobject) {
		dev_err(penfwDevice, "Unable to create "
				     "/sys/firmware/pensando/penfw/bl1 node\n");
		ret = -ENOMEM;
		goto bl1_err;
	}

	if (sysfs_create_group(bl1_kobject, &bl1_attr_group)) {
		dev_err(penfwDevice, "Unable to create bl1 attributes group\n");
		ret = -1;
		goto bl31_err;
	}

	// /sys/firmware/pensando/penfw/bl31
	bl31_kobject = kobject_create_and_add("bl31", penfw_kobject);
	if (!bl31_kobject) {
		dev_err(penfwDevice, "Unable to create "
				     "/sys/firmware/pensando/penfw/bl31 "
				     "node\n");
		ret = -ENOMEM;
		goto bl31_err;
	}

	if (sysfs_create_group(bl31_kobject, &bl31_attr_group)) {
		dev_err(penfwDevice, "Unable to create bl31 attributes "
				     "group\n");
		ret = -1;
		goto lifecycle_err;
	}

	// /sys/firmware/pensando/penfw/lifecycle
	lifecycle_kobject = kobject_create_and_add("lifecycle", penfw_kobject);
	if (!lifecycle_kobject) {
		dev_err(penfwDevice, "Unable to create "
				     "/sys/firmware/pensando/penfw/lifecycle "
				     "node\n");
		ret = -ENOMEM;
		goto lifecycle_err;
	}

	if (sysfs_create_group(lifecycle_kobject, &lifecycle_attr_group)) {
		dev_err(penfwDevice, "Unable to create lifecycle attributes "
				     "group\n");
		ret = -1;
		goto lifecycle_attr_err;
	}

return ret;

lifecycle_attr_err:
	kobject_put(lifecycle_kobject);
lifecycle_err:
	kobject_put(bl31_kobject);
bl31_err:
	kobject_put(bl1_kobject);
bl1_err:
	kobject_put(pentrust_kobject);
pentrust_err:
	kobject_put(penfw_kobject);
penfw_err:
	kobject_put(pensando_kobj);

	return ret;
}

int penfw_sysfs_deinit(void)
{
	if (lifecycle_kobject)
		kobject_put(lifecycle_kobject);
	if (bl31_kobject)
		kobject_put(bl31_kobject);
	if (bl1_kobject)
		kobject_put(bl1_kobject);
	if (pentrust_kobject)
		kobject_put(penfw_kobject);
	if (penfw_kobject)
		kobject_put(penfw_kobject);
	if (pensando_kobj)
		kobject_put(pensando_kobj);

	return 0;
}
