// SPDX-License-Identifier: GPL-2.0
/* Marvell CPT common code
 *
 * Copyright (C) 2018 Marvell International Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/ctype.h>
#include <linux/firmware.h>
#include "cpt_ucode.h"

#define DRV_NAME	"cpt-common"
#define DRV_VERSION	"1.0"

static int is_eng_type(int val, int eng_type)
{
	return val & (1 << eng_type);
}

static int dev_supports_eng_type(struct engine_groups *eng_grps, int eng_type)
{
	return is_eng_type(eng_grps->eng_types_supported, eng_type);
}

static int is_2nd_ucode_used(struct engine_group_info *eng_grp)
{
	if (eng_grp->ucode[1].type)
		return true;
	else
		return false;
}

static void set_ucode_filename(struct microcode *ucode, const char *filename)
{
	strlcpy(ucode->filename, filename, NAME_LENGTH);
}

static char *get_eng_type_str(int eng_type)
{
	char *str = "unknown";

	switch (eng_type) {
	case SE_TYPES:
		str = "SE";
	break;

	case IE_TYPES:
		str = "IE";
	break;

	case AE_TYPES:
		str = "AE";
	break;
	}

	return str;
}

static char *get_ucode_type_str(int ucode_type)
{
	char *str = "unknown";

	switch (ucode_type) {
	case (1 << SE_TYPES):
		str = "SE";
	break;

	case (1 << IE_TYPES):
		str = "IE";
	break;

	case (1 << AE_TYPES):
		str = "AE";
	break;

	case (1 << SE_TYPES | 1 << IE_TYPES):
		str = "SE+IPSEC";
	break;
	}

	return str;
}

static void swap_engines(struct engines *engsl, struct engines *engsr)
{
	struct engines engs;

	engs = *engsl;
	*engsl = *engsr;
	*engsr = engs;
}

static void swap_ucodes(struct microcode *ucodel, struct microcode *ucoder)
{
	struct microcode ucode;

	ucode = *ucodel;
	*ucodel = *ucoder;
	*ucoder = ucode;
}

static int get_ucode_type(struct microcode_hdr *ucode_hdr, int *ucode_type)
{
	char tmp_ver_str[CPT_UCODE_VER_STR_SZ];
	int i, val = 0;
	u8 nn;

	strlcpy(tmp_ver_str, ucode_hdr->ver_str, CPT_UCODE_VER_STR_SZ);
	for (i = 0; i < strlen(tmp_ver_str); i++)
		tmp_ver_str[i] = tolower(tmp_ver_str[i]);

	nn = ucode_hdr->ver_num.nn;
	if (strnstr(tmp_ver_str, "se-", CPT_UCODE_VER_STR_SZ) &&
	    (nn == SE_UC_TYPE1 || nn == SE_UC_TYPE2 || nn == SE_UC_TYPE3))
		val |= 1 << SE_TYPES;
	if (strnstr(tmp_ver_str, "ipsec", CPT_UCODE_VER_STR_SZ) &&
	    (nn == IE_UC_TYPE1 || nn == IE_UC_TYPE2 || nn == IE_UC_TYPE3))
		val |= 1 << IE_TYPES;
	if (strnstr(tmp_ver_str, "ae", CPT_UCODE_VER_STR_SZ) &&
	    nn == AE_UC_TYPE)
		val |= 1 << AE_TYPES;

	*ucode_type = val;

	if (!val)
		return -EINVAL;
	if (is_eng_type(val, AE_TYPES) && (is_eng_type(val, SE_TYPES) ||
	    is_eng_type(val, IE_TYPES)))
		return -EINVAL;
	return 0;
}

static int is_mem_zero(const char *ptr, int size)
{
	int i;

	for (i = 0; i < size; i++)
		if (ptr[i])
			return 0;
	return 1;
}

static int process_tar_file(struct device *dev,
			    struct tar_arch_info_t *tar_arch, char *filename,
			    const u8 *data, int size)
{
	struct tar_ucode_info_t *tar_ucode_info;
	struct microcode_hdr *ucode_hdr;
	int ucode_type, ucode_size;

	/* If size is less than microcode header size then don't report
	 * an error because it might not be microcode file, just process
	 * next file from archive
	 */
	if (size < sizeof(struct microcode_hdr))
		return 0;

	ucode_hdr = (struct microcode_hdr *) data;
	/* If microcode version can't be found don't report an error
	 * because it might not be microcode file, just process next file
	 */
	if (get_ucode_type(ucode_hdr, &ucode_type))
		return 0;

	ucode_size = ntohl(ucode_hdr->code_length) * 2;
	if (!ucode_size || (size < ROUNDUP16(ucode_size) +
	    sizeof(struct microcode_hdr) + CPT_UCODE_SIGN_LEN)) {
		dev_err(dev, "Ucode %s invalid size", filename);
		return -EINVAL;
	}

	tar_ucode_info = kzalloc(sizeof(struct tar_ucode_info_t), GFP_KERNEL);
	if (!tar_ucode_info)
		return -ENOMEM;

	tar_ucode_info->ucode_ptr = data;
	set_ucode_filename(&tar_ucode_info->ucode, filename);
	memcpy(tar_ucode_info->ucode.ver_str, ucode_hdr->ver_str,
	       CPT_UCODE_VER_STR_SZ);
	tar_ucode_info->ucode.ver_num = ucode_hdr->ver_num;
	tar_ucode_info->ucode.type = ucode_type;
	tar_ucode_info->ucode.size = ucode_size;
	list_add_tail(&tar_ucode_info->list, &tar_arch->ucodes);

	return 0;
}

static void release_tar_archive(struct tar_arch_info_t *tar_arch)
{
	struct tar_ucode_info_t *curr, *temp;

	if (!tar_arch)
		return;

	list_for_each_entry_safe(curr, temp, &tar_arch->ucodes, list) {
		list_del(&curr->list);
		kfree(curr);
	}

	if (tar_arch->fw)
		release_firmware(tar_arch->fw);
	kfree(tar_arch);
}

static struct tar_ucode_info_t *get_uc_from_tar_archive(
					struct tar_arch_info_t *tar_arch,
					int ucode_type)
{
	struct tar_ucode_info_t *curr, *uc_found = NULL;

	list_for_each_entry(curr, &tar_arch->ucodes, list) {
		if (!is_eng_type(curr->ucode.type, ucode_type))
			continue;

		if (ucode_type == IE_TYPES &&
		    is_eng_type(curr->ucode.type, SE_TYPES))
			continue;

		if (!uc_found) {
			uc_found = curr;
			continue;
		}

		switch (ucode_type) {
		case AE_TYPES:
			break;

		case SE_TYPES:
			if (uc_found->ucode.ver_num.nn == SE_UC_TYPE2 ||
			    (uc_found->ucode.ver_num.nn == SE_UC_TYPE3 &&
			    curr->ucode.ver_num.nn == SE_UC_TYPE1))
				uc_found = curr;
			break;

		case IE_TYPES:
			if (uc_found->ucode.ver_num.nn == IE_UC_TYPE2 ||
			    (uc_found->ucode.ver_num.nn == IE_UC_TYPE3 &&
			    curr->ucode.ver_num.nn == IE_UC_TYPE1))
				uc_found = curr;
			break;
		}
	}

	return uc_found;
}

static void print_tar_dbg_info(struct device *dev,
			       struct tar_arch_info_t *tar_arch,
			       char *tar_filename)
{
	struct tar_ucode_info_t *curr;

	pr_debug("Tar archive filename %s", tar_filename);
	pr_debug("Tar archive pointer %p, size %ld", tar_arch->fw->data,
		 tar_arch->fw->size);
	list_for_each_entry(curr, &tar_arch->ucodes, list) {
		pr_debug("Ucode filename %s", curr->ucode.filename);
		pr_debug("Ucode version string %s", curr->ucode.ver_str);
		pr_debug("Ucode version %d.%d.%d.%d",
			 curr->ucode.ver_num.nn, curr->ucode.ver_num.xx,
			 curr->ucode.ver_num.yy, curr->ucode.ver_num.zz);
		pr_debug("Ucode type (%d) %s", curr->ucode.type,
			 get_ucode_type_str(curr->ucode.type));
		pr_debug("Ucode size %d", curr->ucode.size);
		pr_debug("Ucode ptr %p\n", curr->ucode_ptr);
	}
}

static struct tar_arch_info_t *load_tar_archive(struct device *dev,
						char *tar_filename)
{
	struct tar_arch_info_t *tar_arch = NULL;
	struct tar_blk_t *tar_blk;
	unsigned int cur_size;
	size_t tar_offs = 0;
	size_t tar_size;
	int ret;

	tar_arch = kzalloc(sizeof(struct tar_arch_info_t), GFP_KERNEL);
	if (!tar_arch)
		goto err;

	INIT_LIST_HEAD(&tar_arch->ucodes);

	/* Load tar archive */
	ret = request_firmware(&tar_arch->fw, tar_filename, dev);
	if (ret)
		goto err;

	if (tar_arch->fw->size < TAR_BLOCK_LEN) {
		dev_err(dev, "Invalid tar archive %s ", tar_filename);
		goto err;
	}

	tar_size = tar_arch->fw->size;
	tar_blk = (struct tar_blk_t *) tar_arch->fw->data;
	if (strncmp(tar_blk->hdr.magic, TAR_MAGIC, TAR_MAGIC_LEN - 1)) {
		dev_err(dev, "Unsupported format of tar archive %s",
			tar_filename);
		goto err;
	}

	while (1) {
		/* Read current file size */
		ret = kstrtouint(tar_blk->hdr.size, 8, &cur_size);
		if (ret)
			goto err;

		if (tar_offs + cur_size > tar_size ||
		    tar_offs + 2*TAR_BLOCK_LEN > tar_size) {
			dev_err(dev, "Invalid tar archive %s ", tar_filename);
			goto err;
		}

		tar_offs += TAR_BLOCK_LEN;
		if (tar_blk->hdr.typeflag == REGTYPE ||
		    tar_blk->hdr.typeflag == AREGTYPE) {
			ret = process_tar_file(dev, tar_arch,
					       tar_blk->hdr.name,
					       &tar_arch->fw->data[tar_offs],
					       cur_size);
			if (ret)
				goto err;
		}

		tar_offs += (cur_size/TAR_BLOCK_LEN) * TAR_BLOCK_LEN;
		if (cur_size % TAR_BLOCK_LEN)
			tar_offs += TAR_BLOCK_LEN;

		/* Check for the end of the archive */
		if (tar_offs + 2*TAR_BLOCK_LEN > tar_size) {
			dev_err(dev, "Invalid tar archive %s ", tar_filename);
			goto err;
		}

		if (is_mem_zero(&tar_arch->fw->data[tar_offs],
		    2*TAR_BLOCK_LEN))
			break;

		/* Read next block from tar archive */
		tar_blk = (struct tar_blk_t *) &tar_arch->fw->data[tar_offs];
	}

	print_tar_dbg_info(dev, tar_arch, tar_filename);
	return tar_arch;
err:
	release_tar_archive(tar_arch);
	return NULL;
}

static struct engines_reserved *find_engines_by_type(
					struct engine_group_info *eng_grp,
					int eng_type)
{
	int i;

	for (i = 0; i < MAX_ENGS_PER_GRP; i++) {
		if (!eng_grp->engs[i].type)
			continue;

		if (eng_grp->engs[i].type == eng_type)
			return &eng_grp->engs[i];
	}

	return NULL;
}

int cpt_uc_supports_eng_type(struct microcode *ucode, int eng_type)
{
	return is_eng_type(ucode->type, eng_type);
}
EXPORT_SYMBOL_GPL(cpt_uc_supports_eng_type);

int cpt_eng_grp_has_eng_type(struct engine_group_info *eng_grp, int eng_type)
{
	struct engines_reserved *engs;

	engs = find_engines_by_type(eng_grp, eng_type);

	return (engs != NULL ? 1 : 0);
}
EXPORT_SYMBOL_GPL(cpt_eng_grp_has_eng_type);

static void print_ucode_info(struct engine_group_info *eng_grp,
			     char *buf, int size)
{
	int len;

	if (eng_grp->mirror.is_ena) {
		scnprintf(buf, size, "%s (shared with engine_group%d)",
			eng_grp->g->grp[eng_grp->mirror.idx].ucode[0].ver_str,
			eng_grp->mirror.idx);
	} else {
		scnprintf(buf, size, "%s", eng_grp->ucode[0].ver_str);
	}

	if (is_2nd_ucode_used(eng_grp)) {
		len = strlen(buf);
		scnprintf(buf + len, size - len, ", %s (used by IE engines)",
			  eng_grp->ucode[1].ver_str);
	}
}

static void print_engs_info(struct engine_group_info *eng_grp,
			    char *buf, int size, int idx)
{
	struct engines_reserved *mirrored_engs = NULL;
	struct engines_reserved *engs;
	int len, i;

	buf[0] = '\0';
	for (i = 0; i < MAX_ENGS_PER_GRP; i++) {
		engs = &eng_grp->engs[i];
		if (!engs->type)
			continue;
		if (idx != -1 &&
		    idx != i)
			continue;

		if (eng_grp->mirror.is_ena)
			mirrored_engs = find_engines_by_type(
					&eng_grp->g->grp[eng_grp->mirror.idx],
					engs->type);
		if (i > 0 &&
		    idx == -1) {
			len = strlen(buf);
			scnprintf(buf+len, size-len, ", ");
		}

		len = strlen(buf);
		scnprintf(buf+len, size-len, "%d %s ", mirrored_engs ?
			  engs->count + mirrored_engs->count : engs->count,
			  get_eng_type_str(engs->type));
		if (mirrored_engs) {
			len = strlen(buf);
			scnprintf(buf+len, size-len,
				  "(%d shared with engine_group%d) ",
				  engs->count <= 0 ? engs->count +
				  mirrored_engs->count : mirrored_engs->count,
				  eng_grp->mirror.idx);
		}
	}
}

static void print_ucode_dbg_info(struct device *dev, struct microcode *ucode)
{
	pr_debug("Ucode info");
	pr_debug("Ucode version string %s", ucode->ver_str);
	pr_debug("Ucode version %d.%d.%d.%d", ucode->ver_num.nn,
		 ucode->ver_num.xx, ucode->ver_num.yy, ucode->ver_num.zz);
	pr_debug("Ucode type %s", get_ucode_type_str(ucode->type));
	pr_debug("Ucode size %d", ucode->size);
	pr_debug("Ucode virt address %16.16llx", (u64)ucode->align_va);
	pr_debug("Ucode phys address %16.16llx\n", ucode->align_dma);
}

static void print_dbg_info(struct device *dev,
			   struct engine_groups *eng_grps)
{
	struct engine_group_info *mirrored_grp;
	struct engine_group_info *grp;
	struct engines_reserved *engs;
	char engs_info[2*NAME_LENGTH];
	char engs_mask[NAME_LENGTH];
	u32 mask[4];
	int i, j;

	pr_debug("Engine groups global info");
	pr_debug("max SE %d, max IE %d, max AE %d",
		 eng_grps->avail.max_se_cnt, eng_grps->avail.max_ie_cnt,
		 eng_grps->avail.max_ae_cnt);
	pr_debug("free SE %d", eng_grps->avail.se_cnt);
	pr_debug("free IE %d", eng_grps->avail.ie_cnt);
	pr_debug("free AE %d", eng_grps->avail.ae_cnt);

	for (i = 0; i < CPT_MAX_ENGINE_GROUPS; i++) {
		grp = &eng_grps->grp[i];
		pr_debug("engine_group%d, state %s", i, grp->is_enabled ?
			 "enabled" : "disabled");
		if (grp->is_enabled) {
			mirrored_grp = &eng_grps->grp[grp->mirror.idx];
			pr_debug("Ucode0 filename %s, version %s",
				 grp->mirror.is_ena ?
				 mirrored_grp->ucode[0].filename :
				 grp->ucode[0].filename,
				 grp->mirror.is_ena ?
				 mirrored_grp->ucode[0].ver_str :
				 grp->ucode[0].ver_str);
			if (is_2nd_ucode_used(grp))
				pr_debug("Ucode1 filename %s, version %s",
					 grp->ucode[1].filename,
					 grp->ucode[1].ver_str);
			else
				pr_debug("Ucode1 not used");
		}

		for (j = 0; j < MAX_ENGS_PER_GRP; j++) {
			engs = &grp->engs[j];
			if (engs->type) {
				print_engs_info(grp, engs_info, 2*NAME_LENGTH,
						j);
				pr_debug("Slot%d: %s", j, engs_info);
				bitmap_to_u32array(mask, 4, engs->bmap,
						   eng_grps->engs_num);
				pr_debug("Mask:  %8.8x %8.8x %8.8x %8.8x",
					 mask[3], mask[2], mask[1], mask[0]);
			} else
				pr_debug("Slot%d not used", j);
		}
		if (grp->is_enabled && eng_grps->ops.print_engines_mask) {
			eng_grps->ops.print_engines_mask(grp, eng_grps->obj,
						engs_mask, NAME_LENGTH);
			pr_debug("Cmask: %s", engs_mask);
		}
	}
}

static int update_engines_avail_count(struct device *dev,
				      struct engines_available *avail,
				      struct engines_reserved *engs, int val)
{
	switch (engs->type) {
	case SE_TYPES:
		avail->se_cnt += val;
	break;

	case IE_TYPES:
		avail->ie_cnt += val;
	break;

	case AE_TYPES:
		avail->ae_cnt += val;
	break;

	default:
		dev_err(dev, "Invalid engine type %d\n", engs->type);
		return -EINVAL;
	}

	return 0;
}

static int update_engines_offset(struct device *dev,
				 struct engines_available *avail,
				 struct engines_reserved *engs)
{
	switch (engs->type) {
	case SE_TYPES:
		engs->offset = 0;
	break;

	case IE_TYPES:
		engs->offset = avail->max_se_cnt;
	break;

	case AE_TYPES:
		engs->offset = avail->max_se_cnt + avail->max_ie_cnt;
	break;

	default:
		dev_err(dev, "Invalid engine type %d\n", engs->type);
		return -EINVAL;
	}

	return 0;
}

static int release_engines(struct device *dev, struct engine_group_info *grp)
{
	int i, ret = 0;

	for (i = 0; i < MAX_ENGS_PER_GRP; i++) {
		if (!grp->engs[i].type)
			continue;

		if (grp->engs[i].count > 0) {
			ret = update_engines_avail_count(dev, &grp->g->avail,
							 &grp->engs[i],
							 grp->engs[i].count);
			if (ret)
				return ret;
		}

		grp->engs[i].type = 0;
		grp->engs[i].count = 0;
		grp->engs[i].offset = 0;
		grp->engs[i].ucode = NULL;
		bitmap_zero(grp->engs[i].bmap, grp->g->engs_num);
	}

	return 0;
}

static int do_reserve_engines(struct device *dev,
			      struct engine_group_info *grp,
			      struct engines *req_engs)
{
	struct engines_reserved *engs = NULL;
	int i, ret = 0;

	for (i = 0; i < MAX_ENGS_PER_GRP; i++) {
		if (!grp->engs[i].type) {
			engs = &grp->engs[i];
			break;
		}
	}

	if (!engs)
		return -ENOMEM;

	engs->type = req_engs->type;
	engs->count = req_engs->count;

	ret = update_engines_offset(dev, &grp->g->avail, engs);
	if (ret)
		return ret;

	if (engs->count > 0) {
		ret = update_engines_avail_count(dev, &grp->g->avail, engs,
						 -engs->count);
		if (ret)
			return ret;
	}

	return 0;
}

static int check_engines_availability(struct device *dev,
				      struct engine_group_info *grp,
				      struct engines *req_eng)
{
	int avail_cnt = 0;

	switch (req_eng->type) {
	case SE_TYPES:
		avail_cnt = grp->g->avail.se_cnt;
	break;

	case IE_TYPES:
		avail_cnt = grp->g->avail.ie_cnt;
	break;

	case AE_TYPES:
		avail_cnt = grp->g->avail.ae_cnt;
	break;

	default:
		dev_err(dev, "Invalid engine type %d\n", req_eng->type);
		return -EINVAL;
	}

	if (avail_cnt < req_eng->count) {
		dev_err(dev,
			"Error available %s engines %d < than requested %d",
			get_eng_type_str(req_eng->type),
			avail_cnt, req_eng->count);
		return -EBUSY;
	}

	return 0;
}

static int reserve_engines(struct device *dev, struct engine_group_info *grp,
			   struct engines *req_engs, int req_cnt)
{
	int i, ret = 0;

	/* Validate if a number of requested engines is available */
	for (i = 0; i < req_cnt; i++) {
		ret = check_engines_availability(dev, grp, &req_engs[i]);
		if (ret)
			goto err;
	}

	/* Reserve requested engines for this engine group */
	for (i = 0; i < req_cnt; i++) {
		ret = do_reserve_engines(dev, grp, &req_engs[i]);
		if (ret)
			goto err;
	}


err:
	return ret;
}

static ssize_t eng_grp_info_show(struct device *dev,
				 struct device_attribute *attr,
				 char *buf)
{
	struct engine_group_info *eng_grp;
	char engs_info[2*NAME_LENGTH];
	char ucode_info[2*NAME_LENGTH];
	char engs_mask[NAME_LENGTH];
	int ret = 0;

	eng_grp = container_of(attr, struct engine_group_info, info_attr);
	mutex_lock(&eng_grp->g->lock);

	print_engs_info(eng_grp, engs_info, 2*NAME_LENGTH, -1);
	print_ucode_info(eng_grp, ucode_info, 2*NAME_LENGTH);
	if (eng_grp->g->ops.print_engines_mask)
		eng_grp->g->ops.print_engines_mask(eng_grp, eng_grp->g,
						   engs_mask, NAME_LENGTH);
	ret = scnprintf(buf, PAGE_SIZE,
			"Microcode : %s\nEngines: %s\nEngines mask: %s\n",
			ucode_info, engs_info, engs_mask);

	mutex_unlock(&eng_grp->g->lock);
	return ret;
}

static int create_sysfs_eng_grps_info(struct device *dev,
				      struct engine_group_info *eng_grp)
{
	int ret = 0;

	eng_grp->info_attr.show = eng_grp_info_show;
	eng_grp->info_attr.store = NULL;
	eng_grp->info_attr.attr.name = eng_grp->sysfs_info_name;
	eng_grp->info_attr.attr.mode = 0440;
	sysfs_attr_init(&eng_grp->info_attr.attr);
	ret = device_create_file(dev, &eng_grp->info_attr);
	if (ret)
		return ret;

	return 0;
}

static void ucode_unload(struct device *dev, struct microcode *ucode)
{
	if (ucode->va) {
		dma_free_coherent(dev, ucode->size + CPT_UCODE_ALIGNMENT,
				  ucode->va, ucode->dma);
		ucode->va = NULL;
		ucode->align_va = NULL;
		ucode->dma = 0;
		ucode->align_dma = 0;
		ucode->size = 0;
	}

	memset(&ucode->ver_str, 0, CPT_UCODE_VER_STR_SZ);
	memset(&ucode->ver_num, 0, sizeof(struct microcode_ver_num));
	set_ucode_filename(ucode, "");
	ucode->type = 0;
}

static int copy_ucode_to_dma_mem(struct device *dev, struct microcode *ucode,
				 const u8 *ucode_data)
{
	int i;

	/*  Allocate DMAable space */
	ucode->va = dma_zalloc_coherent(dev, ucode->size + CPT_UCODE_ALIGNMENT,
					&ucode->dma, GFP_KERNEL);
	if (!ucode->va) {
		dev_err(dev, "Unable to allocate space for microcode");
		return -ENOMEM;
	}
	ucode->align_va = PTR_ALIGN(ucode->va, CPT_UCODE_ALIGNMENT);
	ucode->align_dma = PTR_ALIGN(ucode->dma, CPT_UCODE_ALIGNMENT);

	memcpy((void *) ucode->align_va, (void *) ucode_data +
	       sizeof(struct microcode_hdr), ucode->size);

	/* Byte swap 64-bit */
	for (i = 0; i < (ucode->size / 8); i++)
		((u64 *)ucode->align_va)[i] =
				cpu_to_be64(((u64 *)ucode->align_va)[i]);
	/*  Ucode needs 16-bit swap */
	for (i = 0; i < (ucode->size / 2); i++)
		((u16 *)ucode->align_va)[i] =
				cpu_to_be16(((u16 *)ucode->align_va)[i]);
	return 0;
}

static int ucode_load(struct device *dev, struct microcode *ucode,
		      const char *ucode_filename)
{
	struct microcode_hdr *ucode_hdr;
	const struct firmware *fw;
	int ret = 0;

	set_ucode_filename(ucode, ucode_filename);
	ret = request_firmware(&fw, ucode->filename, dev);
	if (ret)
		return ret;

	ucode_hdr = (struct microcode_hdr *) fw->data;
	memcpy(ucode->ver_str, ucode_hdr->ver_str, CPT_UCODE_VER_STR_SZ);
	ucode->ver_num = ucode_hdr->ver_num;
	ucode->size = ntohl(ucode_hdr->code_length) * 2;
	if (!ucode->size || (fw->size < ROUNDUP16(ucode->size)
	    + sizeof(struct microcode_hdr) + CPT_UCODE_SIGN_LEN)) {
		dev_err(dev, "Ucode %s invalid size", ucode_filename);
		ret = -EINVAL;
		goto err;
	}

	ret = get_ucode_type(ucode_hdr, &ucode->type);
	if (ret) {
		dev_err(dev, "Microcode %s unknown type 0x%x", ucode->filename,
			ucode->type);
		goto err;
	}

	ret = copy_ucode_to_dma_mem(dev, ucode, fw->data);
	if (ret)
		goto err;

	print_ucode_dbg_info(dev, ucode);
err:
	release_firmware(fw);
	return ret;
}

static int enable_eng_grp(struct engine_group_info *eng_grp,
			  void *obj)
{
	int ret = 0;

	/* Point microcode to each core of the group */
	if (!eng_grp->g->ops.set_ucode_base)
		return -EPERM;
	ret = eng_grp->g->ops.set_ucode_base(eng_grp, obj);
	if (ret)
		goto err;

	/* Attach the cores to the group and enable them */
	if (!eng_grp->g->ops.attach_and_enable_cores)
		return -EPERM;
	ret = eng_grp->g->ops.attach_and_enable_cores(eng_grp, obj);
	if (ret)
		goto err;
err:
	return ret;
}

static int disable_eng_grp(struct device *dev,
			   struct engine_group_info *eng_grp,
			   void *obj)
{
	int i, ret = 0;

	/* Disable all engines used by this group */
	if (!eng_grp->g->ops.detach_and_disable_cores)
		return -EPERM;
	ret = eng_grp->g->ops.detach_and_disable_cores(eng_grp, obj);
	if (ret)
		goto err;

	/* Unload ucode used by this engine group */
	ucode_unload(dev, &eng_grp->ucode[0]);
	ucode_unload(dev, &eng_grp->ucode[1]);

	for (i = 0; i < MAX_ENGS_PER_GRP; i++) {
		if (!eng_grp->engs[i].type)
			continue;

		eng_grp->engs[i].ucode = &eng_grp->ucode[0];
	}

	/* Clear UCODE_BASE register for each engine used by this group */
	if (!eng_grp->g->ops.set_ucode_base)
		return -EPERM;
	ret = eng_grp->g->ops.set_ucode_base(eng_grp, obj);
	if (ret)
		goto err;
err:
	return ret;
}

static void setup_eng_grp_mirroring(struct engine_group_info *dst_grp,
				    struct engine_group_info *src_grp)
{
	/* Setup fields for engine group which is mirrored */
	src_grp->mirror.is_ena = false;
	src_grp->mirror.idx = 0;
	src_grp->mirror.ref_count++;

	/* Setup fields for mirroring engine group */
	dst_grp->mirror.is_ena = true;
	dst_grp->mirror.idx = src_grp->idx;
	dst_grp->mirror.ref_count = 0;
}

static void remove_eng_grp_mirroring(struct engine_group_info *dst_grp)
{
	struct engine_group_info *src_grp;

	if (!dst_grp->mirror.is_ena)
		return;

	src_grp = &dst_grp->g->grp[dst_grp->mirror.idx];

	src_grp->mirror.ref_count--;
	dst_grp->mirror.is_ena = false;
	dst_grp->mirror.idx = 0;
	dst_grp->mirror.ref_count = 0;
}

static void update_requested_engs(struct engine_group_info *mirrored_eng_grp,
				  struct engines *engs, int engs_cnt)
{
	struct engines_reserved *mirrored_engs;
	int i;

	for (i = 0; i < engs_cnt; i++) {
		mirrored_engs = find_engines_by_type(mirrored_eng_grp,
						     engs[i].type);
		if (!mirrored_engs)
			continue;

		/* If mirrored group has this type of engines attached then
		 * there are 3 scenarios possible:
		 * 1) mirrored_engs.count == engs[i].count then all engines
		 * from mirrored engine group will be shared with this engine
		 * group
		 * 2) mirrored_engs.count > engs[i].count then only a subset of
		 * engines from mirrored engine group will be shared with this
		 * engine group
		 * 3) mirrored_engs.count < engs[i].count then all engines
		 * from mirrored engine group will be shared with this group
		 * and additional engines will be reserved for exclusively use
		 * by this engine group
		 */
		engs[i].count -= mirrored_engs->count;
	}
}

static struct engine_group_info *find_mirrored_eng_grp(
					struct engine_group_info *grp)
{
	struct engine_groups *eng_grps = grp->g;
	int i;

	for (i = 0; i < CPT_MAX_ENGINE_GROUPS; i++) {
		if (!eng_grps->grp[i].is_enabled)
			continue;
		if (eng_grps->grp[i].ucode[0].type &&
		    eng_grps->grp[i].ucode[1].type)
			continue;
		if (grp->idx == i)
			continue;
		if (!strncasecmp(eng_grps->grp[i].ucode[0].ver_str,
				 grp->ucode[0].ver_str, CPT_UCODE_VER_STR_SZ))
			return &eng_grps->grp[i];
	}

	return NULL;
}

static struct engine_group_info *find_unused_eng_grp(
					struct engine_groups *eng_grps)
{
	int i;

	for (i = 0; i < CPT_MAX_ENGINE_GROUPS; i++)
		if (!eng_grps->grp[i].is_enabled)
			return &eng_grps->grp[i];
	return NULL;
}

static int eng_grp_update_masks(struct device *dev,
				struct engine_group_info *eng_grp)
{
	struct engines_reserved *engs, *mirrored_engs;
	int i, j, cnt, max_cnt, ret = 0;
	struct bitmap tmp_bmap = { 0 };
	int bit;

	for (i = 0; i < MAX_ENGS_PER_GRP; i++) {
		engs = &eng_grp->engs[i];
		if (!engs->type)
			continue;
		if (engs->count <= 0)
			continue;

		switch (engs->type) {
		case SE_TYPES:
			max_cnt = eng_grp->g->avail.max_se_cnt;
		break;

		case IE_TYPES:
			max_cnt = eng_grp->g->avail.max_ie_cnt;
		break;

		case AE_TYPES:
			max_cnt = eng_grp->g->avail.max_ae_cnt;
		break;

		default:
			dev_err(dev, "Invalid engine type %d", engs->type);
			ret = -EINVAL;
			goto end;
		}

		cnt = engs->count;
		WARN_ON(engs->offset + max_cnt > CPT_MAX_ENGINES);
		bitmap_zero(tmp_bmap.bits, eng_grp->g->engs_num);
		for (j = engs->offset; j < engs->offset + max_cnt; j++) {
			if (!eng_grp->g->eng_ref_cnt[j]) {
				bitmap_set(tmp_bmap.bits, j, 1);
				cnt--;
				if (!cnt)
					break;
			}
		}

		if (cnt) {
			ret = -ENOSPC;
			goto end;
		}

		bitmap_copy(engs->bmap, tmp_bmap.bits, eng_grp->g->engs_num);
	}

	if (!eng_grp->mirror.is_ena)
		goto end;

	for (i = 0; i < MAX_ENGS_PER_GRP; i++) {
		engs = &eng_grp->engs[i];
		if (!engs->type)
			continue;

		mirrored_engs = find_engines_by_type(
					&eng_grp->g->grp[eng_grp->mirror.idx],
					engs->type);
		WARN_ON(!mirrored_engs && engs->count <= 0);
		if (!mirrored_engs)
			continue;

		bitmap_copy(tmp_bmap.bits, mirrored_engs->bmap,
			    eng_grp->g->engs_num);
		if (engs->count < 0) {
			bit = find_first_bit(mirrored_engs->bmap,
					     eng_grp->g->engs_num);
			bitmap_clear(tmp_bmap.bits, bit, -engs->count);
		}
		bitmap_or(engs->bmap, engs->bmap, tmp_bmap.bits,
			  eng_grp->g->engs_num);
	}
end:
	return ret;
}

static int delete_engine_group(struct device *dev,
			       struct engine_group_info *eng_grp)
{
	int i, ret = 0;

	if (!eng_grp->is_enabled)
		return -EINVAL;

	if (eng_grp->mirror.ref_count) {
		dev_err(dev, "Can't delete engine_group%d as it is used by:",
			eng_grp->idx);
		for (i = 0; i < CPT_MAX_ENGINE_GROUPS; i++) {
			if (eng_grp->g->grp[i].mirror.is_ena &&
			    eng_grp->g->grp[i].mirror.idx == eng_grp->idx)
				dev_err(dev, "engine_group%d", i);
		}
		return -EINVAL;
	}

	/* Removing engine group mirroring if enabled */
	remove_eng_grp_mirroring(eng_grp);

	/* Disable engine group */
	ret = disable_eng_grp(dev, eng_grp, eng_grp->g->obj);
	if (ret)
		goto err;

	/* Release all engines held by this engine group */
	ret = release_engines(dev, eng_grp);
	if (ret)
		goto err;

	device_remove_file(dev, &eng_grp->info_attr);
	eng_grp->is_enabled = false;
err:
	return ret;
}

static int validate_2_ucodes_scenario(struct device *dev,
				      struct engine_group_info *eng_grp)
{
	struct microcode *se_ucode = NULL, *ie_ucode = NULL;
	struct microcode *ucode;
	int i, ret = 0;

	/* Find ucode which supports SE engines and ucode which supports
	 * IE engines only
	 */
	for (i = 0; i < MAX_ENGS_PER_GRP; i++) {
		ucode = &eng_grp->ucode[i];
		if (cpt_uc_supports_eng_type(ucode, SE_TYPES))
			se_ucode = ucode;
		else if (cpt_uc_supports_eng_type(ucode, IE_TYPES) &&
			 !cpt_uc_supports_eng_type(ucode, SE_TYPES))
			ie_ucode = ucode;
	}

	if (!se_ucode || !ie_ucode) {
		dev_err(dev,
			"Only combination of SE+IE microcodes is supported.");
		ret = -EINVAL;
		goto err;
	}

	/* Keep SE ucode at index 0 */
	if (cpt_uc_supports_eng_type(&eng_grp->ucode[1], SE_TYPES))
		swap_ucodes(&eng_grp->ucode[0], &eng_grp->ucode[1]);
err:
	return ret;
}

static int validate_1_ucode_scenario(struct device *dev,
				     struct engine_group_info *eng_grp,
				     struct engines *engs, int engs_cnt)
{
	int i, ret = 0;

	/* Verify that ucode loaded supports requested engine types */
	for (i = 0; i < engs_cnt; i++) {
		if (cpt_uc_supports_eng_type(&eng_grp->ucode[0], SE_TYPES) &&
		    engs[i].type == IE_TYPES) {
			dev_err(dev,
				"IE engines can't be used with SE microcode.");
			ret = -EINVAL;
			goto err;
		}

		if (!cpt_uc_supports_eng_type(&eng_grp->ucode[0],
					      engs[i].type)) {
			/* Exception to this rule is the case
			 * where IPSec ucode can use SE engines
			 */
			if (cpt_uc_supports_eng_type(&eng_grp->ucode[0],
						     IE_TYPES) &&
			    engs[i].type == SE_TYPES)
				continue;

			dev_err(dev,
				"Microcode %s does not support %s engines",
				eng_grp->ucode[0].filename,
				get_eng_type_str(engs[i].type));
			ret = -EINVAL;
			goto err;
		}
	}
err:
	return ret;
}

static void update_ucode_ptrs(struct engine_group_info *eng_grp)
{
	struct microcode *ucode;

	if (eng_grp->mirror.is_ena)
		ucode = &eng_grp->g->grp[eng_grp->mirror.idx].ucode[0];
	else
		ucode = &eng_grp->ucode[0];
	WARN_ON(!eng_grp->engs[0].type);
	eng_grp->engs[0].ucode = ucode;

	if (eng_grp->engs[1].type) {
		if (is_2nd_ucode_used(eng_grp))
			eng_grp->engs[1].ucode = &eng_grp->ucode[1];
		else
			eng_grp->engs[1].ucode = ucode;
	}
}

int cpt_get_eng_caps_discovery_grp(struct engine_groups *eng_grps, u8 eng_type)
{
	struct engine_group_info *grp;
	int eng_grp_num = 0xff, i;

	switch (eng_type) {
	case SE_TYPES:
		for (i = 0; i < CPT_MAX_ENGINE_GROUPS; i++) {
			grp = &eng_grps->grp[i];
			if (!grp->is_enabled)
				continue;

			if (cpt_eng_grp_has_eng_type(grp, SE_TYPES) &&
			    !cpt_eng_grp_has_eng_type(grp, IE_TYPES) &&
			    !cpt_eng_grp_has_eng_type(grp, AE_TYPES)) {
				eng_grp_num = i;
				break;
			}
		}
		break;

	case IE_TYPES:
		for (i = 0; i < CPT_MAX_ENGINE_GROUPS; i++) {
			grp = &eng_grps->grp[i];
			if (!grp->is_enabled)
				continue;

			if (cpt_eng_grp_has_eng_type(grp, IE_TYPES) &&
			    !cpt_eng_grp_has_eng_type(grp, SE_TYPES)) {
				eng_grp_num = i;
				break;
			}
		}
		break;

	case AE_TYPES:
		for (i = 0; i < CPT_MAX_ENGINE_GROUPS; i++) {
			grp = &eng_grps->grp[i];
			if (!grp->is_enabled)
				continue;

			if (cpt_eng_grp_has_eng_type(grp, eng_type)) {
				eng_grp_num = i;
				break;
			}
		}
		break;
	}
	return eng_grp_num;
}
EXPORT_SYMBOL_GPL(cpt_get_eng_caps_discovery_grp);

int cpt_delete_eng_caps_discovery_grps(struct pci_dev *pdev,
				       struct engine_groups *eng_grps)
{
	struct engine_group_info *grp;
	int i, ret;

	for (i = 0; i < CPT_MAX_ENGINE_GROUPS; i++) {
		grp = &eng_grps->grp[i];
		ret = delete_engine_group(&pdev->dev, grp);
		if (ret)
			return ret;
	}
	return ret;
}
EXPORT_SYMBOL_GPL(cpt_delete_eng_caps_discovery_grps);

static int create_engine_group(struct device *dev,
			       struct engine_groups *eng_grps,
			       struct engines *engs, int engs_cnt,
			       void *ucode_data[], int ucodes_cnt,
			       bool use_uc_from_tar_arch)
{
	struct engine_group_info *mirrored_eng_grp;
	struct tar_ucode_info_t *tar_ucode_info;
	struct engine_group_info *eng_grp;
	int i, ret = 0;

	if (ucodes_cnt > MAX_ENGS_PER_GRP)
		goto err;

	/* Validate if requested engine types are supported by this device */
	for (i = 0; i < engs_cnt; i++)
		if (!dev_supports_eng_type(eng_grps, engs[i].type)) {
			dev_err(dev, "Device does not support %s engines",
				get_eng_type_str(engs[i].type));
			return -EPERM;
		}

	/* Find engine group which is not used*/
	eng_grp = find_unused_eng_grp(eng_grps);
	if (!eng_grp) {
		dev_err(dev, "Error all engine groups are being used");
		return -ENOSPC;
	}

	/* Load ucode */
	for (i = 0; i < ucodes_cnt; i++) {
		if (use_uc_from_tar_arch) {
			tar_ucode_info =
				     (struct tar_ucode_info_t *) ucode_data[i];
			eng_grp->ucode[i] = tar_ucode_info->ucode;
			ret = copy_ucode_to_dma_mem(dev, &eng_grp->ucode[i],
						    tar_ucode_info->ucode_ptr);
		} else
			ret = ucode_load(dev, &eng_grp->ucode[i],
					 (char *) ucode_data[i]);
		if (ret)
			goto err_ucode_unload;
	}

	if (ucodes_cnt > 1) {
		/* Validate scenario where 2 ucodes are used - this
		 * is only allowed for combination of SE+IE ucodes
		 */
		ret = validate_2_ucodes_scenario(dev, eng_grp);
		if (ret)
			goto err_ucode_unload;
	} else {
		/* Validate scenario where 1 ucode is used */
		ret = validate_1_ucode_scenario(dev, eng_grp, engs, engs_cnt);
		if (ret)
			goto err_ucode_unload;
	}

	/* Check if this group mirrors another existing engine group */
	mirrored_eng_grp = find_mirrored_eng_grp(eng_grp);
	if (mirrored_eng_grp) {
		/* Setup mirroring */
		setup_eng_grp_mirroring(eng_grp, mirrored_eng_grp);

		/* Update count of requested engines because some
		 * of them might be shared with mirrored group
		 */
		update_requested_engs(mirrored_eng_grp, engs, engs_cnt);
	}

	/* Reserve engines */
	ret = reserve_engines(dev, eng_grp, engs, engs_cnt);
	if (ret)
		goto err;

	/* Update ucode pointers used by engines */
	update_ucode_ptrs(eng_grp);

	/* Update engine masks used by this group */
	ret = eng_grp_update_masks(dev, eng_grp);
	if (ret)
		goto err_release_engs;

	/* Create sysfs entry for engine group info */
	ret = create_sysfs_eng_grps_info(dev, eng_grp);
	if (ret)
		goto err_release_engs;

	/* Enable engine group */
	ret = enable_eng_grp(eng_grp, eng_grps->obj);
	if (ret)
		goto err_release_engs;

	/* If this engine group mirrors another engine group
	 * then we need to unload ucode as we will use ucode
	 * from mirrored engine group
	 */
	if (eng_grp->mirror.is_ena)
		ucode_unload(dev, &eng_grp->ucode[0]);

	eng_grp->is_enabled = true;
	if (eng_grp->mirror.is_ena)
		dev_info(dev,
			 "Engine_group%d: reuse microcode %s from group %d",
			 eng_grp->idx, mirrored_eng_grp->ucode[0].ver_str,
			 mirrored_eng_grp->idx);
	else
		dev_info(dev, "Engine_group%d: microcode loaded %s",
			 eng_grp->idx, eng_grp->ucode[0].ver_str);
	if (is_2nd_ucode_used(eng_grp))
		dev_info(dev, "Engine_group%d: microcode loaded %s",
			 eng_grp->idx, eng_grp->ucode[1].ver_str);

	return 0;

err_release_engs:
	release_engines(dev, eng_grp);
err_ucode_unload:
	ucode_unload(dev, &eng_grp->ucode[0]);
	ucode_unload(dev, &eng_grp->ucode[1]);
err:
	return ret;
}

static ssize_t ucode_load_store(struct device *dev,
				struct device_attribute *attr,
				const char *buf, size_t count)
{
	struct engines engs[MAX_ENGS_PER_GRP] = { 0 };
	char *ucode_filename[MAX_ENGS_PER_GRP];
	char tmp_buf[NAME_LENGTH] = { 0 };
	char *start, *val, *err_msg, *tmp;
	struct engine_groups *eng_grps;
	int grp_idx = 0, ret = -EINVAL;
	int del_grp_idx = -1;
	int ucode_idx = 0;
	bool has_se, has_ie, has_ae;

	if (strlen(buf) > NAME_LENGTH)
		return -EINVAL;

	eng_grps = container_of(attr, struct engine_groups, ucode_load_attr);
	err_msg = "Invalid engine group format";
	strlcpy(tmp_buf, buf, NAME_LENGTH);
	start = tmp_buf;

	has_se = has_ie = has_ae = false;

	for (;;) {
		val = strsep(&start, ";");
		if (!val)
			break;
		val = strim(val);
		if (!*val)
			continue;

		if (!strncasecmp(val, "engine_group", 12)) {
			if (del_grp_idx != -1)
				goto err_print;
			tmp = strim(strsep(&val, ":"));
			if (!val)
				goto err_print;
			if (strlen(tmp) != 13)
				goto err_print;
			if (kstrtoint((tmp + 12), 10, &del_grp_idx))
				goto err_print;
			val = strim(val);
			if (strncasecmp(val, "null", 4))
				goto err_print;
			if (strlen(val) != 4)
				goto err_print;
		} else if (!strncasecmp(val, "se", 2) && strchr(val, ':')) {
			if (has_se || ucode_idx)
				goto err_print;
			tmp = strim(strsep(&val, ":"));
			if (!val)
				goto err_print;
			if (strlen(tmp) != 2)
				goto err_print;
			if (kstrtoint(strim(val), 10, &engs[grp_idx].count))
				goto err_print;
			engs[grp_idx++].type = SE_TYPES;
			has_se = true;
		} else if (!strncasecmp(val, "ae", 2) && strchr(val, ':')) {
			if (has_ae || ucode_idx)
				goto err_print;
			tmp = strim(strsep(&val, ":"));
			if (!val)
				goto err_print;
			if (strlen(tmp) != 2)
				goto err_print;
			if (kstrtoint(strim(val), 10, &engs[grp_idx].count))
				goto err_print;
			engs[grp_idx++].type = AE_TYPES;
			has_ae = true;
		} else if (!strncasecmp(val, "ie", 2) && strchr(val, ':')) {
			if (has_ie || ucode_idx)
				goto err_print;
			tmp = strim(strsep(&val, ":"));
			if (!val)
				goto err_print;
			if (strlen(tmp) != 2)
				goto err_print;
			if (kstrtoint(strim(val), 10, &engs[grp_idx].count))
				goto err_print;
			engs[grp_idx++].type = IE_TYPES;
			has_ie = true;
		} else {
			if (ucode_idx > 1)
				goto err_print;
			if (!strlen(val))
				goto err_print;
			if (strnstr(val, " ", strlen(val)))
				goto err_print;
			ucode_filename[ucode_idx++] = val;
		}
	}

	/* Validate input parameters */
	if (del_grp_idx == -1) {
		if (!(grp_idx && ucode_idx))
			goto err_print;

		if (ucode_idx > 1 && grp_idx < 2)
			goto err_print;

		if (grp_idx > MAX_ENGS_PER_GRP) {
			err_msg = "Error max 2 engine types can be attached";
			goto err_print;
		}

		if (grp_idx > 1) {
			if ((engs[0].type + engs[1].type) !=
			    (SE_TYPES + IE_TYPES)) {
				err_msg =
				"Only combination of SE+IE engines is allowed";
				goto err_print;
			}

			/* Keep SE engines at zero index */
			if (engs[1].type == SE_TYPES)
				swap_engines(&engs[0], &engs[1]);
		}

	} else {
		if (del_grp_idx < 0 || del_grp_idx >= CPT_MAX_ENGINE_GROUPS) {
			dev_err(dev, "Invalid engine group index %d",
				del_grp_idx);
			goto err;
		}

		if (!eng_grps->grp[del_grp_idx].is_enabled) {
			dev_err(dev, "Error engine_group%d is not configured",
				del_grp_idx);
			ret = -EINVAL;
			goto err;
		}

		if (grp_idx || ucode_idx)
			goto err_print;
	}

	mutex_lock(&eng_grps->lock);

	if (eng_grps->is_rdonly) {
		dev_err(dev, "Disable VFs before modifying engine groups\n");
		ret = -EACCES;
		goto err_unlock;
	}
	if (eng_grps->ops.discover_eng_capabilities) {
		if (eng_grps->ops.discover_eng_capabilities(eng_grps->obj)) {
			dev_err(dev, "Unable to get engine capabilities\n");
			goto err_unlock;
		}
	}

	if (del_grp_idx == -1)
		/* create engine group */
		ret = create_engine_group(dev, eng_grps, engs, grp_idx,
					  (void **) ucode_filename,
					  ucode_idx, false);
	else
		/* delete engine group */
		ret = delete_engine_group(dev, &eng_grps->grp[del_grp_idx]);
	if (ret)
		goto err_unlock;

	print_dbg_info(dev, eng_grps);
err_unlock:
	mutex_unlock(&eng_grps->lock);
	return ret ? ret : count;
err_print:
	dev_err(dev, "%s\n", err_msg);
err:
	return ret;
}

static int cpt_set_ucode_ops(struct engine_groups *eng_grps,
			     struct ucode_ops *uc_ops)
{
	if (!uc_ops)
		return -EINVAL;

	if (!uc_ops->detach_and_disable_cores ||
	    !uc_ops->attach_and_enable_cores ||
	    !uc_ops->set_ucode_base ||
	    !uc_ops->print_engines_mask)
		return -EPERM;

	eng_grps->ops = *uc_ops;
	return 0;
}

static void cpt_clear_ucode_ops(struct engine_groups *eng_grps)
{
	eng_grps->ops.detach_and_disable_cores = NULL;
	eng_grps->ops.attach_and_enable_cores = NULL;
	eng_grps->ops.set_ucode_base = NULL;
	eng_grps->ops.print_engines_mask = NULL;
	eng_grps->ops.discover_eng_capabilities = NULL;
}

int cpt_create_eng_caps_discovery_grps(struct pci_dev *pdev,
				       struct engine_groups *eng_grps)
{
	struct tar_ucode_info_t *tar_ucode_info[MAX_ENGS_PER_GRP] = { 0 };
	struct engines engs[MAX_ENGS_PER_GRP] = { 0 };
	struct tar_arch_info_t *tar_arch = NULL;
	char tar_filename[NAME_LENGTH];
	int ret = -EINVAL;

	sprintf(tar_filename, "cpt%02d-mc.tar", pdev->revision);
	tar_arch = load_tar_archive(&pdev->dev, tar_filename);
	if (!tar_arch)
		return -EINVAL;
	/*
	 * If device supports AE engines and there is AE microcode in tar
	 * archive try to create engine group with AE engines.
	 */
	tar_ucode_info[0] = get_uc_from_tar_archive(tar_arch, AE_TYPES);
	if (tar_ucode_info[0] && dev_supports_eng_type(eng_grps, AE_TYPES)) {

		engs[0].type = AE_TYPES;
		engs[0].count = 2;

		ret = create_engine_group(&pdev->dev, eng_grps, engs, 1,
					  (void **) tar_ucode_info, 1, true);
		if (ret)
			goto release_tar;
	}
	/*
	 * If device supports SE engines and there is SE microcode in tar
	 * archive try to create engine group with SE engines.
	 */
	tar_ucode_info[0] = get_uc_from_tar_archive(tar_arch, SE_TYPES);
	if (tar_ucode_info[0] && dev_supports_eng_type(eng_grps, SE_TYPES)) {

		engs[0].type = SE_TYPES;
		engs[0].count = 2;

		ret = create_engine_group(&pdev->dev, eng_grps, engs, 1,
					  (void **) tar_ucode_info, 1, true);
		if (ret)
			goto release_tar;
	}
	/*
	 * If device supports IE engines and there is IE microcode in tar
	 * archive try to create engine group with IE engines.
	 */
	tar_ucode_info[0] = get_uc_from_tar_archive(tar_arch, IE_TYPES);
	if (tar_ucode_info[0] && dev_supports_eng_type(eng_grps, IE_TYPES)) {

		engs[0].type = IE_TYPES;
		engs[0].count = 2;

		ret = create_engine_group(&pdev->dev, eng_grps, engs, 1,
					  (void **) tar_ucode_info, 1, true);
		if (ret)
			goto release_tar;
	}
release_tar:
	release_tar_archive(tar_arch);
	return ret;
}
EXPORT_SYMBOL_GPL(cpt_create_eng_caps_discovery_grps);

int cpt_try_create_default_eng_grps(struct pci_dev *pdev,
				    struct engine_groups *eng_grps)
{
	struct tar_ucode_info_t *tar_ucode_info[MAX_ENGS_PER_GRP] = { 0 };
	struct engines engs[MAX_ENGS_PER_GRP] = { 0 };
	struct tar_arch_info_t *tar_arch = NULL;
	char tar_filename[NAME_LENGTH];
	int i, ret = 0;

	mutex_lock(&eng_grps->lock);

	/* We don't create engine group for kernel crypto if attempt to create
	 * it was already made (when user enabled VFs for the first time)
	 */
	if (eng_grps->is_first_try)
		goto err;
	eng_grps->is_first_try = true;

	/* We create group for kcrypto only if no groups are configured */
	for (i = 0; i < CPT_MAX_ENGINE_GROUPS; i++)
		if (eng_grps->grp[i].is_enabled)
			goto err;

	sprintf(tar_filename, "cpt%02d-mc.tar", pdev->revision);

	tar_arch = load_tar_archive(&pdev->dev, tar_filename);
	if (!tar_arch)
		goto err;

	/* If device supports SE engines and there is SE microcode in tar
	 * archive try to create engine group with SE engines for kernel
	 * crypto functionality (symmetric crypto)
	 */
	tar_ucode_info[0] = get_uc_from_tar_archive(tar_arch, SE_TYPES);
	if (tar_ucode_info[0] && dev_supports_eng_type(eng_grps, SE_TYPES)) {

		engs[0].type = SE_TYPES;
		engs[0].count = eng_grps->avail.max_se_cnt;

		ret = create_engine_group(&pdev->dev, eng_grps, engs, 1,
					  (void **) tar_ucode_info, 1, true);
		if (ret)
			goto err;
	}
	/* If device supports SE+IE engines and there is SE and IE microcode in
	 * tar archive try to create engine group with SE+IE engines for IPSec.
	 * All SE engines will be shared with engine group 0. This case applies
	 * only to 9X platform.
	 */
	tar_ucode_info[0] = get_uc_from_tar_archive(tar_arch, SE_TYPES);
	tar_ucode_info[1] = get_uc_from_tar_archive(tar_arch, IE_TYPES);
	if (tar_ucode_info[0] && tar_ucode_info[1] &&
	    dev_supports_eng_type(eng_grps, SE_TYPES) &&
	    dev_supports_eng_type(eng_grps, IE_TYPES)) {

		engs[0].type = SE_TYPES;
		engs[0].count = eng_grps->avail.max_se_cnt;
		engs[1].type = IE_TYPES;
		engs[1].count = eng_grps->avail.max_ie_cnt;

		ret = create_engine_group(&pdev->dev, eng_grps, engs, 2,
					  (void **) tar_ucode_info, 2, true);
		if (ret)
			goto err;
	}

	/* If device supports AE engines and there is AE microcode in tar
	 * archive try to create engine group with AE engines for asymmetric
	 * crypto functionality.
	 */
	tar_ucode_info[0] = get_uc_from_tar_archive(tar_arch, AE_TYPES);
	if (tar_ucode_info[0] && dev_supports_eng_type(eng_grps, AE_TYPES)) {

		engs[0].type = AE_TYPES;
		engs[0].count = eng_grps->avail.max_ae_cnt;

		ret = create_engine_group(&pdev->dev, eng_grps, engs, 1,
					  (void **) tar_ucode_info, 1, true);
		if (ret)
			goto err;
	}
	print_dbg_info(&pdev->dev, eng_grps);
err:
	release_tar_archive(tar_arch);
	mutex_unlock(&eng_grps->lock);
	return ret;
}
EXPORT_SYMBOL_GPL(cpt_try_create_default_eng_grps);

void cpt_set_eng_grps_is_rdonly(struct engine_groups *eng_grps, bool is_rdonly)
{
	mutex_lock(&eng_grps->lock);

	eng_grps->is_rdonly = is_rdonly;

	mutex_unlock(&eng_grps->lock);
}
EXPORT_SYMBOL_GPL(cpt_set_eng_grps_is_rdonly);

void cpt_cleanup_eng_grps(struct pci_dev *pdev,
			  struct engine_groups *eng_grps)
{
	struct engine_group_info *grp;
	int i, j;

	mutex_lock(&eng_grps->lock);
	if (eng_grps->is_ucode_load_created) {
		device_remove_file(&pdev->dev,
				   &eng_grps->ucode_load_attr);
		eng_grps->is_ucode_load_created = false;
	}

	/* First delete all mirroring engine groups */
	for (i = 0; i < CPT_MAX_ENGINE_GROUPS; i++)
		if (eng_grps->grp[i].mirror.is_ena)
			delete_engine_group(&pdev->dev, &eng_grps->grp[i]);

	/* Delete remaining engine groups */
	for (i = 0; i < CPT_MAX_ENGINE_GROUPS; i++)
		delete_engine_group(&pdev->dev, &eng_grps->grp[i]);

	/* Release memory */
	for (i = 0; i < CPT_MAX_ENGINE_GROUPS; i++) {
		grp = &eng_grps->grp[i];
		for (j = 0; j < MAX_ENGS_PER_GRP; j++) {
			kfree(grp->engs[j].bmap);
			grp->engs[j].bmap = NULL;
		}
	}

	cpt_clear_ucode_ops(eng_grps);
	mutex_unlock(&eng_grps->lock);
}
EXPORT_SYMBOL_GPL(cpt_cleanup_eng_grps);

int cpt_init_eng_grps(struct pci_dev *pdev, struct engine_groups *eng_grps,
		      struct ucode_ops ops, int pf_type)
{
	struct engine_group_info *grp;
	int i, j, ret = 0;

	mutex_init(&eng_grps->lock);
	eng_grps->obj = pci_get_drvdata(pdev);
	eng_grps->avail.se_cnt = eng_grps->avail.max_se_cnt;
	eng_grps->avail.ie_cnt = eng_grps->avail.max_ie_cnt;
	eng_grps->avail.ae_cnt = eng_grps->avail.max_ae_cnt;

	eng_grps->engs_num = eng_grps->avail.max_se_cnt +
			     eng_grps->avail.max_ie_cnt +
			     eng_grps->avail.max_ae_cnt;
	if (eng_grps->engs_num > CPT_MAX_ENGINES) {
		dev_err(&pdev->dev,
			"Number of engines %d > than max supported %d",
			eng_grps->engs_num, CPT_MAX_ENGINES);
		ret = -EINVAL;
		goto err;
	}

	for (i = 0; i < CPT_MAX_ENGINE_GROUPS; i++) {
		grp = &eng_grps->grp[i];
		grp->g = eng_grps;
		grp->idx = i;

		snprintf(grp->sysfs_info_name, NAME_LENGTH,
			 "engine_group%d", i);
		for (j = 0; j < MAX_ENGS_PER_GRP; j++) {
			grp->engs[j].bmap =
				kcalloc(BITS_TO_LONGS(eng_grps->engs_num),
					sizeof(long), GFP_KERNEL);
			if (!grp->engs[j].bmap) {
				ret = -ENOMEM;
				goto err;
			}
		}
	}

	switch (pf_type) {
	case CPT_81XX:
		/* 81XX CPT PF has SE and AE engines attached */
		eng_grps->eng_types_supported = 1 << SE_TYPES | 1 << AE_TYPES;
	break;

	case CPT_SE_83XX:
		/* 83XX SE CPT PF has only SE engines attached */
		eng_grps->eng_types_supported = 1 << SE_TYPES;
	break;

	case CPT_AE_83XX:
		/* 83XX AE CPT PF has only AE engines attached */
		eng_grps->eng_types_supported = 1 << AE_TYPES;
	break;

	case CPT_96XX:
		/* 96XX CPT PF has SE, IE and AE engines attached */
		eng_grps->eng_types_supported = 1 << SE_TYPES | 1 << IE_TYPES |
						1 << AE_TYPES;
	break;

	default:
		dev_err(&pdev->dev, "Unknown PF type %d\n", pf_type);
		ret = -EINVAL;
		goto err;
	}

	ret = cpt_set_ucode_ops(eng_grps, &ops);
	if (ret)
		goto err;

	eng_grps->ucode_load_attr.show = NULL;
	eng_grps->ucode_load_attr.store = ucode_load_store;
	eng_grps->ucode_load_attr.attr.name = "ucode_load";
	eng_grps->ucode_load_attr.attr.mode = 0220;
	sysfs_attr_init(&eng_grps->ucode_load_attr.attr);
	ret = device_create_file(&pdev->dev,
				 &eng_grps->ucode_load_attr);
	if (ret)
		goto err;
	eng_grps->is_ucode_load_created = true;

	print_dbg_info(&pdev->dev, eng_grps);
	return ret;
err:
	cpt_cleanup_eng_grps(pdev, eng_grps);
	return ret;
}
EXPORT_SYMBOL_GPL(cpt_init_eng_grps);

MODULE_AUTHOR("Marvell International Ltd.");
MODULE_DESCRIPTION("Marvell CPT common layer");
MODULE_LICENSE("GPL v2");
MODULE_VERSION(DRV_VERSION);
