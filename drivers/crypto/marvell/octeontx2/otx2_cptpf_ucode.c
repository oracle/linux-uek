// SPDX-License-Identifier: GPL-2.0
/* Marvell OcteonTX2 CPT driver
 *
 * Copyright (C) 2018 Marvell International Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/ctype.h>
#include <linux/firmware.h>
#include "otx2_cptpf_ucode.h"
#include "otx2_cpt_common.h"
#include "otx2_cpt_mbox_common.h"
#include "rvu_reg.h"

#define CSR_DELAY 30
/* Tar archive defines */
#define TAR_MAGIC "ustar"
#define TAR_MAGIC_LEN 6
#define TAR_BLOCK_LEN 512
#define REGTYPE '0'
#define AREGTYPE '\0'

#define LOADFVC_RLEN 8
#define LOADFVC_MAJOR_OP 0x01
#define LOADFVC_MINOR_OP 0x08

/* tar header as defined in POSIX 1003.1-1990. */
struct tar_hdr_t {
	char name[100];
	char mode[8];
	char uid[8];
	char gid[8];
	char size[12];
	char mtime[12];
	char chksum[8];
	char typeflag;
	char linkname[100];
	char magic[6];
	char version[2];
	char uname[32];
	char gname[32];
	char devmajor[8];
	char devminor[8];
	char prefix[155];
};

struct tar_blk_t {
	union {
		struct tar_hdr_t hdr;
		char block[TAR_BLOCK_LEN];
	};
};

struct tar_arch_info_t {
	struct list_head ucodes;
	const struct firmware *fw;
};

static struct otx2_cpt_bitmap get_cores_bmap(struct device *dev,
					struct otx2_cpt_eng_grp_info *eng_grp)
{
	struct otx2_cpt_bitmap bmap = { 0 };
	bool found = false;
	int i;

	if (eng_grp->g->engs_num > OTX2_CPT_MAX_ENGINES) {
		dev_err(dev, "unsupported number of engines %d on octeontx2\n",
			eng_grp->g->engs_num);
		return bmap;
	}

	for (i = 0; i  < OTX2_CPT_MAX_ETYPES_PER_GRP; i++) {
		if (eng_grp->engs[i].type) {
			bitmap_or(bmap.bits, bmap.bits,
				  eng_grp->engs[i].bmap,
				  eng_grp->g->engs_num);
			bmap.size = eng_grp->g->engs_num;
			found = true;
		}
	}

	if (!found)
		dev_err(dev, "No engines reserved for engine group %d\n",
			eng_grp->idx);
	return bmap;
}

static int is_eng_type(int val, int eng_type)
{
	return val & (1 << eng_type);
}

static int dev_supports_eng_type(struct otx2_cpt_eng_grps *eng_grps,
				 int eng_type)
{
	return is_eng_type(eng_grps->eng_types_supported, eng_type);
}

static int is_2nd_ucode_used(struct otx2_cpt_eng_grp_info *eng_grp)
{
	if (eng_grp->ucode[1].type)
		return true;
	else
		return false;
}

static void set_ucode_filename(struct otx2_cpt_ucode *ucode,
			       const char *filename)
{
	strlcpy(ucode->filename, filename, OTX2_CPT_NAME_LENGTH);
}

static char *get_eng_type_str(int eng_type)
{
	char *str = "unknown";

	switch (eng_type) {
	case OTX2_CPT_SE_TYPES:
		str = "SE";
		break;

	case OTX2_CPT_IE_TYPES:
		str = "IE";
		break;

	case OTX2_CPT_AE_TYPES:
		str = "AE";
		break;
	}
	return str;
}

static char *get_ucode_type_str(int ucode_type)
{
	char *str = "unknown";

	switch (ucode_type) {
	case (1 << OTX2_CPT_SE_TYPES):
		str = "SE";
		break;

	case (1 << OTX2_CPT_IE_TYPES):
		str = "IE";
		break;

	case (1 << OTX2_CPT_AE_TYPES):
		str = "AE";
		break;

	case (1 << OTX2_CPT_SE_TYPES | 1 << OTX2_CPT_IE_TYPES):
		str = "SE+IPSEC";
		break;
	}
	return str;
}

static void swap_engines(struct otx2_cpt_engines *engsl,
			 struct otx2_cpt_engines *engsr)
{
	struct otx2_cpt_engines engs;

	engs = *engsl;
	*engsl = *engsr;
	*engsr = engs;
}

static void swap_ucodes(struct otx2_cpt_ucode *ucodel,
			struct otx2_cpt_ucode *ucoder)
{
	struct otx2_cpt_ucode ucode;

	ucode = *ucodel;
	*ucodel = *ucoder;
	*ucoder = ucode;
}

static int get_ucode_type(struct otx2_cpt_ucode_hdr *ucode_hdr, int *ucode_type)
{
	char tmp_ver_str[OTX2_CPT_UCODE_VER_STR_SZ];
	int i, val = 0;
	u8 nn;

	strlcpy(tmp_ver_str, ucode_hdr->ver_str, OTX2_CPT_UCODE_VER_STR_SZ);
	for (i = 0; i < strlen(tmp_ver_str); i++)
		tmp_ver_str[i] = tolower(tmp_ver_str[i]);

	nn = ucode_hdr->ver_num.nn;
	if (strnstr(tmp_ver_str, "se-", OTX2_CPT_UCODE_VER_STR_SZ) &&
	    (nn == OTX2_CPT_SE_UC_TYPE1 || nn == OTX2_CPT_SE_UC_TYPE2 ||
	     nn == OTX2_CPT_SE_UC_TYPE3))
		val |= 1 << OTX2_CPT_SE_TYPES;
	if (strnstr(tmp_ver_str, "ipsec", OTX2_CPT_UCODE_VER_STR_SZ) &&
	    (nn == OTX2_CPT_IE_UC_TYPE1 || nn == OTX2_CPT_IE_UC_TYPE2 ||
	     nn == OTX2_CPT_IE_UC_TYPE3))
		val |= 1 << OTX2_CPT_IE_TYPES;
	if (strnstr(tmp_ver_str, "ae", OTX2_CPT_UCODE_VER_STR_SZ) &&
	    nn == OTX2_CPT_AE_UC_TYPE)
		val |= 1 << OTX2_CPT_AE_TYPES;

	*ucode_type = val;

	if (!val)
		return -EINVAL;
	if (is_eng_type(val, OTX2_CPT_AE_TYPES) &&
	    (is_eng_type(val, OTX2_CPT_SE_TYPES) ||
	    is_eng_type(val, OTX2_CPT_IE_TYPES)))
		return -EINVAL;

	return 0;
}

static int is_mem_zero(const char *ptr, int size)
{
	int i;

	for (i = 0; i < size; i++) {
		if (ptr[i])
			return 0;
	}
	return 1;
}

static int cptx_set_ucode_base(struct otx2_cpt_eng_grp_info *eng_grp,
			       struct otx2_cptpf_dev *cptpf)
{
	struct otx2_cpt_engs_rsvd *engs;
	dma_addr_t dma_addr;
	int i, bit, ret;

	/* Set PF number for microcode fetches */
	ret = otx2_cpt_write_af_reg(cptpf->pdev, CPT_AF_PF_FUNC,
				    cptpf->pf_id << RVU_PFVF_PF_SHIFT);
	if (ret)
		return ret;

	for (i = 0; i < OTX2_CPT_MAX_ETYPES_PER_GRP; i++) {
		engs = &eng_grp->engs[i];
		if (!engs->type)
			continue;

		dma_addr = engs->ucode->align_dma;

		/*
		 * Set UCODE_BASE only for the cores which are not used,
		 * other cores should have already valid UCODE_BASE set
		 */
		for_each_set_bit(bit, engs->bmap, eng_grp->g->engs_num)
			if (!eng_grp->g->eng_ref_cnt[bit]) {
				ret = otx2_cpt_write_af_reg(cptpf->pdev,
						CPT_AF_EXEX_UCODE_BASE(bit),
						(u64) dma_addr);
				if (ret)
					return ret;
			}
	}
	return 0;
}

static int cpt_set_ucode_base(struct otx2_cpt_eng_grp_info *eng_grp, void *obj)
{
	struct otx2_cptpf_dev *cptpf = obj;
	int ret;

	if (cptpf->cpt1_implemented) {
		cptpf->blkaddr = BLKADDR_CPT1;
		ret = cptx_set_ucode_base(eng_grp, cptpf);
		if (ret)
			return ret;
	}
	cptpf->blkaddr = BLKADDR_CPT0;
	ret = cptx_set_ucode_base(eng_grp, cptpf);

	return ret;
}

static int cptx_detach_and_disable_cores(struct otx2_cpt_eng_grp_info *eng_grp,
					 struct otx2_cptpf_dev *cptpf,
					 struct otx2_cpt_bitmap bmap)
{
	int i, busy, ret;
	int timeout = 10;
	u64 reg;

	/* Detach the cores from group */
	for_each_set_bit(i, bmap.bits, bmap.size) {
		ret = otx2_cpt_read_af_reg(cptpf->pdev, CPT_AF_EXEX_CTL2(i),
					   &reg);
		if (ret)
			return ret;

		if (reg & (1ull << eng_grp->idx)) {
			eng_grp->g->eng_ref_cnt[i]--;
			reg &= ~(1ull << eng_grp->idx);

			ret = otx2_cpt_write_af_reg(cptpf->pdev,
						    CPT_AF_EXEX_CTL2(i), reg);
			if (ret)
				return ret;
		}
	}

	/* Wait for cores to become idle */
	do {
		busy = 0;
		usleep_range(10000, 20000);
		if (timeout-- < 0)
			return -EBUSY;

		for_each_set_bit(i, bmap.bits, bmap.size) {
			ret = otx2_cpt_read_af_reg(cptpf->pdev,
						   CPT_AF_EXEX_STS(i), &reg);
			if (ret)
				return ret;

			if (reg & 0x1) {
				busy = 1;
				break;
			}
		}
	} while (busy);

	/* Disable the cores only if they are not used anymore */
	for_each_set_bit(i, bmap.bits, bmap.size) {
		if (!eng_grp->g->eng_ref_cnt[i]) {
			ret = otx2_cpt_write_af_reg(cptpf->pdev,
						    CPT_AF_EXEX_CTL(i), 0x0);
			if (ret)
				return ret;
		}
	}

	return 0;
}

static int cpt_detach_and_disable_cores(struct otx2_cpt_eng_grp_info *eng_grp,
					void *obj)
{
	struct otx2_cptpf_dev *cptpf = obj;
	struct otx2_cpt_bitmap bmap;
	int ret;

	bmap = get_cores_bmap(&cptpf->pdev->dev, eng_grp);
	if (!bmap.size)
		return -EINVAL;

	if (cptpf->cpt1_implemented) {
		cptpf->blkaddr = BLKADDR_CPT1;
		ret = cptx_detach_and_disable_cores(eng_grp, cptpf, bmap);
		if (ret)
			return ret;
	}
	cptpf->blkaddr = BLKADDR_CPT0;
	ret = cptx_detach_and_disable_cores(eng_grp, cptpf, bmap);

	return ret;
}

static int cptx_attach_and_enable_cores(struct otx2_cpt_eng_grp_info *eng_grp,
					struct otx2_cptpf_dev *cptpf,
					struct otx2_cpt_bitmap bmap)
{
	int i, ret;
	u64 reg;

	/* Attach the cores to the group */
	for_each_set_bit(i, bmap.bits, bmap.size) {
		ret = otx2_cpt_read_af_reg(cptpf->pdev, CPT_AF_EXEX_CTL2(i),
					   &reg);
		if (ret)
			return ret;

		if (!(reg & (1ull << eng_grp->idx))) {
			eng_grp->g->eng_ref_cnt[i]++;
			reg |= 1ull << eng_grp->idx;

			ret = otx2_cpt_write_af_reg(cptpf->pdev,
						    CPT_AF_EXEX_CTL2(i), reg);
			if (ret)
				return ret;
		}
	}

	/* Enable the cores */
	for_each_set_bit(i, bmap.bits, bmap.size) {
		ret = otx2_cpt_add_write_af_reg(cptpf->pdev,
						CPT_AF_EXEX_CTL(i), 0x1);
		if (ret)
			return ret;
	}
	ret = otx2_cpt_send_af_reg_requests(cptpf->pdev);

	return ret;
}

static int cpt_attach_and_enable_cores(struct otx2_cpt_eng_grp_info *eng_grp,
				       void *obj)
{
	struct otx2_cptpf_dev *cptpf = obj;
	struct otx2_cpt_bitmap bmap;
	int ret;

	bmap = get_cores_bmap(&cptpf->pdev->dev, eng_grp);
	if (!bmap.size)
		return -EINVAL;

	if (cptpf->cpt1_implemented) {
		cptpf->blkaddr = BLKADDR_CPT1;
		ret = cptx_attach_and_enable_cores(eng_grp, cptpf, bmap);
		if (ret)
			return ret;
	}
	cptpf->blkaddr = BLKADDR_CPT0;
	ret = cptx_attach_and_enable_cores(eng_grp, cptpf, bmap);

	return ret;
}

static int process_tar_file(struct device *dev,
			    struct tar_arch_info_t *tar_arch, char *filename,
			    const u8 *data, int size)
{
	struct tar_ucode_info_t *tar_ucode_info;
	struct otx2_cpt_ucode_hdr *ucode_hdr;
	int ucode_type, ucode_size;

	/*
	 * If size is less than microcode header size then don't report
	 * an error because it might not be microcode file, just process
	 * next file from archive
	 */
	if (size < sizeof(struct otx2_cpt_ucode_hdr))
		return 0;

	ucode_hdr = (struct otx2_cpt_ucode_hdr *) data;
	/*
	 * If microcode version can't be found don't report an error
	 * because it might not be microcode file, just process next file
	 */
	if (get_ucode_type(ucode_hdr, &ucode_type))
		return 0;

	ucode_size = ntohl(ucode_hdr->code_length) * 2;
	if (!ucode_size || (size < round_up(ucode_size, 16) +
	    sizeof(struct otx2_cpt_ucode_hdr) + OTX2_CPT_UCODE_SIGN_LEN)) {
		dev_err(dev, "Ucode %s invalid size\n", filename);
		return -EINVAL;
	}

	tar_ucode_info = kzalloc(sizeof(*tar_ucode_info), GFP_KERNEL);
	if (!tar_ucode_info)
		return -ENOMEM;

	tar_ucode_info->ucode_ptr = data;
	set_ucode_filename(&tar_ucode_info->ucode, filename);
	memcpy(tar_ucode_info->ucode.ver_str, ucode_hdr->ver_str,
	       OTX2_CPT_UCODE_VER_STR_SZ);
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

		if (ucode_type == OTX2_CPT_IE_TYPES &&
		    is_eng_type(curr->ucode.type, OTX2_CPT_SE_TYPES))
			continue;

		if (!uc_found) {
			uc_found = curr;
			continue;
		}

		switch (ucode_type) {
		case OTX2_CPT_AE_TYPES:
			break;

		case OTX2_CPT_SE_TYPES:
			if (uc_found->ucode.ver_num.nn ==
							OTX2_CPT_SE_UC_TYPE2 ||
			    (uc_found->ucode.ver_num.nn ==
							OTX2_CPT_SE_UC_TYPE3 &&
			     curr->ucode.ver_num.nn == OTX2_CPT_SE_UC_TYPE1))
				uc_found = curr;
			break;

		case OTX2_CPT_IE_TYPES:
			if (uc_found->ucode.ver_num.nn ==
							OTX2_CPT_IE_UC_TYPE2 ||
			    (uc_found->ucode.ver_num.nn ==
							OTX2_CPT_IE_UC_TYPE3 &&
			     curr->ucode.ver_num.nn == OTX2_CPT_IE_UC_TYPE1))
				uc_found = curr;
			break;
		}
	}
	return uc_found;
}

static void print_tar_dbg_info(struct tar_arch_info_t *tar_arch,
			       char *tar_filename)
{
	struct tar_ucode_info_t *curr;

	pr_debug("Tar archive filename %s\n", tar_filename);
	pr_debug("Tar archive pointer %p, size %ld\n", tar_arch->fw->data,
		 tar_arch->fw->size);
	list_for_each_entry(curr, &tar_arch->ucodes, list) {
		pr_debug("Ucode filename %s\n", curr->ucode.filename);
		pr_debug("Ucode version string %s\n", curr->ucode.ver_str);
		pr_debug("Ucode version %d.%d.%d.%d\n",
			 curr->ucode.ver_num.nn, curr->ucode.ver_num.xx,
			 curr->ucode.ver_num.yy, curr->ucode.ver_num.zz);
		pr_debug("Ucode type (%d) %s\n", curr->ucode.type,
			 get_ucode_type_str(curr->ucode.type));
		pr_debug("Ucode size %d\n", curr->ucode.size);
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
		return NULL;

	INIT_LIST_HEAD(&tar_arch->ucodes);

	/* Load tar archive */
	ret = request_firmware(&tar_arch->fw, tar_filename, dev);
	if (ret)
		goto release_tar_arch;

	if (tar_arch->fw->size < TAR_BLOCK_LEN) {
		dev_err(dev, "Invalid tar archive %s\n", tar_filename);
		goto release_tar_arch;
	}

	tar_size = tar_arch->fw->size;
	tar_blk = (struct tar_blk_t *) tar_arch->fw->data;
	if (strncmp(tar_blk->hdr.magic, TAR_MAGIC, TAR_MAGIC_LEN - 1)) {
		dev_err(dev, "Unsupported format of tar archive %s\n",
			tar_filename);
		goto release_tar_arch;
	}

	while (1) {
		/* Read current file size */
		ret = kstrtouint(tar_blk->hdr.size, 8, &cur_size);
		if (ret)
			goto release_tar_arch;

		if (tar_offs + cur_size > tar_size ||
		    tar_offs + 2*TAR_BLOCK_LEN > tar_size) {
			dev_err(dev, "Invalid tar archive %s\n", tar_filename);
			goto release_tar_arch;
		}

		tar_offs += TAR_BLOCK_LEN;
		if (tar_blk->hdr.typeflag == REGTYPE ||
		    tar_blk->hdr.typeflag == AREGTYPE) {
			ret = process_tar_file(dev, tar_arch,
					       tar_blk->hdr.name,
					       &tar_arch->fw->data[tar_offs],
					       cur_size);
			if (ret)
				goto release_tar_arch;
		}

		tar_offs += (cur_size/TAR_BLOCK_LEN) * TAR_BLOCK_LEN;
		if (cur_size % TAR_BLOCK_LEN)
			tar_offs += TAR_BLOCK_LEN;

		/* Check for the end of the archive */
		if (tar_offs + 2*TAR_BLOCK_LEN > tar_size) {
			dev_err(dev, "Invalid tar archive %s\n", tar_filename);
			goto release_tar_arch;
		}

		if (is_mem_zero(&tar_arch->fw->data[tar_offs],
		    2*TAR_BLOCK_LEN))
			break;

		/* Read next block from tar archive */
		tar_blk = (struct tar_blk_t *) &tar_arch->fw->data[tar_offs];
	}

	print_tar_dbg_info(tar_arch, tar_filename);
	return tar_arch;
release_tar_arch:
	release_tar_archive(tar_arch);
	return NULL;
}

static struct otx2_cpt_engs_rsvd *find_engines_by_type(
					struct otx2_cpt_eng_grp_info *eng_grp,
					int eng_type)
{
	int i;

	for (i = 0; i < OTX2_CPT_MAX_ETYPES_PER_GRP; i++) {
		if (!eng_grp->engs[i].type)
			continue;

		if (eng_grp->engs[i].type == eng_type)
			return &eng_grp->engs[i];
	}
	return NULL;
}

int otx2_cpt_uc_supports_eng_type(struct otx2_cpt_ucode *ucode, int eng_type)
{
	return is_eng_type(ucode->type, eng_type);
}

int otx2_cpt_eng_grp_has_eng_type(struct otx2_cpt_eng_grp_info *eng_grp,
				  int eng_type)
{
	struct otx2_cpt_engs_rsvd *engs;

	engs = find_engines_by_type(eng_grp, eng_type);

	return (engs != NULL ? 1 : 0);
}

static void print_ucode_info(struct otx2_cpt_eng_grp_info *eng_grp,
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

static void print_engs_info(struct otx2_cpt_eng_grp_info *eng_grp,
			    char *buf, int size, int idx)
{
	struct otx2_cpt_engs_rsvd *mirrored_engs = NULL;
	struct otx2_cpt_engs_rsvd *engs;
	int len, i;

	buf[0] = '\0';
	for (i = 0; i < OTX2_CPT_MAX_ETYPES_PER_GRP; i++) {
		engs = &eng_grp->engs[i];
		if (!engs->type)
			continue;
		if (idx != -1 && idx != i)
			continue;

		if (eng_grp->mirror.is_ena)
			mirrored_engs = find_engines_by_type(
					&eng_grp->g->grp[eng_grp->mirror.idx],
					engs->type);
		if (i > 0 && idx == -1) {
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

static void print_ucode_dbg_info(struct otx2_cpt_ucode *ucode)
{
	pr_debug("Ucode info\n");
	pr_debug("Ucode version string %s\n", ucode->ver_str);
	pr_debug("Ucode version %d.%d.%d.%d\n", ucode->ver_num.nn,
		 ucode->ver_num.xx, ucode->ver_num.yy, ucode->ver_num.zz);
	pr_debug("Ucode type %s\n", get_ucode_type_str(ucode->type));
	pr_debug("Ucode size %d\n", ucode->size);
	pr_debug("Ucode virt address %16.16llx\n", (u64)ucode->align_va);
	pr_debug("Ucode phys address %16.16llx\n", ucode->align_dma);
}

static void print_engines_mask(struct otx2_cpt_eng_grp_info *eng_grp,
			       void *obj, char *buf, int size)
{
	struct otx2_cptpf_dev *cptpf = obj;
	struct otx2_cpt_bitmap bmap;
	u32 mask[4];

	bmap = get_cores_bmap(&cptpf->pdev->dev, eng_grp);
	if (!bmap.size) {
		scnprintf(buf, size, "unknown");
		return;
	}
	bitmap_to_arr32(mask, bmap.bits, bmap.size);
	scnprintf(buf, size, "%8.8x %8.8x %8.8x %8.8x", mask[3], mask[2],
		  mask[1], mask[0]);
}

static void print_dbg_info(struct device *dev,
			   struct otx2_cpt_eng_grps *eng_grps)
{
	struct otx2_cpt_eng_grp_info *mirrored_grp;
	char engs_info[2*OTX2_CPT_NAME_LENGTH];
	char engs_mask[OTX2_CPT_NAME_LENGTH];
	struct otx2_cpt_eng_grp_info *grp;
	struct otx2_cpt_engs_rsvd *engs;
	u32 mask[4];
	int i, j;

	pr_debug("Engine groups global info\n");
	pr_debug("max SE %d, max IE %d, max AE %d\n",
		 eng_grps->avail.max_se_cnt, eng_grps->avail.max_ie_cnt,
		 eng_grps->avail.max_ae_cnt);
	pr_debug("free SE %d\n", eng_grps->avail.se_cnt);
	pr_debug("free IE %d\n", eng_grps->avail.ie_cnt);
	pr_debug("free AE %d\n", eng_grps->avail.ae_cnt);

	for (i = 0; i < OTX2_CPT_MAX_ENGINE_GROUPS; i++) {
		grp = &eng_grps->grp[i];
		pr_debug("engine_group%d, state %s\n", i, grp->is_enabled ?
			 "enabled" : "disabled");
		if (grp->is_enabled) {
			mirrored_grp = &eng_grps->grp[grp->mirror.idx];
			pr_debug("Ucode0 filename %s, version %s\n",
				 grp->mirror.is_ena ?
				 mirrored_grp->ucode[0].filename :
				 grp->ucode[0].filename,
				 grp->mirror.is_ena ?
				 mirrored_grp->ucode[0].ver_str :
				 grp->ucode[0].ver_str);
			if (is_2nd_ucode_used(grp))
				pr_debug("Ucode1 filename %s, version %s\n",
					 grp->ucode[1].filename,
					 grp->ucode[1].ver_str);
			else
				pr_debug("Ucode1 not used\n");
		}

		for (j = 0; j < OTX2_CPT_MAX_ETYPES_PER_GRP; j++) {
			engs = &grp->engs[j];
			if (engs->type) {
				print_engs_info(grp, engs_info,
						2*OTX2_CPT_NAME_LENGTH,
						j);
				pr_debug("Slot%d: %s\n", j, engs_info);
				bitmap_to_arr32(mask, engs->bmap,
						eng_grps->engs_num);
				pr_debug("Mask:  %8.8x %8.8x %8.8x %8.8x\n",
					 mask[3], mask[2], mask[1], mask[0]);
			} else
				pr_debug("Slot%d not used\n", j);
		}
		if (grp->is_enabled) {
			print_engines_mask(grp, eng_grps->obj, engs_mask,
					   OTX2_CPT_NAME_LENGTH);
			pr_debug("Cmask: %s\n", engs_mask);
		}
	}
}

static int update_engines_avail_count(struct device *dev,
				      struct otx2_cpt_engs_available *avail,
				      struct otx2_cpt_engs_rsvd *engs, int val)
{
	switch (engs->type) {
	case OTX2_CPT_SE_TYPES:
		avail->se_cnt += val;
		break;

	case OTX2_CPT_IE_TYPES:
		avail->ie_cnt += val;
		break;

	case OTX2_CPT_AE_TYPES:
		avail->ae_cnt += val;
		break;

	default:
		dev_err(dev, "Invalid engine type %d\n", engs->type);
		return -EINVAL;
	}

	return 0;
}

static int update_engines_offset(struct device *dev,
				 struct otx2_cpt_engs_available *avail,
				 struct otx2_cpt_engs_rsvd *engs)
{
	switch (engs->type) {
	case OTX2_CPT_SE_TYPES:
		engs->offset = 0;
		break;

	case OTX2_CPT_IE_TYPES:
		engs->offset = avail->max_se_cnt;
		break;

	case OTX2_CPT_AE_TYPES:
		engs->offset = avail->max_se_cnt + avail->max_ie_cnt;
		break;

	default:
		dev_err(dev, "Invalid engine type %d\n", engs->type);
		return -EINVAL;
	}

	return 0;
}

static int release_engines(struct device *dev,
			   struct otx2_cpt_eng_grp_info *grp)
{
	int i, ret = 0;

	for (i = 0; i < OTX2_CPT_MAX_ETYPES_PER_GRP; i++) {
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
			      struct otx2_cpt_eng_grp_info *grp,
			      struct otx2_cpt_engines *req_engs)
{
	struct otx2_cpt_engs_rsvd *engs = NULL;
	int i, ret;

	for (i = 0; i < OTX2_CPT_MAX_ETYPES_PER_GRP; i++) {
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
				      struct otx2_cpt_eng_grp_info *grp,
				      struct otx2_cpt_engines *req_eng)
{
	int avail_cnt = 0;

	switch (req_eng->type) {
	case OTX2_CPT_SE_TYPES:
		avail_cnt = grp->g->avail.se_cnt;
		break;

	case OTX2_CPT_IE_TYPES:
		avail_cnt = grp->g->avail.ie_cnt;
		break;

	case OTX2_CPT_AE_TYPES:
		avail_cnt = grp->g->avail.ae_cnt;
		break;

	default:
		dev_err(dev, "Invalid engine type %d\n", req_eng->type);
		return -EINVAL;
	}

	if (avail_cnt < req_eng->count) {
		dev_err(dev,
			"Error available %s engines %d < than requested %d\n",
			get_eng_type_str(req_eng->type),
			avail_cnt, req_eng->count);
		return -EBUSY;
	}
	return 0;
}

static int reserve_engines(struct device *dev,
			   struct otx2_cpt_eng_grp_info *grp,
			   struct otx2_cpt_engines *req_engs, int req_cnt)
{
	int i, ret = 0;

	/* Validate if a number of requested engines is available */
	for (i = 0; i < req_cnt; i++) {
		ret = check_engines_availability(dev, grp, &req_engs[i]);
		if (ret)
			return ret;
	}

	/* Reserve requested engines for this engine group */
	for (i = 0; i < req_cnt; i++) {
		ret = do_reserve_engines(dev, grp, &req_engs[i]);
		if (ret)
			return ret;
	}
	return 0;
}

static ssize_t eng_grp_info_show(struct device *dev,
				 struct device_attribute *attr,
				 char *buf)
{
	struct otx2_cpt_eng_grp_info *eng_grp;
	char ucode_info[2*OTX2_CPT_NAME_LENGTH];
	char engs_info[2*OTX2_CPT_NAME_LENGTH];
	char engs_mask[OTX2_CPT_NAME_LENGTH];
	int ret;

	eng_grp = container_of(attr, struct otx2_cpt_eng_grp_info, info_attr);
	mutex_lock(&eng_grp->g->lock);

	print_engs_info(eng_grp, engs_info, 2 * OTX2_CPT_NAME_LENGTH, -1);
	print_ucode_info(eng_grp, ucode_info, 2 * OTX2_CPT_NAME_LENGTH);
	print_engines_mask(eng_grp, eng_grp->g, engs_mask,
			   OTX2_CPT_NAME_LENGTH);
	ret = scnprintf(buf, PAGE_SIZE,
			"Microcode : %s\nEngines: %s\nEngines mask: %s\n",
			ucode_info, engs_info, engs_mask);

	mutex_unlock(&eng_grp->g->lock);
	return ret;
}

static int create_sysfs_eng_grps_info(struct device *dev,
				      struct otx2_cpt_eng_grp_info *eng_grp)
{
	int ret;

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

static void ucode_unload(struct device *dev, struct otx2_cpt_ucode *ucode)
{
	if (ucode->va) {
		dma_free_coherent(dev, ucode->size + OTX2_CPT_UCODE_ALIGNMENT,
				  ucode->va, ucode->dma);
		ucode->va = NULL;
		ucode->align_va = NULL;
		ucode->dma = 0;
		ucode->align_dma = 0;
		ucode->size = 0;
	}

	memset(&ucode->ver_str, 0, OTX2_CPT_UCODE_VER_STR_SZ);
	memset(&ucode->ver_num, 0, sizeof(struct otx2_cpt_ucode_ver_num));
	set_ucode_filename(ucode, "");
	ucode->type = 0;
}

static int copy_ucode_to_dma_mem(struct device *dev,
				 struct otx2_cpt_ucode *ucode,
				 const u8 *ucode_data)
{
	u32 i;

	/*  Allocate DMAable space */
	ucode->va = dma_alloc_coherent(dev, ucode->size +
				       OTX2_CPT_UCODE_ALIGNMENT,
				       &ucode->dma, GFP_KERNEL);
	if (!ucode->va) {
		dev_err(dev, "Unable to allocate space for microcode\n");
		return -ENOMEM;
	}
	ucode->align_va = PTR_ALIGN(ucode->va, OTX2_CPT_UCODE_ALIGNMENT);
	ucode->align_dma = PTR_ALIGN(ucode->dma, OTX2_CPT_UCODE_ALIGNMENT);

	memcpy((void *) ucode->align_va, (void *) ucode_data +
	       sizeof(struct otx2_cpt_ucode_hdr), ucode->size);

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

static int ucode_load(struct device *dev, struct otx2_cpt_ucode *ucode,
		      const char *ucode_filename)
{
	struct otx2_cpt_ucode_hdr *ucode_hdr;
	const struct firmware *fw;
	int ret;

	set_ucode_filename(ucode, ucode_filename);
	ret = request_firmware(&fw, ucode->filename, dev);
	if (ret)
		return ret;

	ucode_hdr = (struct otx2_cpt_ucode_hdr *) fw->data;
	memcpy(ucode->ver_str, ucode_hdr->ver_str, OTX2_CPT_UCODE_VER_STR_SZ);
	ucode->ver_num = ucode_hdr->ver_num;
	ucode->size = ntohl(ucode_hdr->code_length) * 2;
	if (!ucode->size || (fw->size < round_up(ucode->size, 16)
	    + sizeof(struct otx2_cpt_ucode_hdr) + OTX2_CPT_UCODE_SIGN_LEN)) {
		dev_err(dev, "Ucode %s invalid size\n", ucode_filename);
		ret = -EINVAL;
		goto release_fw;
	}

	ret = get_ucode_type(ucode_hdr, &ucode->type);
	if (ret) {
		dev_err(dev, "Microcode %s unknown type 0x%x\n",
			ucode->filename, ucode->type);
		goto release_fw;
	}

	ret = copy_ucode_to_dma_mem(dev, ucode, fw->data);
	if (ret)
		goto release_fw;

	print_ucode_dbg_info(ucode);
release_fw:
	release_firmware(fw);
	return ret;
}

static int enable_eng_grp(struct otx2_cpt_eng_grp_info *eng_grp,
			  void *obj)
{
	int ret;

	/* Point microcode to each core of the group */
	ret = cpt_set_ucode_base(eng_grp, obj);
	if (ret)
		return ret;

	/* Attach the cores to the group and enable them */
	ret = cpt_attach_and_enable_cores(eng_grp, obj);

	return ret;
}

static int disable_eng_grp(struct device *dev,
			   struct otx2_cpt_eng_grp_info *eng_grp,
			   void *obj)
{
	int i, ret;

	/* Disable all engines used by this group */
	ret = cpt_detach_and_disable_cores(eng_grp, obj);
	if (ret)
		return ret;

	/* Unload ucode used by this engine group */
	ucode_unload(dev, &eng_grp->ucode[0]);
	ucode_unload(dev, &eng_grp->ucode[1]);

	for (i = 0; i < OTX2_CPT_MAX_ETYPES_PER_GRP; i++) {
		if (!eng_grp->engs[i].type)
			continue;

		eng_grp->engs[i].ucode = &eng_grp->ucode[0];
	}

	/* Clear UCODE_BASE register for each engine used by this group */
	ret = cpt_set_ucode_base(eng_grp, obj);

	return ret;
}

static void setup_eng_grp_mirroring(struct otx2_cpt_eng_grp_info *dst_grp,
				    struct otx2_cpt_eng_grp_info *src_grp)
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

static void remove_eng_grp_mirroring(struct otx2_cpt_eng_grp_info *dst_grp)
{
	struct otx2_cpt_eng_grp_info *src_grp;

	if (!dst_grp->mirror.is_ena)
		return;

	src_grp = &dst_grp->g->grp[dst_grp->mirror.idx];

	src_grp->mirror.ref_count--;
	dst_grp->mirror.is_ena = false;
	dst_grp->mirror.idx = 0;
	dst_grp->mirror.ref_count = 0;
}

static void update_requested_engs(struct otx2_cpt_eng_grp_info *mirror_eng_grp,
				  struct otx2_cpt_engines *engs, int engs_cnt)
{
	struct otx2_cpt_engs_rsvd *mirrored_engs;
	int i;

	for (i = 0; i < engs_cnt; i++) {
		mirrored_engs = find_engines_by_type(mirror_eng_grp,
						     engs[i].type);
		if (!mirrored_engs)
			continue;

		/*
		 * If mirrored group has this type of engines attached then
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

static struct otx2_cpt_eng_grp_info *find_mirrored_eng_grp(
					struct otx2_cpt_eng_grp_info *grp)
{
	struct otx2_cpt_eng_grps *eng_grps = grp->g;
	int i;

	for (i = 0; i < OTX2_CPT_MAX_ENGINE_GROUPS; i++) {
		if (!eng_grps->grp[i].is_enabled)
			continue;
		if (eng_grps->grp[i].ucode[0].type &&
		    eng_grps->grp[i].ucode[1].type)
			continue;
		if (grp->idx == i)
			continue;
		if (!strncasecmp(eng_grps->grp[i].ucode[0].ver_str,
				 grp->ucode[0].ver_str,
				 OTX2_CPT_UCODE_VER_STR_SZ))
			return &eng_grps->grp[i];
	}

	return NULL;
}

static struct otx2_cpt_eng_grp_info *find_unused_eng_grp(
					struct otx2_cpt_eng_grps *eng_grps)
{
	int i;

	for (i = 0; i < OTX2_CPT_MAX_ENGINE_GROUPS; i++) {
		if (!eng_grps->grp[i].is_enabled)
			return &eng_grps->grp[i];
	}
	return NULL;
}

static int eng_grp_update_masks(struct device *dev,
				struct otx2_cpt_eng_grp_info *eng_grp)
{
	struct otx2_cpt_engs_rsvd *engs, *mirrored_engs;
	struct otx2_cpt_bitmap tmp_bmap = { 0 };
	int i, j, cnt, max_cnt;
	int bit;

	for (i = 0; i < OTX2_CPT_MAX_ETYPES_PER_GRP; i++) {
		engs = &eng_grp->engs[i];
		if (!engs->type)
			continue;
		if (engs->count <= 0)
			continue;

		switch (engs->type) {
		case OTX2_CPT_SE_TYPES:
			max_cnt = eng_grp->g->avail.max_se_cnt;
			break;

		case OTX2_CPT_IE_TYPES:
			max_cnt = eng_grp->g->avail.max_ie_cnt;
			break;

		case OTX2_CPT_AE_TYPES:
			max_cnt = eng_grp->g->avail.max_ae_cnt;
			break;

		default:
			dev_err(dev, "Invalid engine type %d\n", engs->type);
			return -EINVAL;
		}

		cnt = engs->count;
		WARN_ON(engs->offset + max_cnt > OTX2_CPT_MAX_ENGINES);
		bitmap_zero(tmp_bmap.bits, eng_grp->g->engs_num);
		for (j = engs->offset; j < engs->offset + max_cnt; j++) {
			if (!eng_grp->g->eng_ref_cnt[j]) {
				bitmap_set(tmp_bmap.bits, j, 1);
				cnt--;
				if (!cnt)
					break;
			}
		}

		if (cnt)
			return -ENOSPC;

		bitmap_copy(engs->bmap, tmp_bmap.bits, eng_grp->g->engs_num);
	}

	if (!eng_grp->mirror.is_ena)
		return 0;

	for (i = 0; i < OTX2_CPT_MAX_ETYPES_PER_GRP; i++) {
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
	return 0;
}

static int delete_engine_group(struct device *dev,
			       struct otx2_cpt_eng_grp_info *eng_grp)
{
	int i, ret;

	if (!eng_grp->is_enabled)
		return -EINVAL;

	if (eng_grp->mirror.ref_count) {
		dev_err(dev, "Can't delete engine_group%d as it is used by engine group(s):",
			eng_grp->idx);
		for (i = 0; i < OTX2_CPT_MAX_ENGINE_GROUPS; i++) {
			if (eng_grp->g->grp[i].mirror.is_ena &&
			    eng_grp->g->grp[i].mirror.idx == eng_grp->idx)
				pr_cont("%d", i);
		}
		pr_cont("\n");
		return -EINVAL;
	}

	/* Removing engine group mirroring if enabled */
	remove_eng_grp_mirroring(eng_grp);

	/* Disable engine group */
	ret = disable_eng_grp(dev, eng_grp, eng_grp->g->obj);
	if (ret)
		return ret;

	/* Release all engines held by this engine group */
	ret = release_engines(dev, eng_grp);
	if (ret)
		return ret;

	device_remove_file(dev, &eng_grp->info_attr);
	eng_grp->is_enabled = false;

	return 0;
}

static int validate_2_ucodes_scenario(struct device *dev,
				      struct otx2_cpt_eng_grp_info *eng_grp)
{
	struct otx2_cpt_ucode *se_ucode = NULL, *ie_ucode = NULL;
	struct otx2_cpt_ucode *ucode;
	int i;

	/*
	 * Find ucode which supports SE engines and ucode which supports
	 * IE engines only
	 */
	for (i = 0; i < OTX2_CPT_MAX_ETYPES_PER_GRP; i++) {
		ucode = &eng_grp->ucode[i];
		if (otx2_cpt_uc_supports_eng_type(ucode, OTX2_CPT_SE_TYPES))
			se_ucode = ucode;
		else if (otx2_cpt_uc_supports_eng_type(ucode,
						       OTX2_CPT_IE_TYPES) &&
			 !otx2_cpt_uc_supports_eng_type(ucode,
							OTX2_CPT_SE_TYPES))
			ie_ucode = ucode;
	}

	if (!se_ucode || !ie_ucode) {
		dev_err(dev,
			"Only combination of SE+IE microcodes is supported.\n");
		return -EINVAL;
	}

	/* Keep SE ucode at index 0 */
	if (otx2_cpt_uc_supports_eng_type(&eng_grp->ucode[1],
					  OTX2_CPT_SE_TYPES))
		swap_ucodes(&eng_grp->ucode[0], &eng_grp->ucode[1]);

	return 0;
}

static int validate_1_ucode_scenario(struct device *dev,
				     struct otx2_cpt_eng_grp_info *eng_grp,
				     struct otx2_cpt_engines *engs,
				     int engs_cnt)
{
	int i;

	/* Verify that ucode loaded supports requested engine types */
	for (i = 0; i < engs_cnt; i++) {
		if (otx2_cpt_uc_supports_eng_type(&eng_grp->ucode[0],
						  OTX2_CPT_SE_TYPES) &&
		    engs[i].type == OTX2_CPT_IE_TYPES) {
			dev_err(dev,
				"IE engines can't be used with SE microcode\n");
			return -EINVAL;
		}

		if (!otx2_cpt_uc_supports_eng_type(&eng_grp->ucode[0],
						   engs[i].type)) {
			/*
			 * Exception to this rule is the case
			 * where IPSec ucode can use SE engines
			 */
			if (otx2_cpt_uc_supports_eng_type(&eng_grp->ucode[0],
							  OTX2_CPT_IE_TYPES) &&
			    engs[i].type == OTX2_CPT_SE_TYPES)
				continue;

			dev_err(dev,
				"Microcode %s does not support %s engines\n",
				eng_grp->ucode[0].filename,
				get_eng_type_str(engs[i].type));
			return -EINVAL;
		}
	}
	return 0;
}

static void update_ucode_ptrs(struct otx2_cpt_eng_grp_info *eng_grp)
{
	struct otx2_cpt_ucode *ucode;

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

static int get_eng_caps_discovery_grp(struct otx2_cpt_eng_grps *eng_grps,
				      u8 eng_type)
{
	struct otx2_cpt_eng_grp_info *grp;
	int eng_grp_num = 0xff, i;

	switch (eng_type) {
	case OTX2_CPT_SE_TYPES:
		for (i = 0; i < OTX2_CPT_MAX_ENGINE_GROUPS; i++) {
			grp = &eng_grps->grp[i];
			if (!grp->is_enabled)
				continue;

			if (otx2_cpt_eng_grp_has_eng_type(grp,
							  OTX2_CPT_SE_TYPES) &&
			    !otx2_cpt_eng_grp_has_eng_type(grp,
							   OTX2_CPT_IE_TYPES) &&
			    !otx2_cpt_eng_grp_has_eng_type(grp,
							   OTX2_CPT_AE_TYPES)) {
				eng_grp_num = i;
				break;
			}
		}
		break;

	case OTX2_CPT_IE_TYPES:
		for (i = 0; i < OTX2_CPT_MAX_ENGINE_GROUPS; i++) {
			grp = &eng_grps->grp[i];
			if (!grp->is_enabled)
				continue;

			if (otx2_cpt_eng_grp_has_eng_type(grp,
							  OTX2_CPT_IE_TYPES) &&
			    !otx2_cpt_eng_grp_has_eng_type(grp,
							   OTX2_CPT_SE_TYPES)) {
				eng_grp_num = i;
				break;
			}
		}
		break;

	case OTX2_CPT_AE_TYPES:
		for (i = 0; i < OTX2_CPT_MAX_ENGINE_GROUPS; i++) {
			grp = &eng_grps->grp[i];
			if (!grp->is_enabled)
				continue;

			if (otx2_cpt_eng_grp_has_eng_type(grp, eng_type)) {
				eng_grp_num = i;
				break;
			}
		}
		break;
	}
	return eng_grp_num;
}

static int delete_eng_caps_discovery_grps(struct pci_dev *pdev,
					  struct otx2_cpt_eng_grps *eng_grps)
{
	struct otx2_cpt_eng_grp_info *grp;
	int i, ret;

	for (i = 0; i < OTX2_CPT_MAX_ENGINE_GROUPS; i++) {
		grp = &eng_grps->grp[i];
		ret = delete_engine_group(&pdev->dev, grp);
		if (ret)
			return ret;
	}
	return ret;
}

static int create_engine_group(struct device *dev,
			       struct otx2_cpt_eng_grps *eng_grps,
			       struct otx2_cpt_engines *engs, int engs_cnt,
			       void *ucode_data[], int ucodes_cnt,
			       bool use_uc_from_tar_arch)
{
	struct otx2_cpt_eng_grp_info *mirrored_eng_grp;
	struct tar_ucode_info_t *tar_ucode_info;
	struct otx2_cpt_eng_grp_info *eng_grp;
	int i, ret = 0;

	if (ucodes_cnt > OTX2_CPT_MAX_ETYPES_PER_GRP)
		return -EINVAL;

	/* Validate if requested engine types are supported by this device */
	for (i = 0; i < engs_cnt; i++)
		if (!dev_supports_eng_type(eng_grps, engs[i].type)) {
			dev_err(dev, "Device does not support %s engines\n",
				get_eng_type_str(engs[i].type));
			return -EPERM;
		}

	/* Find engine group which is not used */
	eng_grp = find_unused_eng_grp(eng_grps);
	if (!eng_grp) {
		dev_err(dev, "Error all engine groups are being used\n");
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
		/*
		 * Validate scenario where 2 ucodes are used - this
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

		/*
		 * Update count of requested engines because some
		 * of them might be shared with mirrored group
		 */
		update_requested_engs(mirrored_eng_grp, engs, engs_cnt);
	}

	ret = reserve_engines(dev, eng_grp, engs, engs_cnt);
	if (ret)
		goto err_ucode_unload;

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

	/*
	 * If this engine group mirrors another engine group
	 * then we need to unload ucode as we will use ucode
	 * from mirrored engine group
	 */
	if (eng_grp->mirror.is_ena)
		ucode_unload(dev, &eng_grp->ucode[0]);

	eng_grp->is_enabled = true;
	if (mirrored_eng_grp)
		dev_info(dev,
			 "Engine_group%d: reuse microcode %s from group %d\n",
			 eng_grp->idx, mirrored_eng_grp->ucode[0].ver_str,
			 mirrored_eng_grp->idx);
	else
		dev_info(dev, "Engine_group%d: microcode loaded %s\n",
			 eng_grp->idx, eng_grp->ucode[0].ver_str);
	if (is_2nd_ucode_used(eng_grp))
		dev_info(dev, "Engine_group%d: microcode loaded %s\n",
			 eng_grp->idx, eng_grp->ucode[1].ver_str);

	return 0;

err_release_engs:
	release_engines(dev, eng_grp);
err_ucode_unload:
	ucode_unload(dev, &eng_grp->ucode[0]);
	ucode_unload(dev, &eng_grp->ucode[1]);
	return ret;
}

static ssize_t ucode_load_store(struct device *dev,
				struct device_attribute *attr,
				const char *buf, size_t count)
{
	struct otx2_cpt_engines engs[OTX2_CPT_MAX_ETYPES_PER_GRP] = { 0 };
	char *ucode_filename[OTX2_CPT_MAX_ETYPES_PER_GRP];
	char tmp_buf[OTX2_CPT_NAME_LENGTH] = { 0 };
	struct otx2_cpt_eng_grps *eng_grps;
	char *start, *val, *err_msg, *tmp;
	int grp_idx = 0, ret = -EINVAL;
	bool has_se, has_ie, has_ae;
	int del_grp_idx = -1;
	int ucode_idx = 0;

	if (strlen(buf) > OTX2_CPT_NAME_LENGTH)
		return -EINVAL;

	eng_grps = container_of(attr, struct otx2_cpt_eng_grps,
				ucode_load_attr);
	err_msg = "Invalid engine group format";
	strlcpy(tmp_buf, buf, OTX2_CPT_NAME_LENGTH);
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
			engs[grp_idx++].type = OTX2_CPT_SE_TYPES;
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
			engs[grp_idx++].type = OTX2_CPT_AE_TYPES;
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
			engs[grp_idx++].type = OTX2_CPT_IE_TYPES;
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

		if (grp_idx > OTX2_CPT_MAX_ETYPES_PER_GRP) {
			err_msg = "Error max 2 engine types can be attached";
			goto err_print;
		}

		if (grp_idx > 1) {
			if ((engs[0].type + engs[1].type) !=
			    (OTX2_CPT_SE_TYPES + OTX2_CPT_IE_TYPES)) {
				err_msg =
				"Only combination of SE+IE engines is allowed";
				goto err_print;
			}

			/* Keep SE engines at zero index */
			if (engs[1].type == OTX2_CPT_SE_TYPES)
				swap_engines(&engs[0], &engs[1]);
		}

	} else {
		if (del_grp_idx < 0 || del_grp_idx >=
						OTX2_CPT_MAX_ENGINE_GROUPS) {
			dev_err(dev, "Invalid engine group index %d\n",
				del_grp_idx);
			return -EINVAL;
		}

		if (!eng_grps->grp[del_grp_idx].is_enabled) {
			dev_err(dev, "Error engine_group%d is not configured\n",
				del_grp_idx);
			return -EINVAL;
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

	return ret;
}

static int create_eng_caps_discovery_grps(struct pci_dev *pdev,
					  struct otx2_cpt_eng_grps *eng_grps)
{
	struct tar_ucode_info_t *tar_info[OTX2_CPT_MAX_ETYPES_PER_GRP] = { 0 };
	struct otx2_cpt_engines engs[OTX2_CPT_MAX_ETYPES_PER_GRP] = { 0 };
	struct tar_arch_info_t *tar_arch = NULL;
	char tar_filename[OTX2_CPT_NAME_LENGTH];
	int ret = -EINVAL;

	sprintf(tar_filename, "cpt%02d-mc.tar", pdev->revision);
	tar_arch = load_tar_archive(&pdev->dev, tar_filename);
	if (!tar_arch)
		return -EINVAL;
	/*
	 * If device supports AE engines and there is AE microcode in tar
	 * archive try to create engine group with AE engines.
	 */
	tar_info[0] = get_uc_from_tar_archive(tar_arch, OTX2_CPT_AE_TYPES);
	if (tar_info[0] && dev_supports_eng_type(eng_grps, OTX2_CPT_AE_TYPES)) {

		engs[0].type = OTX2_CPT_AE_TYPES;
		engs[0].count = 2;

		ret = create_engine_group(&pdev->dev, eng_grps, engs, 1,
					  (void **) tar_info, 1, true);
		if (ret)
			goto release_tar;
	}
	/*
	 * If device supports SE engines and there is SE microcode in tar
	 * archive try to create engine group with SE engines.
	 */
	tar_info[0] = get_uc_from_tar_archive(tar_arch, OTX2_CPT_SE_TYPES);
	if (tar_info[0] && dev_supports_eng_type(eng_grps, OTX2_CPT_SE_TYPES)) {

		engs[0].type = OTX2_CPT_SE_TYPES;
		engs[0].count = 2;

		ret = create_engine_group(&pdev->dev, eng_grps, engs, 1,
					  (void **) tar_info, 1, true);
		if (ret)
			goto release_tar;
	}
	/*
	 * If device supports IE engines and there is IE microcode in tar
	 * archive try to create engine group with IE engines.
	 */
	tar_info[0] = get_uc_from_tar_archive(tar_arch, OTX2_CPT_IE_TYPES);
	if (tar_info[0] && dev_supports_eng_type(eng_grps, OTX2_CPT_IE_TYPES)) {

		engs[0].type = OTX2_CPT_IE_TYPES;
		engs[0].count = 2;

		ret = create_engine_group(&pdev->dev, eng_grps, engs, 1,
					  (void **) tar_info, 1, true);
		if (ret)
			goto release_tar;
	}
release_tar:
	release_tar_archive(tar_arch);
	return ret;
}

/*
 * Get CPT HW capabilities using LOAD_FVC operation.
 */
int otx2_cpt_discover_eng_capabilities(void *obj)
{
	struct otx2_cptpf_dev *cptpf = obj;
	struct otx2_cpt_iq_command iq_cmd;
	union otx2_cpt_opcode_info opcode;
	union otx2_cpt_res_s *result;
	union otx2_cpt_inst_s inst;
	dma_addr_t rptr_baddr;
	struct pci_dev *pdev;
	u32 len, compl_rlen;
	int ret, etype;
	void *rptr;

	/*
	 * We don't get capabilities if it was already done
	 * (when user enabled VFs for the first time)
	 */
	if (cptpf->is_eng_caps_discovered)
		return 0;

	pdev = cptpf->pdev;
	cptpf->blkaddr = BLKADDR_CPT0;
	ret = create_eng_caps_discovery_grps(pdev, &cptpf->eng_grps);
	if (ret)
		goto delete_grps;

	ret = otx2_cptpf_lf_init(cptpf, OTX2_CPT_ALL_ENG_GRPS_MASK,
				 OTX2_CPT_QUEUE_HI_PRIO, 1);
	if (ret)
		goto delete_grps;

	compl_rlen = ALIGN(sizeof(union otx2_cpt_res_s), OTX2_CPT_DMA_MINALIGN);
	len = compl_rlen + LOADFVC_RLEN;

	result = kzalloc(len, GFP_KERNEL);
	if (!result) {
		ret = -ENOMEM;
		goto lf_cleanup;
	}
	rptr_baddr = dma_map_single(&pdev->dev, (void *)result, len,
				    DMA_BIDIRECTIONAL);
	if (dma_mapping_error(&pdev->dev, rptr_baddr)) {
		dev_err(&pdev->dev, "DMA mapping failed\n");
		ret = -EFAULT;
		goto free_result;
	}
	rptr = (u8 *)result + compl_rlen;

	/* Fill in the command */
	opcode.s.major = LOADFVC_MAJOR_OP;
	opcode.s.minor = LOADFVC_MINOR_OP;

	iq_cmd.cmd.u64 = 0;
	iq_cmd.cmd.s.opcode = cpu_to_be16(opcode.flags);

	/* 64-bit swap for microcode data reads, not needed for addresses */
	cpu_to_be64s(&iq_cmd.cmd.u64);
	iq_cmd.dptr = 0;
	iq_cmd.rptr = rptr_baddr + compl_rlen;
	iq_cmd.cptr.u64 = 0;

	for (etype = 1; etype < OTX2_CPT_MAX_ENG_TYPES; etype++) {
		result->s.compcode = OTX2_CPT_COMPLETION_CODE_INIT;
		iq_cmd.cptr.s.grp = get_eng_caps_discovery_grp(
						&cptpf->eng_grps, etype);
		otx2_cpt_fill_inst(&inst, &iq_cmd, rptr_baddr);
		otx2_cpt_send_cmd(&inst, 1, &cptpf->lfs.lf[0]);

		while (result->s.compcode == OTX2_CPT_COMPLETION_CODE_INIT)
			cpu_relax();

		cptpf->eng_caps[etype].u = be64_to_cpup(rptr);
	}
	dma_unmap_single(&pdev->dev, rptr_baddr, len, DMA_BIDIRECTIONAL);
	cptpf->is_eng_caps_discovered = true;
free_result:
	kzfree(result);
lf_cleanup:
	otx2_cptpf_lf_cleanup(&cptpf->lfs);
delete_grps:
	delete_eng_caps_discovery_grps(pdev, &cptpf->eng_grps);

	return ret;
}


int otx2_cpt_try_create_default_eng_grps(struct pci_dev *pdev,
					 struct otx2_cpt_eng_grps *eng_grps)
{
	struct tar_ucode_info_t *tar_info[OTX2_CPT_MAX_ETYPES_PER_GRP] = { 0 };
	struct otx2_cpt_engines engs[OTX2_CPT_MAX_ETYPES_PER_GRP] = { 0 };
	struct tar_arch_info_t *tar_arch = NULL;
	char tar_filename[OTX2_CPT_NAME_LENGTH];
	int i, ret = 0;

	mutex_lock(&eng_grps->lock);

	/*
	 * We don't create engine group for kernel crypto if attempt to create
	 * it was already made (when user enabled VFs for the first time)
	 */
	if (eng_grps->is_first_try)
		goto unlock_mutex;
	eng_grps->is_first_try = true;

	/* We create group for kcrypto only if no groups are configured */
	for (i = 0; i < OTX2_CPT_MAX_ENGINE_GROUPS; i++)
		if (eng_grps->grp[i].is_enabled)
			goto unlock_mutex;

	sprintf(tar_filename, "cpt%02d-mc.tar", pdev->revision);

	tar_arch = load_tar_archive(&pdev->dev, tar_filename);
	if (!tar_arch)
		goto unlock_mutex;

	/*
	 * If device supports SE engines and there is SE microcode in tar
	 * archive try to create engine group with SE engines for kernel
	 * crypto functionality (symmetric crypto)
	 */
	tar_info[0] = get_uc_from_tar_archive(tar_arch, OTX2_CPT_SE_TYPES);
	if (tar_info[0] && dev_supports_eng_type(eng_grps, OTX2_CPT_SE_TYPES)) {

		engs[0].type = OTX2_CPT_SE_TYPES;
		engs[0].count = eng_grps->avail.max_se_cnt;

		ret = create_engine_group(&pdev->dev, eng_grps, engs, 1,
					  (void **) tar_info, 1, true);
		if (ret)
			goto release_tar_arch;
	}

	/*
	 * If device supports SE+IE engines and there is SE and IE microcode in
	 * tar archive try to create engine group with SE+IE engines for IPSec.
	 * All SE engines will be shared with engine group 0.
	 */
	tar_info[0] = get_uc_from_tar_archive(tar_arch, OTX2_CPT_SE_TYPES);
	tar_info[1] = get_uc_from_tar_archive(tar_arch, OTX2_CPT_IE_TYPES);
	if (tar_info[0] && tar_info[1] &&
	    dev_supports_eng_type(eng_grps, OTX2_CPT_SE_TYPES) &&
	    dev_supports_eng_type(eng_grps, OTX2_CPT_IE_TYPES)) {

		engs[0].type = OTX2_CPT_SE_TYPES;
		engs[0].count = eng_grps->avail.max_se_cnt;
		engs[1].type = OTX2_CPT_IE_TYPES;
		engs[1].count = eng_grps->avail.max_ie_cnt;

		ret = create_engine_group(&pdev->dev, eng_grps, engs, 2,
					  (void **) tar_info, 2, true);
		if (ret)
			goto release_tar_arch;
	}

	/*
	 * If device supports AE engines and there is AE microcode in tar
	 * archive try to create engine group with AE engines for asymmetric
	 * crypto functionality.
	 */
	tar_info[0] = get_uc_from_tar_archive(tar_arch, OTX2_CPT_AE_TYPES);
	if (tar_info[0] && dev_supports_eng_type(eng_grps, OTX2_CPT_AE_TYPES)) {

		engs[0].type = OTX2_CPT_AE_TYPES;
		engs[0].count = eng_grps->avail.max_ae_cnt;

		ret = create_engine_group(&pdev->dev, eng_grps, engs, 1,
					  (void **) tar_info, 1, true);
		if (ret)
			goto release_tar_arch;
	}

	print_dbg_info(&pdev->dev, eng_grps);
release_tar_arch:
	release_tar_archive(tar_arch);
unlock_mutex:
	mutex_unlock(&eng_grps->lock);
	return ret;
}

void otx2_cpt_set_eng_grps_is_rdonly(struct otx2_cpt_eng_grps *eng_grps,
				     bool is_rdonly)
{
	mutex_lock(&eng_grps->lock);

	eng_grps->is_rdonly = is_rdonly;

	mutex_unlock(&eng_grps->lock);
}

static int cptx_disable_all_cores(struct otx2_cptpf_dev *cptpf, int total_cores)
{
	int timeout = 10, ret;
	int i, busy;
	u64 reg;

	/* Disengage the cores from groups */
	for (i = 0; i < total_cores; i++) {
		ret = otx2_cpt_add_write_af_reg(cptpf->pdev,
						CPT_AF_EXEX_CTL2(i), 0x0);
		if (ret)
			return ret;

		cptpf->eng_grps.eng_ref_cnt[i] = 0;
	}
	ret = otx2_cpt_send_af_reg_requests(cptpf->pdev);
	if (ret)
		return ret;

	/* Wait for cores to become idle */
	do {
		busy = 0;
		usleep_range(10000, 20000);
		if (timeout-- < 0)
			return -EBUSY;

		for (i = 0; i < total_cores; i++) {
			ret = otx2_cpt_read_af_reg(cptpf->pdev,
						   CPT_AF_EXEX_STS(i), &reg);
			if (ret)
				return ret;

			if (reg & 0x1) {
				busy = 1;
				break;
			}
		}
	} while (busy);

	/* Disable the cores */
	for (i = 0; i < total_cores; i++) {
		ret = otx2_cpt_add_write_af_reg(cptpf->pdev, CPT_AF_EXEX_CTL(i),
						0x0);
		if (ret)
			return ret;
	}
	ret = otx2_cpt_send_af_reg_requests(cptpf->pdev);

	return ret;
}

int otx2_cpt_disable_all_cores(struct otx2_cptpf_dev *cptpf)
{
	int total_cores, ret;

	total_cores = cptpf->eng_grps.avail.max_se_cnt +
		      cptpf->eng_grps.avail.max_ie_cnt +
		      cptpf->eng_grps.avail.max_ae_cnt;

	if (cptpf->cpt1_implemented) {
		cptpf->blkaddr = BLKADDR_CPT1;
		ret = cptx_disable_all_cores(cptpf, total_cores);
		if (ret)
			return ret;
	}
	cptpf->blkaddr = BLKADDR_CPT0;
	ret = cptx_disable_all_cores(cptpf, total_cores);

	return ret;
}

void otx2_cpt_cleanup_eng_grps(struct pci_dev *pdev,
			       struct otx2_cpt_eng_grps *eng_grps)
{
	struct otx2_cpt_eng_grp_info *grp;
	int i, j;

	mutex_lock(&eng_grps->lock);
	if (eng_grps->is_ucode_load_created) {
		device_remove_file(&pdev->dev,
				   &eng_grps->ucode_load_attr);
		eng_grps->is_ucode_load_created = false;
	}

	/* First delete all mirroring engine groups */
	for (i = 0; i < OTX2_CPT_MAX_ENGINE_GROUPS; i++)
		if (eng_grps->grp[i].mirror.is_ena)
			delete_engine_group(&pdev->dev, &eng_grps->grp[i]);

	/* Delete remaining engine groups */
	for (i = 0; i < OTX2_CPT_MAX_ENGINE_GROUPS; i++)
		delete_engine_group(&pdev->dev, &eng_grps->grp[i]);

	/* Release memory */
	for (i = 0; i < OTX2_CPT_MAX_ENGINE_GROUPS; i++) {
		grp = &eng_grps->grp[i];
		for (j = 0; j < OTX2_CPT_MAX_ETYPES_PER_GRP; j++) {
			kfree(grp->engs[j].bmap);
			grp->engs[j].bmap = NULL;
		}
	}
	mutex_unlock(&eng_grps->lock);
}

int otx2_cpt_init_eng_grps(struct pci_dev *pdev,
			   struct otx2_cpt_eng_grps *eng_grps)
{
	struct otx2_cpt_eng_grp_info *grp;
	int i, j, ret;

	mutex_init(&eng_grps->lock);
	eng_grps->obj = pci_get_drvdata(pdev);
	eng_grps->avail.se_cnt = eng_grps->avail.max_se_cnt;
	eng_grps->avail.ie_cnt = eng_grps->avail.max_ie_cnt;
	eng_grps->avail.ae_cnt = eng_grps->avail.max_ae_cnt;

	eng_grps->engs_num = eng_grps->avail.max_se_cnt +
			     eng_grps->avail.max_ie_cnt +
			     eng_grps->avail.max_ae_cnt;
	if (eng_grps->engs_num > OTX2_CPT_MAX_ENGINES) {
		dev_err(&pdev->dev,
			"Number of engines %d > than max supported %d\n",
			eng_grps->engs_num, OTX2_CPT_MAX_ENGINES);
		ret = -EINVAL;
		goto cleanup_eng_grps;
	}

	for (i = 0; i < OTX2_CPT_MAX_ENGINE_GROUPS; i++) {
		grp = &eng_grps->grp[i];
		grp->g = eng_grps;
		grp->idx = i;

		snprintf(grp->sysfs_info_name, OTX2_CPT_NAME_LENGTH,
			 "engine_group%d", i);
		for (j = 0; j < OTX2_CPT_MAX_ETYPES_PER_GRP; j++) {
			grp->engs[j].bmap =
				kcalloc(BITS_TO_LONGS(eng_grps->engs_num),
					sizeof(long), GFP_KERNEL);
			if (!grp->engs[j].bmap) {
				ret = -ENOMEM;
				goto cleanup_eng_grps;
			}
		}
	}

	eng_grps->eng_types_supported = 1 << OTX2_CPT_SE_TYPES |
					1 << OTX2_CPT_IE_TYPES |
					1 << OTX2_CPT_AE_TYPES;

	eng_grps->ucode_load_attr.show = NULL;
	eng_grps->ucode_load_attr.store = ucode_load_store;
	eng_grps->ucode_load_attr.attr.name = "ucode_load";
	eng_grps->ucode_load_attr.attr.mode = 0220;
	sysfs_attr_init(&eng_grps->ucode_load_attr.attr);
	ret = device_create_file(&pdev->dev,
				 &eng_grps->ucode_load_attr);
	if (ret)
		goto cleanup_eng_grps;
	eng_grps->is_ucode_load_created = true;

	print_dbg_info(&pdev->dev, eng_grps);
	return 0;
cleanup_eng_grps:
	otx2_cpt_cleanup_eng_grps(pdev, eng_grps);
	return ret;
}
