/*
 * Copyright (c) 2011, 2015, Oracle and/or its affiliates. All rights reserved.
 *    Author: Knut Omang <knut.omang@oracle.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 *
 * Driver for Oracle Scalable Infiniband Fabric (SIF) Host Channel Adapters
 *
 * sif_ireg.c: Utilities and entry points needed for Infiniband registration
 */

#include <linux/module.h>
#include <linux/utsname.h>
#include <linux/pci.h>
#include <linux/slab.h>
#include <rdma/ib_verbs.h>
#include <rdma/ib_user_verbs.h>
#include "sif_dev.h"
#include "sif_ireg.h"
#include "sif_user.h"
#include "sif_dma.h"
#include "sif_ibpd.h"
#include "sif_ibcq.h"
#include "sif_ibqp.h"
#include "sif_mr.h"
#include "sif_mw.h"
#include "sif_fmr.h"
#include "sif_ah.h"
#include "sif_srq.h"
#include "sif_xrc.h"
#include "sif_sndrcv.h"
#include "sif_hwi.h"
#include "sif_query.h"
#include "sif_pd.h"
#include "sif_base.h"
#include "version.h"
#include "sif_hwmon.h"


static ssize_t show_rev(struct device *dev, struct device_attribute *attr,
			char *buf)
{
	struct sif_dev *sdev = dev_get_drvdata(dev);

	return sprintf(buf, "%x\n", PSIF_REVISION(sdev));
}

static ssize_t show_fw_ver(struct device *device,
			struct device_attribute *attr, char *buf)
{
	struct sif_dev *sdev = dev_get_drvdata(device);
	struct sif_eps *es = &sdev->es[sdev->mbox_epsc];

	return sprintf(buf, "%hu.%hu.0\n", es->ver.fw_major, es->ver.fw_minor);
}

static ssize_t show_eps_api_ver(struct device *device,
				struct device_attribute *attr, char *buf)
{
	struct sif_dev *sdev = dev_get_drvdata(device);
	struct sif_eps *es = &sdev->es[sdev->mbox_epsc];

	return sprintf(buf, "%hu.%hu\n", es->ver.epsc_major, es->ver.epsc_minor);
}

static ssize_t show_hca(struct device *device, struct device_attribute *attr,
			char *buf)
{
	struct sif_dev *sdev = dev_get_drvdata(device);

	return sprintf(buf, "ORCL%d\n", PSIF_DEVICE(sdev));
}

static ssize_t show_board(struct device *device,
			struct device_attribute *attr, char *buf)
{
	struct sif_dev *sdev = dev_get_drvdata(device);
	const char *prod_str = get_product_str(sdev);
	/*
	 * Paranoia level: avoid dumping the whole kernel to
	 * user-space if the zero termination character in the product
	 * string has been compromised
	 */
	const int n = min_t(int, 64, (int)strlen(prod_str));

	return sprintf(buf, "%.*s\n", n, prod_str);
}

static ssize_t show_stats(struct device *device,
			struct device_attribute *attr, char *buf)
{
	struct sif_dev *sdev = dev_get_drvdata(device);
	/* TBD: device specific counters, stats registers */
	sif_log(sdev, SIF_VERBS, "Not implemented");
	return -EOPNOTSUPP;
}


/* PSIF specific extensions */

/* Version information details (git revision of driver and firmware etc) */
static ssize_t show_versioninfo(struct device *device,
				struct device_attribute *attr, char *buf)
{
	struct sif_dev *sdev = dev_get_drvdata(device);
	char **fwv = sdev->es[sdev->mbox_epsc].ver.fw_version;

	return snprintf(buf, PAGE_SIZE, "%s - build user %s at %s\n"
			"sifdrv git tag:\n%s\n%s\n"
			"EPSC firmware: build user %s at %s\nimage revision string %s\n"
			"version tag:\n%s\n%s",
			sif_version.git_repo,
			sif_version.build_user, sif_version.build_git_time,
			sif_version.last_commit,
			(sif_version.git_status[0] != '\0' ? sif_version.git_psifapi_status : ""),
			fwv[FWV_EPS_BUILD_USER], fwv[FWV_EPS_BUILD_GIT_TIME],
			fwv[FWV_EPS_REV_STRING], fwv[FWV_EPS_GIT_LAST_COMMIT],
			(fwv[FWV_EPS_GIT_STATUS][0] != '\0' ? fwv[FWV_EPS_GIT_STATUS] : ""));
}


static ssize_t show_resp_ms(struct device *device,
			struct device_attribute *attr, char *buf)
{
	struct sif_dev *sdev = dev_get_drvdata(device);

	return sprintf(buf, "%d\n", jiffies_to_msecs(sdev->min_resp_ticks));
}


static ssize_t set_resp_ms(struct device *device,
			struct device_attribute *attr,
			const char *buf,
			size_t count)
{
	struct sif_dev *sdev = dev_get_drvdata(device);
	size_t old_val = jiffies_to_msecs(sdev->min_resp_ticks);
	size_t new_val;
	int ret = kstrtoul(buf, 0, &new_val);

	if (ret || !new_val)
		new_val = 1;
	sif_log(sdev, SIF_INFO, "%ld ms -> %ld ms", old_val, new_val);
	sdev->min_resp_ticks = msecs_to_jiffies(new_val);
	return strlen(buf);
}

static ssize_t show_irq_moderation(struct device *device,
				struct device_attribute *attr, char *buf)
{
	struct sif_dev *sdev = dev_get_drvdata(device);

	return sprintf(buf, "%hu\n", sdev->es[sdev->mbox_epsc].eqs.irq_moderation);
}

static ssize_t set_irq_moderation(struct device *device,
				struct device_attribute *attr,
				const char *buf,
				size_t count)
{
	struct sif_dev *sdev = dev_get_drvdata(device);
	struct sif_eps *es = &sdev->es[sdev->mbox_epsc];
	u16 old_val = es->eqs.irq_moderation;
	u16 new_val;

	int ret	= kstrtou16(buf, 0, &new_val);
	struct psif_epsc_csr_req req; /* local epsc wr copy */
	struct psif_epsc_csr_rsp resp;

	if (ret || !new_val)
		new_val = 0;

	if (eps_version_ge(es, 0, 36)) {
		memset(&req, 0, sizeof(req));
		req.opcode = EPSC_HOST_INT_COMMON_CTRL;
		req.uf = 0;
		req.u.int_common.total_usec = (uintptr_t)new_val;
		ret = sif_epsc_wr_poll(sdev, &req, &resp);
		if (ret) {
			sif_log(sdev, SIF_INFO, "Failed to configure device interrupt total moderation\n");
			return ret;
		}
		es->eqs.irq_moderation = new_val;
		sif_log(sdev, SIF_INFO, "Interrupt total moderation: %d usecs -> %d usecs",
			old_val, new_val);
		return strlen(buf);
	} else
		return -1;
}

static ssize_t show_mt_override(struct device *device,
				struct device_attribute *attr, char *buf)
{
	struct sif_dev *sdev = dev_get_drvdata(device);

	switch (sdev->mt_override) {
	case SIFMT_BYPASS:
		sprintf(buf, "bypass\n");
		break;
	case SIFMT_UMEM:
		sprintf(buf, "umem (no override)\n");
		break;
	case SIFMT_UMEM_SPT:
		sprintf(buf, "spt\n");
		break;
	case SIFMT_ZERO:
		sprintf(buf, "zero\n");
		break;
	default:
		/* Sanity check for debugging the driver only */
		sprintf(buf, "***undefined***\n");
		break;
	}
	return strlen(buf);
}


static ssize_t set_mt_override(struct device *device,
			struct device_attribute *attr,
			const char *buf,
			size_t count)
{
	struct sif_dev *sdev = dev_get_drvdata(device);

	if (strcmp(buf, "bypass\n") == 0)
		sdev->mt_override = SIFMT_BYPASS;
	else if (strcmp(buf, "umem\n") == 0 || strcmp(buf, "none\n") == 0)
		sdev->mt_override = SIFMT_UMEM;
	else if (strcmp(buf, "spt\n") == 0)
		sdev->mt_override = SIFMT_UMEM_SPT;
	else if (strcmp(buf, "zero\n") == 0)
		sdev->mt_override = SIFMT_ZERO;
	else
		return -EINVAL;
	return strlen(buf);
}

static DEVICE_ATTR(hw_rev, S_IRUGO, show_rev, NULL);
static DEVICE_ATTR(fw_ver, S_IRUGO, show_fw_ver, NULL);
static DEVICE_ATTR(eps_api_ver, S_IRUGO, show_eps_api_ver, NULL);
static DEVICE_ATTR(hca_type, S_IRUGO, show_hca, NULL);
static DEVICE_ATTR(board_id, S_IRUGO, show_board, NULL);
static DEVICE_ATTR(stats, S_IRUGO, show_stats, NULL);
static DEVICE_ATTR(versioninfo, S_IRUGO, show_versioninfo, NULL);
static DEVICE_ATTR(min_resp_ms, S_IWUSR | S_IRUGO, show_resp_ms, set_resp_ms);
static DEVICE_ATTR(mt_override, S_IWUSR | S_IRUGO, show_mt_override, set_mt_override);
static DEVICE_ATTR(irq_moderation, S_IWUSR | S_IRUGO, show_irq_moderation, set_irq_moderation);

static struct device_attribute *sif_class_attributes[] = {
	&dev_attr_hw_rev,
	&dev_attr_fw_ver,
	&dev_attr_eps_api_ver,
	&dev_attr_hca_type,
	&dev_attr_board_id,
	&dev_attr_stats,
	&dev_attr_versioninfo,
	&dev_attr_min_resp_ms,
	&dev_attr_mt_override,
	&dev_attr_irq_moderation,
};

static u64 dev_show(const struct device *device,
		struct device_attribute *attr,
		char *buf,
		int opcode)
{
	struct sif_dev *sdev = dev_get_drvdata(device);
	struct psif_epsc_csr_req req;
	struct psif_epsc_csr_rsp rsp;

	/* EPSC supports the new requests starting from v.0.43 */
	if (eps_version_ge(&sdev->es[sdev->mbox_epsc], 0, 43)) {
		int ret = 0;

		memset(&req, 0, sizeof(req));
		req.opcode = EPSC_QUERY;
		req.u.query.data.op = opcode;
		ret = sif_epsc_wr(sdev, &req, &rsp);
		if (ret)
			sif_log(sdev, SIF_INFO, "Failed to query tsu error counter\n");
		else
			sprintf(buf, "%llu\n", rsp.data);
	}
	return strlen(buf);
}

#define DEVICE_SHOW(field)					\
static ssize_t show_##field(struct device *dev,		\
			struct device_attribute *attr,		\
			char *buf)				\
{								\
	return dev_show(dev, attr, buf, EPSC_QUERY_##field);	\
}

DEVICE_SHOW(SQ_NUM_BRE);
DEVICE_SHOW(NUM_CQOVF);
DEVICE_SHOW(SQ_NUM_WRFE);
DEVICE_SHOW(RQ_NUM_WRFE);
DEVICE_SHOW(RQ_NUM_LAE);
DEVICE_SHOW(RQ_NUM_LPE);
DEVICE_SHOW(SQ_NUM_LLE);
DEVICE_SHOW(RQ_NUM_LLE);
DEVICE_SHOW(SQ_NUM_LQPOE);
DEVICE_SHOW(RQ_NUM_LQPOE);
DEVICE_SHOW(SQ_NUM_OOS);
DEVICE_SHOW(RQ_NUM_OOS);
DEVICE_SHOW(SQ_NUM_RREE);
DEVICE_SHOW(SQ_NUM_TREE);
DEVICE_SHOW(SQ_NUM_ROE);
DEVICE_SHOW(RQ_NUM_ROE);
DEVICE_SHOW(SQ_NUM_RAE);
DEVICE_SHOW(RQ_NUM_RAE);
DEVICE_SHOW(RQ_NUM_UDSDPRD);
DEVICE_SHOW(RQ_NUM_UCSDPRD);
DEVICE_SHOW(SQ_NUM_RIRE);
DEVICE_SHOW(RQ_NUM_RIRE);
DEVICE_SHOW(SQ_NUM_RNR);
DEVICE_SHOW(RQ_NUM_RNR);

static ssize_t clear_diag(struct device *device,
			struct device_attribute *attr,
			const char *buf,
			size_t count)
{

	struct sif_dev *sdev = dev_get_drvdata(device);
	int ret;
	struct psif_epsc_csr_req req;
	struct psif_epsc_csr_rsp resp;

	if (strcmp(buf, "1\n") == 0) {

		memset(&req, 0, sizeof(req));
		memset(&resp, 0, sizeof(resp));

		req.opcode = EPSC_SET;
		req.u.set.data.op = EPSC_QUERY_RESET_CBLD_DIAG_COUNTERS;
		req.u.set.data.value = 0xffffff;
		ret = sif_epsc_wr_poll(sdev, &req, &resp);
		if (ret)
			sif_log(sdev, SIF_INFO, "Failed to clear psif diag counters\n");
	} else
		return -EINVAL;

	return strlen(buf);
}

static DEVICE_ATTR(clear_diag, S_IWUSR, NULL, clear_diag);
static DEVICE_ATTR(sq_num_bre, S_IRUGO, show_SQ_NUM_BRE, NULL);
static DEVICE_ATTR(num_cqovf, S_IRUGO, show_NUM_CQOVF, NULL);
static DEVICE_ATTR(sq_num_wrfe, S_IRUGO, show_SQ_NUM_WRFE, NULL);
static DEVICE_ATTR(rq_num_wrfe, S_IRUGO, show_RQ_NUM_WRFE, NULL);
static DEVICE_ATTR(rq_num_lae, S_IRUGO, show_RQ_NUM_LAE, NULL);
static DEVICE_ATTR(rq_num_lpe, S_IRUGO, show_RQ_NUM_LPE, NULL);
static DEVICE_ATTR(sq_num_lle, S_IRUGO, show_SQ_NUM_LLE, NULL);
static DEVICE_ATTR(rq_num_lle, S_IRUGO, show_RQ_NUM_LLE, NULL);
static DEVICE_ATTR(sq_num_lqpoe, S_IRUGO, show_SQ_NUM_LQPOE, NULL);
static DEVICE_ATTR(rq_num_lqpoe, S_IRUGO, show_RQ_NUM_LQPOE, NULL);
static DEVICE_ATTR(sq_num_oos, S_IRUGO, show_SQ_NUM_OOS, NULL);
static DEVICE_ATTR(rq_num_oos, S_IRUGO, show_RQ_NUM_OOS, NULL);
static DEVICE_ATTR(sq_num_rree, S_IRUGO, show_SQ_NUM_RREE, NULL);
static DEVICE_ATTR(sq_num_tree, S_IRUGO, show_SQ_NUM_TREE, NULL);
static DEVICE_ATTR(sq_num_roe, S_IRUGO, show_SQ_NUM_ROE, NULL);
static DEVICE_ATTR(rq_num_roe, S_IRUGO, show_RQ_NUM_ROE, NULL);
static DEVICE_ATTR(sq_num_rae, S_IRUGO, show_SQ_NUM_RAE, NULL);
static DEVICE_ATTR(rq_num_rae, S_IRUGO, show_RQ_NUM_RAE, NULL);
static DEVICE_ATTR(rq_num_udsdprd, S_IRUGO, show_RQ_NUM_UDSDPRD, NULL);
static DEVICE_ATTR(rq_num_ucsdprd, S_IRUGO, show_RQ_NUM_UCSDPRD, NULL);
static DEVICE_ATTR(sq_num_rire, S_IRUGO, show_SQ_NUM_RIRE, NULL);
static DEVICE_ATTR(rq_num_rire, S_IRUGO, show_RQ_NUM_RIRE, NULL);
static DEVICE_ATTR(sq_num_rnr, S_IRUGO, show_SQ_NUM_RNR, NULL);
static DEVICE_ATTR(rq_num_rnr, S_IRUGO, show_RQ_NUM_RNR, NULL);

static struct attribute *sif_diag_counters_class_attributes[] = {
	&dev_attr_clear_diag.attr,
	&dev_attr_sq_num_bre.attr,
	&dev_attr_num_cqovf.attr,
	&dev_attr_sq_num_wrfe.attr,
	&dev_attr_rq_num_wrfe.attr,
	&dev_attr_rq_num_lae.attr,
	&dev_attr_rq_num_lpe.attr,
	&dev_attr_sq_num_lle.attr,
	&dev_attr_rq_num_lle.attr,
	&dev_attr_sq_num_lqpoe.attr,
	&dev_attr_rq_num_lqpoe.attr,
	&dev_attr_sq_num_oos.attr,
	&dev_attr_rq_num_oos.attr,
	&dev_attr_sq_num_rree.attr,
	&dev_attr_sq_num_tree.attr,
	&dev_attr_sq_num_roe.attr,
	&dev_attr_rq_num_roe.attr,
	&dev_attr_sq_num_rae.attr,
	&dev_attr_rq_num_rae.attr,
	&dev_attr_rq_num_udsdprd.attr,
	&dev_attr_rq_num_ucsdprd.attr,
	&dev_attr_sq_num_rire.attr,
	&dev_attr_rq_num_rire.attr,
	&dev_attr_sq_num_rnr.attr,
	&dev_attr_rq_num_rnr.attr,
	NULL,
};

static struct attribute_group diag_counters_attr_group = {
	.attrs = sif_diag_counters_class_attributes,
	.name = "diag_counters",
};

static struct ib_ucontext *sif_alloc_ucontext(struct ib_device *ibdev,
					struct ib_udata *udata)
{
	int ret;
	struct sif_dev *sdev = to_sdev(ibdev);
	struct sif_ucontext *s_uc;

	s_uc = kzalloc(sizeof(*s_uc), GFP_KERNEL);
	if (!s_uc)
		return NULL;

	s_uc->pd = alloc_pd(sdev);
	if (!s_uc->pd) {
		ret = -ENOMEM;
		goto alloc_pd_failed;
	}
	s_uc->pd->ibpd.device = ibdev;

	s_uc->cb = alloc_cb(sdev, false);
	if (!s_uc->cb) {
		ret = -ENOMEM;
		goto alloc_cb_failed;
	}

	if (udata) {
		struct sif_get_context_ext cmd;
		struct sif_get_context_resp_ext resp;
		u16 major_ver, minor_ver;

		memset(&cmd, 0, sizeof(cmd));
		ib_copy_from_udata(&cmd, udata, sizeof(cmd));

		s_uc->abi_version = cmd.abi_version;
		major_ver = s_uc->abi_version >> 8;
		minor_ver = s_uc->abi_version & 0xff;
		if (major_ver != SIF_UVERBS_ABI_MAJOR_VERSION) {
			if (major_ver < 10 && major_ver > 0) {
				sif_log(sdev, SIF_INFO,
					"User verbs abi version mismatch - driver has v.%d.%d - libsif has v.%d.%d",
					SIF_UVERBS_ABI_MAJOR_VERSION, SIF_UVERBS_ABI_MINOR_VERSION,
					major_ver, minor_ver);
				ret = -EINVAL;
				goto udata_copy_failed;
			} else {
				static bool printed;
				/* TBD: remove - bw comp - in this case probably not set */
				/* Set to final version that does not report to us */
				if (!printed) {
					sif_log(sdev, SIF_INFO,
						"Invalid version info - upgrade libsif!");
					printed = true;
				}
				s_uc->abi_version = SIF_UVERBS_VERSION(3, 1);
			}
		}
		memset(&resp, 0, sizeof(resp));
		resp.sq_sw_ext_sz = sdev->ba[sq_sw].ext_sz;
		resp.sq_hw_ext_sz = sdev->ba[sq_hw].ext_sz;
		resp.rq_ext_sz = sdev->ba[rq_sw].ext_sz;
		resp.cq_ext_sz = sdev->ba[cq_sw].ext_sz;
		resp.sq_entry_per_block = sdev->ba[sq_sw].entry_per_block;
		resp.rq_entry_per_block = sdev->ba[rq_sw].entry_per_block;
		resp.cq_entry_per_block = sdev->ba[cq_sw].entry_per_block;
		ret = ib_copy_to_udata(udata, &resp, sizeof(resp));
		if (ret)
			goto udata_copy_failed;
	}

	sif_log(sdev, SIF_VERBS_V, " at %p with pd %d used for CQs libsif abi v.%d.%d",
		s_uc, s_uc->pd->idx, s_uc->abi_version >> 8, s_uc->abi_version & 0xff);
	return &s_uc->ib_uc;

udata_copy_failed:
	release_cb(sdev, s_uc->cb);
alloc_cb_failed:
	dealloc_pd(s_uc->pd);
alloc_pd_failed:
	kfree(s_uc);
	return ERR_PTR(ret);
}

static int sif_dealloc_ucontext(struct ib_ucontext *ib_uc)
{
	int ret;
	u32 pd_idx = 0;
	struct sif_dev *sdev = to_sdev(ib_uc->device);
	struct sif_ucontext *s_uc =
	    container_of(ib_uc, struct sif_ucontext, ib_uc);

	sif_logs(SIF_VERBS_V, pd_idx = s_uc->pd->idx);

	ret = dealloc_pd(s_uc->pd);
	if (ret) {
		sif_log(sdev, SIF_INFO, "Failed (status %d) to deallocate pd %d", ret, s_uc->pd->idx);
		return ret;
	}

	release_cb(sdev, s_uc->cb);
	kfree(s_uc);
	sif_log(sdev, SIF_VERBS_V, "at %p done (cq pd index %d)", s_uc, pd_idx);
	return 0;
}


static int sif_mmap_block(struct sif_ucontext *uc, struct vm_area_struct *vma,
			enum sif_tab_type type, u32 index, int vm_flags)
{
	struct sif_dev *sdev = to_sdev(uc->ib_uc.device);
	struct sif_table *tp = &sdev->ba[type];
	struct sif_table_block *b;
	struct sif_pd *pd;
	u64 start, block_sz;
	off_t len;
	off_t offset;
	int ret;

	if (tp->entry_per_block <= 1) {
		sif_log(sdev, SIF_INFO,
			"Failed to map %s block index %d: direct user access not available with flat_alloc scheme",
			sif_table_name(type), index);
		return -EPERM;
	}
	if (tp->block_cnt <= index) {
		sif_log(sdev, SIF_INFO, "Failed to map %s block index %d: out of range - block_cnt %d",
			sif_table_name(type), index, tp->block_cnt);
		return -EINVAL;
	}

	b = sif_get_block(tp, index);
	pd = b->pd;
	if (!pd) {
		sif_log(sdev, SIF_INFO, "Failed to map %s block index %d: not allocated",
			sif_table_name(type), index);
		return -ENODEV;
	}
	if (pd == uc->pd)
		goto pd_ok; /* CQ case */

	if (!sif_is_user_pd(pd)) {
		sif_log(sdev, SIF_INFO, "Failed to map %s block index %d, pd %d - owned by kernel space",
			sif_table_name(type), index, pd->idx);
		return -EACCES;
	}

	/* TBD: Security aspects of XRC domain access
	 * (in the xrc case, we don't have a user context at the moment)
	 */
	if (pd->ibpd.uobject && pd->ibpd.uobject->context != &uc->ib_uc) {
		sif_log(sdev, SIF_INFO, "Failed to map %s block index %d: belongs to another user context",
			sif_table_name(type), index);
		return -EACCES;
	}
pd_ok:
	block_sz = tp->ext_sz * tp->entry_per_block;
	len = vma->vm_end - vma->vm_start;
	if (block_sz != len) {
		sif_log(sdev, SIF_INFO, "Failed to map %s block index %d: Expected map len %lld, got %ld",
			sif_table_name(type), index,
			block_sz, len);
		return -EINVAL;
	}

	vma->vm_flags |= VM_DONTEXPAND | VM_DONTDUMP;
	vma->vm_flags |= vm_flags;
	start = vma->vm_start;

	offset = block_sz * index;

	ret = sif_mem_vma_map_part(tp->mem, vma, offset, len);
	if (ret)
		return ret;

	/* TBD: ehca uses a vm_operations_struct and vma->private_data to ref.count
	 * but MLX does not - is it necessary?
	 * Also remap_pfn_range requires the mm sema to be held, but other drivers dont take it
	 * - is it already held by the caller here?
	 */
	return 0;
}


static int sif_mmap_cb(struct sif_ucontext *uc, struct vm_area_struct *vma, u32 index)
{
	struct sif_dev *sdev = to_sdev(uc->ib_uc.device);
	struct sif_cb *cb = sif_cb_from_uc(uc, index);
	off_t len;
	dma_addr_t cb_start;
	int ret;

	if (!cb) {
		sif_log(sdev, SIF_INFO, "Failed to associate cb %d with context", index);
		return -EINVAL;
	}

	len = vma->vm_end - vma->vm_start;
	if (len != PAGE_SIZE) {
		sif_log(sdev, SIF_INFO, "Failed to map cb index %d: Expected map len %ld, got %ld",
			index, PAGE_SIZE, len);
		return -EINVAL;
	}
	cb_start = pci_resource_start(sdev->pdev, SIF_CBU_BAR) + index * PAGE_SIZE;
	vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);
	vma->vm_flags |= VM_WRITE;
	ret = io_remap_pfn_range(vma, vma->vm_start, cb_start >> PAGE_SHIFT,
				PAGE_SIZE, vma->vm_page_prot);
	if (ret)
		sif_log(sdev, SIF_INFO, "io_remap_pfn_range failed with %d", ret);
	return ret;
}


#define def_map_queue(type) \
static int sif_mmap_##type(struct sif_ucontext *uc, struct vm_area_struct *vma, u32 index)\
{\
	struct sif_dev *sdev = to_sdev(uc->ib_uc.device);\
	struct sif_##type *type;\
	u64 q_sz;\
	off_t len;\
	\
	type = safe_get_sif_##type(sdev, index);\
	if (!type) {\
		sif_log(sdev, SIF_INFO, "Failed to map " #type \
			" index %d out of range", index);\
		sif_log(sdev, SIF_INFO, "%p : %p", sdev->ba[type##_hw].bitmap, sdev->ba[qp].bitmap);\
		return -EINVAL;\
	} \
	\
	q_sz = type->mem->size;\
	len = vma->vm_end - vma->vm_start;\
	if (q_sz < len) {\
		sif_log(sdev, SIF_INFO, "Failed to map " #type " index %d: "\
			"Expected map req for <= %lld bytes, got %ld", index, q_sz, len);\
		return -EINVAL;\
	} \
	\
	vma->vm_flags |= VM_DONTEXPAND | VM_DONTDUMP;\
	vma->vm_flags |= VM_READ|VM_WRITE;\
	\
	return sif_mem_vma_map_part(type->mem, vma, 0, len);\
}

def_map_queue(sq)
def_map_queue(rq)
def_map_queue(cq)

static int sif_mmap(struct ib_ucontext *ib_uc, struct vm_area_struct *vma)
{
	enum sif_mmap_cmd cmd;
	u32 index;
	struct sif_dev *sdev = to_sdev(ib_uc->device);
	struct sif_ucontext *s_uc = to_sctx(ib_uc);

	mmap_get_cmd(vma->vm_pgoff << PAGE_SHIFT, &cmd, &index);

	sif_log(sdev, SIF_MMAP,
		"pg offset 0x%lx start 0x%lx, end 0x%lx len 0x%lx, flags 0x%lx index %d",
		vma->vm_pgoff, vma->vm_start, vma->vm_end, vma->vm_end - vma->vm_start,
		vma->vm_flags, index);

	switch (cmd) {
	case SIF_MAP_SQ_SW:
		return sif_mmap_block(s_uc, vma, sq_sw, index, VM_READ|VM_WRITE);
	case SIF_MAP_RQ_SW:
		return sif_mmap_block(s_uc, vma, rq_sw, index, VM_READ|VM_WRITE);
	case SIF_MAP_CQ_SW:
		return sif_mmap_block(s_uc, vma, cq_sw, index, VM_READ|VM_WRITE);
	case SIF_MAP_SQ_HW:
		return sif_mmap_block(s_uc, vma, sq_hw, index, VM_READ);
	case SIF_MAP_RQ_HW:
		return sif_mmap_block(s_uc, vma, rq_hw, index, VM_READ);
	case SIF_MAP_CQ_HW:
		return sif_mmap_block(s_uc, vma, cq_hw, index, VM_READ);
	case SIF_MAP_CB:
		return sif_mmap_cb(s_uc, vma, index);
	case SIF_MAP_SQ:
		return sif_mmap_sq(s_uc, vma, index);
	case SIF_MAP_RQ:
		return sif_mmap_rq(s_uc, vma, index);
	case SIF_MAP_CQ:
		return sif_mmap_cq(s_uc, vma, index);
	default:
		break;
	}
	sif_log(sdev, SIF_MMAP, "cmd %d not implemented", cmd);
	return -EOPNOTSUPP;
}

static int sif_get_protocol_stats(struct ib_device *ibdev,
				union rdma_protocol_stats *stats)
{
	struct sif_dev *sdev = to_sdev(ibdev);

	sif_log(sdev, SIF_VERBS, "Not implemented");
	return -EOPNOTSUPP;
}


static enum rdma_link_layer sif_get_link_layer(struct ib_device *ibdev, u8 port_num)
{
	struct sif_dev *sdev = to_sdev(ibdev);

	sif_log(sdev, SIF_VERBS, "returns IB_LINK_LAYER_INFINIBAND for port %d", port_num);
	return IB_LINK_LAYER_INFINIBAND;
}

static int sif_port_callback(struct ib_device *ibdev, u8 portno, struct kobject *obj)
{
	struct sif_dev *sdev = to_sdev(ibdev);

	sif_log(sdev, SIF_VERBS, "port %d", portno);
	return 0;
}

static inline struct ib_cq *sif_ib_create_cq(struct ib_device *ibdev, int cqe,
					int comp_vector, struct ib_ucontext *context,
					struct ib_udata *udata)
{
	return sif_create_cq(ibdev, cqe, comp_vector, context, udata, SIFPX_OFF);
}

/* putting this function here to avoid sif_epsc.h from being rdma/ib_verbs.h dependent */
static int sif_eps_wr_ex(struct ib_device *ibdev, enum psif_mbox_type eps_num,
	struct  psif_epsc_csr_req *req, struct psif_epsc_csr_rsp *cqe)
{
	struct sif_dev *sdev = to_sdev(ibdev);

	return sif_eps_wr(sdev, eps_num, req, cqe);

}

int sif_register_ib_device(struct sif_dev *sdev)
{
	int ret = 0;
	int i;
	struct ib_device *dev = &sdev->ib_dev;
	struct psif_epsc_device_attr epsdev;

	/* We need to do a query_device to get the node_guid */
	ret = epsc_query_device(sdev, &epsdev);
	if (ret)
		return ret;

	strlcpy(dev->name, "sif%d", IB_DEVICE_NAME_MAX);

	dev->owner = THIS_MODULE;
	dev->uverbs_abi_ver = SIF_UVERBS_ABI_VERSION;

	/* SIF supported user verbs */
	dev->uverbs_cmd_mask =
		(1ull << IB_USER_VERBS_CMD_GET_CONTEXT) |
		(1ull << IB_USER_VERBS_CMD_QUERY_DEVICE) |
		(1ull << IB_USER_VERBS_CMD_QUERY_PORT) |
		(1ull << IB_USER_VERBS_CMD_ALLOC_PD) |
		(1ull << IB_USER_VERBS_CMD_DEALLOC_PD) |
		(1ull << IB_USER_VERBS_CMD_CREATE_AH) |
		(1ull << IB_USER_VERBS_CMD_MODIFY_AH) |
		(1ull << IB_USER_VERBS_CMD_QUERY_AH) |
		(1ull << IB_USER_VERBS_CMD_DESTROY_AH) |
		(1ull << IB_USER_VERBS_CMD_REG_MR) |
		(1ull << IB_USER_VERBS_CMD_REG_SMR) |
		(1ull << IB_USER_VERBS_CMD_REREG_MR) |
		(1ull << IB_USER_VERBS_CMD_DEREG_MR) |
		(1ull << IB_USER_VERBS_CMD_CREATE_COMP_CHANNEL) |
		(1ull << IB_USER_VERBS_CMD_CREATE_CQ) |
		(1ull << IB_USER_VERBS_CMD_RESIZE_CQ) |
		(1ull << IB_USER_VERBS_CMD_DESTROY_CQ) |
		(1ull << IB_USER_VERBS_CMD_POLL_CQ) |
		(1ull << IB_USER_VERBS_CMD_PEEK_CQ) |
		(1ull << IB_USER_VERBS_CMD_REQ_NOTIFY_CQ) |
		(1ull << IB_USER_VERBS_CMD_CREATE_QP) |
		(1ull << IB_USER_VERBS_CMD_QUERY_QP) |
		(1ull << IB_USER_VERBS_CMD_MODIFY_QP) |
		(1ull << IB_USER_VERBS_CMD_DESTROY_QP) |
		(1ull << IB_USER_VERBS_CMD_POST_SEND) |
		(1ull << IB_USER_VERBS_CMD_POST_RECV) |
		(1ull << IB_USER_VERBS_CMD_ATTACH_MCAST) |
		(1ull << IB_USER_VERBS_CMD_DETACH_MCAST) |
		(1ull << IB_USER_VERBS_CMD_CREATE_SRQ) |
		(1ull << IB_USER_VERBS_CMD_MODIFY_SRQ) |
		(1ull << IB_USER_VERBS_CMD_QUERY_SRQ) |
		(1ull << IB_USER_VERBS_CMD_DESTROY_SRQ) |
		(1ull << IB_USER_VERBS_CMD_POST_SRQ_RECV)
	      | (1ull << IB_USER_VERBS_CMD_OPEN_XRCD) |
		(1ull << IB_USER_VERBS_CMD_CLOSE_XRCD) |
		(1ull << IB_USER_VERBS_CMD_CREATE_XSRQ) |
		(1ull << IB_USER_VERBS_CMD_OPEN_QP)
	      | (1ull << IB_USER_VERBS_CMD_ALLOC_SHPD) |
		(1ull << IB_USER_VERBS_CMD_SHARE_PD)
	      ;

	dev->get_protocol_stats = sif_get_protocol_stats;

	dev->query_device = sif_query_device;
	dev->modify_device = sif_modify_device;

	dev->query_port = sif_query_port;
	dev->modify_port = sif_modify_port;

	dev->get_link_layer = sif_get_link_layer;
	dev->query_gid = sif_query_gid;
	dev->query_pkey = sif_query_pkey;

	dev->alloc_ucontext = sif_alloc_ucontext;
	dev->dealloc_ucontext = sif_dealloc_ucontext;
	dev->mmap = sif_mmap;

	dev->alloc_pd = sif_alloc_pd;
	dev->dealloc_pd = sif_dealloc_pd;
	dev->create_ah = sif_create_ah;
	dev->destroy_ah = sif_destroy_ah;
	dev->query_ah = sif_query_ah;

	dev->create_srq = sif_create_srq;
	dev->modify_srq = sif_modify_srq;
	dev->query_srq = sif_query_srq;
	dev->destroy_srq = sif_destroy_srq;

	dev->create_qp = sif_create_qp;
	dev->modify_qp = sif_modify_qp;
	dev->query_qp = sif_query_qp;
	dev->destroy_qp = sif_destroy_qp;

	dev->post_send = sif_post_send;
	dev->post_recv = sif_post_recv;
	dev->post_srq_recv = sif_post_srq_recv;

	dev->create_cq = sif_ib_create_cq;
	dev->destroy_cq = sif_destroy_cq;
	dev->resize_cq = sif_resize_cq;
	dev->poll_cq = sif_poll_cq;
	dev->peek_cq = sif_peek_cq;
	dev->req_notify_cq = sif_req_notify_cq;
	dev->req_ncomp_notif = sif_req_ncomp_notif;

	dev->get_dma_mr = sif_get_dma_mr;
	dev->reg_phys_mr = sif_reg_phys_mr;
	dev->rereg_phys_mr = sif_rereg_phys_mr;
	dev->reg_user_mr = sif_reg_user_mr;
	dev->dereg_mr = sif_dereg_mr;

	dev->alloc_fmr = sif_alloc_fmr;
	dev->map_phys_fmr = sif_map_phys_fmr;
	dev->unmap_fmr = sif_unmap_phys_fmr_list;
	dev->dealloc_fmr = sif_dealloc_fmr;

	dev->attach_mcast = sif_multicast_attach;
	dev->detach_mcast = sif_multicast_detach;

	/* All our mad handling happens via the normal QP0 paths
	 * this function is for devices which implements the SMA
	 * in software:
	 */
	dev->process_mad = NULL;

	dev->alloc_xrcd = sif_alloc_xrcd;
	dev->dealloc_xrcd = sif_dealloc_xrcd;
	dev->alloc_shpd = sif_alloc_shpd;
	dev->share_pd = sif_share_pd;
	dev->remove_shpd = sif_remove_shpd;

	dev->node_guid = cpu_to_be64(epsdev.node_guid);

	snprintf(dev->node_desc, sizeof(dev->node_desc), "sif_%s",
		 init_utsname()->nodename);

	dev->node_type = RDMA_NODE_IB_CA;
	dev->phys_port_cnt = sdev->limited_mode ? 0 : epsdev.phys_port_cnt;
	dev->num_comp_vectors = sdev->es[sdev->mbox_epsc].eqs.cnt - 2;

	ret = ib_register_device(dev, sif_port_callback);
	if (ret) {
		sif_log(sdev, SIF_VERBS, "Fail to register IB device: error %d",
			-ret);
		goto err_ibreg;
	}

	for (i = 0; i < ARRAY_SIZE(sif_class_attributes); ++i) {
		ret = device_create_file(&dev->dev, sif_class_attributes[i]);
		if (ret) {
			sif_log(sdev, SIF_VERBS,
				"Fail to register with sysfs: error %d!", -ret);
			goto err_sysfsreg;
		}
	}

	/* Diag_counters */
	ret = sysfs_create_group(&dev->dev.kobj, &diag_counters_attr_group);
	if (ret) {
		sif_log(sdev, SIF_VERBS,
			"Fail to register diag_counters with sysfs: error %d!", -ret);
		goto err_sysfsreg;
	}

	sif_register_hwmon_dev(sdev);
	/* Populate the external kernel API (see sif_verbs.h): */
	sdev->sv.eps_wr = sif_eps_wr_ex;
	sdev->sv.create_cq = sif_create_cq;
	sdev->ib_dev.local_dma_lkey = sdev->dma_mr->index;

	sdev->registered = true;
	complete(&sdev->ready_for_events);
	sif_log(sdev, SIF_VERBS_V, "%s registered with IB", sdev->ib_dev.name);
	return 0;

err_sysfsreg:
	ib_unregister_device(dev);
err_ibreg:
	sif_log(sdev, SIF_INFO, "Exit - error %d", -ret);
	return ret;
}

void sif_unregister_ib_device(struct sif_dev *sdev)
{
	struct ib_device *ibdev = &sdev->ib_dev;

	sif_unregister_hwmon_dev(sdev);
	sdev->registered = false;
	ib_unregister_device(ibdev);
	sif_logi(ibdev, SIF_VERBS, "done unregistering device");
}
