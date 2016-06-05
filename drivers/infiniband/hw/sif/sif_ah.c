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
 * sif_ah.c: Implementation of IB address handles for SIF
 */

#include <rdma/ib_verbs.h>
#include <linux/seq_file.h>
#include "sif_dev.h"
#include "psif_hw_data.h"
#include "sif_defs.h"
#include "sif_base.h"
#include "sif_ah.h"
#include "sif_query.h"

struct ib_ah *sif_create_ah(struct ib_pd *ibpd, struct ib_ah_attr *ah_attr,
			struct ib_udata *udata)
{
	struct sif_ah *ah;
	struct sif_dev *sdev = to_sdev(ibpd->device);
	struct sif_pd *pd = to_spd(ibpd);
	struct ib_ah *ret;

	volatile struct psif_ah *ah_p;
	struct psif_ah lah;
	int index;
	u8 ipd = 0;

	sif_log(sdev, SIF_AH, "for pd %d", pd->idx);

	index = sif_alloc_ah_idx(sdev);
	if (index < 0) {
		ret = ERR_PTR(-ENOMEM);
		goto err_create_ah;
	}
	ah = get_sif_ah(sdev, index);
	memset(ah, 0, sizeof(struct sif_ah));
	ah->index = index;
	ah_p = &ah->d;

	/* TBD: Many attrs should come from device cap-limits and
	 * as provided by user
	 */

	/* Update hw */
	memset(&lah, 0, sizeof(lah));
	lah.sl = ah_attr->sl;
	lah.port = ah_attr->port_num - 1;
	lah.pd = pd->idx;
	lah.remote_lid = ah_attr->dlid;
	lah.local_lid_path = ah_attr->src_path_bits;
	lah.loopback =
		(sdev->port[lah.port].lid | lah.local_lid_path) == ah_attr->dlid ?
		LOOPBACK : NO_LOOPBACK;

	/* If sif_calc_ipd() fails, we use zero */
	sif_calc_ipd(sdev, ah_attr->port_num, (enum ib_rate)ah_attr->static_rate, &ipd);
	lah.ipd = ipd;

	if (ah_attr->ah_flags & IB_AH_GRH) {
		lah.use_grh = USE_GRH;
		/* We need to byte swap these an extra time as we are receiving
		 * them in big endian format, and they are subject to copy/convert as well:
		 */
		lah.grh_remote_gid_0 = cpu_to_be64(ah_attr->grh.dgid.global.subnet_prefix);
		lah.grh_remote_gid_1 = cpu_to_be64(ah_attr->grh.dgid.global.interface_id);
		lah.grh_flowlabel = ah_attr->grh.flow_label;
		lah.grh_hoplmt = ah_attr->grh.hop_limit;
		/* TBD: ah_attr->grh.sgid_index? */

		sif_log(sdev, SIF_AH, " - with grh dgid %llx.%llx",
			lah.grh_remote_gid_0,
			lah.grh_remote_gid_1);
	}

	copy_conv_to_hw(ah_p, &lah, sizeof(lah));

	sif_log(sdev, SIF_AH, "ah %d - remote_lid 0x%x src_path_bits 0x%x sl %d, %s",
		ah->index, lah.remote_lid, lah.local_lid_path, lah.sl,
		(lah.loopback ? "(loopback)" : ""));
	sif_logs(SIF_DUMP, write_struct_psif_ah(NULL, 0, &lah));


	if (udata) {
		struct sif_create_ah_resp_ext resp;
		int ret;

		memset(&resp, 0, sizeof(resp));
		resp.index = ah->index;
		ret = ib_copy_to_udata(udata, &resp, sizeof(resp));
		if (ret) {
			sif_destroy_ah(&ah->ibah);
			return ERR_PTR(ret);
		}
	}
	return &ah->ibah;
err_create_ah:
	return ret;
}

int sif_destroy_ah(struct ib_ah *ibah)
{
	struct sif_ah *ah = to_sah(ibah);
	struct sif_dev *sdev = to_sdev(ibah->device);
	int index = ah->index;

	sif_logi(ibah->device, SIF_AH, "index 0x%x", index);

	sif_clear_ah(sdev, index);
	sif_free_ah_idx(sdev, index);

	return 0;
}

int sif_modify_ah(struct ib_ah *ibah, struct ib_ah_attr *ah_attr)
{
	sif_logi(ibah->device, SIF_AH, "Not implemented");
	return -EOPNOTSUPP;
}

int sif_query_ah(struct ib_ah *ibah, struct ib_ah_attr *ah_attr)
{

	struct sif_ah *ah = to_sah(ibah);
	struct psif_ah lah;

	ah_attr->ah_flags = 0;
	copy_conv_to_sw(&lah, &ah->d, sizeof(lah));
	ah_attr->sl = lah.sl;
	ah_attr->port_num = lah.port + 1;
	/* TBD: Convert from delay to rate */
	ah_attr->static_rate = lah.ipd;
	ah_attr->dlid = lah.remote_lid;

	if (lah.use_grh == USE_GRH) {
		ah_attr->ah_flags |= IB_AH_GRH;
		ah_attr->grh.dgid.global.subnet_prefix = lah.grh_remote_gid_0;
		ah_attr->grh.dgid.global.interface_id = lah.grh_remote_gid_1;
		ah_attr->grh.flow_label = lah.grh_flowlabel;
		ah_attr->grh.hop_limit = lah.grh_hoplmt;
	}

	sif_logi(ibah->device, SIF_AH, "ah %d - remote_lid 0x%x src_path_bits 0x%x %s",
		ah->index, lah.remote_lid, lah.local_lid_path,
		(lah.loopback ? "(loopback)" : ""));
	return 0;
}


void sif_dfs_print_ah(struct seq_file *s, struct sif_dev *sdev,
		loff_t pos)
{
	if (unlikely(pos < 0))
		seq_puts(s, "# Index  Port    PD Rem.lid  IPD\n");
	else {
		struct psif_ah *ah_p = get_ah(sdev, pos);
		struct psif_ah lah;

		copy_conv_to_sw(&lah, ah_p, sizeof(struct psif_ah));
		seq_printf(s, "%7lld %5d %5d %7d%5d\n",
			pos, lah.port + 1, lah.pd, lah.remote_lid, lah.ipd);
	}
}
