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
 * sif_hwi.c: Hardware init for SIF - combines the various init steps for psif
 */

#include "sif_dev.h"
#include "sif_hwi.h"
#include "sif_base.h"
#include "sif_cq.h"
#include "sif_pqp.h"
#include "sif_qp.h"
#include "sif_ibqp.h"
#include "sif_pd.h"
#include "sif_eq.h"
#include "sif_xrc.h"
#include "sif_defs.h"
#include "sif_query.h"
#include "psif_hw_data.h"
#include "psif_hw_setget.h"
#include <net/checksum.h>
#include <rdma/ib_mad.h>
#include <rdma/ib_smi.h>

/* Create the special SIF privileged QP which is used
 * for special sif specific work requests such as for instance
 * requesting completion event notification on a cq.
 */

static void sif_pqp_fini(struct sif_dev *sdev);


static int sif_chip_init(struct sif_dev *sdev);
static void sif_chip_deinit(struct sif_dev *sdev);


static int sif_pqp_init(struct sif_dev *sdev)
{
	struct sif_pqp *pqp;
	struct sif_eps *es = &sdev->es[sdev->mbox_epsc];
	int i;
	int ret = 0;
	uint n_pqps = es->eqs.cnt - 2;

	sdev->pqp = sif_kmalloc(sdev, sizeof(struct sif_pqp *) * n_pqps, GFP_KERNEL | __GFP_ZERO);
	if (!sdev->pqp)
		return -ENOMEM;

	for (i = 0; i < n_pqps; i++) {
		pqp = sif_create_pqp(sdev, i);
		if (IS_ERR(pqp)) {
			if ((i > 0) &&
			    !(eps_version_ge(es, 0, 42))) {
				sif_log(sdev, SIF_INFO,
				"SIF device has an old FW version that only supports one pqp");
				break;
			}
			ret = PTR_ERR(pqp);
			goto failed;
		}
		sdev->pqp[i] = pqp;
	}
	sdev->pqp_cnt = i;
	atomic_set(&sdev->next_pqp, 0);
	return 0;

failed:
	sdev->pqp_cnt = i;
	sif_pqp_fini(sdev);
	return ret;
}


static void sif_pqp_fini(struct sif_dev *sdev)
{
	/* we must maintain a consistent state of the PQP array
	 * during takedown as these operations themselves
	 * generate PQP requests..
	 */
	while (sdev->pqp_cnt > 0) {
		int i = sdev->pqp_cnt - 1;
		struct sif_pqp *pqp = sdev->pqp[i];

		if (i > 0) {
			/* Remove ourselves first, except the final PQP */
			sdev->pqp[i] = NULL;
			sdev->pqp_cnt--;
		}
		sif_destroy_pqp(sdev, pqp);
		if (i == 0)
			sdev->pqp_cnt--;
	}
	kfree(sdev->pqp);
	sdev->pqp = NULL;
}


static void sif_ki_spqp_fini(struct sif_dev *sdev);

static int sif_ki_spqp_init(struct sif_dev *sdev)
{
	int i;
	int ret = 0;
	int n = max(sif_ki_spqp_size, 0U);
	int bm_len = max(1, n/8);

	mutex_init(&sdev->ki_spqp.lock);
	sdev->ki_spqp.spqp =
#ifdef CONFIG_NUMA
		kmalloc_node(sizeof(struct sif_st_pqp *) * n, GFP_KERNEL | __GFP_ZERO,
			sdev->pdev->dev.numa_node);
#else
		kmalloc(sizeof(struct sif_st_pqp *) * n, GFP_KERNEL | __GFP_ZERO);
#endif
	if (!sdev->ki_spqp.spqp)
		return -ENOMEM;

	sdev->ki_spqp.bitmap =
#ifdef CONFIG_NUMA
		kmalloc_node(sizeof(ulong) * bm_len, GFP_KERNEL | __GFP_ZERO,
			sdev->pdev->dev.numa_node);
#else
		kmalloc(sizeof(ulong) * bm_len, GFP_KERNEL | __GFP_ZERO);
#endif
	if (!sdev->ki_spqp.bitmap) {
		ret = -ENOMEM;
		goto bm_failed;
	}

	for (i = 0; i < n; i++) {
		struct sif_st_pqp *spqp = sif_create_inv_key_st_pqp(sdev);

		if (IS_ERR(spqp)) {
			ret = PTR_ERR(spqp);
			break;
		}
		sdev->ki_spqp.spqp[i] = spqp;
		spqp->index = i;
	}
	sdev->ki_spqp.pool_sz = i;
	if (ret && i) {
		sif_log(sdev, SIF_INFO, "Failed to create %d INVALIDATE_KEY stencil QPs", i);
		sif_ki_spqp_fini(sdev);
	}

	if (i)
		sif_log(sdev, SIF_INIT, "Created %d INVALIDATE_KEY stencil QPs", i);
bm_failed:
	if (ret)
		kfree(sdev->ki_spqp.spqp);
	return 0;  /* Never fail on stencil PQP allocation */
}


static void sif_ki_spqp_fini(struct sif_dev *sdev)
{
	int i;

	if (!sdev->ki_spqp.spqp)
		return;
	for (i = sdev->ki_spqp.pool_sz - 1; i >= 0; i--)
		sif_destroy_st_pqp(sdev, sdev->ki_spqp.spqp[i]);
	kfree(sdev->ki_spqp.bitmap);
	kfree(sdev->ki_spqp.spqp);
	sdev->ki_spqp.spqp = NULL;
}


static void sif_hw_kernel_cb_fini(struct sif_dev *sdev)
{
	int i;

	while (sdev->kernel_cb_cnt > 0) {
		int j = sdev->kernel_cb_cnt - 1;

		for (i = 0; i < 2; i++)
			if (sdev->kernel_cb[i][j])
				release_cb(sdev, sdev->kernel_cb[i][j]);
		sdev->kernel_cb_cnt--;
	}
	for (i = 0; i < 2; i++)
		kfree(sdev->kernel_cb[i]);
}



static int sif_hw_kernel_cb_init(struct sif_dev *sdev)
{
	int i;
	uint n_cbs = min(sif_cb_max, num_present_cpus());

	if (!n_cbs)
		n_cbs = 1;

	for (i = 0; i < 2; i++) {
		sdev->kernel_cb[i] = kcalloc(n_cbs, sizeof(struct sif_cb *), GFP_KERNEL);
		if (!sdev->kernel_cb[i])
			goto alloc_failed;
	}

	for (i = 0; i < n_cbs; i++) {
		sdev->kernel_cb[0][i] = alloc_cb(sdev, false);
		if (!sdev->kernel_cb[0][i])
			goto alloc_failed;
		sdev->kernel_cb[1][i] = alloc_cb(sdev, true);
		if (!sdev->kernel_cb[1][i])
			goto alloc_failed;
	}
	sdev->kernel_cb_cnt = i;
	return 0;

alloc_failed:
	sdev->kernel_cb_cnt = i;
	sif_hw_kernel_cb_fini(sdev);
	return -ENOMEM;
}


static int get_tsl_map(struct sif_dev *sdev,
		int opcode,
		int port,
		struct psif_tsl_map *map)
{
	struct psif_epsc_csr_req req;
	struct psif_epsc_csr_rsp rsp;

	/* EPSC supports the new requests starting from v.0.56 */
	if (eps_fw_version_ge(&sdev->es[sdev->mbox_epsc], 0, 56)) {
		int ret = 0;

		memset(&req, 0, sizeof(req));
		req.opcode = EPSC_QUERY;
		req.u.query.data.op = opcode;
		req.u.query.data.index = port;

		ret = sif_epsc_wr(sdev, &req, &rsp);
		if (ret) {
			sif_log(sdev, SIF_INFO, "Failed to query sl to tsl map, opcode %s, port %d",
				string_enum_psif_epsc_query_op(opcode) + strlen("EPSC_QUERY_"),
				port);
			return ret;
		}
		*map = *((struct psif_tsl_map *)&rsp.data);
		return 0;
	}

	sif_log(sdev, SIF_INFO, "PSIF API %s has fw version less than %s. Cannot retrieve SL2TSL map",
		"0.98", "0.56");
	return -EOPNOTSUPP;
}


static void setup_sl2tsl_map(struct sif_dev *sdev)
{
	int port;
	int sl;
	int qosl;


	/* TBD: separate bulk and rcv pqp vcb/tsl */
	for (port = 0; port < 2; ++port) {
		sdev->pqp_rcn_tsl[port] = TSL_PRIV;
		sdev->pqp_bulk_tsl[port] = TSL_PRIV;
		sdev->pqp_qosl_rcn_hint[port] = QOSL_LOW_LATENCY;
		sdev->pqp_qosl_bulk_hint[port] = QOSL_LOW_LATENCY;
	}

	/* Default or least aggressive common denominator */
	memset(sdev->sl2tsl + 0, TSL_DATA, sizeof(sdev->sl2tsl));
	memset(sdev->qp0_tsl + 0, TSL_DATA, sizeof(sdev->qp0_tsl));

	if (eps_fw_version_lt(&sdev->es[sdev->mbox_epsc], 0, 50)) {
		sif_log(sdev, SIF_INFO, "Using a single TSL for regular QPs (fw < 0.50)");
		return;
	}

	/* See BZ 3883 and https://cod.no.oracle.com/gerrit/r/#/c/6587/ */
	for (sl = 0; sl < 16; ++sl)
		for (port = 0; port < 2; ++port)
			for (qosl = QOSL_HIGH_BANDWIDTH; qosl <= QOSL_LOW_LATENCY; ++qosl)
				sdev->sl2tsl[sl][port][qosl] = port ? TSL_DATA_1 : TSL_DATA;

	if (eps_fw_version_lt(&sdev->es[sdev->mbox_epsc], 0, 57)) {
		sif_log(sdev, SIF_INFO, "Setting up TSL per port (0.50 <= fw <= 0.56)");
		return;
	}

#define GET_TSL(i) map.m ## i ## _tsl
#define GET_QOS(i) map.m ## i ## _tqos

	{
		struct psif_tsl_map map;
		int opc;

		sif_log(sdev, SIF_TSL, "Retrieving SL to TSL map from epsc (fw >= 0.56)");

		for (port = 0; port < 2; ++port) {
			if (get_tsl_map(sdev, EPSC_QUERY_MAP_PQP_TO_TSL, port + 1, &map))
				return;
			/* RCN pqp info in first entry, bulk in second */
			sdev->pqp_rcn_tsl[port] = GET_TSL(0);
			sdev->pqp_bulk_tsl[port] = GET_TSL(1);
			sdev->pqp_qosl_rcn_hint[port] = GET_QOS(0);
			sdev->pqp_qosl_bulk_hint[port] = GET_QOS(1);
		}

		for (opc = EPSC_QUERY_MAP_SL_TO_TSL_LO; opc <= EPSC_QUERY_MAP_SL_TO_TSL_HI; ++opc) {
			bool last8 = opc == EPSC_QUERY_MAP_SL_TO_TSL_HI;

			for (port = 0; port < 2; ++port) {
				if (get_tsl_map(sdev, opc, port + 1, &map))
					return;
				for (qosl = QOSL_HIGH_BANDWIDTH; qosl <= QOSL_LOW_LATENCY; ++qosl) {
					sdev->sl2tsl[8*last8 + 0][port][qosl] = GET_TSL(0);
					sdev->sl2tsl[8*last8 + 1][port][qosl] = GET_TSL(1);
					sdev->sl2tsl[8*last8 + 2][port][qosl] = GET_TSL(2);
					sdev->sl2tsl[8*last8 + 3][port][qosl] = GET_TSL(3);
					sdev->sl2tsl[8*last8 + 4][port][qosl] = GET_TSL(4);
					sdev->sl2tsl[8*last8 + 5][port][qosl] = GET_TSL(5);
					sdev->sl2tsl[8*last8 + 6][port][qosl] = GET_TSL(6);
					sdev->sl2tsl[8*last8 + 7][port][qosl] = GET_TSL(7);

					sdev->qp_qosl_hint[8*last8 + 0][port] = GET_QOS(0);
					sdev->qp_qosl_hint[8*last8 + 1][port] = GET_QOS(1);
					sdev->qp_qosl_hint[8*last8 + 2][port] = GET_QOS(2);
					sdev->qp_qosl_hint[8*last8 + 3][port] = GET_QOS(3);
					sdev->qp_qosl_hint[8*last8 + 4][port] = GET_QOS(4);
					sdev->qp_qosl_hint[8*last8 + 5][port] = GET_QOS(5);
					sdev->qp_qosl_hint[8*last8 + 6][port] = GET_QOS(6);
					sdev->qp_qosl_hint[8*last8 + 7][port] = GET_QOS(7);
				}
			}
		}

		if (!eps_version_ge(&sdev->es[sdev->mbox_epsc], 1, 6)) {
			sif_log(sdev, SIF_INFO, "FW version does not not support special QP0 TSL");
			return;
		}
		for (port = 0; port < 2; ++port) {
			if (get_tsl_map(sdev, EPSC_QUERY_MAP_QP0_TO_TSL, port + 1, &map))
				return;
			sdev->qp0_tsl[port] = GET_TSL(0);
			sdev->qp0_qosl_hint[port] = GET_QOS(0);
		}
	}
#undef GET_TSL
#undef GET_QOS
}


static void dump_sl2tsl_map(struct sif_dev *sdev)
{
	int sl;
	int port;
	int qosl;

	for (port = 0; port < 2; ++port) {
		sif_log(sdev, SIF_TSL, "rcn  pqp port:%d tsl:%2d fw_hint:%s",
			port + 1, sdev->pqp_rcn_tsl[port],
			string_enum_psif_tsu_qos(sdev->pqp_qosl_rcn_hint[port]) + strlen("QOSL_"));
		sif_log(sdev, SIF_TSL, "bulk pqp port:%d tsl:%2d fw_hint:%s",
			port + 1, sdev->pqp_bulk_tsl[port],
			string_enum_psif_tsu_qos(sdev->pqp_qosl_bulk_hint[port]) + strlen("QOSL_"));
	}

	for (port = 0; port < 2; ++port)
		for (sl = 0; sl < 16; ++sl)
			for (qosl = QOSL_HIGH_BANDWIDTH; qosl <= QOSL_LOW_LATENCY; ++qosl)
				sif_log(sdev, SIF_TSL,
					"plain qp port:%d sl:%2d qosl:%-14s tsl:%2d fw_hint:%s",
					port + 1, sl, string_enum_psif_tsu_qos(qosl) + strlen("QOSL_"),
					sdev->sl2tsl[sl][port][qosl],
					string_enum_psif_tsu_qos(sdev->qp_qosl_hint[sl][port]) +
					strlen("QOSL_"));

	for (port = 0; port < 2; ++port) {
		sif_log(sdev, SIF_TSL, "qp0 port:%d tsl:%2d fw_hint:%s",
			port + 1, sdev->qp0_tsl[port],
			string_enum_psif_tsu_qos(sdev->qp0_qosl_hint[port]) + strlen("QOSL_"));
	}
}

/* Device is degraded; set limited mode and report cause */
static int sif_handle_degraded(struct sif_dev *sdev)
{
	int ret = 0;

	sdev->limited_mode = true;
	if (eps_version_ge(&sdev->es[sdev->mbox_epsc], 1, 0)) {
		struct psif_epsc_csr_req req;
		struct psif_epsc_csr_rsp rsp;

		/* Ask the EPSC if it's running in degraded mode */
		memset(&req, 0, sizeof(req));
		req.opcode = EPSC_QUERY;
		req.u.query.data.op = EPSC_QUERY_DEGRADED_CAUSE;
		ret = sif_epsc_wr(sdev, &req, &rsp);
		if (ret) {
			sif_log(sdev, SIF_INFO,
				"Request to the EPSC for degraded cause failed with %d", ret);
			return ret;
		}
		if (rsp.data != 0)
			epsc_report_degraded(sdev, rsp.data);
		sif_log(sdev, SIF_EPS, "Device reports degraded mode, mask 0x%llx", rsp.data);
	}
	return ret;
}


int sif_hw_init(struct sif_dev *sdev)
{
	int i;
	int ret = -ENOMEM;
	struct sif_pd *pd = NULL;

	/* PSIF 2.x requires MRRS to be at least 512, ref BZ #3301 */
	if (pcie_get_readrq(sdev->pdev) < 512) {
		sif_log(sdev, SIF_INFO, "PSIF 2.x requires MRRS to be at least 512 bytes");
		ret = -EINVAL;
		goto chip_init_failed;
	}

	sif_mem_init(sdev);

	/* Misc. PSIF chip version specific
	 * configuration (must be before base_init):
	 */
	ret = sif_chip_init(sdev);
	if (ret)
		goto chip_init_failed;

	/* Configure all the base tables with the EPSC */
	ret = sif_base_init(sdev);
	if (ret)
		goto base_failed;

	/* Allocate collect buffers for kernel usage */
	ret = sif_hw_kernel_cb_init(sdev);
	if (ret)
		goto cb_alloc_failed;

	ret = sif_init_pd(sdev);
	if (ret)
		goto pd_init_failed;

	/* We need a kernel protection domain for resource allocation */
	pd = alloc_pd(sdev);
	if (!pd)
		goto pd_alloc_failed;
	pd->ibpd.device = &sdev->ib_dev;
	sdev->pd = pd;
	if (sdev->degraded)
		sif_handle_degraded(sdev);
	if (sdev->limited_mode) {
		sif_log(sdev, SIF_INFO, "Running in limited mode\n");
		return 0;
	}

	/* Initialize the SL to TSL map, before any QPs are created */
	setup_sl2tsl_map(sdev);
	dump_sl2tsl_map(sdev);

	/* Reserve indices for qp 0 and 1, ports 1 and 2 */
	for (i = 0; i <= 3; i++)
		sif_alloc_qp_idx(pd);

	ret = sif_pqp_init(sdev);
	if (ret)
		goto pqp_failed;

	ret = sif_ki_spqp_init(sdev);
	if (ret)
		goto ki_spqp_failed;

	ret = sif_init_xrcd(sdev);
	if (ret)
		goto xrcd_failed;

	return 0;

xrcd_failed:
	sif_ki_spqp_fini(sdev);
ki_spqp_failed:
	sif_pqp_fini(sdev);
pqp_failed:
	/* Release indices for qp 0 and 1 */
	for (i = 3; i >= 0; i--)
		sif_free_qp_idx(pd, i);
	dealloc_pd(pd);

pd_alloc_failed:
	sif_deinit_pd(sdev);
pd_init_failed:
	sif_hw_kernel_cb_fini(sdev);
cb_alloc_failed:
	sif_base_deinit(sdev);
base_failed:
	sif_chip_deinit(sdev);
chip_init_failed:
	return ret;
}

void sif_hw_deinit(struct sif_dev *sdev)
{
	int i;

	if (!sdev->limited_mode) {
		sif_log(sdev, SIF_PQP, "enter");
		sif_ki_spqp_fini(sdev);
		sif_pqp_fini(sdev);

		/* Release indices for qp 0 and 1 */
		for (i = 3; i >= 0; i--)
			sif_free_qp_idx(sdev->pd, i);
	}

	dealloc_pd(sdev->pd);
	sif_deinit_pd(sdev);
	sif_hw_kernel_cb_fini(sdev);
	sif_base_deinit(sdev);
	sif_chip_deinit(sdev);
}


int force_pcie_link_retrain(struct sif_dev *sdev)
{
	int err, parent_pcie_cap;
	u16 parent_lnkctl;

	parent_pcie_cap = pci_find_capability(sdev->pdev->bus->self, PCI_CAP_ID_EXP);
	err = pci_read_config_word(sdev->pdev, parent_pcie_cap + PCI_EXP_LNKCTL, &parent_lnkctl);
	parent_lnkctl |= PCI_EXP_LNKCTL_RL;
	err = pci_write_config_word(sdev->pdev->bus->self, parent_pcie_cap + PCI_EXP_LNKCTL,
				parent_lnkctl);
	return err;
}


static int sif_chip_init(struct sif_dev *sdev)
{
	u16 devid;

	/* Chip version specific config */
	devid = sdev->pdev->device;
	switch (devid) {
	case PCI_DEVICE_ID_PSIF_VF:
		sdev->is_vf = true;
		sdev->num_vfs = 0;
		sdev->mbox_epsc = MBOX_EPSC;
		sdev->eps_cnt = MBOX_EPSC + 1;
		break;

	case PCI_DEVICE_ID_PSIF_PF:
		sdev->is_vf = false;
		sdev->mbox_epsc = MBOX_EPSC;
		sdev->eps_cnt = MBOX_EPSC + 1;
		break;

	case PCI_DEVICE_ID_SN1_VF:
		sdev->is_vf = true;
		sdev->num_vfs = 0;
		sdev->mbox_epsc = SIBS_MBOX_EPSC;
		sdev->eps_cnt = SIBS_MBOX_EPSC + 1;
		break;

	case PCI_DEVICE_ID_SN1_PF:
		sdev->is_vf = false;
		sdev->mbox_epsc = SIBS_MBOX_EPSC;
		sdev->eps_cnt = SIBS_MBOX_EPSC + 1;
		break;

	default:
		sif_log(sdev, SIF_INFO, "Unknown device id %x", devid);
		return -ENODEV;
	}

	if (!sif_vf_en && sdev->is_vf) {
		sif_log(sdev, SIF_INFO, "Parameter vf_en=0: VF driver load disabled");
		return -EINVAL;
	}


	sdev->es = kcalloc(sdev->eps_cnt, sizeof(struct sif_eps), GFP_KERNEL);
	if (!sdev->es)
		return -ENOMEM;

	return 0;
}


static void sif_chip_deinit(struct sif_dev *sdev)
{
	kfree(sdev->es);
	sdev->es = NULL;
}
