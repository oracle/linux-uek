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
 * sif_query.c: SIF implementation of some of IB query APIs
 */
#include <linux/version.h>
#include <rdma/ib_verbs.h>
#include <rdma/ib_mad.h>
#include "sif_dev.h"
#include "sif_query.h"
#include "sif_defs.h"
#include "sif_qp.h"

int epsc_query_device(struct sif_dev *sdev, struct psif_epsc_device_attr *ldev)
{
	int ret;
	struct psif_epsc_csr_rsp cqe;
	struct psif_epsc_csr_req req;
	struct sif_eps *es = &sdev->es[sdev->mbox_epsc];

	memset(&req, 0, sizeof(req));
	/* MMU context nil - passthrough */
	req.opcode = EPSC_QUERY_DEVICE;
	req.u.query_hw.address =
		(u64)es->data_dma_hdl + offsetof(struct sif_epsc_data, dev);
	req.u.query_hw.mmu_cntx = sdev->ba[epsc_csr_rsp].mmu_ctx.mctx;
	ret = sif_epsc_wr(sdev, &req, &cqe);

	/* Copy data irrespective of how the EPSC operation went */
	if (eps_version_ge(es, 0, 31))
		copy_conv_to_sw(ldev, &es->data->dev, sizeof(*ldev));
	else
		memcpy(ldev, &es->data->dev, sizeof(*ldev));

	return ret;
}

int sif_query_device(struct ib_device *ibdev, struct ib_device_attr *props)
{
	int ret;
	struct sif_dev *sdev = to_sdev(ibdev);
	struct psif_epsc_device_attr ldev;

	ret = epsc_query_device(sdev, &ldev);
	if (ret)
		return ret;

	memset(props, 0, sizeof(*props));
	props->fw_ver = ldev.fw_ver;
	props->sys_image_guid = cpu_to_be64(ldev.sys_image_guid);
	props->max_mr_size = ~0ull;
	props->page_size_cap = 0xfffffe00; /* TBD: Sensible value? Use what Mellanox uses */
	props->vendor_id = ldev.vendor_id;
	props->vendor_part_id = ldev.vendor_part_id;
	props->hw_ver = ldev.hw_ver;
	props->max_qp = sdev->ba[qp].entry_cnt; /* TBD: min(ldev.max_qp, sdev->ba[qp].entry_cnt) */
	props->max_qp_wr = min_t(u32, SIF_SW_MAX_SQE, ldev.max_srq_wr); /* Max on _any_ work queue */
	props->device_cap_flags =
		IB_DEVICE_BAD_PKEY_CNTR |
		IB_DEVICE_BAD_QKEY_CNTR |
		IB_DEVICE_AUTO_PATH_MIG |
		IB_DEVICE_CURR_QP_STATE_MOD |
		IB_DEVICE_SHUTDOWN_PORT |
		IB_DEVICE_PORT_ACTIVE_EVENT |
		IB_DEVICE_SYS_IMAGE_GUID |
		IB_DEVICE_RC_RNR_NAK_GEN |
		IB_DEVICE_UD_IP_CSUM |
		IB_DEVICE_UD_TSO |
		IB_DEVICE_XRC |
		IB_DEVICE_BLOCK_MULTICAST_LOOPBACK;

	/* returns max_sge SIF_HW_MAX_SEND_SGE -1 for IPoIB datagram mode */
	/* TBD: Add test for uvnic */
	props->max_sge = SIF_HW_MAX_SEND_SGE -
			 (sif_find_kernel_ulp_caller() == IPOIB_ULP);

	props->max_sge_rd = ldev.max_sge_rd;
	props->max_cq = sdev->ba[cq_sw].entry_cnt;
	props->max_cqe = SIF_SW_MAX_CQE;
	/* Make sure we never fill the CQ completely on rev 1-3 - Bug #3657 */
	if (PSIF_REVISION(sdev) <= 3)
		props->max_cqe = SIF_SW_MAX_CQE - 1;
	props->max_mr = sdev->ba[key].entry_cnt;
	props->max_pd = SIF_MAX_PD_INDEX - 1; /* 0 not used, limited by hw field size */
	props->max_qp_rd_atom = ldev.max_qp_rd_atom;
	props->max_ee_rd_atom = ldev.max_ee_rd_atom;
	props->max_res_rd_atom = props->max_qp_rd_atom * sdev->ba[qp].entry_cnt;
	props->max_qp_init_rd_atom = ldev.max_qp_init_rd_atom;
	props->max_ee_init_rd_atom = ldev.max_ee_init_rd_atom;
	props->atomic_cap = ldev.atomic_cap;
	props->max_ee = ldev.max_ee;
	props->max_rdd = ldev.max_rdd;
	props->max_mw = ldev.max_mw;
	props->max_raw_ipv6_qp = min_t(u32, ldev.max_raw_ipv6_qp, props->max_qp);
	props->max_raw_ethy_qp = min_t(u32, ldev.max_raw_ethy_qp, props->max_qp);
	props->max_mcast_grp = ldev.max_mcast_grp;
	props->max_mcast_qp_attach = ldev.max_mcast_qp_attach;
	props->max_total_mcast_qp_attach = ldev.max_total_mcast_qp_attach;
	props->max_ah = sdev->ba[ah].entry_cnt;
	props->max_fmr = props->max_mr;
	props->max_map_per_fmr = 0x7ffff000; /* Should be props->max_mr_size but that breaks ibv_devinfo */
	props->max_srq = sdev->ba[rq_hw].entry_cnt;
	props->max_srq_wr = ldev.max_srq_wr;
	props->max_srq_sge = ldev.max_srq_sge;
	props->max_pkeys = ldev.max_pkeys;
	props->local_ca_ack_delay = ldev.local_ca_ack_delay;
	return ret;
}



static int epsc_query_port(struct sif_dev *sdev, u8 port, struct psif_epsc_port_attr *lpa)
{
	int ret;
	struct sif_eps *es = &sdev->es[sdev->mbox_epsc];
	struct psif_epsc_csr_rsp cqe;
	struct psif_epsc_csr_req req;
	const u8 psif_port = port - 1; /* sif port index starts at 0 */
	struct psif_epsc_port_attr *ps;

	if (port > 2) {
		sif_log(sdev, SIF_INFO, "error: request for port %d while PSIF has only 2 ports",
			port);
		return -EINVAL;
	}

	ps = &es->data->port[psif_port];

	memset(&req, 0, sizeof(req));
	req.opcode = psif_port == PORT_1 ? EPSC_QUERY_PORT_1 : EPSC_QUERY_PORT_2;
	req.u.query_hw.address =
		(u64)es->data_dma_hdl + offsetof(struct sif_epsc_data, port[psif_port]);
	req.u.query_hw.mmu_cntx = sdev->ba[epsc_csr_rsp].mmu_ctx.mctx;

	ret = sif_epsc_wr(sdev, &req, &cqe);

	/* Copy data irrespective of how the EPSC operation went */
	if (eps_version_ge(es, 0, 31))
		copy_conv_to_sw(lpa, ps, sizeof(*lpa));
	else
		memcpy(lpa, ps, sizeof(*lpa));

	if (!ret)
		sif_log(sdev, SIF_VERBS, "port %d lid %d sm_lid %d seq 0x%llx",
			port, lpa->lid, lpa->sm_lid, cqe.seq_num);
	else
		sif_log(sdev, SIF_INFO, "error: port %d seq 0x%llx failed with status %s (ret = %d)",
			port, cqe.seq_num, string_enum_psif_epsc_csr_status(cqe.status),
			ret);
	return ret;
}

int sif_calc_ipd(struct sif_dev	 *sdev, u8 port, enum ib_rate static_rate, u8 *ipd)
{
	int path = ib_rate_to_mult(static_rate);
	int link;
	u8 active_speed = sdev->port[port - 1].active_speed;
	u8 active_width = sdev->port[port - 1].active_width;

	if (static_rate == IB_RATE_PORT_CURRENT) {
		*ipd = 0;
		return 0;
	}

	if (unlikely(path < 0)) {
		sif_log(sdev, SIF_INFO, " Invalid static rate = %x\n",
			path);
		return -EINVAL;
	}

	if (unlikely(active_speed < (u8)IB_SPEED_SDR || active_width < (u8)IB_WIDTH_1X)) {
		sif_log(sdev, SIF_INFO, "Failed to use cached port attributes for port %u\n", port);
		return -EDEADLK;
	}

	/* 2^active_width * active_speed */
	link = (1 << active_width)*active_speed;

	if (path >= link)
		*ipd = 0;
	else
		*ipd = (link/path)-1;
	return 0;
}


int sif_query_port(struct ib_device *ibdev, u8 port, struct ib_port_attr *props)
{
	int ret;
	struct sif_dev *sdev = to_sdev(ibdev);
	struct psif_epsc_port_attr lpa;

	ret = epsc_query_port(sdev, port, &lpa);
	memset(props, 0, sizeof(*props));
	props->state = lpa.state;
	props->max_mtu = IB_MTU_4096;
	props->active_mtu = lpa.active_mtu;
	props->gid_tbl_len = lpa.gid_tbl_len;
	props->port_cap_flags = lpa.port_cap_flags;
	props->max_msg_sz = lpa.max_msg_sz;
	props->bad_pkey_cntr = lpa.bad_pkey_cntr;
	props->qkey_viol_cntr = lpa.qkey_viol_cntr;
	props->pkey_tbl_len = lpa.pkey_tbl_len;
	props->lid = lpa.lid;
	props->sm_lid = lpa.sm_lid;
	props->lmc = lpa.lmc;
	props->max_vl_num = lpa.max_vl_num;
	props->sm_sl = lpa.sm_sl;
	props->subnet_timeout = lpa.subnet_timeout;
	props->init_type_reply = lpa.init_type_reply;
	props->active_width = lpa.active_width;
	props->active_speed = lpa.active_speed;
	props->phys_state = lpa.phys_state;

	/* Cache values */
	sdev->port[port - 1] = *props;
	return ret;
}

int sif_query_gid(struct ib_device *ibdev, u8 port_num, int index, union ib_gid *gid)
{
	int ret = 0;
	ulong log_class = SIF_VERBS;
	struct sif_dev *sdev = to_sdev(ibdev);
	struct psif_epsc_csr_rsp cqe;
	struct psif_epsc_csr_req req;

	memset(&req, 0, sizeof(req));
	req.opcode = EPSC_QUERY_GID;
	req.u.query_table.port = port_num;
	req.u.query_table.index = index;
	ret = sif_epsc_wr(sdev, &req, &cqe);
	if (ret)
		return ret;

	/* Apparently clients expect to get GIDs in network byte order
	 * which requires an extra swap here:
	 */
	gid->global.subnet_prefix = be64_to_cpu(cqe.data);
	gid->global.interface_id = be64_to_cpu(cqe.info);

	if (ret)
		log_class = SIF_INFO;
	sif_logi(ibdev, log_class,
		 " port_num %d, GID Table index %d - > %llx.%llx",
		port_num, index, gid->global.subnet_prefix, gid->global.interface_id);
	return ret;
}


int sif_query_pkey(struct ib_device *ibdev, u8 port, u16 index,
			  u16 *pkey)
{
	int ret = 0;
	struct sif_dev *sdev = to_sdev(ibdev);
	struct psif_epsc_csr_rsp cqe;
	struct psif_epsc_csr_req req;

	memset(&req, 0, sizeof(req));
	req.opcode = EPSC_QUERY_PKEY;
	req.u.query_table.port = port;
	req.u.query_table.index = index;
	ret = sif_epsc_wr(sdev, &req, &cqe);
	if (ret) {
		sif_log(sdev, SIF_INFO, "port %u index %u: Failed with status %d", port, index, ret);
		return ret;
	}
	*pkey = (u16)cqe.data;
	sif_logi(ibdev, SIF_VERBS_V, "port %u index %u -> key 0x%x",
		port, index, *pkey);
	return ret;
}


/* Called from sif_modify_device when IB_DEVICE_MODIFY_EXTENDED is set
 * PSIF specific extension bits defined in sif_verbs.h
 */
static int sif_modify_device_extended(struct sif_dev *sdev, struct ib_device_modify *device_modify,
			struct psif_epsc_csr_req *req)
{
	struct sif_device_modify *dm =
		container_of(device_modify, struct sif_device_modify, ib);

	/* TBD: Simplifying firmware support? */
	sif_log(sdev, SIF_INFO, "uf %d eoib_ctrl %x eoib_data %x (not implemented)",
		dm->uf, dm->eoib_ctrl, dm->eoib_data);
	return -EOPNOTSUPP;
}


int sif_modify_device(struct ib_device *ibdev,
		int device_modify_mask,
		struct ib_device_modify *device_modify)
{
	int ret = 0;
	struct sif_dev *sdev = to_sdev(ibdev);
	struct psif_epsc_csr_rsp cqe;
	struct psif_epsc_csr_req req;

	memset(&req, 0, sizeof(req));
	req.opcode = EPSC_MODIFY_DEVICE;
	if (device_modify_mask & IB_DEVICE_MODIFY_SYS_IMAGE_GUID) {
		req.u.device.modify_mask |= PSIF_DEVICE_MODIFY_SYS_IMAGE_GUID;
		sif_logi(ibdev, SIF_VERBS, "sys_image_guid = 0x%llx",
			device_modify->sys_image_guid);
		req.u.device.sys_image_guid = device_modify->sys_image_guid;
	}
	if (device_modify_mask & IB_DEVICE_MODIFY_NODE_DESC) {
		req.u.device.modify_mask |= PSIF_DEVICE_MODIFY_NODE_DESC;
		sif_logi(ibdev, SIF_VERBS, "node_desc = %s",
			device_modify->node_desc);
		strncpy(req.u.device.node_desc, device_modify->node_desc,
			ARRAY_SIZE(req.u.device.node_desc)-1);
		strncpy(ibdev->node_desc, device_modify->node_desc,
			ARRAY_SIZE(ibdev->node_desc)-1);
	}

	/** PSIF specific extensions (sif_verbs.h) **/
	if (device_modify_mask & IB_DEVICE_MODIFY_EXTENDED)
		ret = sif_modify_device_extended(sdev, device_modify, &req);

	ret = sif_epsc_wr(sdev, &req, &cqe);
	if (ret)
		sif_log(sdev, SIF_INFO, "Failed with status %d", ret);
	return ret;
}

int sif_modify_port(struct ib_device *ibdev,
		u8 port, int port_modify_mask,
		struct ib_port_modify *props)
{
	int ret = 0;
	struct sif_dev *sdev = to_sdev(ibdev);
	struct psif_epsc_csr_rsp cqe;
	struct psif_epsc_csr_req req;

	sif_logi(ibdev, SIF_VERBS,
		"via eps - port %d mask %x init_type %d, set mask %x, clr mask %x",
		port, port_modify_mask,
		props->init_type,
		props->set_port_cap_mask,
		props->clr_port_cap_mask);

	memset(&req, 0, sizeof(req));
	/* TBD: Why both port and different op for port 1 and 2? */
	req.u.port.port = port;
	if (port == 1)
		req.opcode = EPSC_MODIFY_PORT_1;
	else if (port == 2)
		req.opcode = EPSC_MODIFY_PORT_2;
	else {
		/* No such port */
		ret = -EINVAL;
		goto out;
	}

	/* TBD: Check later on if we can let this mask straight through 1-1 */
	if (port_modify_mask & IB_PORT_SHUTDOWN)
		req.u.port.modify_mask |= PSIF_PORT_SHUTDOWN;
	if (port_modify_mask & IB_PORT_INIT_TYPE) {
		req.u.port.modify_mask |= PSIF_PORT_INIT_TYPE;
		req.u.port.init_type = props->init_type;
	}
	if (port_modify_mask & IB_PORT_RESET_QKEY_CNTR)
		req.u.port.modify_mask |= PSIF_PORT_RESET_QKEY_CNTR;
	if (port_modify_mask & (1<<4))
		req.u.port.modify_mask |= PSIF_PORT_RESET_PKEY_CNTR;
	req.u.port.set_port_cap_mask = props->set_port_cap_mask;
	req.u.port.clr_port_cap_mask = props->clr_port_cap_mask;
	ret = sif_epsc_wr(sdev, &req, &cqe);
	if (ret)
		sif_log(sdev, SIF_INFO, "Failed with status %d", ret);
out:
	return ret;
}


