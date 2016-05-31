/*
 * Copyright (c) 2013, 2015, Oracle and/or its affiliates. All rights reserved.
 *    Author: Knut Omang <knut.omang@oracle.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 *
 * Driver for Oracle Scalable Infiniband Fabric (SIF) Host Channel Adapters
 *
 * sif_fwa.c: Firmware access API (netlink based out-of-band comm)
 *
 */
#include "sif_dev.h"
#include "sif_fwa.h"

#include <net/netlink.h>
#include <net/genetlink.h>
#include "sif_enl.h"
#include "sif_defs.h"
#include "sif_query.h"
#include "sif_base.h"
#include "sif_qp.h"
#include "psif_hw_csr.h"
#include "sif_drvapi.h"

/* Generic netlink protocol family definition */
static struct genl_family sif_enl_family = {
	.id = GENL_ID_GENERATE,
	.hdrsize = 0,
	.name = "sif_enl",
	.version = 1,
	.maxattr = 16
};

/* Netlink request handlers */
static int sif_fwa_req(struct sk_buff *skb, struct genl_info *info);
static int sif_fwa_drv_req(struct sk_buff *skb, struct genl_info *info);

/* Netlink req operation definition */
static struct genl_ops sif_enl_ops[] = {
	{
		.cmd = SIF_ENL_CMD_REQ,
		.flags = 0,
		.policy = sif_enl_policy,
		.doit = sif_fwa_req,
		.dumpit = NULL,
	},

	{
		.cmd = SIF_ENL_CMD_REQ_DRV,
		.flags = 0,
		.policy = sif_enl_policy,
		.doit = sif_fwa_drv_req,
		.dumpit = NULL,
	}
};


/* Global datastructure to keep track of instances and number of active
 * processes:
 */

struct fwa_data {
	struct list_head sdev_list;  /* Access to devices */
	spinlock_t lock;             /* Protects device list */
};

static struct fwa_data fwa;


/* Called from sif_init/exit to set up/clean up global data structures
 * such as netlink communication and device registry:
 */
int sif_fwa_init(void)
{
	int stat;

	INIT_LIST_HEAD(&fwa.sdev_list);
	spin_lock_init(&fwa.lock);

	stat = genl_register_family_with_ops(&sif_enl_family, sif_enl_ops);
	if (stat)
		goto fail;

	sif_log0(SIF_INIT, "Enabled firmware access API");
	return 0;
fail:
	sif_log0(SIF_INIT, "ERROR: Failed to enable firmware access API - error %d", stat);
	return stat;
}

void sif_fwa_exit(void)
{
	sif_log0(SIF_INIT, "Disabling firmware access API");
	genl_unregister_family(&sif_enl_family);
}


/* Called from probe to register a new device */
int sif_fwa_register(struct sif_dev *sdev)
{
	struct pci_dev *pdev = sdev->pdev;

	sif_log(sdev, SIF_INIT, "register device %02x:%02x.%d",
		pdev->bus->number, PCI_SLOT(pdev->devfn), PCI_FUNC(pdev->devfn));
	spin_lock(&fwa.lock);
	list_add_tail(&sdev->fwa.list, &fwa.sdev_list);
	spin_unlock(&fwa.lock);
	return 0;
}

/* Called from remove to unregister a device */
void sif_fwa_unregister(struct sif_dev *sdev)
{
	spin_lock(&fwa.lock);
	list_del(&sdev->fwa.list);
	spin_unlock(&fwa.lock);
}


static struct sif_dev *fwa_find_dev(struct genl_info *info)
{
	struct sif_dev *sdev = NULL;
	struct sif_dev *s;

	u16 domain = nla_get_u16(info->attrs[SIF_ENL_A_COMPLEX]);
	u16 bus = nla_get_u16(info->attrs[SIF_ENL_A_BUS]);
	u16 devfn = nla_get_u16(info->attrs[SIF_ENL_A_DEVFN]);

	/* TBD: Ref.count access to sdev */
	sif_log0(SIF_FWA, "bus %x devfn %x",
		bus, devfn);

	spin_lock(&fwa.lock);
	list_for_each_entry(s, &fwa.sdev_list, fwa.list) {
		if (domain == pci_domain_nr(s->pdev->bus) &&
			bus == s->pdev->bus->number &&
			devfn == s->pdev->devfn) {
			sdev = s;
			break;
		}
		sif_log(s, SIF_FWA, "bus %x devfn %x", s->pdev->bus->number, s->pdev->devfn);
	}
	spin_unlock(&fwa.lock);
	return sdev;
}


static int fwa_valid_opcode(struct sif_dev *sdev, struct psif_epsc_csr_req *req,
		enum psif_mbox_type eps_num)
{
	switch (req->opcode) {
	case EPSC_SETUP:
	case EPSC_SETUP_BASEADDR:
	case EPSC_SET_BASEADDR:
	case EPSC_SET_BASEADDR_EQ:
	case EPSC_SET_ONE_CSR:
		/* These are kernel only */
		return -EPERM;
	case EPSC_HOST_INT_CHANNEL_CTRL:
	case EPSC_HOST_INT_COMMON_CTRL:
	case EPSC_SET_LID:
	case EPSC_SET_EOIB_MAC:
	case EPSC_UF_RESET:
	case EPSC_MODIFY_QP:
	case EPSC_GET_SINGLE:
	case EPSC_GET_ONE_CSR:
	case EPSC_QUERY:
	case EPSC_SET:
	case EPSC_QUERY_QP:
	case EPSC_QUERY_DEVICE:
	case EPSC_QUERY_PORT_1:
	case EPSC_QUERY_PORT_2:
	case EPSC_QUERY_PKEY:
	case EPSC_QUERY_GID:
	case EPSC_MODIFY_DEVICE:
	case EPSC_MODIFY_PORT_1:
	case EPSC_MODIFY_PORT_2:
	case EPSC_MC_ATTACH:
	case EPSC_MC_DETACH:
	case EPSC_MC_QUERY:
	case EPSC_FLASH_START:
	case EPSC_FLASH_ERASE_SECTOR:
	case EPSC_FLASH_RD:
	case EPSC_FLASH_WR:
	case EPSC_FLASH_STOP:
	case EPSC_A_CONTROL:
	case EPSC_LINK_CNTRL:
	case EPSC_UPDATE:
	case EPSC_UF_CTRL:
	case EPSC_VIMMA_CTRL:
		/* These are not meaningful for the EPSAs for now */
		if (eps_num == sdev->mbox_epsc)
			return 0;
		else
			return -EPERM;
	case EPSC_NOOP:
	case EPSC_MAILBOX_PING:
	case EPSC_KEEP_ALIVE:
	case EPSC_EVENT_ACK:
	case EPSC_EVENT_INDEX:
	case EPSC_TEST_HOST_RD:
	case EPSC_TEST_HOST_WR:
	case EPSC_FW_VERSION:
	case EPSC_LOG_CTRL:
	case EPSC_LOG_REQ_NOTIFY:
	case EPSC_A_COMMAND:
	case EPSC_EXERCISE_MMU:
	case EPSC_CLI_ACCESS:
		break;
	case EPSC_LAST_OP:
	default:
		/* Fail on all unknown operations: */
		sif_log(sdev, SIF_FWA, "Unknown operation %d", req->opcode);
		return -EINVAL;
	}
	return 0;
}


static int sif_fwa_verify_find_dev(struct genl_info *info, struct sif_dev **sdev_p, int payload_len)
{
	struct sif_dev *sdev;
	int len;

	if (!info->attrs[SIF_ENL_A_COMPLEX]) {
		sif_log0(SIF_FWA, "PCI complex no. not set!");
		return -EINVAL;
	}

	if (!info->attrs[SIF_ENL_A_BUS]) {
		sif_log0(SIF_FWA, "PCI bus no. not set!");
		return -EINVAL;
	}

	if (!info->attrs[SIF_ENL_A_DEVFN]) {
		sif_log0(SIF_FWA, "PCI device/function not set!");
		return -EINVAL;
	}

	if (!info->attrs[SIF_ENL_A_PAYLOAD]) {
		sif_log0(SIF_FWA, "Received empty request!");
		return -EINVAL;
	}
	len = nla_len(info->attrs[SIF_ENL_A_PAYLOAD]);
	if (len < payload_len) {
		sif_log0(SIF_FWA, "Request too short!");
		return -EFAULT;
	}

	/* TBD: Better input checking... */

	sdev = fwa_find_dev(info);
	if (!sdev) {
		sif_log0(SIF_FWA, "No such device found!");
		return -ENODEV;
	}
	*sdev_p = sdev;
	return 0;
}


static int sif_fwa_drv_req(struct sk_buff *skb, struct genl_info *info)
{
	int msg_sz;
	int stat;
	size_t data_sz = 0;
	struct sif_dev *sdev;
	struct sif_drv_req *req = NULL;
	struct sif_drv_rsp rsp;
	enum psif_mbox_type eps_num;
	struct sk_buff *resp_skb;
	void *data;
	int ret;

	if (!capable(CAP_NET_ADMIN)) {
		sif_log0(SIF_FWA, "Request from client without the CAP_NET_ADMIN privilege");
		return -EPERM;
	}

	ret = sif_fwa_verify_find_dev(info, &sdev, sizeof(struct sif_drv_req));
	if (ret)
		return ret;

	req = nla_data(info->attrs[SIF_ENL_A_PAYLOAD]);

	sif_log(sdev, SIF_FWA, "op %d", req->opcode);

	if (IS_SIBS(sdev)) {
		sif_log(sdev, SIF_FWA, "Device does not have any EPS-A modules");
		return -EINVAL;
	}

	eps_num = epsa_to_mbox(req->u.epsa.epsa);
	if (eps_num == (enum psif_mbox_type)-1) {
		sif_log(sdev, SIF_FWA, "Unknown EPS-A %d", req->u.epsa.epsa);
		return -EINVAL;
	}

	switch (req->opcode) {
	case SIF_DRV_CMD_EPSA_SETUP:
		ret = sif_activate_epsa(sdev, eps_num);
		rsp.opcode = SIF_DRV_CMD_EPSA_SETUP;
		rsp.eps_rsp.status = ret;
		break;
	case SIF_DRV_CMD_EPSA_TEARDOWN:
		break;
	}

	if (ret)
		return ret;

	/* Start building a response */
	msg_sz = NLMSG_DEFAULT_SIZE + data_sz;
	resp_skb = nlmsg_new(msg_sz, GFP_KERNEL);
	if (!resp_skb)
		return -ENOMEM;

	data = genlmsg_put_reply(resp_skb, info, &sif_enl_family,
				0, SIF_ENL_CMD_RSP_DRV);
	if (data == NULL) {
		stat = -ENOMEM;
		goto put_fail;
	}

	stat = nla_put(resp_skb, SIF_ENL_A_PAYLOAD, sizeof(struct sif_drv_rsp), &rsp);
	if (stat) {
		sif_log(sdev, SIF_FWA, "failed to append response to netlink packet");
		goto put_fail;
	}

	/* Recompute message header */
	genlmsg_end(resp_skb, data);

	stat = genlmsg_reply(resp_skb, info);
	if (stat) {
		sif_log(sdev, SIF_FWA, "failed to send reply - status %d", stat);
		goto put_fail;
	}

	sif_log(sdev, SIF_FWA, "Sent response with drv opcode %d msg sz %d",
		rsp.opcode, msg_sz);
	return 0;
put_fail:
	nlmsg_free(resp_skb);
	return stat;
}

static int sif_fwa_req(struct sk_buff *skb, struct genl_info *info)
{
	int len;
	int stat;
	int msg_sz;
	struct sif_dev *sdev;
	enum psif_mbox_type eps_num;
	struct sif_eps *es;
	void *data;
	size_t data_sz = 0;
	struct psif_epsc_csr_req *req = NULL;
	struct psif_epsc_csr_rsp rsp;
	struct psif_query_qp *qqp;
	struct sk_buff *resp_skb;
	void *kaddr = NULL;

	if (!capable(CAP_NET_ADMIN)) {
		sif_log0(SIF_FWA, "Request from client without the CAP_NET_ADMIN privilege");
		return -EPERM;
	}

	stat = sif_fwa_verify_find_dev(info, &sdev, sizeof(struct psif_epsc_csr_req));
	if (stat)
		return stat;

	req = nla_data(info->attrs[SIF_ENL_A_PAYLOAD]);

	if (info->attrs[SIF_ENL_A_INDEX]) {
		eps_num = nla_get_u32(info->attrs[SIF_ENL_A_INDEX]);
		if (IS_SIBS(sdev)) {
			if (eps_num == MBOX_EPSC)
				eps_num = SIBS_MBOX_EPSC;
			else {
				sif_log(sdev, SIF_FWA, "Invalid EPS selection (%d)", eps_num);
				return -EINVAL;
			}
		}
		if (eps_num >= sdev->eps_cnt) {
			sif_log(sdev, SIF_FWA, "Invalid EPS selection (%d)", eps_num);
			return -EINVAL;
		}
	} else {
		/* Default to use the EPSC (bw.comp) */
		eps_num = sdev->mbox_epsc;
	}

	sif_log(sdev, SIF_FWA, "%s to %s",
		string_enum_psif_epsc_csr_opcode(req->opcode),
		string_enum_psif_mbox_type(eps_num));

	es = &sdev->es[eps_num];
	if (es->state != ES_ACTIVE) {
		sif_log0(SIF_FWA, "Communication with EPS%s has not been set up (state = %d)!",
			eps_name(sdev, eps_num), es->state);
		return -ENODEV;
	}

	/* Check that this opcode is valid in this context */
	stat = fwa_valid_opcode(sdev, req, eps_num);
	if (stat) {
		if (stat == -EPERM)
			sif_log(sdev, SIF_FWA,
				"Operation %s not permitted for EPS%s from user space",
				string_enum_psif_epsc_csr_opcode(req->opcode),
				eps_name(sdev, eps_num));
		return stat;
	}


	/* The below opcodes picks up additional data from (fixed) buffers */
	switch (req->opcode) {
	case EPSC_QUERY_DEVICE:
		req->u.query_hw.address =
			(u64)es->data_dma_hdl +
			offsetof(struct sif_epsc_data, dev);
		kaddr = &es->data->dev;
		data_sz = sizeof(struct psif_epsc_device_attr);
		break;
	case EPSC_QUERY_PORT_1:
		req->u.query_hw.address =
			(u64)es->data_dma_hdl +
			offsetof(struct sif_epsc_data, port[0]);
		kaddr = &es->data->port[0];
		data_sz = sizeof(struct psif_epsc_port_attr);
		break;
	case EPSC_QUERY_PORT_2:
		req->u.query_hw.address =
			(u64)es->data_dma_hdl +
			offsetof(struct sif_epsc_data, port[1]);
		kaddr = &es->data->port[1];
		data_sz = sizeof(struct psif_epsc_port_attr);
		break;
	case EPSC_QUERY_QP:
	{
		struct sif_qp *qps;
		u32 qp_idx = req->u.query_qp.ctrl.qp_num;

		if (qp_idx >= sdev->ba[qp].entry_cnt)
			return -ENOENT;
		qps = get_sif_qp(sdev, qp_idx);
		kaddr = qqp = &qps->qqp;
		req->u.query_qp.address = sif_qqp_dma_addr(sdev, qps);
		data_sz = sizeof(struct psif_query_qp);
		break;
	}
	case EPSC_FLASH_RD:
	case EPSC_FLASH_WR:
		data_sz = req->u.flash.length;
		if (data_sz)
			kaddr = &es->data->flash;

		/* Use the reserved 'flash' buffer allocated with the EPSC's resp.queue: */
		req->u.flash.host_addr = es->data_dma_hdl +
			offsetof(struct sif_epsc_data, flash);
		req->u.flash.mmu_cntx = sdev->ba[epsc_csr_rsp].mmu_ctx.mctx;
		break;
	case EPSC_CLI_ACCESS:
		data_sz = MAX_FWA_NL_PAYLOAD;
		kaddr = &es->data->epsc_cli;

		/* Use the reserved 'epsc_cli' buffer allocated with the EPSC's resp. queue: */
		req->u.cli.host_addr = es->data_dma_hdl +
			offsetof(struct sif_epsc_data, epsc_cli);
		req->u.cli.mmu_cntx = sdev->ba[epsc_csr_rsp].mmu_ctx.mctx;
		break;
	case EPSC_VIMMA_CTRL:
		data_sz = MAX_FWA_NL_PAYLOAD;
		kaddr = &es->data->vimm_agent;

		/* Use the reserved 'vimm_agent' buffer allocated with the EPSC's resp. queue: */
		req->u.vimma_ctrl.host_addr = es->data_dma_hdl +
			offsetof(struct sif_epsc_data, vimm_agent);
		req->u.vimma_ctrl.mmu_cntx = sdev->ba[epsc_csr_rsp].mmu_ctx.mctx;
		break;
	case EPSC_UPDATE:
		switch (req->u.update.opcode) {
		case EPSC_UPDATE_OP_READ:
		case EPSC_UPDATE_OP_WRITE:
			/* Use the reserved 'flash' buffer allocated with the EPSC's resp.queue: */
			req->u.update.host_addr = es->data_dma_hdl +
				offsetof(struct sif_epsc_data, flash);
			req->u.update.mmu_cntx = sdev->ba[epsc_csr_rsp].mmu_ctx.mctx;
			/* fall through */
		case EPSC_UPDATE_OP_POLL:
			data_sz = req->u.update.length;
			kaddr = &es->data->flash;
			break;
		default:
			break;
		}
		break;
	default:
		break;
	}

	/* Copy any extra input data to the kernel buffer: */
	if (info->attrs[SIF_ENL_A_DATA]) {
		len = nla_len(info->attrs[SIF_ENL_A_DATA]);
		data = nla_data(info->attrs[SIF_ENL_A_DATA]);
		switch (req->opcode) {
		case EPSC_UPDATE:
			if (req->u.update.opcode != EPSC_UPDATE_OP_WRITE)
				break;
			/* fall through */
		case EPSC_FLASH_WR:
		case EPSC_CLI_ACCESS:
		case EPSC_VIMMA_CTRL:
			if (kaddr) {
				memcpy(kaddr, data, len);
				sif_log(sdev, SIF_FWA, "dma kaddr %p data %p len %x",
					kaddr, data, len);
				mb();
			} else
				sif_log(sdev, SIF_FWA, "Found aux.data input but no data area");
			break;
		default:
			sif_log(sdev, SIF_FWA, "Found aux.data input in unexpected op %s",
				string_enum_psif_epsc_csr_opcode(req->opcode));
			break;
		}
	}

	stat = sif_eps_wr(sdev, eps_num, req, &rsp);
	switch (stat) {
	case -ETIMEDOUT:
		return stat;
	default:
		break;
	}

	if (data_sz > MAX_FWA_NL_PAYLOAD)
		return -EMSGSIZE;

	/* Start building a response */
	msg_sz = NLMSG_DEFAULT_SIZE + data_sz;
	resp_skb = nlmsg_new(msg_sz, GFP_KERNEL);
	if (!resp_skb) {
		sif_log(sdev, SIF_FWA, "failed to allocate netlink packet");
		return -ENOMEM;
	}

	data = genlmsg_put_reply(resp_skb, info, &sif_enl_family,
				0, SIF_ENL_CMD_RSP);
	if (data == NULL) {
		sif_log(sdev, SIF_FWA, "failed to add generic netlink header");
		stat = -ENOMEM;
		goto put_fail;
	}

	stat = nla_put(resp_skb, SIF_ENL_A_PAYLOAD, sizeof(struct psif_epsc_csr_rsp), &rsp);
	if (stat) {
		sif_log(sdev, SIF_FWA, "failed to append response to netlink packet");
		goto put_fail;
	}

	if (kaddr && req->opcode != EPSC_FLASH_WR &&
	    !(req->opcode == EPSC_UPDATE && req->u.update.opcode == EPSC_UPDATE_OP_WRITE)) {
		stat = nla_put(resp_skb, SIF_ENL_A_DATA, data_sz, kaddr);
		if (stat) {
			sif_log(sdev, SIF_FWA, "failed to append %ld bytes of data", data_sz);
			goto put_fail;
		}
	}

	/* Recompute message header */
	genlmsg_end(resp_skb, data);

	stat = genlmsg_reply(resp_skb, info);
	if (stat) {
		sif_log(sdev, SIF_FWA, "failed to send reply - status %d", stat);
		goto put_fail;
	}

	sif_log(sdev, SIF_FWA, "Sent response with opcode %s msg sz %d",
		string_enum_psif_epsc_csr_opcode(rsp.opcode), msg_sz);
	return 0;
put_fail:
	nlmsg_free(resp_skb);
	return stat;
}
