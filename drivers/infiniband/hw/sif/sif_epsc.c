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
 * sif_epsc.c: Implementation of API for communication with the EPSC
 *
 *  In general this module has to make sure that
 *  1) we never have more packets outstanding with the EPS than hw_enties
 *  2) we do not post more packets than we have completion entries for,
 *     eg. we must ensure that completions not yet forwarded as a result of
 *     a *waitfor* call is not overwritten by hw.
 */

#include "sif_epsc.h"
#include "sif_eq.h"
#include "sif_dev.h"
#include "sif_base.h"
#include "psif_hw_csr.h"
#include "psif_hw_data.h"
#include "psif_hw_setget.h"
#include "sif_dma.h"
#include "sif_query.h"
#include "sif_elog.h"
#include "sif_hwi.h"
#include "sif_spt.h"
#include "sif_defs.h"
#include <linux/bitmap.h>
#include <linux/seq_file.h>
#include <xen/xen.h>

#define CSR_ONLINE_MASK 0x8000

#define EPSC_LOG_MODE_BUFFER EPSC_LOG_MODE_SCAT


static int write_csr(struct sif_dev *sdev, u32 addr, u64 val);
static u64 read_csr(struct sif_dev *sdev, u32 addr, bool local);

union sif_mailbox {
	u64 raw;
	struct psif_epsc_csr_doorbell x;
};

static int __sif_eps_send_keep_alive(struct sif_dev *sdev, enum psif_mbox_type eps_num,
			bool force);

static enum psif_mbox_type sif_tab2mbox(struct sif_dev *sdev, enum sif_tab_type tab_type)
{
	return (tab_type & ~1) == epsc_csr_req ? sdev->mbox_epsc
		: ((tab_type - epsa0_csr_req) >> 1);
}


static enum sif_tab_type sif_mbox2req_tab(struct sif_dev *sdev, enum psif_mbox_type eps_num)
{
	return eps_num == sdev->mbox_epsc ? epsc_csr_req
		: epsa0_csr_req + (eps_num << 1);
}

static enum sif_tab_type sif_mbox2rsp_tab(struct sif_dev *sdev, enum psif_mbox_type eps_num)
{
	return eps_num == sdev->mbox_epsc ? epsc_csr_rsp
		: epsa0_csr_rsp + (eps_num << 1);
}


const char *eps_name(struct sif_dev *sdev, enum psif_mbox_type eps_num)
{
	if (eps_num == sdev->mbox_epsc)
		return "C";

	switch (eps_num) {
	case MBOX_EPSA0:
		return "A-0";
	case MBOX_EPSA1:
		return "A-1";
	case MBOX_EPSA2:
		return "A-2";
	case MBOX_EPSA3:
		return "A-3";
	default:
		break;
	}
	return "(nonexisting eps)";
}


const char *eps_suffix(struct sif_dev *sdev, enum psif_mbox_type eps_num)
{
	if (eps_num == sdev->mbox_epsc)
		return "c";

	switch (eps_num) {
	case MBOX_EPSA0:
		return "a0";
	case MBOX_EPSA1:
		return "a1";
	case MBOX_EPSA2:
		return "a2";
	case MBOX_EPSA3:
		return "a3";
	default:
		break;
	}
	return "(nonexisting eps)";
}


bool is_eps_rsp_tab(enum sif_tab_type type)
{
	switch (type) {
	case epsc_csr_rsp:
	case epsa0_csr_rsp:
	case epsa1_csr_rsp:
	case epsa2_csr_rsp:
	case epsa3_csr_rsp:
		return true;
	default:
		return false;
	}
}


int eps_status_to_err(enum psif_epsc_csr_status status)
{
	switch (status) {
	case EPSC_SUCCESS:
		return 0;
	case EPSC_EKEYREJECTED:
		return -EKEYREJECTED;
	case EPSC_EADDRNOTAVAIL:
		return -EPERM;
	case EPSC_EOPNOTSUPP:
		return -EOPNOTSUPP;
	case EPSC_ENOMEM:
		return -ENOMEM;
	case EPSC_ENODATA: /* ENODATA is not an error */
		return 0;
	case EPSC_EAGAIN:
		return -EAGAIN;
	case EPSC_ECANCELED:
		return -ECANCELED;
	case EPSC_ECONNRESET:
		return -ECONNRESET;
	case EPSC_ECSR:
		return -EACCES;
	case EPSC_MODIFY_QP_OUT_OF_RANGE:
		return -ERANGE;
	case EPSC_MODIFY_QP_INVALID:
		return -EINVAL;
	case EPSC_MODIFY_CANNOT_CHANGE_QP_ATTR:
		return -EBUSY;
	case EPSC_MODIFY_INVALID_QP_STATE:
	case EPSC_MODIFY_INVALID_MIG_STATE:
		return -EINVAL;
	case EPSC_MODIFY_TIMEOUT:
		return -ETIMEDOUT;
	case EPSC_ETEST_HEAD:
	case EPSC_ETEST_TAIL:
	case EPSC_ETEST_PATTERN:
		return -EIO;
	case EPSC_EADDRINUSE:
		return -EADDRINUSE;
	case EPSC_EINVALID_VHCA:
		return -ECHRNG;
	case EPSC_EINVALID_PORT:
		return -ELNRNG;
	case EPSC_EINVALID_ADDRESS:
		return -EADDRNOTAVAIL;
	case EPSC_EINVALID_PARAMETER:
		return -EINVAL;
	case EPSC_FAIL:
		return -ENOTRECOVERABLE;
	default:
		return -EUCLEAN; /* If this is returned, this function needs corrections */
	}
}


struct psif_epsc_csr_req *get_eps_csr_req(struct sif_dev *sdev,
	enum psif_mbox_type eps_num, int index)
{
	enum sif_tab_type type = sif_mbox2req_tab(sdev, eps_num);

	return (struct psif_epsc_csr_req *)
		(sif_mem_kaddr(sdev->ba[type].mem, index * sdev->ba[type].ext_sz));
}

struct psif_epsc_csr_rsp *get_eps_csr_rsp(struct sif_dev *sdev,
	enum psif_mbox_type eps_num, int index)
{
	enum sif_tab_type type = sif_mbox2rsp_tab(sdev, eps_num);

	return (struct psif_epsc_csr_rsp *)
		(sif_mem_kaddr(sdev->ba[type].mem, index * sdev->ba[type].ext_sz));
}

static inline u16 get_eps_mailbox_seq_num(volatile struct psif_epsc_csr_rsp *rsp)
{
	return rsp->seq_num & (CSR_ONLINE_MASK - 1);
}

/* Cond. call completion on an entry in the response queue
 * Assumes the eps lock is held
 */
static inline void __epsc_complete(struct sif_dev *sdev, enum psif_mbox_type eps_num, int idx)
{
	struct sif_eps *es = &sdev->es[eps_num];
	struct sif_eps_cqe *cqe = es->cqe[idx];

	if (cqe && cqe->need_complete)
		complete(&cqe->cmpl);
}

void epsc_complete(struct sif_dev *sdev, enum psif_mbox_type eps_num, int idx)
{
	unsigned long flags;
	struct sif_eps *es = &sdev->es[eps_num];

	spin_lock_irqsave(&es->lock, flags);
	__epsc_complete(sdev, eps_num, idx);
	spin_unlock_irqrestore(&es->lock, flags);
}

static int sif_eps_api_version_ok(struct sif_dev *sdev, enum psif_mbox_type eps_num)
{
	bool psif_version_ok;
	bool epsc_version_ok;
	struct sif_eps *es = &sdev->es[eps_num];

	/* Validate that we have compatible versions */
	sif_log(sdev, SIF_INFO_V, "Connected to SIF version %d.%d,  EPS%s API version %d.%d",
		es->ver.psif_major, es->ver.psif_minor,
		eps_name(sdev, eps_num),
		es->ver.epsc_major, es->ver.epsc_minor);

	psif_version_ok =
		es->ver.psif_major == PSIF_MAJOR_VERSION &&
		es->ver.psif_minor == PSIF_MINOR_VERSION;

	if (!psif_version_ok) {
		u32 ever, dver, rev1ver;

		sif_log(sdev, SIF_INFO,
		" *** PSIF architecture version mismatch: driver expects v.%d.%d, fw supports v.%d.%d ***",
			PSIF_MAJOR_VERSION, PSIF_MINOR_VERSION,
			es->ver.psif_major, es->ver.psif_minor);
		ever = PSIF_API_VERSION(es->ver.psif_major, es->ver.psif_minor);
		rev1ver = PSIF_API_VERSION(4, 06);
		dver = PSIF_VERSION;
		if ((dver > rev1ver && ever <= rev1ver) ||
			(ever > rev1ver && dver <= rev1ver)) {
			sif_log(sdev, SIF_INFO, "Wrong driver build for this chip revision!");
			return -ENOEXEC;
		}
	}

	epsc_version_ok =
		es->ver.epsc_major == EPSC_MAJOR_VERSION &&
		es->ver.epsc_minor == EPSC_MINOR_VERSION;

	if (!epsc_version_ok) {
		sif_log(sdev, SIF_INFO_V,
		" *** EPS%s API version mismatch: driver expects v.%d.%d, firmware implements v.%d.%d ***",
			eps_name(sdev, eps_num),
			EPSC_MAJOR_VERSION, EPSC_MINOR_VERSION,
			es->ver.epsc_major, es->ver.epsc_minor);
	}

	/* PSIF version must match exactly, any EPSC version is ok */
	if (!psif_version_ok)
		return -ENOEXEC;
	return 0;
}


static int sif_eps_firmware_version_ok(struct sif_dev *sdev, enum psif_mbox_type eps_num)
{
	int ret;
	int i = 0, fi = 0;
	struct psif_epsc_csr_req req;
	struct psif_epsc_csr_rsp rsp;
	char *p;
	char *start;
	char *vs;
	struct sif_eps *es = &sdev->es[eps_num];

	memset(&req, 0, sizeof(req));
	req.opcode = EPSC_FW_VERSION;
	req.u.fw_version.host_addr =
		(u64)es->data_dma_hdl + offsetof(struct sif_epsc_data, fw_version);

	ret = sif_eps_wr_poll(sdev, eps_num, &req, &rsp);
	if (ret)
		return ret;

	/* Parse the string we got: */
	p = start = es->data->fw_version;
	for (i = 0; i < MAX_FW_VERSION_INFO_SZ; i++) {
		if (p[i] == '\0') {
			sif_log(sdev, SIF_VERBS, "fw_version[%d]: %s",
				fi, start);
			es->ver.fw_version[fi++] = start;
			/* skip 0 byte */
			start = p + i + 1;
			if (fi >= FWV_MAX)
				break;
		}
	}
	sif_log(sdev, SIF_INFO_V, "EPSC firmware image revision string %s",
		es->ver.fw_version[FWV_EPS_REV_STRING]);
	sif_log(sdev, SIF_INFO_V, "EPSC firmware version tag:\n%s",
		es->ver.fw_version[FWV_EPS_GIT_LAST_COMMIT]);
	if (es->ver.fw_version[FWV_EPS_GIT_STATUS][0] != '\0')
		sif_log(sdev, SIF_INFO,	" *** epsfw git status at build time: ***\n%s",
			es->ver.fw_version[FWV_EPS_GIT_STATUS]);

	vs = es->ver.fw_version[FWV_EPS_REV_STRING];
	if (sscanf(vs, "%hu.%hu", &es->ver.fw_major, &es->ver.fw_minor) != 2)
		return -EINVAL;

	if (vs[0] == 'R' && es->ver.fw_minor == 0)
		es->ver.fw_minor = 1;

	sif_log(sdev, SIF_INIT, "EPSC firmware revision: %hu.%hu",
		es->ver.fw_major, es->ver.fw_minor);
	return 0;
}


static int sif_eps_log_ctrl(struct sif_dev *sdev, enum psif_mbox_type eps_num,
		enum psif_epsc_log_mode mode,
		enum psif_epsc_log_level level)
{
	int ret;
	struct psif_epsc_csr_req req;
	struct psif_epsc_csr_rsp rsp;
	struct sif_eps *es = &sdev->es[eps_num];

	if (eps_num != sdev->mbox_epsc) {
		/* TBD: Data area has not been allocated for EPSAs! */
		return -ENOMEM;
	}

	if (!es->data->log.size) {
		sif_log(sdev, SIF_INFO, "cannot redirect - no data buffer configured");
		return -ENOMEM;
	}

	memset(&req, 0, sizeof(req));
	req.opcode = EPSC_LOG_CTRL;
	/* TBD: Higher log levels than debug will give a feedback loop... */
	req.u.log_ctrl.level = level > EPS_LOG_DEBUG ? EPS_LOG_DEBUG : level;
	req.u.log_ctrl.mode = mode;
	req.u.log_ctrl.mmu_cntx = sdev->ba[epsc_csr_rsp].mmu_ctx.mctx;

	if (mode == EPSC_LOG_MODE_HOST) {
		req.u.log_ctrl.stat_base =
			(u64)es->data_dma_hdl + offsetof(struct sif_epsc_data, log);
		req.u.log_ctrl.base =
			(u64)es->data_dma_hdl + offsetof(struct sif_epsc_data, log_data_area);
		req.u.log_ctrl.length =
			es->data->log.size;
	}

	ret = sif_eps_wr_poll(sdev, eps_num, &req, &rsp);
	if (!ret) {
		if (mode == EPSC_LOG_MODE_HOST) {
			sif_log(sdev, SIF_INFO,
				"Enabled EPS log redirect to buffer at %p (sz 0x%llx)",
				es->data->log_data_area,
				es->data->log.size);
			ret = sif_elog_init(sdev, eps_num);
			if (ret)
				sif_log(sdev, SIF_INFO, "Failed to create eps logging device for EPS%s",
					eps_name(sdev, eps_num));
			es->log_redir_en = true;
		} else {
			if (es->log_redir_en) {
				sif_elog_deinit(sdev, eps_num);
				es->log_redir_en = false;
			}
			sif_log(sdev, SIF_INFO,	"Disabled EPS log redirect");
		}
	}
	return ret;
}


int epsc_set_mmu_upper(struct sif_dev *sdev, u16 value)
{
	int ret;

	if (eps_version_ge(&sdev->es[sdev->mbox_epsc], 0, 103)) {
		struct psif_epsc_csr_req req;
		struct psif_epsc_csr_rsp rsp;

		memset(&req, 0, sizeof(req));
		req.opcode = EPSC_SET;
		req.u.set.data.op = EPSC_QUERY_TA_UPPER_TWELVE;
		req.u.set.info.op = EPSC_QUERY_PA_UPPER_TWELVE;
		req.u.set.data.value = value;
		req.u.set.info.value = value;
		ret = sif_epsc_wr_poll(sdev, &req, &rsp);
	} else {
		u64 v = read_csr(sdev, 0x200000, false);

		v &= ~((0xfffull << 48) | (0xfffull << 32));
		v |= ((u64)value << 48) | ((u64)value << 32);
		ret = write_csr(sdev, 0x200000, v);
	}
	if (ret)
		sif_log(sdev, SIF_INFO, "Failed to set mmu_upper bits!");

	if (PSIF_REVISION(sdev) <= 3)
		/* Enable WA for Bug #4096: TA/PA upper has no effect on level0 contexts */
		sdev->single_pte_pt = true;
	return ret;
}



/* special epsc initialization */
static void eps_struct_init(struct sif_dev *sdev)
{
	struct sif_eps *es;
	u8 i;

	for (i = 0; i < sdev->eps_cnt; i++) {
		memset(sdev->es, 0, sizeof(*sdev->es));
		es = &sdev->es[i];
		es->sdev = sdev;
		es->eps_num = i;
		spin_lock_init(&es->lock);

		if (i != sdev->mbox_epsc)
			continue;

		/* EPSC is implicitly started at power on */
		if (es->state == ES_NOT_RUNNING)
			es->state = ES_RUNNING;
	}
}


static int eps_set_state(struct sif_dev *sdev, enum psif_mbox_type eps_num,
			enum sif_eps_state new_state)
{
	unsigned long flags;
	struct sif_eps *es = &sdev->es[eps_num];
	int ret = 0;

	spin_lock_irqsave(&es->lock, flags);
	switch (es->state) {
	case ES_NOT_RUNNING:
	case ES_RUNNING:
		if (new_state == ES_INIT || new_state == ES_NOT_RUNNING)
			break;
		ret = -EINVAL;
		goto init_failed;
	case ES_INIT:
		if (new_state == ES_ACTIVE || new_state == ES_NOT_RUNNING)
			break;
		ret = -ENODEV;
		goto init_failed;
	case ES_ACTIVE:
		if (new_state == ES_RUNNING)
			break;
		ret = -EBUSY;
		goto init_failed;
	}
	es->state = new_state;
	spin_unlock_irqrestore(&es->lock, flags);
	return 0;
init_failed:
	sif_log(sdev, SIF_INIT, "Invalid EPS%s state transition (%d -> %d)",
		eps_name(sdev, eps_num), es->state, new_state);
	spin_unlock_irqrestore(&es->lock, flags);
	return ret;
}


/* Define the atomic op completer device capabilites and device control here as
 * not able to find it in the pci_reg.h. This should be get into the pci_reg.h.
 */
#define ATOMIC_OP_32_BIT_COMPLETER_SUPPORTED (1ULL << 7)
#define ATOMIC_OP_64_BIT_COMPLETER_SUPPORTED (1ULL << 8)
#define CAS_OP_128_BIT_COMPLETER_SUPPORTED (1ULL << 9)
#define ATOMIC_OP_REQUESTER_ENABLE (1ULL << 6)
static enum psif_epsc_csr_atomic_op sif_get_atomic_config(struct sif_dev *sdev,
							enum psif_mbox_type eps_num)
{
	struct pci_dev *parent;
	int pcie_cap, pcie_parent_cap;
	u16 pdevcap2, devctrl2;
	int ret = 0;
	enum psif_epsc_csr_atomic_op atomic_op_flags = PSIF_PCIE_ATOMIC_OP_NONE;
	parent = pci_upstream_bridge(sdev->pdev);

	if (!parent) {
		sif_log(sdev, SIF_INFO,
			"No parent bridge device, cannot determine atomic capabilities!");
		return PSIF_PCIE_ATOMIC_OP_NONE;
	}

	pcie_parent_cap = pci_find_capability(parent, PCI_CAP_ID_EXP);

	if (!pcie_parent_cap) {
		sif_log(sdev, SIF_INFO,
			"PCIe capability in parent device not found, cannot determine atomic capabilities!");
		return PSIF_PCIE_ATOMIC_OP_NONE;
	}

	ret = pci_read_config_word(parent, pcie_parent_cap + PCI_EXP_DEVCAP2, &pdevcap2);
	if (ret) {
		/* set to PSIF_PCIE_ATOMIC_OP_NONE if pci read fails*/
		return atomic_op_flags;
	}
	if (pdevcap2 & (ATOMIC_OP_32_BIT_COMPLETER_SUPPORTED |
			ATOMIC_OP_64_BIT_COMPLETER_SUPPORTED |
			CAS_OP_128_BIT_COMPLETER_SUPPORTED)) {
		pcie_cap = pci_find_capability(sdev->pdev, PCI_CAP_ID_EXP);
		ret = pci_read_config_word(sdev->pdev, pcie_cap + PCI_EXP_DEVCTL2, &devctrl2);
		/* check whether PSIF set the ATOMIC_OP_REQUESTER_ENABLE bit */
		if (!(devctrl2 & ATOMIC_OP_REQUESTER_ENABLE)) {
			ret = pci_write_config_word(sdev->pdev, pcie_cap + PCI_EXP_DEVCTL2,
						    (devctrl2 | ATOMIC_OP_REQUESTER_ENABLE));
			if (ret) {
				/* set to PSIF_PCIE_ATOMIC_OP_NONE if pci write fails*/
				return atomic_op_flags;
			}
			sif_log(sdev, SIF_INFO,
				"Set atomic_op_requester_enable in devctrl2 (%x)\n", devctrl2);
		}

		/* Always enable SQS atomic and IB global atomic if RC supports atomicOp */
		atomic_op_flags = PSIF_PCIE_ATOMIC_OP_BOTH;
		/* EPS-A cores do not need to worry about different IB atomic mode, as they only
		 * need to know whether PSIF has atomic_op_requester_enable set.
		 */
		if (eps_num == sdev->mbox_epsc) {
			/* SQS atomics does not work in these revisions: */
			bool disable_sqs_atomics = PSIF_REVISION(sdev) <= 3 ?
				true : sif_feature(force_sqs_atomic_disable);

			if (disable_sqs_atomics &&
			    sif_feature(force_ib_atomic_hca_mode)) {
				atomic_op_flags = PSIF_PCIE_ATOMIC_OP_NONE;
			} else if (disable_sqs_atomics) {
				atomic_op_flags = PSIF_PCIE_ATOMIC_OP_IB;
			} else if (sif_feature(force_ib_atomic_hca_mode)) {
				atomic_op_flags = PSIF_PCIE_ATOMIC_OP_SQS;
			}
		}
	}
	return atomic_op_flags;
}


/* Helper function to handle the legacy cases of endianness conversion for the
 * initial config request (see #3804)
 */
static struct psif_epsc_csr_config *eps_init_config(struct sif_eps *es, struct psif_epsc_csr_config *lcfg)
{
#ifdef __LITTLE_ENDIAN
	switch (es->ver.seq_set_proto) {
	case 0:
		return lcfg;
	case 1:
	case 2:
		/* Use a config struct in network byte order */
		copy_conv_to_hw(&es->ver.nb_cfg, lcfg, sizeof(*lcfg));
		return &es->ver.nb_cfg;
	}
#else
	struct sif_dev *sdev = es->sdev;

	switch (es->ver.seq_set_proto) {
	case 0:
		/* Legacy mode:
		 * Handling not endian neutral and becomes different depending on
		 * EPSC platform endianness..
		 */
		if (IS_SIBS(sdev)) {
			sif_log(sdev, SIF_INFO, "Using straight through mode");
			return lcfg;
		}
		sif_log(sdev, SIF_INFO, "Converting config to LE (bw comp mode)");
		copy_conv_to_le(&es->ver.nb_cfg, lcfg, sizeof(*lcfg));
		return &es->ver.nb_cfg;
	case 1:
	case 2:
		return lcfg;
	}
#endif
	return NULL;
}


/* Initial setup of communication with the EPSC:
 * The initial phase consists of using the mailbox to communicate
 * about about where the request and response queues of the EPSC
 * should be placed in memory, and a few basic configuration options.
 * This is done via
 *  1) A reset cycle
 *  2) An optional (supported by all new firmware) protocol version negotiation
 *  3) Transfer of the psif_epsc_csr_config request which informs EPSC about where to find the
 *     req and resp queues, which is used for all following communication
 *     for the rest of the driver instance's lifetime.
 */

/* This driver supports all initial mailbox exchange protocol versions up to and
 * including this version:
 */
#define MAILBOX_SUPPORTED_PROTOCOL 2

int sif_eps_init(struct sif_dev *sdev, enum sif_tab_type type)
{
	/* We get called with the response queue type */
	enum psif_mbox_type eps_num = sif_tab2mbox(sdev, type);
	struct sif_table *req_tp = &sdev->ba[type - 1];
	struct sif_table *rsp_tp = &sdev->ba[type];
	struct psif_epsc_csr_config lconfig;
	struct psif_epsc_csr_config *config;
	struct sif_eps_cqe lcqe;
	struct psif_epsc_csr_rsp lrsp;
	union sif_mailbox set, get;
	struct psif_epsc_csr_rsp *cqe;
	struct sif_eps *es = &sdev->es[eps_num];
	int ret = 0;
	u16 seq_num = 0; /* Init runs in separate seq.numbers */
	int i;
	ulong timeout = es->keepalive_interval = sdev->min_resp_ticks * 2;
	ulong timeout_time = jiffies + timeout;
	u64 tries = 0;
	size_t bsz;
	size_t config_cycle_count = sizeof(struct psif_epsc_csr_config)/sizeof(u32);
	bool restarted_reset = false;
	ulong cpu_eqs;

	/* Max mailbox exchange protocol version supported by this driver */
	u16 mailbox_seq_version_to_use = 2;

	if (eps_num == sdev->mbox_epsc)
		eps_struct_init(sdev);

	es->last_seq = 0;

	ret = eps_set_state(sdev, eps_num, ES_INIT);
	if (ret)
		return ret;

	es->last_seq = 0;
	atomic_set(&es->cur_reqs, 1); /* The initial request is not "posted" */
	es->max_reqs = 0;
	es->mask = req_tp->entry_cnt - 1;
	es->lowpri_lim = req_tp->entry_cnt - min_t(int, req_tp->entry_cnt/2, 2);

	if (rsp_tp->entry_cnt != req_tp->entry_cnt) {
		sif_log(sdev, SIF_INFO,
			"Illegal config - EPS queues must have the same length");
		return -EINVAL;
	}

	bsz = sizeof(struct sif_eps_cqe *) * rsp_tp->entry_cnt;
	es->cqe = kzalloc(bsz, GFP_KERNEL);
	if (!es->cqe) {
		sif_log(sdev, SIF_INFO,
			"Failed to allocate %ld bytes for EPS%s completions", bsz,
			eps_suffix(sdev, eps_num));
		return -ENOMEM;
	}

	/* Use extra allocated space at the end of the completion array for the data area
	 * TBD: This code is not safe if any of the data elements cross a 2M page boundary
	 * - should move it out as a separate allocation.
	 */
	es->data = sif_mem_kaddr(rsp_tp->mem, rsp_tp->table_sz);
	es->data_dma_hdl = sif_mem_dma(rsp_tp->mem, rsp_tp->table_sz);
	es->data->log.size = sif_eps_log_size;

	/* Initialize the first response status to != 0 */
	cqe = get_eps_csr_rsp(sdev, eps_num, 0);
	set_psif_epsc_csr_rsp__seq_num(cqe, (u64)-1);

	sif_log(sdev, SIF_INIT, "Data area for EPSC queries: %p (dma %pad) len %ld",
		es->data, &es->data_dma_hdl, sizeof(struct sif_epsc_data));
	memset(&lconfig, 0, sizeof(lconfig));
	config = &lconfig;
	memset(&lrsp, 0x6a, sizeof(struct psif_epsc_csr_rsp));
	lcqe.rsp = &lrsp;
	lcqe.need_complete = false;

	if (!sdev->is_vf) {
		/* PF only: If sif_vf_max is >= 0, enable that number of VFs.
		 * If vf_max == -1: enable Exadata mode as follows:
		 *    if Xen PV domain automatically enable all VFs,
		 *    otherwise enable no VFs - only physical function.
		 * If vf_max == -2: Default to NVRAM settings from firmware
		 *    = bw comp mode.
		 */
		if (sif_vf_max >= 0)
			lconfig.num_ufs = min_t(int, pci_sriov_get_totalvfs(sdev->pdev),sif_vf_max) + 1;
		else if (sif_vf_max == -2)
			lconfig.num_ufs = 0; /* Use firmware defaults */
		else if (xen_pv_domain())
			lconfig.num_ufs = pci_sriov_get_totalvfs(sdev->pdev) + 1;
		else
			lconfig.num_ufs = 1;
	}

	lconfig.hwapi_major_ver = PSIF_MAJOR_VERSION;
	lconfig.hwapi_minor_ver = PSIF_MINOR_VERSION;
	lconfig.epsapi_major_ver = EPSC_MAJOR_VERSION;
	lconfig.epsapi_minor_ver = EPSC_MINOR_VERSION;

	lconfig.request = req_tp->sif_base;
	lconfig.response = rsp_tp->sif_base;
	lconfig.extent_req = req_tp->ext_sz;
	lconfig.extent_rsp = rsp_tp->ext_sz;
	lconfig.entries = rsp_tp->entry_cnt;
	if (!sdev->is_vf)
		lconfig.atomic_support = sif_get_atomic_config(sdev, eps_num);
	else
		lconfig.atomic_support = PSIF_PCIE_ATOMIC_OP_NONE;
	/* Ask the EPSC to reset the function we are accessing - starting from a clean state */
	lconfig.clean_state = 1;

#ifndef __LITTLE_ENDIAN
	/* Tell the EPSC that host is big endian */
	sif_log(sdev, SIF_INFO, "Configure for big endian host");
	lconfig.big_endian = 1;
#endif
	if (!sdev->is_vf && sif_feature(vlink_connect)) {
		sif_log(sdev, SIF_INIT, "Associate all vlink state info with state of external port");
		lconfig.vlink_connect = 1;
	}

	lconfig.sparc_pages = (sdev->mi.page_size == 0x2000) ? 1 : 0;
	if (rsp_tp->mem->mem_type != SIFMT_BYPASS) {
		sif_log(sdev, SIF_INFO,
			"Failed EPSC mappings: GVA2GPA mode not supported yet, consider reducing epsc_size");
		ret = -ENOMEM;
		goto err_map_ctx;
	}

	/* Allocate bypass mmu context (for responses) with wr_access set */
	ret = sif_map_ctx(sdev, &rsp_tp->mmu_ctx, rsp_tp->mem, rsp_tp->sif_base,
			rsp_tp->table_sz, true);
	if (ret) {
		sif_log(sdev, SIF_INFO, "Failed to set mmu context for epsc_rsp");
		goto err_map_ctx;
	}

	/* Pass the populated context on to the EPS */
	lconfig.mmu_cntx = rsp_tp->mmu_ctx.mctx;

eps_reset:
	sif_log(sdev, SIF_INIT, "Resetting EPS%s..", eps_name(sdev, eps_num));

	/* 1) EPSC reset cycles:
	 * Special write cycle to reset EPS communication
	 */
	set.raw = MAILBOX_RESTART;
	do {
		tries++;
		eps_mailbox_write(sdev, eps_num, set.raw);
		get.raw = eps_mailbox_read(sdev, eps_num);
	} while (get.raw != 0 && time_is_after_jiffies(timeout_time));

	if (get.raw != MAILBOX_RESTART) {
		sif_log(sdev, SIF_INFO,
			"Failed to reset EPS%s after %lld tries (%ld ticks) - last read 0x%llx",
			eps_name(sdev, eps_num), tries, timeout, get.raw);
		ret = -ENODEV;
		goto epsc_failed;
	}

	/* 2) Meta protocol version negotiation:
	 *    This step is basically used to determine how the initial config request
	 *    should look:
	 */
	timeout_time = jiffies + timeout;
	tries = 0;

	if (restarted_reset && mailbox_seq_version_to_use > 1) {
		/* 2nd attempt - very old firmware - skip the protocol probing algo.. */
		goto proto_probing_done;
	}
	set.x.head = set.x.tail = MAILBOX_SEQ_SET_PROTOCOL;

	if (!restarted_reset) {
		/* Handle bug #4101:
		 * Some old firmware versions will respond with the same mailbox protocol version
		 * as the one requested by the driver, no matter what. We must check that we don't have
		 * this version by trying version 0xffff which does not exist. If we get v.0xffff back
		 * we know we have this old firmware and can retry with v.0.
		 * v.2 and later will respond with the negotiated version.
		 */
		set.x.data = 0xffff;
	} else {
		/* The meta protocol number we request - if this fails, we are at the legacy firmware
		 * version which does not support this stage, and where config data is
		 * expected in LE order (See #3804)
		 */
		set.x.data = mailbox_seq_version_to_use;
	}

	do {
		tries++;
		eps_mailbox_write(sdev, eps_num, set.raw);
		get.raw = eps_mailbox_read(sdev, eps_num);
	} while (get.x.head != MAILBOX_SEQ_SET_PROTOCOL && get.raw != MAILBOX_IN_ERROR
		&& time_is_after_jiffies(timeout_time));

	if (time_is_before_eq_jiffies(timeout_time)) {
		sif_log(sdev, SIF_INFO,
		"Failed to get seq.protocol info from EPS%s after %lld tries (%ld ticks) - last read 0x%llx",
			eps_name(sdev, eps_num), tries, timeout, get.raw);
		if (!restarted_reset) {
			restarted_reset = true;
			sif_log(sdev, SIF_INFO,
			"- assuming very old firmware without protocol version probing: restarting..");
			goto eps_reset;
		} else {
			ret = -ESRCH;
			goto epsc_failed;
		}
	}

	if (!restarted_reset && get.x.data == 0xffff) {
		/* We have identified bug #4101 in firmware:
		 * Firmware that responds wrongly on the mailbox exchange protocol,
		 * retry with version 0:
		 */
		sif_log(sdev, SIF_INFO,
		"- found old firmware which responds wrongly to protocol version probing: restarting..");
		restarted_reset = true;
		mailbox_seq_version_to_use = 0;
		goto eps_reset;
	}

	if (get.x.head != MAILBOX_SEQ_SET_PROTOCOL) {
		sif_log(sdev, SIF_INFO, "Legacy firmware found - no SEQ_SET_PROTOCOL supported");
		es->ver.seq_set_proto = 0;
	} else if (get.x.data > MAILBOX_SUPPORTED_PROTOCOL) {
		mailbox_seq_version_to_use = MAILBOX_SUPPORTED_PROTOCOL;
		restarted_reset = true;
		goto eps_reset;
	} else
		es->ver.seq_set_proto = get.x.data;

proto_probing_done:
	sif_log(sdev, SIF_INFO_V, "In contact with EPS%s with initial mailbox negotiation protocol v.%d",
		eps_name(sdev, eps_num), es->ver.seq_set_proto);
	if (!es->ver.seq_set_proto)
		sif_log(sdev, SIF_INFO,
		"***** Warning: firmware update necessary, support for this version discontinued! *****");

	/* Set up the config struct correctly for transfer */
	config = eps_init_config(es, &lconfig);
	if (!config)
		goto epsc_failed;

	/* At this point it is safe to enable bus master for PSIF
	 * Firmware guarantees that we do not get here until all state
	 * from any previous runs have been cleared out
	 */
	pci_set_master(sdev->pdev);

	/* 3) Transfer the psif_epsc_csr_config request via the mailbox.
	 *    The result is then expected as response in the first response queue
	 *    element in the area pointed to by the request transferred here:
	 */
	tries = 0;
	sif_log(sdev, SIF_INIT,
		"Setting up EPS%s: req at %llx, rsp at %llx, entries %d cycles %ld",
		eps_name(sdev, eps_num), lconfig.request, lconfig.response,
		lconfig.entries, sizeof(lconfig)/sizeof(u32));


	seq_num = 0;
	for (i = 0; i < config_cycle_count; i++) {
		set.x.head = set.x.tail = ++seq_num;
		set.x.data = ((u32 *)(config))[i];
		tries = 0;
		timeout_time = jiffies + timeout;
		do {
			tries++;
			eps_mailbox_write_data(sdev, eps_num, set.raw);
			get.raw = eps_mailbox_read_data(sdev, eps_num);
		} while (((get.x.head != seq_num) || (get.x.tail != seq_num)) &&
			get.raw != MAILBOX_IN_ERROR &&
			time_is_after_jiffies(timeout_time));
		if (get.raw == MAILBOX_IN_ERROR && time_is_after_jiffies(timeout_time)) {
			sif_log(sdev, SIF_INFO,
				"Writing config data failed before timeout - retrying...");
			goto eps_reset;
		} else if (seq_num > 0xa && time_is_before_eq_jiffies(timeout_time)) {
			config_cycle_count = i;
			sif_log(sdev, SIF_INFO,
				"Unable to get part %d (%lld tries) - old firmware? - retrying...",
				i, tries);
			goto eps_reset;
		} else if (set.x.data != get.x.data || time_is_before_eq_jiffies(timeout_time)) {
			sif_log(sdev, SIF_INFO,
			"Failed during init sequence for EPS%s, part %d (%lld tries) set %llx get %llx, expected seq %x %s",
				eps_name(sdev, eps_num), i, tries, set.raw, get.raw, seq_num,
				(time_is_before_jiffies(timeout_time) ? "[timeout]" : ""));
			ret = -EIO;
			goto epsc_failed;
		}
	}

	sdev->es[eps_num].timeout  = timeout_time;

	/* Set storage for this initial request manually before polling */
	es->cqe[0] = &lcqe;

	/* At this point we expect to have a valid response in the first position: */
	ret = sif_eps_poll_cqe(sdev, eps_num, 0, &lcqe);
	if (ret) {
		goto epsc_failed;
	}
	/* We are up and running with the EPSC, figure out what
	 * this firmware offers.
	 */

	/* in protocol version 2 bits 16-31 of the response sequence number contain
	 * an ID the driver has to provide in requests
     */
	es->mbox_id = (lrsp.seq_num >> 16) & 0xffff;

	memcpy(&es->ver, &lrsp.data, sizeof(lrsp.data));

	/* The addr field now contains the number of available event queues from this EPS */
	es->eqs.max_cnt = lrsp.addr & 0xffff;
	/* minimum number of async EPSC EQ entries per port is in the higher 16 bits
	 * and is an offset to 16
	 */
	es->eqs.min_sw_entry_cnt = ((lrsp.addr >> 16) & 0xffff) + 16;

	/* PSIF has flagged that it is running in degraded mode */
	if (lrsp.info & PSIF_INFO_FLAG_DEGRADED) {
		sif_log(sdev, SIF_INFO, "PSIF device is degraded");
		sdev->degraded = true;
	}

	if (sif_cq_eq_max < 1)
		sif_cq_eq_max = 1; /* Adjust - need at least 1 completion event queue */

	/* Limit the number of eqs we allocate resources for to the
	 * cq_eq_max module parameter setting and the number of CPUs in the system:
	 */
	cpu_eqs = min_t(ulong, sif_cq_eq_max, num_present_cpus());
	es->eqs.cnt = min_t(ulong, es->eqs.max_cnt, cpu_eqs + 2);

	ret = sif_eps_api_version_ok(sdev, eps_num);
	if (ret)
		goto epsc_failed;

	/* APIs are ok - now request, report and possibly
	 * validate epsc firmware (build) version info
	 */
	ret = sif_eps_firmware_version_ok(sdev, eps_num);
	if (ret)
		goto epsc_failed;

	sif_cb_init(sdev);

#if defined(CONFIG_ARCH_DMA_ADDR_T_64BIT) && defined(__sparc__)
	/* The kernel is currently using iommu bypass mode in the sparc iommu, and
	 * the PSIF MMU requires a fixed configuration of the upper 12 bits of the
	 * DMA addresses: we need bit 63 set in all GVA2GPA accesses.
	 */
	{
		u16 upper_12 = sif_mem_dma(rsp_tp->mem, 0) >> PSIF_TABLE_PTR_SHIFT;

		ret = epsc_set_mmu_upper(sdev, upper_12);
		if (ret)
			goto epsc_failed;
	}
#endif

	/* Interrupt setup */
	if (eps_num == sdev->mbox_epsc) {
		ret = sif_enable_msix(sdev);
		if (ret)
			goto epsc_failed;
	}

	/* Set up the event queues as a special case here */
	ret = sif_eq_init(sdev, es, &lrsp);
	if (ret)
		goto epsc_eq_init_failed;

	if (sif_eps_log_size)
		ret = sif_eps_log_ctrl(sdev, eps_num, EPSC_LOG_MODE_HOST, sif_eps_log_level);
	if (ret)
		goto epsc_log_ctrl_failed;

	eps_set_state(sdev, eps_num, ES_ACTIVE);
	return ret;


epsc_log_ctrl_failed:
	sif_eq_deinit(sdev, es);
epsc_eq_init_failed:
	if (eps_num == sdev->mbox_epsc)
		sif_disable_msix(sdev);
epsc_failed:
	sif_unmap_ctx(sdev, &rsp_tp->mmu_ctx);
err_map_ctx:
	kfree(es->cqe);
	return ret;
}


int sif_eps_deinit(struct sif_dev *sdev, enum sif_tab_type rsp_type)
{
	enum psif_mbox_type eps_num = sif_tab2mbox(sdev, rsp_type);
	struct sif_eps *es = &sdev->es[eps_num];
	struct sif_table *rsp_tp = &sdev->ba[rsp_type];
	struct psif_epsc_csr_req req;
	struct psif_epsc_csr_rsp rsp;

	if (es->data->log.size)
		sif_eps_log_ctrl(sdev, eps_num, EPSC_LOG_MODE_BUFFER, sif_eps_log_level);
	sif_eq_deinit(sdev, es);

	if (eps_num == sdev->mbox_epsc)
		sif_disable_msix(sdev);

	/* Note that beyond this point the EQs no longer exists so we need to use poll
	 * mode for the remaining epsc communication.
	 */

	/* Flush TLB for old FW version. On current FW versions this is done
	 * automatically by FW.
	 * During takedown TLB invalidate is not generally possible since it requires
	 * working privileged QPs. Instead flush the whole TLB in one go.
	 */
	if (!eps_fw_version_ge(es, 0, 54) && !sdev->is_vf)
		sif_flush_tlb(sdev);

	/* Tell the EPSC that we have terminated cleanly: */
	memset(&req, 0, sizeof(req));
	req.opcode = EPSC_TEARDOWN;
	sif_epsc_wr_poll(sdev, &req, &rsp);

	sif_unmap_ctx(sdev, &rsp_tp->mmu_ctx);
	kfree(es->cqe);

	return 0;
}


#define epsc_seq(x) (x & 0x7fff)

/* process any queued responses from the EPS
 * Return the number processed, or -errno upon errors:
 * assumes es->lock is held
 */
static inline int __eps_process_cqe(struct sif_dev *sdev, enum psif_mbox_type eps_num)
{
	struct sif_eps *es = &sdev->es[eps_num];
	int ret = 0;
	int rsp_cnt = 0;
	u64 seq_num_expected, seq_num;
	u32 idx;
	u16 ql;
	struct psif_epsc_csr_rsp *cqe;
	struct sif_eps_cqe *lcqe;

	for (;;) {
		seq_num_expected = es->first_seq | CSR_ONLINE_MASK;
		idx = es->first_seq & es->mask;
		cqe = get_eps_csr_rsp(sdev, eps_num, idx);
		seq_num = be64_to_cpu((volatile u64)(cqe->seq_num)) & 0xffff;

		if (seq_num != seq_num_expected)
			break;
		lcqe = es->cqe[idx];
		if (lcqe) {
			rmb();
			sif_log(sdev, SIF_EPS, "copying to caller rsp at %p", lcqe->rsp);
			copy_conv_to_sw(lcqe->rsp, cqe, sizeof(struct psif_epsc_csr_rsp));
			if (lcqe->rsp->status != EPSC_SUCCESS && sif_feature(pcie_trigger))
				force_pcie_link_retrain(sdev);
			rsp_cnt++;
			__epsc_complete(sdev, eps_num, idx);
			es->cqe[idx] = NULL;
		}
		ql = atomic_dec_return(&es->cur_reqs);
		es->first_seq = (es->first_seq + 1) & ~CSR_ONLINE_MASK;
		ret++;
	}
	if (ret < 0) {
		sif_log(sdev, SIF_INFO, "failed with status %d", ret);
		return ret;
	}

	if (ret > 0) {
		sif_log(sdev, SIF_EPS,
			"processed %d (%d with resp) requests - first_seq 0x%x, oustanding %d",
			ret, rsp_cnt, es->first_seq, atomic_read(&es->cur_reqs));
		mb();
	}
	__sif_eps_send_keep_alive(sdev, eps_num, false);

	return ret;
}


static int eps_process_cqe(struct sif_dev *sdev, enum psif_mbox_type eps_num)
{
	int ret;
	unsigned long flags;
	struct sif_eps *es = &sdev->es[eps_num];

	spin_lock_irqsave(&es->lock, flags);
	ret = __eps_process_cqe(sdev, eps_num);
	spin_unlock_irqrestore(&es->lock, flags);
	return ret;
}


static void eps_reset_cmpl(struct sif_dev *sdev, u16 seq_num, enum psif_mbox_type eps_num)
{
	struct sif_eps *es = &sdev->es[eps_num];
	struct sif_table *t = &sdev->ba[sif_mbox2rsp_tab(sdev, eps_num)];
	u16 idx = seq_num % t->entry_cnt;
	unsigned long flags;

	/* Protect against nil'ing it while anyone accessing cqe */
	spin_lock_irqsave(&es->lock, flags);
	es->cqe[idx] = NULL;
	spin_unlock_irqrestore(&es->lock, flags);
}


/* Asynchronous post of an EPS work request.
 * returns nonzero if there is no more room
 * in completion queue for a new entry.
 * If seq_num is nonzero, the caller is expected to handle the
 * completion using sif_epsc_poll_cqe, otherwise the entry is marked as
 * "response ignored by the caller".
 * If wait is set, post with flag EPSC_FL_NOTIFY to receive an interrupt from the eps:
 *
 */
static int __sif_post_eps_wr(struct sif_dev *sdev, enum psif_mbox_type eps_num,
		struct psif_epsc_csr_req *lreq, u16 *seq_num,
		struct sif_eps_cqe *lcqe, bool wait)
{
	struct psif_epsc_csr_req *req;
	struct sif_table *t = &sdev->ba[sif_mbox2rsp_tab(sdev, eps_num)];
	struct sif_eps *es = &sdev->es[eps_num];
	u32 idx;
	union sif_mailbox lmbx;
	u16 cur_reqs;
	u16 limit = in_interrupt() ? t->entry_cnt : es->lowpri_lim;
	unsigned long timeout = sdev->min_resp_ticks * 8;
	int ret = 0;
	bool waiting = false;

	if (unlikely(lreq->opcode != EPSC_KEEP_ALIVE))
		es->timeout = jiffies + timeout;
restart:

	if (atomic_read(&es->cur_reqs)) {
		/* Make sure emptying the queue takes preference over filling it up: */
		ret = __eps_process_cqe(sdev, eps_num);

		if (ret > 0)
			ret = 0; /* Got some rsps */
		else if (ret < 0)
			return ret;
	}

	/* Allocate a new seq.number */
	cur_reqs = atomic_inc_return(&es->cur_reqs);
	if (cur_reqs > limit) {
		u16 tried_seq_num = (es->last_seq + 1) & ~CSR_ONLINE_MASK;

		atomic_dec(&es->cur_reqs);
		if (!waiting)
			atomic_inc(&es->waiters);
		if (es->first_seq != es->last_full_seq) {
			sif_log(sdev, SIF_INFO_V,
			"req.queue full: seq %d, first %d, cur_reqs %d, %slimit %d, epsc_req_size is %d",
				tried_seq_num, es->first_seq, cur_reqs,
				(in_interrupt() ? "" : "(low pri) "), limit, t->entry_cnt);
			es->last_full_seq = es->first_seq;
		}


		if (in_interrupt()) {
			/* Only the EVENT_INDEX updates are sent from interrupt level and
			 * they are high pri, and should have reserved space:
			 */
			sif_log(sdev, SIF_INFO,
			"Warning: Interrupt level EPSC req. while over limit (%d/%d), tried seq %d!",
				cur_reqs, limit, tried_seq_num);
			sif_logs(SIF_INFO, write_struct_psif_epsc_csr_req(NULL, 0, lreq));
			return -EFAULT;
		}

		if (time_is_after_jiffies(es->timeout))
			goto restart;
		else {
			sif_log(sdev, SIF_INFO,
				"Timeout waiting for previous response (seq %d) to complete",
				es->first_seq);
			return -EAGAIN;
		}
	}
	if (waiting)
		atomic_dec(&es->waiters);

	if (cur_reqs > es->max_reqs)
		es->max_reqs = cur_reqs;

	es->last_seq = (es->last_seq + 1) & ~CSR_ONLINE_MASK;
	idx = es->last_seq & es->mask;
	req = get_eps_csr_req(sdev, eps_num, idx);

	lreq->seq_num = es->last_seq | CSR_ONLINE_MASK;
	if (wait) {
		/* Request interrupt upon completion */
		lreq->flags |= EPSC_FL_NOTIFY;
	}

	/* Tell where to copy the completion upon arrival: */
	es->cqe[idx] = lcqe;
	if (lcqe) {
		sif_log(sdev, SIF_EPS, "set cqe[%d] = %p", idx, lcqe);

		/* set the software host order copy seq_num to something useful for comparison
		 * in the poll routines:
		 */
		lcqe->rsp->seq_num = get_psif_epsc_csr_req__seq_num(req);
		lcqe->need_complete = wait;
	}
	wmb();
	sif_log(sdev, SIF_EPS, "opcode %s seq.%d to addr %p %s",
		string_enum_psif_epsc_csr_opcode(lreq->opcode),
		es->last_seq, req, (wait ? "wait" : ""));

	/* Update hw accessible req */
	copy_conv_to_hw(req, lreq, sizeof(struct psif_epsc_csr_req));

	/* Doorbell - notify hw */
	lmbx.x.head = CSR_ONLINE_MASK | lreq->seq_num;
	if (es->ver.seq_set_proto == 2) {
		lmbx.x.tail = es->mbox_id;
		lmbx.x.data = lreq->opcode;
	} else {
		lmbx.x.tail = lmbx.x.head;
		lmbx.x.data = 0x5a5a5a5a; /* Not used - just an easy recognizable pattern */
	}
	eps_mailbox_write(sdev, eps_num, lmbx.raw);

	if (seq_num)
		*seq_num = es->last_seq;
	return ret;
}

/* Asynchronous post of an EPS work request.
 * returns nonzero if there is no more room
 * in completion queue for a new entry.
 * If seq_num is nonzero, the caller is expected to handle the
 * completion using sif_epsc_poll_cqe, otherwise the entry is marked as
 * "response ignored by the caller".
 * If wait is set, post with flag EPSC_FL_NOTIFY to receive an interrupt from the eps:
 *
 */
int sif_post_eps_wr(struct sif_dev *sdev, enum psif_mbox_type eps_num,
		struct psif_epsc_csr_req *lreq, u16 *seq_num,
		struct sif_eps_cqe *lcqe, bool wait)
{
	struct sif_eps *es = &sdev->es[eps_num];
	unsigned long flags;
	int ret;

	spin_lock_irqsave(&es->lock, flags);
	ret = __sif_post_eps_wr(sdev, eps_num, lreq, seq_num, lcqe, wait);
	spin_unlock_irqrestore(&es->lock, flags);
	return ret;
}

int sif_post_epsc_wr(struct sif_dev *sdev, struct psif_epsc_csr_req *lreq,
		u16 *seq_num, struct sif_eps_cqe *lcqe, bool wait)
{
	return sif_post_eps_wr(sdev, sdev->mbox_epsc, lreq, seq_num, lcqe, wait);
}


/* Poll waiting for response on request seq_num.
 * Polls for different completions may be executing this code in parallel:
 */
int sif_eps_poll_cqe(struct sif_dev *sdev, enum psif_mbox_type eps_num,
		u16 seq_num, struct sif_eps_cqe *lcqe)
{
	struct sif_eps *es = &sdev->es[eps_num];
	int ret = 0;
	ulong timeout = sdev->min_resp_ticks * 8;
	int npolled = 0;

	while (seq_num != get_eps_mailbox_seq_num(lcqe->rsp)) {
		ret = eps_process_cqe(sdev, eps_num);
		if (ret < 0)
			goto out;

		if (time_is_before_eq_jiffies(es->timeout)) {
			if (sif_feature(pcie_trigger))
				force_pcie_link_retrain(sdev);

			sif_log(sdev, SIF_INFO,
			"No response for req %#x from EPS (rsp->seq_num 0x%x) in %ld ms - #reqs outstanding %d",
				seq_num, get_eps_mailbox_seq_num(lcqe->rsp), timeout,
				atomic_read(&es->cur_reqs));
			ret = -ETIMEDOUT;
			goto out;
		}
		cpu_relax();
		npolled += ret;
	}

	ret = eps_status_to_err(lcqe->rsp->status);

	/* We got something, reset the timeout for all waiters */
	es->timeout = jiffies + timeout;
out:
	if (ret < 0) {
		int log_level = lcqe->rsp->opcode == EPSC_MODIFY_QP ? SIF_QPE : SIF_INFO;

		if (sif_feature(pcie_trigger))
			force_pcie_link_retrain(sdev);
		if (ret != -ETIMEDOUT)
			sif_log(sdev, log_level,
				"Error response (%s) for req 0x%x from EPS (errno %d)",
				string_enum_psif_epsc_csr_status(lcqe->rsp->status),
				get_eps_mailbox_seq_num(lcqe->rsp), ret);
		eps_reset_cmpl(sdev, seq_num, eps_num);
	} else
		sif_log(sdev, SIF_EPS, "seq 0x%x polled", seq_num);
	return ret;
}


int sif_epsc_poll_cqe(struct sif_dev *sdev, u16 seq_num, struct sif_eps_cqe *lcqe)
{
	return sif_eps_poll_cqe(sdev, sdev->mbox_epsc, seq_num, lcqe);
}


/* Wait up to @timeout ticks for an earlier posted event
 * with ID @seq_num to complete
 */
static int eps_waitfor_timeout(struct sif_dev *sdev, enum psif_mbox_type eps_num,
			u16 seq_num, unsigned long timeout,
			struct sif_eps_cqe *lcqe)
{
	struct completion *cmpl = &lcqe->cmpl;
	unsigned long rem_time, wait_time;
	volatile struct psif_epsc_csr_rsp *rsp = lcqe->rsp;
	int ret;
	unsigned int attempts = 4;


	rem_time = wait_time = timeout/attempts;
	for (;;) {
		ret = eps_process_cqe(sdev, eps_num);
		if (ret < 0)
			goto out;

		if (get_eps_mailbox_seq_num(rsp) != seq_num) {
			rem_time = wait_for_completion_interruptible_timeout(cmpl, rem_time);
			if (!rem_time) {
				rem_time = wait_time;
				if (!--attempts) {
					sif_log(sdev, SIF_INFO, "req %u timed out after %ld ms",
						seq_num, timeout);
					ret = -ETIMEDOUT;
					goto out;
				}
			}
			continue;
		}
		break;
	}

	ret = eps_status_to_err(rsp->status);
out:
	if (ret < 0) {
		if (ret != -ETIMEDOUT) {
			sif_log(sdev, SIF_INFO,
				"Error response (%s) for req 0x%x from EPS",
				string_enum_psif_epsc_csr_status(rsp->status),
				get_eps_mailbox_seq_num(rsp));
		}
		eps_reset_cmpl(sdev, seq_num, eps_num);
	}
	return ret;
}

/* Wait for an earlier posted request with ID @seq_num to complete
 */
static int eps_waitfor(struct sif_dev *sdev, enum psif_mbox_type eps_num,
		u16 seq_num, struct sif_eps_cqe *cqe)
{
	ulong timeout = sdev->min_resp_ticks * (1 + atomic_read(&sdev->es[eps_num].cur_reqs)) * 8;

	return eps_waitfor_timeout(sdev, eps_num, seq_num, timeout, cqe);
}

int sif_epsc_waitfor(struct sif_dev *sdev, u16 seq_num,
		struct sif_eps_cqe *cqe)
{
	return eps_waitfor(sdev, sdev->mbox_epsc, seq_num, cqe);
}

/* Synchronous post of an EPS work request.
 * Will wait until request completes and return the completion
 * notification. Uses EPSC interrupts for wakeup.
 */

int sif_eps_wr(struct sif_dev *sdev, enum psif_mbox_type eps_num,
	struct  psif_epsc_csr_req *req, struct psif_epsc_csr_rsp *cqe)
{
	u16 seq_num;
	int ret;
	struct sif_eps_cqe lcqe;

	lcqe.rsp = cqe;
	init_completion(&lcqe.cmpl);
restart:
	ret = sif_post_eps_wr(sdev, eps_num, req, &seq_num, &lcqe, true);
	if (ret)
		return ret;

	ret = eps_waitfor(sdev, eps_num, seq_num, &lcqe);
	if (ret == -EAGAIN) {
		sif_log(sdev, SIF_EPS, "EPS%s requests retry for req# %d",
			eps_name(sdev, eps_num), seq_num);
		goto restart;
	}
	sif_log(sdev, SIF_EPS, "Received EPS%s completion for req# %d",
		eps_name(sdev, eps_num), seq_num);
	return ret;
}


int sif_epsc_wr(struct sif_dev *sdev, struct psif_epsc_csr_req *req,
		struct psif_epsc_csr_rsp *cqe)
{
	return sif_eps_wr(sdev, sdev->mbox_epsc, req, cqe);
}


/* Same as sif_eps_wr but poll for completion */
int sif_eps_wr_poll(struct sif_dev *sdev, enum psif_mbox_type eps_num,
		struct psif_epsc_csr_req *req, struct psif_epsc_csr_rsp *cqe)
{
	u16 seq_num;
	int ret;
	struct sif_eps_cqe lcqe;

	lcqe.rsp = cqe;
restart:
	ret = sif_post_eps_wr(sdev, eps_num, req, &seq_num, &lcqe, false);
	if (ret)
		return ret;

	ret = sif_eps_poll_cqe(sdev, eps_num, seq_num, &lcqe);
	if (ret == -EAGAIN) {
		sif_log(sdev, SIF_EPS, "EPS%s requests retry for req# %d",
			eps_name(sdev, eps_num), seq_num);
		goto restart;
	}
	if (!ret)
		sif_log(sdev, SIF_EPS, "Received EPS%s completion for req# %d",
			eps_name(sdev, eps_num), seq_num);
	return ret;
}

int sif_epsc_wr_poll(struct sif_dev *sdev, struct psif_epsc_csr_req *req,
		struct psif_epsc_csr_rsp *rsp)
{
	return sif_eps_wr_poll(sdev, sdev->mbox_epsc, req, rsp);
}



/* EPS-A support */
int sif_activate_epsa(struct sif_dev *sdev, enum psif_mbox_type eps_num)
{
	enum sif_tab_type type = epsa0_csr_req + (eps_num * 2);

	/* First initiate communication protocol with the EPS# */
	int ret = sif_table_init(sdev, type);

	if (ret)
		return ret;
	ret = sif_table_init(sdev, type + 1);
	if (ret)
		return ret;

	/* The rest of the init operations does not involve any memory setup,
	 * it just communicates the table base pointers setup up with the EPSC
	 * on to the EPSA.
	 */

	/* Only key (DMA validation) is needed so far */
	ret = sif_table_update(sdev, eps_num, key);
	return ret;
}

inline bool sif_eps_keep_alive_timeout(struct sif_eps *es)
{
	return time_is_before_jiffies(es->last_req_posted + es->keepalive_interval);
}


static int __sif_eps_send_keep_alive(struct sif_dev *sdev, enum psif_mbox_type eps_num,
			bool force)
{
	struct psif_epsc_csr_req req;
	struct sif_eps *es = &sdev->es[eps_num];
	int ret = 0;

	if (sif_eps_keep_alive_timeout(es) || force) {
		sif_log(sdev, SIF_INTR, "Sending keep-alive (force=%i)", force);
		if (force)
			atomic64_inc(&sdev->wa_stats.wa4059[SND_INTR_KEEP_ALIVE_WA4059_CNT]);
		else
			atomic64_inc(&sdev->wa_stats.wa4059[SND_THREAD_KEEP_ALIVE_WA4059_CNT]);

		/* prevent infinite loop with __sif_post_eps_wr */
		es->last_req_posted = jiffies;

		memset(&req, 0, sizeof(req));
		req.opcode = EPSC_KEEP_ALIVE;
		ret = __sif_post_eps_wr(sdev, eps_num, &req, NULL, NULL, false);
	}
	return ret;
}

int sif_eps_send_keep_alive(struct sif_dev *sdev, enum psif_mbox_type eps_num,
			int force)
{
	struct sif_eps *es = &sdev->es[eps_num];
	unsigned long flags;
	int ret;

	spin_lock_irqsave(&es->lock, flags);
	ret = __sif_eps_send_keep_alive(sdev, eps_num, force);
	spin_unlock_irqrestore(&es->lock, flags);
	return ret;
}

/**** Low level mailbox handling ****/

u64 eps_mailbox_read(struct sif_dev *sdev, u8 epsno)
{
	return be64_to_cpu(__raw_readq(&sdev->eps->eps[epsno].out));
}

void eps_mailbox_write(struct sif_dev *sdev, u8 epsno, u64 value)
{
	sdev->es[epsno].last_req_posted = jiffies;
	wmb();
	__raw_writeq(cpu_to_be64(value), &sdev->eps->eps[epsno].in);
	wmb();
}

u64 eps_mailbox_read_data(struct sif_dev *sdev, u8 epsno)
{
	union sif_mailbox set;

	set.raw = eps_mailbox_read(sdev, epsno);
	if (sdev->es[epsno].ver.seq_set_proto <= 1)
		set.x.data = le32_to_cpu(set.x.data);
	else
		set.x.data = be32_to_cpu(set.x.data);
	return set.raw;
}

void eps_mailbox_write_data(struct sif_dev *sdev, u8 epsno, u64 value)
{
	union sif_mailbox set;

	set.raw = value;
	if (sdev->es[epsno].ver.seq_set_proto <= 1)
		set.x.data = cpu_to_le32(set.x.data);
	else
		set.x.data = cpu_to_be32(set.x.data);
	value = set.raw;
	eps_mailbox_write(sdev, epsno, value);
}


/**** High level synchronous CSR operations */

/* Read a 64 bit CSR register */
static u64 read_csr(struct sif_dev *sdev, u32 addr, bool local)
{
	struct psif_epsc_csr_rsp resp;
	struct psif_epsc_csr_req req;
	int ret;

	memset(&req, 0, sizeof(req));
	req.opcode = local ? EPSC_GET_SINGLE : EPSC_GET_ONE_CSR;
	req.addr = addr;

	ret = sif_epsc_wr_poll(sdev, &req, &resp);
	if (ret)
		return -1;

	sif_log(sdev, SIF_CSR, "%s address 0x%x value 0x%llx",
		(local ? "UF local" : "global"), addr, resp.data);
	return resp.data;
}

/* Write a 64 bit EPS CSR register. Only valid for old FW. */
static int write_csr(struct sif_dev *sdev, u32 addr, u64 val)
{
	struct psif_epsc_csr_rsp resp;
	struct psif_epsc_csr_req req;
	int ret;

	memset(&req, 0, sizeof(req));
	req.opcode = EPSC_SET_ONE_CSR;
	req.addr = addr;
	req.u.single.data = val;
	sif_log(sdev, SIF_CSR, "write address 0x%x value 0x%llx",
		addr, val);

	ret = sif_epsc_wr_poll(sdev, &req, &resp);
	if (ret)
		return ret;
	return ret;
}


/* Read a 64 bit CSR register (local UF mapping) */
u64 sif_read_local_csr(struct sif_dev *sdev, u32 addr)
{
	return read_csr(sdev, addr, true);
}

/* Read a 64 bit CSR register (global PSIF mapping - uf 0 only) */
u64 sif_read_global_csr(struct sif_dev *sdev, u32 addr)
{
	return read_csr(sdev, addr, false);
}

/* Write a 64 bit EPS CSR register (global PSIF mapping - uf 0 only) */
int sif_write_global_csr(struct sif_dev *sdev, u32 addr, u64 val)
{
	return write_csr(sdev, addr, val);
}


/* Helper for dfs iteration */
int sif_eps_next_used(struct sif_table *table, int index)
{
	struct sif_dev *sdev = table->sdev;
	enum psif_mbox_type eps_num = sif_tab2mbox(sdev, table->type);
	struct sif_eps *es = &sdev->es[eps_num];
	int first, last;

	first = es->first_seq & es->mask;
	last = es->last_seq & es->mask;

	if (es->first_seq == es->last_seq + 1)
		return -1;
	if (first <= last) {
		if (index <= first)
			return first;
		if (index > last)
			return -1;
	} else {
		if (index >= table->entry_cnt)
			return -1;
		if (index > last && index < first)
			return first;
	}
	return index;
}


static void sif_dfs_print_eps(struct seq_file *s, struct sif_dev *sdev,
		loff_t pos, enum psif_mbox_type eps_num)
{
	struct psif_epsc_csr_req *req;
	struct psif_epsc_csr_rsp *rsp;
	struct sif_eps *es = &sdev->es[eps_num];
	u16 seq, rsp_seq;

	if (unlikely(pos < 0)) {
		u32 sz = sdev->ba[epsc_csr_req].entry_cnt;

		seq_printf(s,
			"# EPS%s Request queue, outstanding %d/%d max.%d waiters %d first/last seq. %d/%d\n"
			"# %6s %15s %8s %15s %6s\n",
			eps_suffix(sdev, eps_num), atomic_read(&es->cur_reqs),
			sz, es->max_reqs, atomic_read(&es->waiters),
			es->first_seq, es->last_seq,
			"Entry", "req.opcode", "req.seq", "rsp.opcode", "rsp.seq");
		return;
	}

	req = get_eps_csr_req(sdev, eps_num, pos);
	seq = get_psif_epsc_csr_req__seq_num(req) & ~CSR_ONLINE_MASK;

	/* Correlate to response queue */
	rsp = get_eps_csr_rsp(sdev, eps_num, pos);
	rsp_seq = get_psif_epsc_csr_rsp__seq_num(rsp) & ~CSR_ONLINE_MASK;

	seq_printf(s, "%8lld %15s %8d %15s %8d\n", pos,
		string_enum_psif_epsc_csr_opcode(get_psif_epsc_csr_req__opcode(req)) + 5,
		seq,
		string_enum_psif_epsc_csr_opcode(get_psif_epsc_csr_rsp__opcode(rsp)) + 5,
		rsp_seq);
}


void sif_dfs_print_epsc(struct seq_file *s, struct sif_dev *sdev,
		loff_t pos)
{
	sif_dfs_print_eps(s, sdev, pos, sdev->mbox_epsc);
}

void sif_dfs_print_epsa0(struct seq_file *s, struct sif_dev *sdev,
		loff_t pos)
{
	sif_dfs_print_eps(s, sdev, pos, MBOX_EPSA0);
}

void sif_dfs_print_epsa1(struct seq_file *s, struct sif_dev *sdev,
		loff_t pos)
{
	sif_dfs_print_eps(s, sdev, pos, MBOX_EPSA1);
}

void sif_dfs_print_epsa2(struct seq_file *s, struct sif_dev *sdev,
		loff_t pos)
{
	sif_dfs_print_eps(s, sdev, pos, MBOX_EPSA2);
}

void sif_dfs_print_epsa3(struct seq_file *s, struct sif_dev *sdev,
		loff_t pos)
{
	sif_dfs_print_eps(s, sdev, pos, MBOX_EPSA3);
}

void epsc_report_degraded(struct sif_dev *sdev, u64 cause_mask)
{
	unsigned int cause;

	for (cause = 0; cause < 64; cause++) {
		if ((1L << cause) & cause_mask) {
			sif_log(sdev, SIF_INFO, "Device reports degraded cause %s",
				string_enum_psif_epsc_degrade_cause((enum psif_epsc_degrade_cause)cause));
		}
	}
}
