/* SPDX-License-Identifier: GPL-2.0 */
/* Marvell BPHY RVU Ethernet driver
 *
 * Copyright (C) 2025 Marvell.
 *
 */

#ifndef OTX2_BPHYPF_H
#define OTX2_BPHYPF_H

#include <linux/ethtool.h>
#include <linux/pci.h>
#include <linux/iommu.h>
#include <linux/net_tstamp.h>
#include <linux/ptp_clock_kernel.h>
#include <linux/timecounter.h>
#include <linux/soc/marvell/silicons.h>
#include <linux/soc/marvell/octeontx2/asm.h>
#include <net/macsec.h>
#include <net/pkt_cls.h>
#include <net/devlink.h>
#include <linux/time64.h>
#include <linux/dim.h>
#include <uapi/linux/if_macsec.h>

#include <mbox.h>
#include <npc.h>
#include "otx2_reg.h"
#include "otx2_txrx.h"
#include "otx2_devlink.h"
#include <rvu.h>
#include <rvu_trace.h>
#include "qos.h"
#include "rep.h"
#include "cn20k.h"
#include "cn10k_ipsec.h"
#include <rvu_cplt_mbox.h>

#define M(_name, _id, _fn_name, _req_type, _rsp_type)                   \
static struct _req_type __maybe_unused					\
*otx2_mbox_alloc_msg_ ## _fn_name(struct mbox *mbox)                    \
{									\
	struct _req_type *req;						\
	u16 pcifunc = mbox->pfvf->pcifunc;				\
									\
	req = (struct _req_type *)otx2_mbox_alloc_msg_rsp(		\
		&mbox->mbox, 0, sizeof(struct _req_type),		\
		sizeof(struct _rsp_type));				\
	if (!req)							\
		return NULL;						\
	req->hdr.sig = OTX2_MBOX_REQ_SIG;				\
	req->hdr.id = _id;						\
	req->hdr.pcifunc = pcifunc;					\
	trace_otx2_msg_alloc(mbox->mbox.pdev, _id, sizeof(*req), pcifunc); \
	return req;							\
}
MBOX_EBLOCK_CPLT_MESSAGES
#undef M

void otx2_bphypf_set_ethtool_ops(struct net_device *netdev);
int otx2_bphypf_set_npc_parse_mode(struct otx2_nic *pfvf, bool unbind);

#endif
