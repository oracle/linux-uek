// SPDX-License-Identifier: GPL-2.0
/* Marvell RVU Admin Function driver
 *
 * Copyright (C) 2024 Marvell.
 *
 */

#include <linux/module.h>
#include <linux/pci.h>

#include "struct.h"
#include "../rvu.h"

int rvu_mbox_handler_npa_cn20k_aq_enq(struct rvu *rvu,
				      struct npa_cn20k_aq_enq_req *req,
				      struct npa_cn20k_aq_enq_rsp *rsp)
{
	return rvu_npa_aq_enq_inst(rvu, (struct npa_aq_enq_req *)req,
				   (struct npa_aq_enq_rsp *)rsp);
}
EXPORT_SYMBOL(rvu_mbox_handler_npa_cn20k_aq_enq);

int rvu_npa_halo_hwctx_disable(struct npa_aq_enq_req *req)
{
	struct npa_cn20k_aq_enq_req *hreq;

	hreq = (struct npa_cn20k_aq_enq_req *)req;

	hreq->halo.bp_ena_0 = 0;
	hreq->halo.bp_ena_1 = 0;
	hreq->halo.bp_ena_2 = 0;
	hreq->halo.bp_ena_3 = 0;
	hreq->halo.bp_ena_4 = 0;
	hreq->halo.bp_ena_5 = 0;
	hreq->halo.bp_ena_6 = 0;
	hreq->halo.bp_ena_7 = 0;

	hreq->halo_mask.bp_ena_0 = 1;
	hreq->halo_mask.bp_ena_1 = 1;
	hreq->halo_mask.bp_ena_2 = 1;
	hreq->halo_mask.bp_ena_3 = 1;
	hreq->halo_mask.bp_ena_4 = 1;
	hreq->halo_mask.bp_ena_5 = 1;
	hreq->halo_mask.bp_ena_6 = 1;
	hreq->halo_mask.bp_ena_7 = 1;

	return 0;
}
