// SPDX-License-Identifier: GPL-2.0
/* Marvell OcteonTX2 CPT driver
 *
 * Copyright (C) 2018 Marvell International Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include "cpt_reqmgr.h"
#include "cpt9x_mbox_common.h"
#include "cpt9x_reqmgr.h"

static int cpt9x_process_ccode(struct pci_dev *pdev,
			       union cpt_res_s *cpt_status,
			       struct cpt_info_buffer *cpt_info,
			       struct cpt_request_info *req, u32 *res_code)
{
	u8 ccode = cpt_status->s9x.compcode;

	switch (ccode) {
	case CPT_9X_COMP_E_FAULT:
		dev_err(&pdev->dev,
			"Request failed with DMA fault\n");
		dump_sg_list(pdev, req);
	break;

	case CPT_9X_COMP_E_HWERR:
		dev_err(&pdev->dev,
			"Request failed with hardware error\n");
		dump_sg_list(pdev, req);
	break;

	case CPT_9X_COMP_E_INSTERR:
		dev_err(&pdev->dev,
			"Request failed with instruction error\n");
		dump_sg_list(pdev, req);
	break;

	case COMPLETION_CODE_INIT:
		/* check for timeout */
		if (time_after_eq(jiffies, cpt_info->time_in +
				  CPT_COMMAND_TIMEOUT * HZ))
			dev_warn(&pdev->dev, "Request timed out 0x%p", req);
		else if (cpt_info->extra_time < TIME_IN_RESET_COUNT) {
			cpt_info->time_in = jiffies;
			cpt_info->extra_time++;
		}
		return 1;
	break;

	case CPT_9X_COMP_E_GOOD:
		/* Check microcode completion code, it is only valid
		 * when completion code is CPT_COMP_E::GOOD
		 */
		if (cpt_status->s9x.uc_compcode) {
			/* If requested hmac is truncated and ucode returns
			 * s/g write length error then we report success
			 * because ucode writes as many bytes of calculated
			 * hmac as available in gather buffer and reports
			 * s/g write length error if number of bytes in gather
			 * buffer is less than full hmac size.
			 */
			if (req->is_trunc_hmac && cpt_status->s9x.uc_compcode
			    == ERR_SCATTER_GATHER_WRITE_LENGTH) {
				*res_code = 0;
				break;
			}

			dev_err(&pdev->dev,
				"Request failed with software error code 0x%x\n",
				cpt_status->s9x.uc_compcode);
			dump_sg_list(pdev, req);
			break;
		}

		/* Request has been processed with success */
		*res_code = 0;
	break;

	default:
		dev_err(&pdev->dev,
			"Request returned invalid status %d\n", ccode);
	break;
	}

	return 0;
}

void cpt9x_post_process(struct cptlf_wqe *wqe)
{
	process_pending_queue(wqe->lfs->pdev, &wqe->lfs->ops,
			      &wqe->lfs->lf[wqe->lf_num].pqueue);
}

struct reqmgr_ops cpt9x_get_reqmgr_ops(void)
{
	struct reqmgr_ops ops;

	ops.fill_inst = cpt9x_fill_inst;
	ops.process_ccode = cpt9x_process_ccode;
	ops.send_cmd = cpt9x_send_cmd;

	return ops;
}
