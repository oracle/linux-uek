// SPDX-License-Identifier: GPL-2.0
/* Marvell OcteonTx2 RVU Admin Function driver
 *
 * Copyright (C) 2018 Marvell International Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include "cpt_reqmgr.h"
#include "cpt9x_mbox_common.h"

static void cpt9x_fill_inst(union cpt_inst_s *cptinst,
			    struct cpt_info_buffer *info,
			    struct cpt_iq_command *iq_cmd)
{
	cptinst->u[0] = 0x0;
	cptinst->s9x.doneint = true;
	cptinst->s9x.res_addr = (u64) info->comp_baddr;
	cptinst->u[2] = 0x0;
	cptinst->u[3] = 0x0;
	cptinst->s9x.ei0 = iq_cmd->cmd.u64;
	cptinst->s9x.ei1 = iq_cmd->dptr;
	cptinst->s9x.ei2 = iq_cmd->rptr;
	cptinst->s9x.ei3 = iq_cmd->cptr.u64;
}

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
		if (time_after_eq(jiffies,
				  (cpt_info->time_in +
				  (CPT_COMMAND_TIMEOUT * HZ)))) {
			dev_err(&pdev->dev, "Request timed out\n");
		} else if ((ccode == (COMPLETION_CODE_INIT)) &&
			   (cpt_info->extra_time <
			    TIME_IN_RESET_COUNT)) {
			cpt_info->time_in = jiffies;
			cpt_info->extra_time++;
			return 1;
		}
	break;

	case CPT_9X_COMP_E_GOOD:
		/* Check microcode completion code, it is only valid
		 * when completion code is CPT_COMP_E::GOOD
		 */
		if (cpt_status->s9x.uc_compcode) {
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

/*
 * On 9X platform the parameter insts_num is used as a count of instructions
 * to be enqueued. The valid values for insts_num are:
 * 1 - 1 CPT instruction will be enqueued during LMTST operation
 * 2 - 2 CPT instructions will be enqueued during LMTST operation
 */
void cpt9x_send_cmd(union cpt_inst_s *cptinst, u32 insts_num, void *obj)
{
	struct cptlf_info *lf = (struct cptlf_info *) obj;
	void *lmtline = lf->lmtline;
	void *ioreg = lf->ioreg;
	long ret;

	/*
	 * Make sure memory areas pointed in CPT_INST_S
	 * are flushed before the instruction is sent to CPT
	 */
	smp_wmb();

	do {
		/* Copy CPT command to LMTLINE */
		memcpy(lmtline, cptinst, insts_num * CPT_INST_SIZE);

		/* Make sure compiler does not reorder memcpy and ldeor.
		 * LMTST transactions are always flushed from the write
		 * buffer immediately, a DMB is not required to push out
		 * LMTSTs.
		 */
		barrier();
		/* LDEOR initiates atomic transfer to I/O device
		 * The following will cause the LMTST to fail (the LDEOR
		 * returns zero):
		 * - No stores have been performed to the LMTLINE since it was
		 * last invalidated.
		 * - The bytes which have been stored to LMTLINE since it was
		 * last invalidated form a pattern that is non-contiguous, does
		 * not start at byte 0, or does not end on a 8-byte boundary.
		 * (i.e.comprises a formation of other than 1–16 8-byte
		 * words.)
		 *
		 * These rules are designed such that an operating system
		 * context switch or hypervisor guest switch need have no
		 * knowledge of the LMTST operations; the switch code does not
		 * need to store to LMTCANCEL. Also note as LMTLINE data cannot
		 * be read, there is no information leakage between processes.
		 */
		__asm__ volatile(
			"  .cpu		generic+lse\n"
			"  ldeor	xzr, %0, [%1]\n"
			: "=r" (ret) : "r" (ioreg) : "memory");
	} while (!ret);
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
