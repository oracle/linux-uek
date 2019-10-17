// SPDX-License-Identifier: GPL-2.0
/* Marvell OcteonTX and OcteonTX2 ZIP Virtual Function driver
 *
 * Copyright (C) 2019 Marvell International Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include "zip_vf_deflate.h"

s32 zip_vf_deflate_bufs_alloc(struct zip_vf_device *vf,
			      struct zip_vf_state *s,
			      struct zip_operation *ops)
{
	struct device *dev = &vf->pdev->dev;

	/* Input buffer allocation */
	if ((ops->input_len + ops->history_len) <= MAX_DEFLATE_BUF_SIZE) {
		s->input.dbuf = (union zip_zptr_s *) dmam_alloc_coherent(dev,
						MAX_DEFLATE_BUF_SIZE,
						&s->input.dma_addr,
						GFP_KERNEL | __GFP_ZERO);
		if (!s->input.dbuf)
			return -ENOMEM;

	} else {
		return -EINVAL;
	}

	/* Output buffer allocation */
	if (ops->output_len  <= MAX_DEFLATE_BUF_SIZE) {
		s->output.dbuf = (union zip_zptr_s *) dmam_alloc_coherent(dev,
						MAX_DEFLATE_BUF_SIZE,
						&s->output.dma_addr,
						GFP_KERNEL | __GFP_ZERO);
		if (!s->output.dbuf)
			return -ENOMEM;

	} else {
		return -EINVAL;
	}

	/* Result buffer allocation */
	s->result.rbuf = (union zip_zres_s *) dmam_alloc_coherent(dev,
					ZIP_RESULT_SIZE,
					&s->result.dma_addr,
					GFP_KERNEL | __GFP_ZERO);
	if (!s->result.rbuf)
		return -ENOMEM;

	return 0;
}

void zip_vf_deflate_bufs_free(struct zip_vf_device *vf,
			      struct zip_vf_state *s)
{
	if (likely(s->result.rbuf))
		dmam_free_coherent(&vf->pdev->dev, ZIP_RESULT_SIZE,
						s->result.rbuf,
						s->result.dma_addr);

	if (likely(s->output.dbuf))
		dmam_free_coherent(&vf->pdev->dev, MAX_DEFLATE_BUF_SIZE,
						s->output.dbuf,
						s->output.dma_addr);

	if (likely(s->input.dbuf))
		dmam_free_coherent(&vf->pdev->dev, MAX_DEFLATE_BUF_SIZE,
						s->input.dbuf,
						s->input.dma_addr);
}

static void zip_vf_prepare_deflate_cmd(struct zip_operation *ops,
				       struct zip_vf_state *s,
				       union zip_inst_s *cmd)
{
	union zip_zres_s *result = s->result.rbuf;

	memset(cmd, 0, sizeof(*cmd));
	memset(result, 0, sizeof(*result));

	cmd->s.hg = 0;

	/*
	 * Userspace library should make sure ops->history_len
	 * should be zero when no history available
	 */
	cmd->s.historylength = ops->history_len;

	cmd->s.halg = 0;
	cmd->s.iv = 0;
	cmd->s.bf = ops->begin_file;
	cmd->s.sf = 1;

	/* End of file */
	if (ops->flush == ZIP_FLUSH_FINISH) {
		cmd->s.ef = 1;
		cmd->s.sf = 0;
	}

	/*
	 *   Compression Coding
	 *   0 for auto huffman coding
	 *   1 for dynamic huffman coding
	 *   2 for force fixed huffman coding
	 *   3 for lzs coding
	 */
	cmd->s.cc = ops->ccode;
	cmd->s.ss = ops->speed;
	cmd->s.adlercrc32 = ops->csum;
	cmd->s.op = ZIP_OP_E_COMP;

	/* IWORD # 2 and 3 - decompression context pointer */
	/* IWORD # 4 and 5 - decompression history pointer */
	cmd->s.dg = 0;

	/* IWORD # 6 and 7 - compression input/history pointer */
	cmd->s.inp_ptr_addr.s.addr  = (u64)s->input.dma_addr;
	cmd->s.inp_ptr_ctl.s.length = ops->input_len + ops->history_len;

	cmd->s.ds = 0;
	/* IWORD # 8 and 9 - Output pointer */
	cmd->s.out_ptr_addr.s.addr = (u64)s->output.dma_addr;
	cmd->s.out_ptr_ctl.s.length = ops->output_len;

	/* Maximum number of output-stream bytes that can be written */
	cmd->s.totaloutputlength = ops->output_len;

	/* IWORD # 10 and 11 - Result pointer */
	cmd->s.res_ptr_addr.s.addr = (u64)s->result.dma_addr;

	/* Clear Completion code */
	result->s.compcode = 0;
}

s32 zip_vf_deflate(struct zip_vf_device *vf, struct zip_vf_state *s,
		   struct zip_operation *ops)
{
	struct device *dev = &vf->pdev->dev;
	union zip_inst_s *cmd = &s->zip_cmd;
	union zip_zres_s *result = s->result.rbuf;

	zip_vf_prepare_deflate_cmd(ops, s, cmd);

	zip_vf_load_instr(vf, cmd);

	atomic64_inc(&vf->stats.comp_req_submit);
	atomic64_add(ops->input_len, &vf->stats.comp_in_bytes);

	if (zip_vf_poll_result(result)) {
		dev_err(dev, "Request timed out\n");
		return -ETIMEDOUT;
	}

	atomic64_inc(&vf->stats.comp_req_complete);
	ops->compcode = result->s.compcode;

	switch (ops->compcode) {
	case NOTDONE:
		dev_err(dev, "Instruction not completed\n");
		return ZIP_ERROR;

	case SUCCESS:
		break;

	case DTRUNC:
		dev_err(dev, "Output truncate error\n");
		return ZIP_ERROR;

	default:
		dev_err(dev, "Failed to deflate: %d\n", result->s.compcode);
		return ZIP_ERROR;
	}

	/* Update the CRC depending on the format */
	switch (ops->format) {
	case RAW_FORMAT:
		ops->csum = result->s.adler32;
		break;

	case ZLIB_FORMAT:
		ops->csum = result->s.adler32;
		break;

	case GZIP_FORMAT:
		ops->csum = result->s.crc32;
		break;

	case LZS_FORMAT:
		break;

	default:
		dev_err(dev, "Unknown Format: %d\n", ops->format);
	}

	atomic64_add(result->s.totalbyteswritten, &vf->stats.comp_out_bytes);

	/* Update output_len */
	if (ops->output_len < result->s.totalbyteswritten) {
		dev_err(dev, "output_len (%d) < total bytes written(%d)\n",
			ops->output_len, result->s.totalbyteswritten);
		ops->output_len = 0;
	} else {
		ops->output_len -= result->s.totalbyteswritten;
	}

	return 0;
}
