/* SPDX-License-Identifier: GPL-2.0
 * Marvell OcteonTX and OcteonTX2 ZIP Virtual Function driver
 *
 * Copyright (C) 2019 Marvell International Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef __ZIP_VF_DEFLATE_H__
#define __ZIP_VF_DEFLATE_H__

#include "zip_vf.h"

#define MAX_DEFLATE_BUF_SIZE   65535

#define ZIP_RESULT_SIZE 128

#define ZIP_ERROR -1
#define ZIP_FLUSH_FINISH 4

#define ZIP_HASH_NONE 0
#define ZIP_HASH_SHA1 1
#define ZIP_HASH_SHA256 2

/**
 * Enumeration zip_op_e
 *
 * ZIP Operation Enumeration
 * Enumerates ZIP_INST_S[OP].
 */
enum zip_ops_enum {
	ZIP_OP_E_DECOMP,
	ZIP_OP_E_NOCOMP,
	ZIP_OP_E_COMP
};

/* ZIP VF data buffer structure */
struct zip_vf_dbuf {
	dma_addr_t dma_addr; /* DMA handle */
	union zip_zptr_s *dbuf; /* Virtual Address */
};

/* ZIP VF result buffer structure */
struct zip_vf_rbuf {
	dma_addr_t dma_addr; /* DMA handle */
	union zip_zres_s *rbuf; /* Virtual Address */
};

struct zip_vf_state {
	union zip_inst_s zip_cmd; /* ZIP instruction structure */
	union zip_zptr_s *history; /* Decompression Histroy pointer */
	union zip_hash_s *hstate; /* Hash state structure pointer */
	struct zip_vf_dbuf input; /*Data input buffer */
	struct zip_vf_dbuf output; /*Data output buffer */
	struct zip_vf_rbuf result; /* Result buffer */
};

static inline int zip_vf_poll_result(union zip_zres_s *result)
{
	int retries = 1000;

	while (!result->s.compcode) {
		if (!--retries)
			return -ETIMEDOUT;
		udelay(10);
		/*
		 * Force re-reading of compcode which is updated
		 * by the ZIP coprocessor.
		 */
		rmb();
	}
	return 0;
}

s32 zip_vf_deflate_bufs_alloc(struct zip_vf_device *vf,
			      struct zip_vf_state *s,
			      struct zip_operation *ops);
s32 zip_vf_deflate(struct zip_vf_device *vf, struct zip_vf_state *s,
		   struct zip_operation *ops);
void zip_vf_deflate_bufs_free(struct zip_vf_device *vf,
			      struct zip_vf_state *s);

#endif /* __ZIP_VF_DEFLATE_H__ */
