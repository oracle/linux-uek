/*
 * Copyright (c) 2006, 2023 Oracle and/or its affiliates.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *	Redistribution and use in source and binary forms, with or
 *	without modification, are permitted provided that the following
 *	conditions are met:
 *
 *	 - Redistributions of source code must retain the above
 *	   copyright notice, this list of conditions and the following
 *	   disclaimer.
 *
 *	 - Redistributions in binary form must reproduce the above
 *	   copyright notice, this list of conditions and the following
 *	   disclaimer in the documentation and/or other materials
 *	   provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 */

#include <linux/kref.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/errno.h>
#include <rdma/ib_umem.h>
#include <rdma/ib_user_verbs.h>
#include <rdma/ib_cache.h>
#include "mlx5_ib.h"
#include "srq.h"
#include "qp.h"

#ifndef WITHOUT_ORACLE_EXTENSIONS
#include "oracle_ext.h"

unsigned int mlx5_ib_verify_cqe_flag;
module_param_named(verify_cqe, mlx5_ib_verify_cqe_flag, uint, 0644);
MODULE_PARM_DESC(verify_cqe, "verify_cqe: 0 = Disable cqe verification, 1 = Enable cqe verification. Default=0");

void verify_cqe(struct mlx5_cqe64 *cqe64, struct mlx5_ib_cq *cq)
{
	int i = 0;
	u64 temp_xor = 0;
	struct mlx5_ib_dev *dev = to_mdev(cq->ibcq.device);

	u32 cons_index = cq->mcq.cons_index;
	u64 *eight_byte_raw_cqe = (u64 *)cqe64;
	u8 *temp_bytewise_xor = (u8 *)(&temp_xor);
	u8 cqe_bytewise_xor = (cons_index & 0xff) ^
				((cons_index & 0xff00) >> 8) ^
				((cons_index & 0xff0000) >> 16);

	for (i = 0; i < sizeof(struct mlx5_cqe64); i += sizeof(u64)) {
		temp_xor ^= *eight_byte_raw_cqe;
		eight_byte_raw_cqe++;
	}

	for (i = 0; i < (sizeof(u64)); i++) {
		cqe_bytewise_xor ^= *temp_bytewise_xor;
		temp_bytewise_xor++;
	}

	if (cqe_bytewise_xor == 0xff)
		return;

	dev_err(&dev->mdev->pdev->dev,
		"Faulty CQE - checksum failure: cqe=0x%x cqn=0x%x cqe_bytewise_xor=0x%x\n",
		cq->ibcq.cqe, cq->mcq.cqn, cqe_bytewise_xor);
	dev_err(&dev->mdev->pdev->dev,
		"cons_index=%u arm_sn=%u irqn=%u cqe_size=0x%x\n",
		cq->mcq.cons_index, cq->mcq.arm_sn, cq->mcq.irqn, cq->mcq.cqe_sz);

	print_hex_dump(KERN_WARNING, "cqe_dump: ", DUMP_PREFIX_OFFSET,
		       16, 1, cqe64, sizeof(*cqe64), false);
}

#endif /* !WITHOUT_ORACLE_EXTENSIONS */
