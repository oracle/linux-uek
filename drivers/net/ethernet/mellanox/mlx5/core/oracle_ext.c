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

#include <linux/errno.h>
#include <linux/notifier.h>
#include <linux/mlx5/vport.h>
#include <linux/mlx5/eq.h>
#include "mlx5_core.h"
#include "lib/eq.h"
#include "eswitch.h"
#include "mlx5_irq.h"

#ifndef WITHOUT_ORACLE_EXTENSIONS

unsigned int mlx5_core_verify_eqe_flag;
module_param_named(verify_eqe, mlx5_core_verify_eqe_flag, uint, 0644);
MODULE_PARM_DESC(verify_eqe, "verify_eqe: 0 = Disable eqe verification, 1 = Enable eqe verification. Default=0");

unsigned int mlx5_reap_eq_irq_aff_change;
module_param(mlx5_reap_eq_irq_aff_change, int, 0644);
MODULE_PARM_DESC(mlx5_reap_eq_irq_aff_change, "mlx5_reap_eq_irq_aff_change: 0 = Disable MLX5 EQ Reap upon IRQ affinity change, \
		1 = Enable MLX5 EQ Reap upon IRQ affinity change. Default=0");

void verify_eqe(struct mlx5_eq *eq, struct mlx5_eqe *eqe)
{
	u64 *eight_byte_raw_eqe = (u64 *)eqe;
	u8 eqe_bytewise_xor = (eq->cons_index & 0xff) ^
			      ((eq->cons_index & 0xff00) >> 8) ^
			      ((eq->cons_index & 0xff0000) >> 16);

	int i = 0;
	u64 temp_xor = 0;
	u8 *temp_bytewise_xor = (u8 *)(&temp_xor);

	for (i = 0; i < sizeof(struct mlx5_eqe); i += sizeof(u64)) {
		temp_xor ^= *eight_byte_raw_eqe;
		eight_byte_raw_eqe++;
	}

	for (i = 0; i < (sizeof(u64)); i++) {
		eqe_bytewise_xor ^= *temp_bytewise_xor;
		temp_bytewise_xor++;
	}

	if (eqe_bytewise_xor == 0xff)
		return;

	dev_err(&eq->dev->pdev->dev,
		"Faulty EQE - checksum failure: ci=0x%x eqe_type=0x%x eqe_bytewise_xor=0x%x",
		eq->cons_index, eqe->type, eqe_bytewise_xor);

	dev_err(&eq->dev->pdev->dev,
		"EQ addr=%p eqn=%u irqn=%u vec_index=%u",
		eq, eq->eqn, eq->irqn, eq->vecidx);

	print_hex_dump(KERN_WARNING, "eqe_dump: ", DUMP_PREFIX_OFFSET,
		       16, 1, eqe, sizeof(*eqe), false);
}

void mlx5_eq_reap_irq_notify(struct irq_affinity_notify *notify, const cpumask_t *mask)
{
	u32 eqe_count;
	struct mlx5_eq_comp *eq = container_of(notify, struct mlx5_eq_comp, notify);

	if (mlx5_reap_eq_irq_aff_change) {
		mlx5_core_warn(eq->core.dev, "irqn = 0x%x migration notified, EQ 0x%x: Cons = 0x%x\n",
			       eq->core.irqn, eq->core.eqn, eq->core.cons_index);

		while (!rtnl_trylock())
			msleep(20);

		eqe_count = mlx5_eq_poll_irq_disabled(eq);
		if (eqe_count)
			mlx5_core_warn(eq->core.dev, "Recovered %d eqes on EQ 0x%x\n",
				       eqe_count, eq->core.eqn);
		rtnl_unlock();
	}
}

void mlx5_eq_reap_irq_release(struct kref *ref) {}
#endif /* !WITHOUT_ORACLE_EXTENSIONS */
