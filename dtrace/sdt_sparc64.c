/*
 * FILE:	sdt_sparc64.c
 * DESCRIPTION:	Statically Defined Tracing: arch support (sparc64)
 *
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 *
 * Copyright (c) 2010, 2017, Oracle and/or its affiliates. All rights reserved.
 */

#include <linux/sdt.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>
#include <asm/cacheflush.h>
#include <asm/pgtable.h>

#include "dtrace.h"
#include "dtrace_dev.h"
#include "sdt_impl.h"

/*
 * The trampoline follows the instruction sequence (if sdp_id > 0xfff):
 *	save
 *	sethi	%hi(sdp->sdp_id), %o0
 *	or	%o0, %lo(sdp->sdp_id), %o0
 *	mov	%i0, %o1
 *	mov	%i1, %o2
 *	mov	%i2, %o3
 *	mov	%i3, %o4
 *	call	dtrace_probe
 *	 mov	%i4, %o5
 *	ret
 *	 restore
 *
 * otherwise it follows:
 *	save
 *	or	%g0, sdp->sdp_id, %o0
 *	mov	%i0, %o1
 *	mov	%i1, %o2
 *	mov	%i2, %o3
 *	mov	%i3, %o4
 *	call	dtrace_probe
 *	 mov	%i4, %o5
 *	ret
 *	 restore
 *
 * For is-enabled probes, we just drop an "or %g0, 1, %o0"
 * directly into the delay slot.
 */
#define	SDT_TRAMP_SIZE	11

#define SA(x)			((long)ALIGN((x), 4))
#define MINFRAME		STACKFRAME_SZ

#define	SDT_REG_G0		0
#define	SDT_REG_O0		8
#define	SDT_REG_O1		(SDT_REG_O0 + 1)
#define	SDT_REG_O2		(SDT_REG_O1 + 1)
#define	SDT_REG_O3		(SDT_REG_O2 + 1)
#define	SDT_REG_O4		(SDT_REG_O3 + 1)
#define	SDT_REG_O5		(SDT_REG_O4 + 1)
#define	SDT_REG_I0		24
#define	SDT_REG_I1		(SDT_REG_I0 + 1)
#define	SDT_REG_I2		(SDT_REG_I1 + 1)
#define	SDT_REG_I3		(SDT_REG_I2 + 1)
#define	SDT_REG_I4		(SDT_REG_I3 + 1)
#define	SDT_REG_I5		(SDT_REG_I4 + 1)

#define SDT_OP_SETHI		0x1000000
#define SDT_OP_OR		0x80100000

#define SDT_FMT2_RD_SHIFT	25
#define SDT_IMM22_SHIFT		10
#define SDT_IMM22_MASK		0x3fffff
#define SDT_IMM10_MASK		0x3ff

#define SDT_FMT3_RD_SHIFT	25
#define SDT_FMT3_RS1_SHIFT	14
#define SDT_FMT3_RS2_SHIFT	0
#define SDT_FMT3_IMM		(1 << 13)

#define	SDT_SIMM13_MASK		0x1fff
#define SDT_SIMM13_MAX		((int32_t)0xfff)

#define	SDT_SAVE		(0x9de3a000 | \
				 ((-SA(MINFRAME)) & SDT_SIMM13_MASK))
#define SDT_SETHI(v, rd)	(SDT_OP_SETHI | (rd << SDT_FMT2_RD_SHIFT) | \
				 ((v >> SDT_IMM22_SHIFT) & SDT_IMM22_MASK))
#define	SDT_ORLO(rs, v, rd)	(SDT_OP_OR | ((rs) << SDT_FMT3_RS1_SHIFT) | \
				 ((rd) << SDT_FMT3_RD_SHIFT) | SDT_FMT3_IMM | \
				 ((v) & SDT_IMM10_MASK))
#define	SDT_ORSIMM13(rs, v, rd)	(SDT_OP_OR | ((rs) << SDT_FMT3_RS1_SHIFT) | \
				 ((rd) << SDT_FMT3_RD_SHIFT) | SDT_FMT3_IMM | \
				 ((v) & SDT_SIMM13_MASK))
#define	SDT_MOV(rs, rd)		(SDT_OP_OR | \
				 (SDT_REG_G0 << SDT_FMT3_RS1_SHIFT) | \
				 ((rs) << SDT_FMT3_RS2_SHIFT) | \
				 ((rd) << SDT_FMT3_RD_SHIFT))
#define SDT_CALL(s, d)		(((uint32_t)1 << 30) | \
				 ((((uintptr_t)(d) - (uintptr_t)(s)) >> 2) & \
				  0x3fffffff))
#define	SDT_RET			0x81c7e008
#define	SDT_RESTORE		0x81e80000

void sdt_provide_probe_arch(sdt_probe_t *sdp, struct module *mp, int idx)
{
	asm_instr_t	*trampoline = &(PDATA(mp)->sdt_tab[idx *
							   SDT_TRAMP_SIZE]);
	asm_instr_t	*instr = trampoline;

	if (sdp->sdp_ptype == SDTPT_OFFSETS) {
		*instr++ = SDT_SAVE;

		if (sdp->sdp_id > (uint32_t)SDT_SIMM13_MAX)  {
			*instr++ = SDT_SETHI(sdp->sdp_id, SDT_REG_O0);
			*instr++ = SDT_ORLO(SDT_REG_O0, sdp->sdp_id,
					    SDT_REG_O0);
		} else {
			*instr++ = SDT_ORSIMM13(SDT_REG_G0, sdp->sdp_id,
						SDT_REG_O0);
		}

		*instr++ = SDT_MOV(SDT_REG_I0, SDT_REG_O1);
		*instr++ = SDT_MOV(SDT_REG_I1, SDT_REG_O2);
		*instr++ = SDT_MOV(SDT_REG_I2, SDT_REG_O3);
		*instr++ = SDT_MOV(SDT_REG_I3, SDT_REG_O4);
		*instr = SDT_CALL(instr, dtrace_probe);
		instr++;
		*instr++ = SDT_MOV(SDT_REG_I4, SDT_REG_O5);

		*instr++ = SDT_RET;
		*instr++ = SDT_RESTORE;

		sdp->sdp_patchval = SDT_CALL(sdp->sdp_patchpoint, trampoline);
	} else {				/* SDTPT_IS_ENABLED */
		/*
		 * We want to change the insn in the delay slot,
		 * which will be the arg setup.  There is no
		 * trampoline.
		 */
		sdp->sdp_patchpoint++; /* next insn */
		sdp->sdp_patchval = SDT_ORSIMM13(SDT_REG_G0, 1, SDT_REG_O0);
	}

	sdp->sdp_savedval = *sdp->sdp_patchpoint;
}

/*
 * Allocates SDT trampoline that is executable.
 */
int sdt_provide_module_arch(void *arg, struct module *mp)
{
	if (mp->sdt_probec > 0 && PDATA(mp)->sdt_tab == NULL) {
		asm_instr_t *tramp = dtrace_alloc_text(mp, mp->sdt_probec *
						       SDT_TRAMP_SIZE *
						       sizeof (asm_instr_t));

		if (tramp == NULL)
			return 0;

		PDATA(mp)->sdt_tab = tramp;
	}

	return 1;
}

void sdt_destroy_module(void *arg, struct module *mp)
{
	if (PDATA(mp)->sdt_tab != NULL) {
		dtrace_free_text(PDATA(mp)->sdt_tab);
		PDATA(mp)->sdt_tab = NULL;
	}
}

void sdt_enable_arch(sdt_probe_t *sdp, dtrace_id_t id, void *arg)
{
	*sdp->sdp_patchpoint = sdp->sdp_patchval;
	flushi(sdp->sdp_patchpoint);
}

void sdt_disable_arch(sdt_probe_t *sdp, dtrace_id_t id, void *arg)
{
	*sdp->sdp_patchpoint = sdp->sdp_savedval;
	flushi(sdp->sdp_patchpoint);
}

int sdt_dev_init_arch(void)
{
	return 0;
}

void sdt_dev_exit_arch(void)
{
}
