/*
 * FILE:	dtrace_dif.c
 * DESCRIPTION:	Dynamic Tracing: DIF object functions
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

#include <linux/dtrace_cpu.h>
#include <linux/fdtable.h>
#include <linux/hardirq.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/if_infiniband.h>
#include <linux/in6.h>
#include <linux/inet.h>
#include <linux/jiffies.h>
#include <linux/kdev_t.h>
#include <linux/slab.h>
#include <linux/socket.h>
#include <linux/vmalloc.h>
#include <net/ipv6.h>
#include <asm/byteorder.h>

#include <linux/mount.h>

#include "dtrace.h"

size_t				dtrace_global_maxsize = 16 * 1024;

/*
 * This externally visible variable (accessible through the backtick (`)
 * syntax is provided as a source of well-known, zero-filled memory.  Some
 * translators use this in their implementation.
 */
const char			dtrace_zero[256] = { 0, };

uint64_t			dtrace_vtime_references;

static const char		dtrace_hexdigits[] = "0123456789abcdef";

static int dtrace_difo_err(uint_t pc, const char *format, ...)
{
	char	buf[256];

	if (dtrace_err_verbose) {
		va_list	alist;
		size_t	len = strlen(format);

		pr_err("dtrace DIF object error: [%u]: ", pc);

		if (len >= 256 - sizeof(KERN_ERR)) {
			pr_err("<invalid format string>");
			return 1;
		}

		memcpy(buf, KERN_ERR, sizeof(KERN_ERR));
		memcpy(buf + sizeof(KERN_ERR), format, len);

		va_start(alist, format);
		vprintk(buf, alist);
		va_end(alist);
	}

	return 1;
}

/*
 * Validate a DTrace DIF object by checking the IR instructions.  The following
 * rules are currently enforced by dtrace_difo_validate():
 *
 * 1. Each instruction must have a valid opcode
 * 2. Each register, string, variable, or subroutine reference must be valid
 * 3. No instruction can modify register %r0 (must be zero)
 * 4. All instruction reserved bits must be set to zero
 * 5. The last instruction must be a "ret" instruction
 * 6. All branch targets must reference a valid instruction _after_ the branch
 */
int dtrace_difo_validate(dtrace_difo_t *dp, dtrace_vstate_t *vstate,
			 uint_t nregs, const cred_t *cr)
{
	int	err = 0, i;
	int	(*efunc)(uint_t pc, const char *, ...) = dtrace_difo_err;
	int	kcheckload = 0;
	uint_t	pc;

	kcheckload = cr == NULL ||
		     (vstate->dtvs_state->dts_cred.dcr_visible &
		      DTRACE_CRV_KERNEL) == 0;

	dp->dtdo_destructive = 0;

	for (pc = 0; pc < dp->dtdo_len && err == 0; pc++) {
		dif_instr_t	instr = dp->dtdo_buf[pc];
		uint_t		r1 = DIF_INSTR_R1(instr);
		uint_t		r2 = DIF_INSTR_R2(instr);
		uint_t		rd = DIF_INSTR_RD(instr);
		uint_t		rs = DIF_INSTR_RS(instr);
		uint_t		label = DIF_INSTR_LABEL(instr);
		uint_t		v = DIF_INSTR_VAR(instr);
		uint_t		subr = DIF_INSTR_SUBR(instr);
		uint_t		type = DIF_INSTR_TYPE(instr);
		uint_t		op = DIF_INSTR_OP(instr);

		switch (op) {
		case DIF_OP_OR:
		case DIF_OP_XOR:
		case DIF_OP_AND:
		case DIF_OP_SLL:
		case DIF_OP_SRL:
		case DIF_OP_SRA:
		case DIF_OP_SUB:
		case DIF_OP_ADD:
		case DIF_OP_MUL:
		case DIF_OP_SDIV:
		case DIF_OP_UDIV:
		case DIF_OP_SREM:
		case DIF_OP_UREM:
		case DIF_OP_COPYS:
			if (r1 >= nregs)
				err += efunc(pc, "invalid register %u\n", r1);
			if (r2 >= nregs)
				err += efunc(pc, "invalid register %u\n", r2);
			if (rd >= nregs)
				err += efunc(pc, "invalid register %u\n", rd);
			if (rd == 0)
				err += efunc(pc, "cannot write to %r0\n");
			break;
		case DIF_OP_NOT:
		case DIF_OP_MOV:
		case DIF_OP_ALLOCS:
			if (r1 >= nregs)
				err += efunc(pc, "invalid register %u\n", r1);
			if (r2 != 0)
				err += efunc(pc, "non-zero reserved bits\n");
			if (rd >= nregs)
				err += efunc(pc, "invalid register %u\n", rd);
			if (rd == 0)
				err += efunc(pc, "cannot write to %r0\n");
			break;
		case DIF_OP_LDSB:
		case DIF_OP_LDSH:
		case DIF_OP_LDSW:
		case DIF_OP_LDUB:
		case DIF_OP_LDUH:
		case DIF_OP_LDUW:
		case DIF_OP_LDX:
			if (r1 >= nregs)
				err += efunc(pc, "invalid register %u\n", r1);
			if (r2 != 0)
				err += efunc(pc, "non-zero reserved bits\n");
			if (rd >= nregs)
				err += efunc(pc, "invalid register %u\n", rd);
			if (rd == 0)
				err += efunc(pc, "cannot write to %r0\n");
			if (kcheckload)
				dp->dtdo_buf[pc] = DIF_INSTR_LOAD(
							op + DIF_OP_RLDSB -
							     DIF_OP_LDSB,
							r1, rd);
			break;
		case DIF_OP_RLDSB:
		case DIF_OP_RLDSH:
		case DIF_OP_RLDSW:
		case DIF_OP_RLDUB:
		case DIF_OP_RLDUH:
		case DIF_OP_RLDUW:
		case DIF_OP_RLDX:
			if (r1 >= nregs)
				err += efunc(pc, "invalid register %u\n", r1);
			if (r2 != 0)
				err += efunc(pc, "non-zero reserved bits\n");
			if (rd >= nregs)
				err += efunc(pc, "invalid register %u\n", rd);
			if (rd == 0)
				err += efunc(pc, "cannot write to %r0\n");
			break;
		case DIF_OP_ULDSB:
		case DIF_OP_ULDSH:
		case DIF_OP_ULDSW:
		case DIF_OP_ULDUB:
		case DIF_OP_ULDUH:
		case DIF_OP_ULDUW:
		case DIF_OP_ULDX:
			if (r1 >= nregs)
				err += efunc(pc, "invalid register %u\n", r1);
			if (r2 != 0)
				err += efunc(pc, "non-zero reserved bits\n");
			if (rd >= nregs)
				err += efunc(pc, "invalid register %u\n", rd);
			if (rd == 0)
				err += efunc(pc, "cannot write to %r0\n");
			break;
		case DIF_OP_STB:
		case DIF_OP_STH:
		case DIF_OP_STW:
		case DIF_OP_STX:
			if (r1 >= nregs)
				err += efunc(pc, "invalid register %u\n", r1);
			if (r2 != 0)
				err += efunc(pc, "non-zero reserved bits\n");
			if (rd >= nregs)
				err += efunc(pc, "invalid register %u\n", rd);
			if (rd == 0)
				err += efunc(pc, "cannot write to 0 address\n");
			break;
		case DIF_OP_CMP:
		case DIF_OP_SCMP:
			if (r1 >= nregs)
				err += efunc(pc, "invalid register %u\n", r1);
			if (r2 >= nregs)
				err += efunc(pc, "invalid register %u\n", r2);
			if (rd != 0)
				err += efunc(pc, "non-zero reserved bits\n");
			break;
		case DIF_OP_TST:
			if (r1 >= nregs)
				err += efunc(pc, "invalid register %u\n", r1);
			if (r2 != 0 || rd != 0)
				err += efunc(pc, "non-zero reserved bits\n");
			break;
		case DIF_OP_BA:
		case DIF_OP_BE:
		case DIF_OP_BNE:
		case DIF_OP_BG:
		case DIF_OP_BGU:
		case DIF_OP_BGE:
		case DIF_OP_BGEU:
		case DIF_OP_BL:
		case DIF_OP_BLU:
		case DIF_OP_BLE:
		case DIF_OP_BLEU:
			if (label >= dp->dtdo_len)
				err += efunc(pc, "invalid branch target %u\n",
					     label);
			if (label <= pc)
				err += efunc(pc, "backward branch to %u\n",
					     label);
			break;
		case DIF_OP_RET:
			if (r1 != 0 || r2 != 0)
				err += efunc(pc, "non-zero reserved bits\n");
			if (rd >= nregs)
				err += efunc(pc, "invalid register %u\n", rd);
			break;
		case DIF_OP_NOP:
		case DIF_OP_POPTS:
		case DIF_OP_FLUSHTS:
			if (r1 != 0 || r2 != 0 || rd != 0)
				err += efunc(pc, "non-zero reserved bits\n");
			break;
		case DIF_OP_SETX:
			if (DIF_INSTR_INTEGER(instr) >= dp->dtdo_intlen)
				err += efunc(pc, "invalid integer ref %u\n",
					     DIF_INSTR_INTEGER(instr));
			if (rd >= nregs)
				err += efunc(pc, "invalid register %u\n", rd);
			if (rd == 0)
				err += efunc(pc, "cannot write to %r0\n");
			break;
		case DIF_OP_SETS:
			if (DIF_INSTR_STRING(instr) >= dp->dtdo_strlen)
				err += efunc(pc, "invalid string ref %u\n",
					     DIF_INSTR_STRING(instr));
			if (rd >= nregs)
				err += efunc(pc, "invalid register %u\n", rd);
			if (rd == 0)
				err += efunc(pc, "cannot write to %r0\n");
			break;
		case DIF_OP_LDGA:
		case DIF_OP_LDTA:
			if (r1 > DIF_VAR_ARRAY_MAX)
				err += efunc(pc, "invalid array %u\n", r1);
			if (r2 >= nregs)
				err += efunc(pc, "invalid register %u\n", r2);
			if (rd >= nregs)
				err += efunc(pc, "invalid register %u\n", rd);
			if (rd == 0)
				err += efunc(pc, "cannot write to %r0\n");
			break;
		case DIF_OP_LDGS:
		case DIF_OP_LDTS:
		case DIF_OP_LDLS:
		case DIF_OP_LDGAA:
		case DIF_OP_LDTAA:
			if (v < DIF_VAR_OTHER_MIN || v > DIF_VAR_OTHER_MAX)
				err += efunc(pc, "invalid variable %u\n", v);
			if (rd >= nregs)
				err += efunc(pc, "invalid register %u\n", rd);
			if (rd == 0)
				err += efunc(pc, "cannot write to %r0\n");
			break;
		case DIF_OP_STGS:
		case DIF_OP_STTS:
		case DIF_OP_STLS:
		case DIF_OP_STGAA:
		case DIF_OP_STTAA:
			if (v < DIF_VAR_OTHER_UBASE || v > DIF_VAR_OTHER_MAX)
				err += efunc(pc, "invalid variable %u\n", v);
			if (rs >= nregs)
				err += efunc(pc, "invalid register %u\n", rd);
			break;
		case DIF_OP_CALL:
			if (subr > DIF_SUBR_MAX)
				err += efunc(pc, "invalid subr %u\n", subr);
			if (rd >= nregs)
				err += efunc(pc, "invalid register %u\n", rd);
			if (rd == 0)
				err += efunc(pc, "cannot write to %r0\n");

			if (subr == DIF_SUBR_COPYOUT ||
			    subr == DIF_SUBR_COPYOUTSTR)
				dp->dtdo_destructive = 1;
			break;
		case DIF_OP_PUSHTR:
			if (type != DIF_TYPE_STRING && type != DIF_TYPE_CTF)
				err += efunc(pc, "invalid ref type %u\n", type);
			if (r2 >= nregs)
				err += efunc(pc, "invalid register %u\n", r2);
			if (rs >= nregs)
				err += efunc(pc, "invalid register %u\n", rs);
			break;
		case DIF_OP_PUSHTV:
			if (type != DIF_TYPE_CTF)
				err += efunc(pc, "invalid val type %u\n", type);
			if (r2 >= nregs)
				err += efunc(pc, "invalid register %u\n", r2);
			if (rs >= nregs)
				err += efunc(pc, "invalid register %u\n", rs);
			break;
		default:
			err += efunc(pc, "invalid opcode %u\n",
				     DIF_INSTR_OP(instr));
		}
	}

	if (dp->dtdo_len != 0 &&
	    DIF_INSTR_OP(dp->dtdo_buf[dp->dtdo_len - 1]) != DIF_OP_RET) {
		err += efunc(dp->dtdo_len - 1,
			     "expected 'ret' as last DIF instruction\n");
	}

	if (!(dp->dtdo_rtype.dtdt_flags & DIF_TF_BYREF)) {
		/*
		 * If we're not returning by reference, the size must be either
		 * 0 or the size of one of the base types.
		 */
		switch (dp->dtdo_rtype.dtdt_size) {
		case 0:
		case sizeof(uint8_t):
		case sizeof(uint16_t):
		case sizeof(uint32_t):
		case sizeof(uint64_t):
			break;

		default:
			err += efunc(dp->dtdo_len - 1, "bad return size\n");
		}
	}

	for (i = 0; i < dp->dtdo_varlen && err == 0; i++) {
		dtrace_difv_t		*v = &dp->dtdo_vartab[i],
					*existing = NULL;
		dtrace_diftype_t	*vt, *et;
		uint_t			id, ndx;

		if (v->dtdv_scope != DIFV_SCOPE_GLOBAL &&
		    v->dtdv_scope != DIFV_SCOPE_THREAD &&
		    v->dtdv_scope != DIFV_SCOPE_LOCAL) {
			err += efunc(i, "unrecognized variable scope %d\n",
				     v->dtdv_scope);
			break;
		}

		if (v->dtdv_kind != DIFV_KIND_ARRAY &&
		    v->dtdv_kind != DIFV_KIND_SCALAR) {
			err += efunc(i, "unrecognized variable type %d\n",
				     v->dtdv_kind);
			break;
		}

		if ((id = v->dtdv_id) > DIF_VARIABLE_MAX) {
			err += efunc(i, "%d exceeds variable id limit\n", id);
			break;
		}

		if (id < DIF_VAR_OTHER_UBASE)
			continue;

		/*
		 * For user-defined variables, we need to check that this
		 * definition is identical to any previous definition that we
		 * encountered.
		 */
		ndx = id - DIF_VAR_OTHER_UBASE;

		switch (v->dtdv_scope) {
		case DIFV_SCOPE_GLOBAL:
			if (ndx < vstate->dtvs_nglobals) {
				dtrace_statvar_t	*svar;

				if ((svar = vstate->dtvs_globals[ndx]) != NULL)
					existing = &svar->dtsv_var;
			}

			break;

		case DIFV_SCOPE_THREAD:
			if (ndx < vstate->dtvs_ntlocals)
				existing = &vstate->dtvs_tlocals[ndx];
			break;

		case DIFV_SCOPE_LOCAL:
			if (ndx < vstate->dtvs_nlocals) {
				dtrace_statvar_t	*svar;

				if ((svar = vstate->dtvs_locals[ndx]) != NULL)
					existing = &svar->dtsv_var;
			}

			break;
		}

		vt = &v->dtdv_type;

		if (vt->dtdt_flags & DIF_TF_BYREF) {
			if (vt->dtdt_size == 0) {
				err += efunc(i, "zero-sized variable\n");
				break;
			}

			if (v->dtdv_scope == DIFV_SCOPE_GLOBAL &&
			    vt->dtdt_size > dtrace_global_maxsize) {
				err += efunc(i, "oversized by-ref global\n");
				break;
			}
		}

		if (existing == NULL || existing->dtdv_id == 0)
			continue;

		ASSERT(existing->dtdv_id == v->dtdv_id);
		ASSERT(existing->dtdv_scope == v->dtdv_scope);

		if (existing->dtdv_kind != v->dtdv_kind)
			err += efunc(i, "%d changed variable kind\n", id);

		et = &existing->dtdv_type;

		if (vt->dtdt_flags != et->dtdt_flags) {
			err += efunc(i, "%d changed variable type flags\n", id);
			break;
		}

		if (vt->dtdt_size != 0 && vt->dtdt_size != et->dtdt_size) {
			err += efunc(i, "%d changed variable type size\n", id);
			break;
		}
	}

	return err;
}

/*
 * Validate a DTrace DIF object that it is to be used as a helper.  Helpers
 * are much more constrained than normal DIFOs.  Specifically, they may
 * not:
 *
 * 1. Make calls to subroutines other than copyin(), copyinstr() or
 *    miscellaneous string routines
 * 2. Access DTrace variables other than the args[] array, and the
 *    curthread, pid, ppid, tid, execname, zonename, uid and gid variables.
 * 3. Have thread-local variables.
 * 4. Have dynamic variables.
 */
int dtrace_difo_validate_helper(dtrace_difo_t *dp)
{
	int	(*efunc)(uint_t pc, const char *, ...) = dtrace_difo_err;
	int	err = 0;
	uint_t	pc;

	for (pc = 0; pc < dp->dtdo_len; pc++) {
		dif_instr_t	instr = dp->dtdo_buf[pc];
		uint_t		v = DIF_INSTR_VAR(instr);
		uint_t		subr = DIF_INSTR_SUBR(instr);
		uint_t		op = DIF_INSTR_OP(instr);

		switch (op) {
		case DIF_OP_OR:
		case DIF_OP_XOR:
		case DIF_OP_AND:
		case DIF_OP_SLL:
		case DIF_OP_SRL:
		case DIF_OP_SRA:
		case DIF_OP_SUB:
		case DIF_OP_ADD:
		case DIF_OP_MUL:
		case DIF_OP_SDIV:
		case DIF_OP_UDIV:
		case DIF_OP_SREM:
		case DIF_OP_UREM:
		case DIF_OP_COPYS:
		case DIF_OP_NOT:
		case DIF_OP_MOV:
		case DIF_OP_RLDSB:
		case DIF_OP_RLDSH:
		case DIF_OP_RLDSW:
		case DIF_OP_RLDUB:
		case DIF_OP_RLDUH:
		case DIF_OP_RLDUW:
		case DIF_OP_RLDX:
		case DIF_OP_ULDSB:
		case DIF_OP_ULDSH:
		case DIF_OP_ULDSW:
		case DIF_OP_ULDUB:
		case DIF_OP_ULDUH:
		case DIF_OP_ULDUW:
		case DIF_OP_ULDX:
		case DIF_OP_STB:
		case DIF_OP_STH:
		case DIF_OP_STW:
		case DIF_OP_STX:
		case DIF_OP_ALLOCS:
		case DIF_OP_CMP:
		case DIF_OP_SCMP:
		case DIF_OP_TST:
		case DIF_OP_BA:
		case DIF_OP_BE:
		case DIF_OP_BNE:
		case DIF_OP_BG:
		case DIF_OP_BGU:
		case DIF_OP_BGE:
		case DIF_OP_BGEU:
		case DIF_OP_BL:
		case DIF_OP_BLU:
		case DIF_OP_BLE:
		case DIF_OP_BLEU:
		case DIF_OP_RET:
		case DIF_OP_NOP:
		case DIF_OP_POPTS:
		case DIF_OP_FLUSHTS:
		case DIF_OP_SETX:
		case DIF_OP_SETS:
		case DIF_OP_LDGA:
		case DIF_OP_LDLS:
		case DIF_OP_STGS:
		case DIF_OP_STLS:
		case DIF_OP_PUSHTR:
		case DIF_OP_PUSHTV:
			break;

		case DIF_OP_LDGS:
			if (v >= DIF_VAR_OTHER_UBASE)
				break;

			if (v >= DIF_VAR_ARG0 && v <= DIF_VAR_ARG9)
				break;

			if (v == DIF_VAR_CURTHREAD || v == DIF_VAR_PID ||
			    v == DIF_VAR_PPID || v == DIF_VAR_TID ||
			    v == DIF_VAR_EXECNAME || v == DIF_VAR_ZONENAME ||
			    v == DIF_VAR_UID || v == DIF_VAR_GID)
				break;

			err += efunc(pc, "illegal variable %u\n", v);
			break;

		case DIF_OP_LDTA:
		case DIF_OP_LDGAA:
		case DIF_OP_LDTAA:
			err += efunc(pc, "illegal dynamic variable load\n");
			break;

		case DIF_OP_STTS:
		case DIF_OP_STGAA:
		case DIF_OP_STTAA:
			err += efunc(pc, "illegal dynamic variable store\n");
			break;

		case DIF_OP_CALL:
			if (subr == DIF_SUBR_ALLOCA ||
			    subr == DIF_SUBR_BCOPY ||
			    subr == DIF_SUBR_COPYIN ||
			    subr == DIF_SUBR_COPYINTO ||
			    subr == DIF_SUBR_COPYINSTR ||
			    subr == DIF_SUBR_INDEX ||
			    subr == DIF_SUBR_INET_NTOA ||
			    subr == DIF_SUBR_INET_NTOA6 ||
			    subr == DIF_SUBR_INET_NTOP ||
			    subr == DIF_SUBR_LINK_NTOP ||
			    subr == DIF_SUBR_LLTOSTR ||
			    subr == DIF_SUBR_RINDEX ||
			    subr == DIF_SUBR_STRCHR ||
			    subr == DIF_SUBR_STRJOIN ||
			    subr == DIF_SUBR_STRRCHR ||
			    subr == DIF_SUBR_STRSTR ||
			    subr == DIF_SUBR_HTONS ||
			    subr == DIF_SUBR_HTONL ||
			    subr == DIF_SUBR_HTONLL ||
			    subr == DIF_SUBR_NTOHS ||
			    subr == DIF_SUBR_NTOHL ||
			    subr == DIF_SUBR_NTOHLL)
				break;

			err += efunc(pc, "invalid subr %u\n", subr);
			break;

		default:
			err += efunc(pc, "invalid opcode %u\n",
				     DIF_INSTR_OP(instr));
		}
	}

	return err;
}

/*
 * Returns 1 if the expression in the DIF object can be cached on a per-thread
 * basis; 0 if not.
 */
int dtrace_difo_cacheable(dtrace_difo_t *dp)
{
	int	i;

	if (dp == NULL)
		return 0;

	for (i = 0; i < dp->dtdo_varlen; i++) {
		dtrace_difv_t	*v = &dp->dtdo_vartab[i];

		if (v->dtdv_scope != DIFV_SCOPE_GLOBAL)
			continue;

		switch (v->dtdv_id) {
		case DIF_VAR_CURTHREAD:
		case DIF_VAR_PID:
		case DIF_VAR_TID:
		case DIF_VAR_EXECNAME:
		case DIF_VAR_ZONENAME:
			break;

		default:
			return 0;
		}
	}

	/*
	 * This DIF object may be cacheable.  Now we need to look for any
	 * array loading instructions, any memory loading instructions, or
	 * any stores to thread-local variables.
	 */
	for (i = 0; i < dp->dtdo_len; i++) {
		uint_t	op = DIF_INSTR_OP(dp->dtdo_buf[i]);

		if ((op >= DIF_OP_LDSB && op <= DIF_OP_LDX) ||
		    (op >= DIF_OP_ULDSB && op <= DIF_OP_ULDX) ||
		    (op >= DIF_OP_RLDSB && op <= DIF_OP_RLDX) ||
		    op == DIF_OP_LDGA || op == DIF_OP_STTS)
			return 0;
	}

	return 1;
}

/*
 * This routine calculates the dynamic variable chunksize for a given DIF
 * object.  The calculation is not fool-proof, and can probably be tricked by
 * malicious DIF -- but it works for all compiler-generated DIF.  Because this
 * calculation is likely imperfect, dtrace_dynvar() is able to gracefully fail
 * if a dynamic variable size exceeds the chunksize.
 */
static void dtrace_difo_chunksize(dtrace_difo_t *dp, dtrace_vstate_t *vstate)
{
	uint64_t		sval = 0;
	dtrace_key_t		tupregs[DIF_DTR_NREGS + 2]; /* + thread + id */
	const dif_instr_t	*text = dp->dtdo_buf;
	uint_t			pc, srd = 0;
	uint_t			ttop = 0;
	size_t			size, ksize;
	uint_t			id, i;

	for (pc = 0; pc < dp->dtdo_len; pc++) {
		dif_instr_t	instr = text[pc];
		uint_t		op = DIF_INSTR_OP(instr);
		uint_t		rd = DIF_INSTR_RD(instr);
		uint_t		r1 = DIF_INSTR_R1(instr);
		uint_t		nkeys = 0;
		uchar_t		scope;
		dtrace_key_t	*key = tupregs;

		switch (op) {
		case DIF_OP_SETX:
			sval = dp->dtdo_inttab[DIF_INSTR_INTEGER(instr)];
			srd = rd;
			continue;

		case DIF_OP_STTS:
			key = &tupregs[DIF_DTR_NREGS];
			key[0].dttk_size = 0;
			key[1].dttk_size = 0;
			nkeys = 2;
			scope = DIFV_SCOPE_THREAD;
			break;

		case DIF_OP_STGAA:
		case DIF_OP_STTAA:
			nkeys = ttop;

			if (DIF_INSTR_OP(instr) == DIF_OP_STTAA)
				key[nkeys++].dttk_size = 0;

			key[nkeys++].dttk_size = 0;

			if (op == DIF_OP_STTAA)
				scope = DIFV_SCOPE_THREAD;
			else
				scope = DIFV_SCOPE_GLOBAL;

			break;

		case DIF_OP_PUSHTR:
			if (ttop == DIF_DTR_NREGS)
				return;

			/*
			 * If the register for the size of the "pushtr" is %r0
			 * (or the value is 0) and the type is a string, we'll
			 * use the system-wide default string size.
			 */
			if ((srd == 0 || sval == 0) && r1 == DIF_TYPE_STRING)
				tupregs[ttop++].dttk_size =
						dtrace_strsize_default;
			else {
				if (srd == 0)
					return;

				tupregs[ttop++].dttk_size = sval;
			}

			break;

		case DIF_OP_PUSHTV:
			if (ttop == DIF_DTR_NREGS)
				return;

			tupregs[ttop++].dttk_size = 0;
			break;

		case DIF_OP_FLUSHTS:
			ttop = 0;
			break;

		case DIF_OP_POPTS:
			if (ttop != 0)
				ttop--;
			break;
		}

		sval = 0;
		srd = 0;

		if (nkeys == 0)
			continue;

		/*
		 * We have a dynamic variable allocation; calculate its size.
		 */
		for (ksize = 0, i = 0; i < nkeys; i++)
			ksize += P2ROUNDUP(key[i].dttk_size, sizeof(uint64_t));

		size = sizeof(dtrace_dynvar_t);
		size += sizeof(dtrace_key_t) * (nkeys - 1);
		size += ksize;

		/*
		 * Now we need to determine the size of the stored data.
		*/
		id = DIF_INSTR_VAR(instr);

		for (i = 0; i < dp->dtdo_varlen; i++) {
			dtrace_difv_t	*v = &dp->dtdo_vartab[i];

			if (v->dtdv_id == id && v->dtdv_scope == scope) {
				size += v->dtdv_type.dtdt_size;
				break;
			}
		}

		if (i == dp->dtdo_varlen)
			return;

		/*
		 * We have the size.  If this is larger than the chunk size
		 * for our dynamic variable state, reset the chunk size.
		 */
		size = P2ROUNDUP(size, sizeof(uint64_t));

		if (size > vstate->dtvs_dynvars.dtds_chunksize)
			vstate->dtvs_dynvars.dtds_chunksize = size;
	}
}

void dtrace_difo_hold(dtrace_difo_t *dp)
{
	int	i;

	dp->dtdo_refcnt++;
	ASSERT(dp->dtdo_refcnt != 0);

	for (i = 0; i < dp->dtdo_varlen; i++) {
		dtrace_difv_t	*v = &dp->dtdo_vartab[i];

		if (v->dtdv_id != DIF_VAR_VTIMESTAMP)
			continue;

		if (dtrace_vtime_references++ == 0)
			dtrace_vtime_enable();
	}
}

void dtrace_difo_init(dtrace_difo_t *dp, dtrace_vstate_t *vstate)
{
	int	i, oldsvars, osz, nsz, otlocals, ntlocals;
	uint_t	id;

	ASSERT(MUTEX_HELD(&dtrace_lock));
	ASSERT(dp->dtdo_buf != NULL && dp->dtdo_len != 0);

	for (i = 0; i < dp->dtdo_varlen; i++) {
		dtrace_difv_t		*v = &dp->dtdo_vartab[i];
		dtrace_statvar_t	*svar, ***svarp;
		size_t			dsize = 0;
		uint8_t			scope = v->dtdv_scope;
		int			*np;

		if ((id = v->dtdv_id) < DIF_VAR_OTHER_UBASE)
			continue;

		id -= DIF_VAR_OTHER_UBASE;

		switch (scope) {
		case DIFV_SCOPE_THREAD:
			while (id >= (otlocals = vstate->dtvs_ntlocals)) {
				dtrace_difv_t	*tlocals;

				if ((ntlocals = (otlocals << 1)) == 0)
					ntlocals = 1;

				osz = otlocals * sizeof(dtrace_difv_t);
				nsz = ntlocals * sizeof(dtrace_difv_t);

				tlocals = vzalloc(nsz);

				if (osz != 0) {
					memcpy(tlocals, vstate->dtvs_tlocals,
					       osz);
					vfree(vstate->dtvs_tlocals);
				}

				vstate->dtvs_tlocals = tlocals;
				vstate->dtvs_ntlocals = ntlocals;
			}

			vstate->dtvs_tlocals[id] = *v;
			continue;

		case DIFV_SCOPE_LOCAL:
			np = &vstate->dtvs_nlocals;
			svarp = &vstate->dtvs_locals;

			if (v->dtdv_type.dtdt_flags & DIF_TF_BYREF)
				dsize = NR_CPUS *
					(v->dtdv_type.dtdt_size +
					 sizeof(uint64_t));
			else
				dsize = NR_CPUS * sizeof(uint64_t);

			break;

		case DIFV_SCOPE_GLOBAL:
			np = &vstate->dtvs_nglobals;
			svarp = &vstate->dtvs_globals;

			if (v->dtdv_type.dtdt_flags & DIF_TF_BYREF)
				dsize = v->dtdv_type.dtdt_size +
					sizeof(uint64_t);

			break;

		default:
			ASSERT(0);
			continue; /* not reached */
		}

		while (id >= (oldsvars = *np)) {
			dtrace_statvar_t	**statics;
			int			newsvars, oldsize, newsize;

			if ((newsvars = (oldsvars << 1)) == 0)
				newsvars = 1;

			oldsize = oldsvars * sizeof(dtrace_statvar_t *);
			newsize = newsvars * sizeof(dtrace_statvar_t *);

			statics = vzalloc(newsize);

			if (oldsize != 0) {
				memcpy(statics, *svarp, oldsize);
				vfree(*svarp);
			}

			*svarp = statics;
			*np = newsvars;
		}

		if ((svar = (*svarp)[id]) == NULL) {
			svar = kzalloc(sizeof(dtrace_statvar_t), GFP_KERNEL);
			svar->dtsv_var = *v;

			if ((svar->dtsv_size = dsize) != 0) {
				svar->dtsv_data =
					(uint64_t)(uintptr_t)vzalloc(dsize);
			}

			(*svarp)[id] = svar;
		}

		svar->dtsv_refcnt++;
	}

	dtrace_difo_chunksize(dp, vstate);
	dtrace_difo_hold(dp);
}

dtrace_difo_t * dtrace_difo_duplicate(dtrace_difo_t *dp,
				      dtrace_vstate_t *vstate)
{
	dtrace_difo_t	*new;
	size_t		sz;

	ASSERT(dp->dtdo_buf != NULL);
	ASSERT(dp->dtdo_refcnt != 0);

	new = kzalloc(sizeof(dtrace_difo_t), GFP_KERNEL);

	ASSERT(dp->dtdo_buf != NULL);
	sz = dp->dtdo_len * sizeof(dif_instr_t);
	new->dtdo_buf = vmalloc(sz);
	memcpy(new->dtdo_buf, dp->dtdo_buf, sz);
	new->dtdo_len = dp->dtdo_len;

	if (dp->dtdo_strtab != NULL) {
		ASSERT(dp->dtdo_strlen != 0);
		new->dtdo_strtab = vmalloc(dp->dtdo_strlen);
		memcpy(new->dtdo_strtab, dp->dtdo_strtab, dp->dtdo_strlen);
		new->dtdo_strlen = dp->dtdo_strlen;
	}

	if (dp->dtdo_inttab != NULL) {
		ASSERT(dp->dtdo_intlen != 0);
		sz = dp->dtdo_intlen * sizeof(uint64_t);
		new->dtdo_inttab = vmalloc(sz);
		memcpy(new->dtdo_inttab, dp->dtdo_inttab, sz);
		new->dtdo_intlen = dp->dtdo_intlen;
	}

	if (dp->dtdo_vartab != NULL) {
		ASSERT(dp->dtdo_varlen != 0);
		sz = dp->dtdo_varlen * sizeof(dtrace_difv_t);
		new->dtdo_vartab = vmalloc(sz);
		memcpy(new->dtdo_vartab, dp->dtdo_vartab, sz);
		new->dtdo_varlen = dp->dtdo_varlen;
	}

	dtrace_difo_init(new, vstate);

	return new;
}

void dtrace_difo_destroy(dtrace_difo_t *dp, dtrace_vstate_t *vstate)
{
	int	i;

	ASSERT(dp->dtdo_refcnt == 0);

	for (i = 0; i < dp->dtdo_varlen; i++) {
		dtrace_difv_t		*v = &dp->dtdo_vartab[i];
		dtrace_statvar_t	*svar, **svarp;
		uint_t			id;
		uint8_t			scope = v->dtdv_scope;
		int			*np;

		switch (scope) {
		case DIFV_SCOPE_THREAD:
			continue;

		case DIFV_SCOPE_LOCAL:
			np = &vstate->dtvs_nlocals;
			svarp = vstate->dtvs_locals;
			break;

		case DIFV_SCOPE_GLOBAL:
			np = &vstate->dtvs_nglobals;
			svarp = vstate->dtvs_globals;
			break;

		default:
			BUG();
		}

		if ((id = v->dtdv_id) < DIF_VAR_OTHER_UBASE)
			continue;

		id -= DIF_VAR_OTHER_UBASE;
		ASSERT(id < *np);

		svar = svarp[id];
		ASSERT(svar != NULL);
		ASSERT(svar->dtsv_refcnt > 0);

		if (--svar->dtsv_refcnt > 0)
			continue;

		if (svar->dtsv_size != 0) {
			ASSERT((void *)(uintptr_t)svar->dtsv_data != NULL);
			vfree((void *)(uintptr_t)svar->dtsv_data);
		}

		kfree(svar);
		svarp[id] = NULL;
	}

	vfree(dp->dtdo_buf);
        vfree(dp->dtdo_inttab);
        vfree(dp->dtdo_strtab);
        vfree(dp->dtdo_vartab);
        kfree(dp);
}

void dtrace_difo_release(dtrace_difo_t *dp, dtrace_vstate_t *vstate)
{
	int	i;

	ASSERT(MUTEX_HELD(&dtrace_lock));
	ASSERT(dp->dtdo_refcnt != 0);

	for (i = 0; i < dp->dtdo_varlen; i++) {
		dtrace_difv_t *v = &dp->dtdo_vartab[i];

		if (v->dtdv_id != DIF_VAR_VTIMESTAMP)
			continue;

		ASSERT(dtrace_vtime_references > 0);

		if (--dtrace_vtime_references == 0)
			dtrace_vtime_disable();
	}

	if (--dp->dtdo_refcnt == 0)
		dtrace_difo_destroy(dp, vstate);
}

/*
 * The key for a thread-local variable consists of the lower 63 bits of the
 * task pid, prefixed by a bit indicating whether an interrupt is active (1) or
 * not (0).
 * We add DIF_VARIABLE_MAX to the pid to assure that the thread key is never
 * equal to a variable identifier.  This is necessary (but not sufficient) to
 * assure that global associative arrays never collide with thread-local
 * variables.  To guarantee that they cannot collide, we must also define the
 * order for keying dynamic variables.  That order is:
 *
 *   [ key0 ] ... [ keyn ] [ variable-key ] [ tls-key ]
 *
 * Because the variable-key and the tls-key are in orthogonal spaces, there is
 * no way for a global variable key signature to match a thread-local key
 * signature.
 */
#define DTRACE_TLS_THRKEY(where)					\
	{								\
		uint_t	intr = in_irq() ? 1 : 0;			\
									\
		(where) = ((current->pid + DIF_VARIABLE_MAX) &		\
			   (((uint64_t)1 << 63) - 1)) |			\
			  ((uint64_t)intr << 63);			\
	}

#ifndef FIXME
# define DTRACE_ALIGNCHECK(addr, size, flags)
#endif

/*
 * Test whether a range of memory starting at testaddr of size testsz falls
 * within the range of memory described by addr, sz.  We take care to avoid
 * problems with overflow and underflow of the unsigned quantities, and
 * disallow all negative sizes.  Ranges of size 0 are allowed.
 */
#define DTRACE_INRANGE(testaddr, testsz, baseaddr, basesz) \
	((testaddr) - (baseaddr) < (basesz) && \
	 (testaddr) + (testsz) - (baseaddr) <= (basesz) && \
	 (testaddr) + (testsz) >= (testaddr))

#define DTRACE_LOADFUNC(bits)						\
	uint##bits##_t dtrace_load##bits(uintptr_t addr)		\
	{								\
		size_t			size = bits / NBBY;		\
		uint##bits##_t		rval;				\
		int			i;				\
		volatile uint16_t	*flags = (volatile uint16_t *)	\
			    &this_cpu_core->cpuc_dtrace_flags;		\
									\
		/*							\
		 * Deviation from the OpenSolaris code...  Protect	\
		 * against dereferencing the NULL pointer since that	\
		 * really causes us a lot of grief (crash).		\
		 */							\
		if (addr == 0) {					\
			*flags |= CPU_DTRACE_BADADDR;			\
			this_cpu_core->cpuc_dtrace_illval = addr;	\
			return 0;					\
		}							\
									\
		DTRACE_ALIGNCHECK(addr, size, flags);			\
									\
		for (i = 0; i < dtrace_toxranges; i++) {		\
			if (addr >= dtrace_toxrange[i].dtt_limit)	\
				continue;				\
									\
			if (addr + size <= dtrace_toxrange[i].dtt_base)	\
				continue;				\
									\
			/*						\
			 * This address falls within a toxic region.	\
			 */						\
			*flags |= CPU_DTRACE_BADADDR;			\
			this_cpu_core->cpuc_dtrace_illval = addr;	\
			return 0;					\
		}							\
									\
		*flags |= CPU_DTRACE_NOFAULT;				\
		rval = *((volatile uint##bits##_t *)addr);		\
		*flags &= ~CPU_DTRACE_NOFAULT;				\
									\
		return !(*flags & CPU_DTRACE_FAULT) ? rval : 0;		\
	}

#ifdef CONFIG_64BIT
# define dtrace_loadptr	dtrace_load64
#else
# define dtrace_loadptr	dtrace_load32
#endif

/*
 * Use the DTRACE_LOADFUNC macro to define functions for each of loading a
 * uint8_t, a uint16_t, a uint32_t and a uint64_t.
 */
DTRACE_LOADFUNC(8)
DTRACE_LOADFUNC(16)
DTRACE_LOADFUNC(32)
DTRACE_LOADFUNC(64)

#define DT_BSWAP_8(x)	((x) & 0xff)
#define DT_BSWAP_16(x)	((DT_BSWAP_8(x) << 8) | DT_BSWAP_8((x) >> 8))
#define DT_BSWAP_32(x)	((DT_BSWAP_16(x) << 16) | DT_BSWAP_16((x) >> 16))
#define DT_BSWAP_64(x)	((DT_BSWAP_32(x) << 32) | DT_BSWAP_32((x) >> 32))

static int dtrace_inscratch(uintptr_t dest, size_t size,
			    dtrace_mstate_t *mstate)
{
	if (dest < mstate->dtms_scratch_base)
		return 0;

	if (dest + size < dest)
		return 0;

	if (dest + size > mstate->dtms_scratch_ptr)
		return 0;

	return 1;
}

static int dtrace_canstore_statvar(uint64_t addr, size_t sz,
				   dtrace_statvar_t **svars, int nsvars)
{
	int i;

	for (i = 0; i < nsvars; i++) {
		dtrace_statvar_t	*svar = svars[i];

		if (svar == NULL || svar->dtsv_size == 0)
			continue;

		if (DTRACE_INRANGE(addr, sz, svar->dtsv_data, svar->dtsv_size))
			return 1;
	}

	return 0;
}

/*
 * Check to see if the address is within a memory region to which a store may
 * be issued.  This includes the DTrace scratch areas, and any DTrace variable
 * region.  The caller of dtrace_canstore() is responsible for performing any
 * alignment checks that are needed before stores are actually executed.
 */
static int dtrace_canstore(uint64_t addr, size_t sz, dtrace_mstate_t *mstate,
			   dtrace_vstate_t *vstate)
{
	/*
	 * First, check to see if the address is in scratch space...
	 */
	if (DTRACE_INRANGE(addr, sz, mstate->dtms_scratch_base,
			   mstate->dtms_scratch_size))
		return 1;

	/*
	 * Now check to see if it's a dynamic variable.  This check will pick
	 * up both thread-local variables and any global dynamically-allocated
	 * variables.
	 */
	if (DTRACE_INRANGE(addr, sz, (uintptr_t)vstate->dtvs_dynvars.dtds_base,
			   vstate->dtvs_dynvars.dtds_size)) {
		dtrace_dstate_t	*dstate = &vstate->dtvs_dynvars;
		uintptr_t	base = (uintptr_t)dstate->dtds_base +
				       (dstate->dtds_hashsize *
					sizeof(dtrace_dynhash_t));
		uintptr_t	chunkoffs;
		uint64_t	num;

		/*
		 * Before we assume that we can store here, we need to make
		 * sure that it isn't in our metadata -- storing to our
		 * dynamic variable metadata would corrupt our state.  For
		 * the range to not include any dynamic variable metadata,
		 * it must:
		 *
		 *      (1) Start above the hash table that is at the base of
		 *      the dynamic variable space
		 *
		 *      (2) Have a starting chunk offset that is beyond the
		 *      dtrace_dynvar_t that is at the base of every chunk
		 *
		 *      (3) Not span a chunk boundary
		 */
		if (addr < base)
			return 0;

		num = addr - base;
		chunkoffs = do_div(num, dstate->dtds_chunksize);

		if (chunkoffs < sizeof(dtrace_dynvar_t))
			return 0;

		if (chunkoffs + sz > dstate->dtds_chunksize)
			return 0;

		return 1;
	}

	/*
	 * Finally, check the static local and global variables.  These checks
	 * take the longest, so we perform them last.
	 */
	if (dtrace_canstore_statvar(addr, sz, vstate->dtvs_locals,
				    vstate->dtvs_nlocals))
		return 1;

	if (dtrace_canstore_statvar(addr, sz, vstate->dtvs_globals,
				    vstate->dtvs_nglobals))
		return 1;

	return 0;
}

/*
 * Convenience routine to check to see if the address is within a memory
 * region in which a load may be issued given the user's privilege level;
 * if not, it sets the appropriate error flags and loads 'addr' into the
 * illegal value slot.
 *
 * DTrace subroutines (DIF_SUBR_*) should use this helper to implement
 * appropriate memory access protection.
 */
static int
dtrace_canload(uint64_t addr, size_t sz, dtrace_mstate_t *mstate,
	       dtrace_vstate_t *vstate)
{
	volatile uintptr_t	*illval = &this_cpu_core->cpuc_dtrace_illval;

	/*
	 * If we hold the privilege to read from kernel memory, then
	 * everything is readable.
	 */
	if ((mstate->dtms_access & DTRACE_ACCESS_KERNEL) != 0)
		return 1;

	/*
	 * You can obviously read that which you can store.
	 */
	if (dtrace_canstore(addr, sz, mstate, vstate))
		return 1;

	/*
	 * We're allowed to read from our own string table.
	 */
	if (DTRACE_INRANGE(addr, sz, (uintptr_t)mstate->dtms_difo->dtdo_strtab,
			   mstate->dtms_difo->dtdo_strlen))
		return 1;

	DTRACE_CPUFLAG_SET(CPU_DTRACE_KPRIV);
	*illval = addr;

	return 0;
}

/*
 * Convenience routine to check to see if a given string is within a memory
 * region in which a load may be issued given the user's privilege level;
 * this exists so that we don't need to issue unnecessary dtrace_strlen()
 * calls in the event that the user has all privileges.
 */
static int
dtrace_strcanload(uint64_t addr, size_t sz, dtrace_mstate_t *mstate,
    dtrace_vstate_t *vstate)
{
	size_t	strsz;

	/*
	 * If we hold the privilege to read from kernel memory, then
	 * everything is readable.
	 */
	if ((mstate->dtms_access & DTRACE_ACCESS_KERNEL) != 0)
		return 1;

	strsz = 1 + dtrace_strlen((char *)(uintptr_t)addr, sz);
	if (dtrace_canload(addr, strsz, mstate, vstate))
		return 1;

	return 0;
}

/*
 * Convenience routine to check to see if a given variable is within a memory
 * region in which a load may be issued given the user's privilege level.
 */
int dtrace_vcanload(void *src, dtrace_diftype_t *type, dtrace_mstate_t *mstate,
		    dtrace_vstate_t *vstate)
{
	size_t	sz;

	ASSERT(type->dtdt_flags & DIF_TF_BYREF);

	/*
	 * If we hold the privilege to read from kernel memory, then
	 * everything is readable.
	 */
	if ((mstate->dtms_access & DTRACE_ACCESS_KERNEL) != 0)
		return 1;

	if (type->dtdt_kind == DIF_TYPE_STRING)
		sz = dtrace_strlen(
			src,
			vstate->dtvs_state->dts_options[DTRACEOPT_STRSIZE]
		     ) + 1;
	else
		sz = type->dtdt_size;

	return dtrace_canload((uintptr_t)src, sz, mstate, vstate);
}

/*
 * Copy src to dst using safe memory accesses.  The src is assumed to be unsafe
 * memory specified by the DIF program.  The dst is assumed to be safe memory
 * that we can store to directly because it is managed by DTrace.  As with
 * standard bcopy, overlapping copies are handled properly.
 */
static void dtrace_bcopy(const void *src, void *dst, size_t len)
{
	if (len != 0) {
		uint8_t		*s1 = dst;
		const uint8_t	*s2 = src;

		if (s1 <= s2) {
			do {
				*s1++ = dtrace_load8((uintptr_t)s2++);
			} while (--len != 0);
		} else {
			s2 += len;
			s1 += len;

			do {
				*--s1 = dtrace_load8((uintptr_t)--s2);
			} while (--len != 0);
		}
	}
}

/*
 * Copy src to dst using safe memory accesses, up to either the specified
 * length, or the point that a nul byte is encountered.  The src is assumed to
 * be unsafe memory specified by the DIF program.  The dst is assumed to be
 * safe memory that we can store to directly because it is managed by DTrace.
 * Unlike dtrace_bcopy(), overlapping regions are not handled.
 */
static void dtrace_strcpy(const void *src, void *dst, size_t len)
{
	if (len != 0) {
		uint8_t		*s1 = dst, c;
		const uint8_t	*s2 = src;

		do {
			*s1++ = c = dtrace_load8((uintptr_t)s2++);
		} while (--len != 0 && c != '\0');
	}
}
/*
 * Copy src to dst, deriving the size and type from the specified (BYREF)
 * variable type.  The src is assumed to be unsafe memory specified by the DIF
 * program.  The dst is assumed to be DTrace variable memory that is of the
 * specified type; we assume that we can store to directly.
 */
static void dtrace_vcopy(void *src, void *dst, dtrace_diftype_t *type)
{
	ASSERT(type->dtdt_flags & DIF_TF_BYREF);

	if (type->dtdt_kind == DIF_TYPE_STRING)
		dtrace_strcpy(src, dst, type->dtdt_size);
	else
		dtrace_bcopy(src, dst, type->dtdt_size);
}

/*
 * Compare s1 to s2 using safe memory accesses.  The s1 data is assumed to be
 * unsafe memory specified by the DIF program.  The s2 data is assumed to be
 * safe memory that we can access directly because it is managed by DTrace.
 */
static int dtrace_bcmp(const void *s1, const void *s2, size_t len)
{
	volatile uint16_t	*flags;

	flags = (volatile uint16_t *)&this_cpu_core->cpuc_dtrace_flags;

	if (s1 == s2)
		return 0;

	if (s1 == NULL || s2 == NULL)
		return 1;

	if (s1 != s2 && len != 0) {
		const uint8_t	*ps1 = s1;
		const uint8_t	*ps2 = s2;

		do {
			if (dtrace_load8((uintptr_t)ps1++) != *ps2++)
				return 1;
		} while (--len != 0 && !(*flags & CPU_DTRACE_FAULT));
	}

	return 0;
}

/*
 * Zero the specified region using a simple byte-by-byte loop.  Note that this
 * is for safe DTrace-managed memory only.
 */
void dtrace_bzero(void *dst, size_t len)
{
	uchar_t	*cp;

	for (cp = dst; len != 0; len--)
		*cp++ = 0;
}

#define DTRACE_DYNHASH_FREE	0
#define DTRACE_DYNHASH_SINK	1
#define DTRACE_DYNHASH_VALID	2

/*
 * Depending on the value of the op parameter, this function looks-up,
 * allocates or deallocates an arbitrarily-keyed dynamic variable.  If an
 * allocation is requested, this function will return a pointer to a
 * dtrace_dynvar_t corresponding to the allocated variable -- or NULL if no
 * variable can be allocated.  If NULL is returned, the appropriate counter
 * will be incremented.
 */
static dtrace_dynvar_t *dtrace_dynvar(dtrace_dstate_t *dstate, uint_t nkeys,
				      dtrace_key_t *key, size_t dsize,
				      dtrace_dynvar_op_t op,
				      dtrace_mstate_t *mstate,
				      dtrace_vstate_t *vstate)
{
	uint64_t		hashval = DTRACE_DYNHASH_VALID;
	dtrace_dynhash_t	*hash = dstate->dtds_hash;
	dtrace_dynvar_t		*free, *new_free, *next, *dvar, *start,
				*prev = NULL;
	processorid_t		me = smp_processor_id(), cpu = me;
	dtrace_dstate_percpu_t	*dcpu = &dstate->dtds_percpu[me];
	size_t			bucket, ksize;
	size_t			chunksize = dstate->dtds_chunksize;
	uintptr_t		kdata, lock;
	dtrace_dstate_state_t	nstate;
	uint_t			i;

        ASSERT(nkeys != 0);

	/*
	 * Hash the key.  As with aggregations, we use Jenkins' "One-at-a-time"
	 * algorithm.  For the by-value portions, we perform the algorithm in
	 * 16-bit chunks (as opposed to 8-bit chunks).  This speeds things up a
	 * bit, and seems to have only a minute effect on distribution.  For
	 * the by-reference data, we perform "One-at-a-time" iterating (safely)
	 * over each referenced byte.  It's painful to do this, but it's much
	 * better than pathological hash distribution.  The efficacy of the
	 * hashing algorithm (and a comparison with other algorithms) may be
	 * found by running the ::dtrace_dynstat MDB dcmd.
	 */
	for (i = 0; i < nkeys; i++) {
		if (key[i].dttk_size == 0) {
			uint64_t	val = key[i].dttk_value;

			hashval += (val >> 48) & 0xffff;
			hashval += (hashval << 10);
			hashval ^= (hashval >> 6);

			hashval += (val >> 32) & 0xffff;
			hashval += (hashval << 10);
			hashval ^= (hashval >> 6);

			hashval += (val >> 16) & 0xffff;
			hashval += (hashval << 10);
			hashval ^= (hashval >> 6);

			hashval += val & 0xffff;
			hashval += (hashval << 10);
			hashval ^= (hashval >> 6);
		} else {
			/*
			 * This is incredibly painful, but it beats the hell
			 * out of the alternative.
			 */
			uint64_t	j, size = key[i].dttk_size;
			uintptr_t	base = (uintptr_t)key[i].dttk_value;

			if (!dtrace_canload(base, size, mstate, vstate))
				break;

			for (j = 0; j < size; j++) {
				hashval += dtrace_load8(base + j);
				hashval += (hashval << 10);
				hashval ^= (hashval >> 6);
			}
		}
	}

	if (DTRACE_CPUFLAG_ISSET(CPU_DTRACE_FAULT))
		return NULL;

	hashval += (hashval << 3);
	hashval ^= (hashval >> 11);
	hashval += (hashval << 15);

	/*
	 * There is a remote chance (ideally, 1 in 2^31) that our hashval
	 * comes out to be one of our two sentinel hash values.  If this
	 * actually happens, we set the hashval to be a value known to be a
	 * non-sentinel value.
	 */
	if (hashval == DTRACE_DYNHASH_FREE || hashval == DTRACE_DYNHASH_SINK)
		hashval = DTRACE_DYNHASH_VALID;

	/*
	 * Yes, it's painful to do a divide here.  If the cycle count becomes
	 * important here, tricks can be pulled to reduce it.  (However, it's
	 * critical that hash collisions be kept to an absolute minimum;
	 * they're much more painful than a divide.)  It's better to have a
	 * solution that generates few collisions and still keeps things
	 * relatively simple.
	 *
	 * Linux cannot do a straight 64-bit divide without gcc requiring
	 * linking in code that the kernel doesn't link, so we need to use an
	 * alternative.
	 *
	 *	bucket = hashval % dstate->dtds_hashsize;
	 */
	{
	    uint64_t	num;

	    num = hashval;
	    bucket = do_div(num, dstate->dtds_hashsize);
	}

	if (op == DTRACE_DYNVAR_DEALLOC) {
		volatile uintptr_t	*lockp = &hash[bucket].dtdh_lock;

		for (;;) {
			while ((lock = *lockp) & 1)
				continue;

			if (cmpxchg(lockp, lock, (lock + 1)) == lock)
				break;
		}

		dtrace_membar_producer();
	}

top:
	prev = NULL;
	lock = hash[bucket].dtdh_lock;

	dtrace_membar_consumer();

	start = hash[bucket].dtdh_chain;
	ASSERT(start != NULL && (start->dtdv_hashval == DTRACE_DYNHASH_SINK ||
	       start->dtdv_hashval != DTRACE_DYNHASH_FREE ||
	       op != DTRACE_DYNVAR_DEALLOC));

	for (dvar = start; dvar != NULL; dvar = dvar->dtdv_next) {
		dtrace_tuple_t	*dtuple = &dvar->dtdv_tuple;
		dtrace_key_t	*dkey = &dtuple->dtt_key[0];

		if (dvar->dtdv_hashval != hashval) {
			if (dvar->dtdv_hashval == DTRACE_DYNHASH_SINK) {
				/*
				 * We've reached the sink, and therefore the
				 * end of the hash chain; we can kick out of
				 * the loop knowing that we have seen a valid
				 * snapshot of state.
				 */
				ASSERT(dvar->dtdv_next == NULL);
				ASSERT(dvar == &dtrace_dynhash_sink);
				break;
			}

			if (dvar->dtdv_hashval == DTRACE_DYNHASH_FREE) {
				/*
				 * We've gone off the rails:  somewhere along
				 * the line, one of the members of this hash
				 * chain was deleted.  Note that we could also
				 * detect this by simply letting this loop run
				 * to completion, as we would eventually hit
				 * the end of the dirty list.  However, we
				 * want to avoid running the length of the
				 * dirty list unnecessarily (it might be quite
				 * long), so we catch this as early as
				 * possible by detecting the hash marker.  In
				 * this case, we simply set dvar to NULL and
				 * break; the conditional after the loop will
				 * send us back to top.
				 */
				dvar = NULL;
				break;
			}

			goto next;
		}

		if (dtuple->dtt_nkeys != nkeys)
			goto next;

		for (i = 0; i < nkeys; i++, dkey++) {
			if (dkey->dttk_size != key[i].dttk_size)
				goto next;	/* size or type mismatch */

			if (dkey->dttk_size != 0) {
				if (dtrace_bcmp(
					  (void *)(uintptr_t)key[i].dttk_value,
					  (void *)(uintptr_t)dkey->dttk_value,
					  dkey->dttk_size))
					goto next;
			} else {
				if (dkey->dttk_value != key[i].dttk_value)
					goto next;
			}
		}

		if (op != DTRACE_DYNVAR_DEALLOC)
			return dvar;

		ASSERT(dvar->dtdv_next == NULL ||
		dvar->dtdv_next->dtdv_hashval != DTRACE_DYNHASH_FREE);

		if (prev != NULL) {
			ASSERT(hash[bucket].dtdh_chain != dvar);
			ASSERT(start != dvar);
			ASSERT(prev->dtdv_next == dvar);
			prev->dtdv_next = dvar->dtdv_next;
		} else {
			if (cmpxchg(&hash[bucket].dtdh_chain, start,
				    dvar->dtdv_next) != start) {
				/*
				 * We have failed to atomically swing the
				 * hash table head pointer, presumably because
				 * of a conflicting allocation on another CPU.
				 * We need to reread the hash chain and try
				 * again.
				 */
				goto top;
			}
		}

		dtrace_membar_producer();

		/*
		 * Now set the hash value to indicate that it's free.
		 */
		ASSERT(hash[bucket].dtdh_chain != dvar);
		dvar->dtdv_hashval = DTRACE_DYNHASH_FREE;

		dtrace_membar_producer();

		/*
		 * Set the next pointer to point at the dirty list, and
		 * atomically swing the dirty pointer to the newly freed dvar.
		 */
		do {
			next = dcpu->dtdsc_dirty;
			dvar->dtdv_next = next;
		} while (cmpxchg(&dcpu->dtdsc_dirty, next, dvar) != next);

		/*
		 * Finally, unlock this hash bucket.
		 */
		ASSERT(hash[bucket].dtdh_lock == lock);
		ASSERT(lock & 1);
		hash[bucket].dtdh_lock++;

		return NULL;
next:
		prev = dvar;
		continue;
	}

	if (dvar == NULL) {
		/*
		 * If dvar is NULL, it is because we went off the rails:
		 * one of the elements that we traversed in the hash chain
		 * was deleted while we were traversing it.  In this case,
		 * we assert that we aren't doing a dealloc (deallocs lock
		 * the hash bucket to prevent themselves from racing with
		 * one another), and retry the hash chain traversal.
		 */
		ASSERT(op != DTRACE_DYNVAR_DEALLOC);
		goto top;
	}

	if (op != DTRACE_DYNVAR_ALLOC) {
		/*
		 * If we are not to allocate a new variable, we want to
		 * return NULL now.  Before we return, check that the value
		 * of the lock word hasn't changed.  If it has, we may have
		 * seen an inconsistent snapshot.
		 */
		if (op == DTRACE_DYNVAR_NOALLOC) {
			if (hash[bucket].dtdh_lock != lock)
				goto top;
		} else {
			ASSERT(op == DTRACE_DYNVAR_DEALLOC);
			ASSERT(hash[bucket].dtdh_lock == lock);
			ASSERT(lock & 1);
			hash[bucket].dtdh_lock++;
		}

		return NULL;
	}

	/*
	 * We need to allocate a new dynamic variable.  The size we need is the
	 * size of dtrace_dynvar plus the size of nkeys dtrace_key_t's plus the
	 * size of any auxiliary key data (rounded up to 8-byte alignment) plus
	 * the size of any referred-to data (dsize).  We then round the final
	 * size up to the chunksize for allocation.
	 */
	for (ksize = 0, i = 0; i < nkeys; i++)
		ksize += P2ROUNDUP(key[i].dttk_size, sizeof(uint64_t));

	/*
	 * This should be pretty much impossible, but could happen if, say,
	 * strange DIF specified the tuple.  Ideally, this should be an
	 * assertion and not an error condition -- but that requires that the
	 * chunksize calculation in dtrace_difo_chunksize() be absolutely
	 * bullet-proof.  (That is, it must not be able to be fooled by
	 * malicious DIF.)  Given the lack of backwards branches in DIF,
	 * solving this would presumably not amount to solving the Halting
	 * Problem -- but it still seems awfully hard.
	 */
	if (sizeof(dtrace_dynvar_t) + sizeof(dtrace_key_t) * (nkeys - 1) +
	    ksize + dsize > chunksize) {
		dcpu->dtdsc_drops++;
		return NULL;
	}

	nstate = DTRACE_DSTATE_EMPTY;

	do {
retry:
		free = dcpu->dtdsc_free;

		if (free == NULL) {
			dtrace_dynvar_t	*clean = dcpu->dtdsc_clean;
			void		*rval;

			if (clean == NULL) {
				/*
				 * We're out of dynamic variable space on
				 * this CPU.  Unless we have tried all CPUs,
				 * we'll try to allocate from a different
				 * CPU.
				 */
				switch (dstate->dtds_state) {
				case DTRACE_DSTATE_CLEAN: {
					dtrace_dstate_state_t	*sp =
						(dtrace_dstate_state_t *)
							&dstate->dtds_state;

					if (++cpu >= NR_CPUS)
						cpu = 0;

					if (dcpu->dtdsc_dirty != NULL &&
					    nstate == DTRACE_DSTATE_EMPTY)
						nstate = DTRACE_DSTATE_DIRTY;

					if (dcpu->dtdsc_rinsing != NULL)
						nstate = DTRACE_DSTATE_RINSING;

					dcpu = &dstate->dtds_percpu[cpu];

					if (cpu != me)
						goto retry;

					cmpxchg(sp, DTRACE_DSTATE_CLEAN,
						nstate);

					/*
					 * To increment the correct bean
					 * counter, take another lap.
					 */
					goto retry;
				}

				case DTRACE_DSTATE_DIRTY:
					dcpu->dtdsc_dirty_drops++;
					break;

				case DTRACE_DSTATE_RINSING:
					dcpu->dtdsc_rinsing_drops++;
					break;

				case DTRACE_DSTATE_EMPTY:
					dcpu->dtdsc_drops++;
					break;
				}

				DTRACE_CPUFLAG_SET(CPU_DTRACE_DROP);
				return NULL;
			}

			/*
			 * The clean list appears to be non-empty.  We want to
			 * move the clean list to the free list; we start by
			 * moving the clean pointer aside.
			 */
			if (cmpxchg(&dcpu->dtdsc_clean, clean, NULL) != clean)
				/*
				 * We are in one of two situations:
				 *
				 *  (a) The clean list was switched to the
				 *      free list by another CPU.
				 *
				 *  (b) The clean list was added to by the
				 *      cleansing cyclic.
				 *
				 * In either of these situations, we can
				 * just reattempt the free list allocation.
				 */
				goto retry;

			ASSERT(clean->dtdv_hashval == DTRACE_DYNHASH_FREE);

			/*
			 * Now we'll move the clean list to the free list.
			 * It's impossible for this to fail:  the only way
			 * the free list can be updated is through this
			 * code path, and only one CPU can own the clean list.
			 * Thus, it would only be possible for this to fail if
			 * this code were racing with dtrace_dynvar_clean().
			 * (That is, if dtrace_dynvar_clean() updated the clean
			 * list, and we ended up racing to update the free
			 * list.)  This race is prevented by the dtrace_sync()
			 * in dtrace_dynvar_clean() -- which flushes the
			 * owners of the clean lists out before resetting
			 * the clean lists.
			 */
			rval = cmpxchg(&dcpu->dtdsc_free, NULL, clean);
			ASSERT(rval == NULL);

			goto retry;
		}

		dvar = free;
		new_free = dvar->dtdv_next;
	} while (cmpxchg(&dcpu->dtdsc_free, free, new_free) != free);

	/*
	 * We have now allocated a new chunk.  We copy the tuple keys into the
	 * tuple array and copy any referenced key data into the data space
	 * following the tuple array.  As we do this, we relocate dttk_value
	 * in the final tuple to point to the key data address in the chunk.
	 */
	kdata = (uintptr_t)&dvar->dtdv_tuple.dtt_key[nkeys];
	dvar->dtdv_data = (void *)(kdata + ksize);
	dvar->dtdv_tuple.dtt_nkeys = nkeys;

	for (i = 0; i < nkeys; i++) {
		dtrace_key_t	*dkey = &dvar->dtdv_tuple.dtt_key[i];
		size_t		kesize = key[i].dttk_size;

		if (kesize != 0) {
			dtrace_bcopy(
				(const void *)(uintptr_t)key[i].dttk_value,
				(void *)kdata, kesize);
			dkey->dttk_value = kdata;
			kdata += P2ROUNDUP(kesize, sizeof(uint64_t));
		} else
			dkey->dttk_value = key[i].dttk_value;

		dkey->dttk_size = kesize;
	}

	ASSERT(dvar->dtdv_hashval == DTRACE_DYNHASH_FREE);
	dvar->dtdv_hashval = hashval;
	dvar->dtdv_next = start;

	if (cmpxchg(&hash[bucket].dtdh_chain, start, dvar) == start)
		return dvar;

	/*
	 * The cas has failed.  Either another CPU is adding an element to
	 * this hash chain, or another CPU is deleting an element from this
	 * hash chain.  The simplest way to deal with both of these cases
	 * (though not necessarily the most efficient) is to free our
	 * allocated block and tail-call ourselves.  Note that the free is
	 * to the dirty list and _not_ to the free list.  This is to prevent
	 * races with allocators, above.
	 */
	dvar->dtdv_hashval = DTRACE_DYNHASH_FREE;

	dtrace_membar_producer();

	do {
		free = dcpu->dtdsc_dirty;
		dvar->dtdv_next = free;
	} while (cmpxchg(&dcpu->dtdsc_dirty, free, dvar) != free);

	return dtrace_dynvar(dstate, nkeys, key, dsize, op, mstate, vstate);
}

/*
 * Return a string.  In the event that the user lacks the privilege to access
 * arbitrary kernel memory, we copy the string out to scratch memory so that we
 * don't fail access checking.
 *
 * dtrace_dif_variable() uses this routine as a helper for various
 * builtin values such as 'execname' and 'probefunc.'
 */
static uintptr_t dtrace_dif_varstr(uintptr_t addr, dtrace_state_t *state,
				   dtrace_mstate_t *mstate)
{
	uint64_t	size = state->dts_options[DTRACEOPT_STRSIZE];
	uintptr_t	ret;
	size_t		strsz;

	/*
	 * The easy case: this probe is allowed to read all of memory, so
	 * we can just return this as a vanilla pointer.
	 */
	if ((mstate->dtms_access & DTRACE_ACCESS_KERNEL) != 0)
		return addr;

	/*
	 * This is the tougher case: we copy the string in question from
	 * kernel memory into scratch memory and return it that way: this
	 * ensures that we won't trip up when access checking tests the
	 * BYREF return value.
	 */
	strsz = dtrace_strlen((char *)addr, size) + 1;

	if (mstate->dtms_scratch_ptr + strsz >
	    mstate->dtms_scratch_base + mstate->dtms_scratch_size) {
		DTRACE_CPUFLAG_SET(CPU_DTRACE_NOSCRATCH);
		return (uintptr_t)NULL;
	}

	dtrace_strcpy((const void *)addr, (void *)mstate->dtms_scratch_ptr,
		      strsz);
	ret = mstate->dtms_scratch_ptr;
	mstate->dtms_scratch_ptr += strsz;

	return ret;
}

/*
 * This function implements the DIF emulator's variable lookups.  The emulator
 * passes a reserved variable identifier and optional built-in array index.
 *
 * This function is annotated to be always inlined in dtrace_dif_emulate()
 * because (1) that is the only place where it is called from, and (2) it has
 * come to our attention that some GCC versions inline it automatically while
 * others do not and that messes up the number of frames to skip (aframes).
 */
static uint64_t __always_inline dtrace_dif_variable(dtrace_mstate_t *mstate,
						    dtrace_state_t *state,
						    uint64_t v, uint64_t ndx)
{
	/*
	 * If we're accessing one of the uncached arguments, we'll turn this
	 * into a reference in the args array.
	 */
	if (v >= DIF_VAR_ARG0 && v <= DIF_VAR_ARG9) {
		ndx = v - DIF_VAR_ARG0;
		v = DIF_VAR_ARGS;
	}

	switch (v) {
	case DIF_VAR_ARGS:
		ASSERT(mstate->dtms_present & DTRACE_MSTATE_ARGS);

		if (ndx >=
		    sizeof(mstate->dtms_arg) / sizeof(mstate->dtms_arg[0])) {
			int			aframes =
					mstate->dtms_probe->dtpr_aframes + 1;
			dtrace_provider_t	*pv;
			uint64_t		val;

			pv = mstate->dtms_probe->dtpr_provider;
			if (pv->dtpv_pops.dtps_getargval != NULL)
				val = pv->dtpv_pops.dtps_getargval(
					pv->dtpv_arg,
					mstate->dtms_probe->dtpr_id,
					mstate->dtms_probe->dtpr_arg,
					ndx, aframes);
			else
				val = dtrace_getarg(ndx, aframes);

			/*
			 * This is regrettably required to keep the compiler
			 * from tail-optimizing the call to dtrace_getarg().
			 * The condition always evaluates to true, but the
			 * compiler has no way of figuring that out a priori.
			 * (None of this would be necessary if the compiler
			 * could be relied upon to _always_ tail-optimize
			 * the call to dtrace_getarg() -- but it can't.)
			 */
			if (mstate->dtms_probe != NULL)
				return val;

			ASSERT(0);
		}

		return mstate->dtms_arg[ndx];

	case DIF_VAR_UREGS: {
		if (!dtrace_priv_proc(state))
			return 0;

		return dtrace_getreg(current, ndx);
	}

	case DIF_VAR_CURTHREAD:
		if (!dtrace_priv_kernel(state))
			return 0;

		return (uint64_t)(uintptr_t)current;

	case DIF_VAR_TIMESTAMP:
		if (!(mstate->dtms_present & DTRACE_MSTATE_TIMESTAMP)) {
			mstate->dtms_timestamp = current->dtrace_start;
			mstate->dtms_present |= DTRACE_MSTATE_TIMESTAMP;
		}

		return ktime_to_ns(mstate->dtms_timestamp);

	case DIF_VAR_WALLTIMESTAMP:
		return ktime_to_ns(dtrace_get_walltime());

	case DIF_VAR_VTIMESTAMP:
		ASSERT(dtrace_vtime_references != 0);

		return ktime_to_ns(current->dtrace_vtime);

	case DIF_VAR_IPL:
		if (!dtrace_priv_kernel(state))
			return 0;

		if (!(mstate->dtms_present & DTRACE_MSTATE_IPL)) {
			mstate->dtms_ipl = dtrace_getipl();
			mstate->dtms_present |= DTRACE_MSTATE_IPL;
		}

		return mstate->dtms_ipl;

	case DIF_VAR_EPID:
		ASSERT(mstate->dtms_present & DTRACE_MSTATE_EPID);
		ASSERT(mstate->dtms_present & DTRACE_MSTATE_EPID);

		return mstate->dtms_epid;

	case DIF_VAR_ID:
		ASSERT(mstate->dtms_present & DTRACE_MSTATE_PROBE);
		return mstate->dtms_probe->dtpr_id;

	case DIF_VAR_STACKDEPTH:
		if (!dtrace_priv_kernel(state))
			return 0;
		if (!(mstate->dtms_present & DTRACE_MSTATE_STACKDEPTH)) {
			int	aframes = mstate->dtms_probe->dtpr_aframes + 2;

			mstate->dtms_stackdepth = dtrace_getstackdepth(
							mstate, aframes);
			mstate->dtms_present |= DTRACE_MSTATE_STACKDEPTH;
		}

		return mstate->dtms_stackdepth;

	case DIF_VAR_USTACKDEPTH:
		if (!dtrace_priv_proc(state))
			return 0;

		if (!(mstate->dtms_present & DTRACE_MSTATE_USTACKDEPTH)) {
			/*
			 * See comment in DIF_VAR_PID.
			 */
			if (DTRACE_ANCHORED(mstate->dtms_probe) &&
			    in_interrupt())
				mstate->dtms_ustackdepth = 0;
			else
				mstate->dtms_ustackdepth =
					dtrace_getustackdepth();

			mstate->dtms_present |= DTRACE_MSTATE_USTACKDEPTH;
		}

		return mstate->dtms_ustackdepth;

	case DIF_VAR_CALLER:
		if (!dtrace_priv_kernel(state))
			return 0;

		if (!(mstate->dtms_present & DTRACE_MSTATE_CALLER)) {
			int	aframes = mstate->dtms_probe->dtpr_aframes + 1;

			if (!DTRACE_ANCHORED(mstate->dtms_probe)) {
				/*
				 * If this is an unanchored probe, we are
				 * required to go through the slow path:
				 * dtrace_caller() only guarantees correct
				 * results for anchored probes.
				 */
				uint64_t	caller[2];

				dtrace_getpcstack(caller, 2, aframes,
					(uint32_t *)(uintptr_t)
							mstate->dtms_arg[0]);
				mstate->dtms_caller = caller[1];
			} else if ((mstate->dtms_caller =
					dtrace_caller(aframes, 0)) == -1) {
				/*
				 * We have failed to do this the quick way;
				 * we must resort to the slower approach of
				 * calling dtrace_getpcstack().
				 */
				uint64_t	caller;

				dtrace_getpcstack(&caller, 1, aframes, NULL);
				mstate->dtms_caller = caller;
			}

			mstate->dtms_present |= DTRACE_MSTATE_CALLER;
		}

		return mstate->dtms_caller;

	case DIF_VAR_UCALLER:
		if (!dtrace_priv_proc(state))
			return 0;

		if (!(mstate->dtms_present & DTRACE_MSTATE_UCALLER)) {
			uint64_t	ustack[4];

			/*
			 * dtrace_getupcstack() fills in the first uint64_t with
			 * the current PID, and the second uint64_t with the
			 * current TGID.  The third uint64_t will be the
			 * program counter at user-level.  The fourth uint64_t
			 * will contain the caller, which is what we're after.
			 */
			ustack[3] = 0;
			dtrace_getupcstack(ustack, 4);

			mstate->dtms_ucaller = ustack[3];
			mstate->dtms_present |= DTRACE_MSTATE_UCALLER;
		}

		return mstate->dtms_ucaller;

	case DIF_VAR_PROBEPROV:
		ASSERT(mstate->dtms_present & DTRACE_MSTATE_PROBE);

		return dtrace_dif_varstr(
			(uintptr_t)mstate->dtms_probe->dtpr_provider->dtpv_name,
			state, mstate);

	case DIF_VAR_PROBEMOD:
		ASSERT(mstate->dtms_present & DTRACE_MSTATE_PROBE);
		return dtrace_dif_varstr(
			(uintptr_t)mstate->dtms_probe->dtpr_mod, state,
			mstate);

	case DIF_VAR_PROBEFUNC:
		ASSERT(mstate->dtms_present & DTRACE_MSTATE_PROBE);

		return dtrace_dif_varstr(
			(uintptr_t)mstate->dtms_probe->dtpr_func, state,
			mstate);

	case DIF_VAR_PROBENAME:
		ASSERT(mstate->dtms_present & DTRACE_MSTATE_PROBE);

		return dtrace_dif_varstr(
			(uintptr_t)mstate->dtms_probe->dtpr_name, state,
			mstate);

	case DIF_VAR_PID:
		if (!dtrace_priv_proc(state))
			return 0;

		/*
		 * It is always safe to dereference current, it always points
		 * to a valid task_struct.
		 */
		return (uint64_t)current->tgid;

	case DIF_VAR_PPID:
		if (!dtrace_priv_proc(state))
			return 0;

		/*
		 * It is always safe to dereference current, it always points
		 * to a valid task_struct.
		 *
		 * Additionally, it is safe to dereference one's parent, since
		 * it is never NULL after process birth.
		 */
		return (uint64_t)current->real_parent->tgid;

	case DIF_VAR_TID:
		return (uint64_t)current->pid;

	case DIF_VAR_EXECNAME:
		if (!dtrace_priv_proc(state))
			return 0;

		/*
		 * It is always safe to dereference current, it always points
		 * to a valid task_struct.
		 */
		return dtrace_dif_varstr((uintptr_t)current->comm, state,
					 mstate);

	case DIF_VAR_ZONENAME:
		return 0;

	case DIF_VAR_UID:
		if (!dtrace_priv_proc(state))
			return 0;

		/*
		 * It is always safe to dereference current, it always points
		 * to a valid task_struct.
		 *
		 * Additionally, it is safe to dereference one's own process
		 * credential, since this is never NULL after process birth.
		 */
		return (uint64_t)from_kuid(current_user_ns(),
					   current_real_cred()->uid);

	case DIF_VAR_GID:
		if (!dtrace_priv_proc(state))
			return 0;

		/*
		 * It is always safe to dereference current, it always points
		 * to a valid task_struct.
		 *
		 * Additionally, it is safe to dereference one's own process
		 * credential, since this is never NULL after process birth.
		 */
		return (uint64_t)from_kgid(current_user_ns(),
					   current_real_cred()->gid);

	case DIF_VAR_ERRNO: {
		int64_t	arg0;

		ASSERT(mstate->dtms_present & DTRACE_MSTATE_PROBE);

		if (!dtrace_priv_proc(state))
			return 0;

		/*
		 * We need to do some magic here to get the correct semantics
		 * for the 'errno' variable.  It can only have a non-zero value
		 * when executing a system call, and for Linux, only after the
		 * actual system call implementation has completed, indicating
		 * in its return value either an error code (-2048 < errno < 0)
		 * or a valid result.  So, the only time we can expect a valid
		 * value in errno is during the processing of any return probe
		 * in the syscall provider.  In all other cases, it should have
		 * the value 0.
		 *
		 * So, we only look at probes that match: syscall:::return
		 */
		if (strncmp(mstate->dtms_probe->dtpr_provider->dtpv_name,
			    "syscall", 7) != 0)
			return 0;
		if (strncmp(mstate->dtms_probe->dtpr_name, "return", 6) != 0)
			return 0;

		/*
		 * Error number is present if arg0 lies between 0 and -2048,
		 * exclusive.
		 */
		arg0 = (int64_t)mstate->dtms_arg[ndx];
		if (arg0 < 0 && arg0 > -2048)
			return (uint64_t)-arg0;

		return 0;
	}

	case DIF_VAR_CURCPU:
		return (uint64_t)(uintptr_t)this_cpu_info;

	default:
		DTRACE_CPUFLAG_SET(CPU_DTRACE_ILLOP);
		return 0;
	}
}

#define DTRACE_V4MAPPED_OFFSET	(sizeof(uint32_t) * 3)

/*
 * Emulate the execution of DTrace ID subroutines invoked by the call opcode.
 * Notice that we don't bother validating the proper number of arguments or
 * their types in the tuple stack.  This isn't needed because all argument
 * interpretation is safe because of our load safety -- the worst that can
 * happen is that a bogus program can obtain bogus results.
 */
static void dtrace_dif_subr(uint_t subr, uint_t rd, uint64_t *regs,
			    dtrace_key_t *tupregs, int nargs,
			    dtrace_mstate_t *mstate, dtrace_state_t *state)
{
	volatile uint16_t	*flags = &this_cpu_core->cpuc_dtrace_flags;
	volatile uintptr_t	*illval = &this_cpu_core->cpuc_dtrace_illval;
	dtrace_vstate_t		*vstate = &state->dts_vstate;
	struct mutex		mtx;

	union {
		rwlock_t ri;
		uintptr_t rw;
	} r;

	dt_dbg_dif("        Subroutine %d\n", subr);

	switch (subr) {
	case DIF_SUBR_RAND:
		regs[rd] = jiffies * 2416 + 374441;
		regs[rd] = do_div(regs[rd], 1771875);
		break;

	case DIF_SUBR_MUTEX_OWNED:
		if (!dtrace_canload(tupregs[0].dttk_value,
				    sizeof(struct mutex), mstate, vstate))
			break;

		dtrace_bcopy((const void *)(uintptr_t)tupregs[0].dttk_value,
			     &mtx, sizeof(struct mutex));
		if (*flags & CPU_DTRACE_FAULT)
			break;

		regs[rd] = mutex_owned(&mtx);
		break;

	case DIF_SUBR_MUTEX_OWNER:
		regs[rd] = 0;
		if (!dtrace_canload(tupregs[0].dttk_value,
				    sizeof(struct mutex), mstate, vstate))
			break;

		dtrace_bcopy((const void *)(uintptr_t)tupregs[0].dttk_value,
			     &mtx, sizeof(struct mutex));
		if (*flags & CPU_DTRACE_FAULT)
			break;

#ifdef CONFIG_SMP
		regs[rd] = (uintptr_t)__mutex_owner(&mtx);
#else
		regs[rd] = 0;
#endif
		break;

	case DIF_SUBR_MUTEX_TYPE_ADAPTIVE:
		if (!dtrace_canload(tupregs[0].dttk_value,
				    sizeof(struct mutex), mstate, vstate)) {
			regs[rd] = 0;
			break;
		}

		/*
		 * On Linux, all mutexes are adaptive.
		 */
		regs[rd] = 1;
		break;

	case DIF_SUBR_MUTEX_TYPE_SPIN:
		if (!dtrace_canload(tupregs[0].dttk_value,
				    sizeof(struct mutex), mstate, vstate)) {
			regs[rd] = 0;
			break;
		}

		/*
		 * On Linux, all mutexes are adaptive.
		 */
		regs[rd] = 0;
		break;

	case DIF_SUBR_RW_READ_HELD: {
		if (!dtrace_canload(tupregs[0].dttk_value, sizeof(rwlock_t),
		    mstate, vstate)) {
			regs[rd] = 0;
			break;
		}

		r.rw = dtrace_loadptr(tupregs[0].dttk_value);
		regs[rd] = !write_can_lock(&r.ri) && read_can_lock(&r.ri);
		break;
	}

	case DIF_SUBR_RW_WRITE_HELD:
		if (!dtrace_canload(tupregs[0].dttk_value, sizeof(rwlock_t),
		    mstate, vstate)) {
			regs[rd] = 0;
			break;
		}

		r.rw = dtrace_loadptr(tupregs[0].dttk_value);
		regs[rd] = !write_can_lock(&r.ri);
		break;

	case DIF_SUBR_RW_ISWRITER:
		if (!dtrace_canload(tupregs[0].dttk_value, sizeof(rwlock_t),
		    mstate, vstate)) {
			regs[rd] = 0;
			break;
		}

		r.rw = dtrace_loadptr(tupregs[0].dttk_value);
		/*
		 * On Linux there is no way to determine whether someone is
		 * trying to acquire a write lock.
		 */
		regs[rd] = !write_can_lock(&r.ri);
		break;

	case DIF_SUBR_BCOPY: {
		/*
		 * We need to be sure that the destination is in the scratch
		 * region -- no other region is allowed.
		 */
		uintptr_t	src = tupregs[0].dttk_value;
		uintptr_t	dest = tupregs[1].dttk_value;
		size_t		size = tupregs[2].dttk_value;

		if (!dtrace_inscratch(dest, size, mstate)) {
			*flags |= CPU_DTRACE_BADADDR;
			*illval = regs[rd];
			break;
		}

		if (!dtrace_canload(src, size, mstate, vstate)) {
			regs[rd] = 0;
			break;
		}

		dtrace_bcopy((void *)src, (void *)dest, size);
		break;
	}

	case DIF_SUBR_ALLOCA:
	case DIF_SUBR_COPYIN: {
		uintptr_t	dest = P2ROUNDUP(mstate->dtms_scratch_ptr, 8);
		uint64_t	size = tupregs[
					subr == DIF_SUBR_ALLOCA ? 0 : 1
				       ].dttk_value;
		size_t		scratch_size = (dest -
						mstate->dtms_scratch_ptr) +
					       size;

		/*
		 * This action doesn't require any credential checks since
		 * probes will not activate in user contexts to which the
		 * enabling user does not have permissions.
		 */

		/*
		 * Rounding up the user allocation size could have overflowed
		 * a large, bogus allocation (like -1ULL) to 0.
		 */
		if (scratch_size < size ||
		    !DTRACE_INSCRATCH(mstate, scratch_size)) {
			DTRACE_CPUFLAG_SET(CPU_DTRACE_NOSCRATCH);
			regs[rd] = 0;
			break;
		}

		if (subr == DIF_SUBR_COPYIN) {
			DTRACE_CPUFLAG_SET(CPU_DTRACE_NOFAULT);
			dtrace_copyin(tupregs[0].dttk_value, dest, size, flags);
			DTRACE_CPUFLAG_CLEAR(CPU_DTRACE_NOFAULT);
		}

		mstate->dtms_scratch_ptr += scratch_size;
		regs[rd] = dest;
		break;
	}

	case DIF_SUBR_COPYINTO: {
		uint64_t	size = tupregs[1].dttk_value;
		uintptr_t	dest = tupregs[2].dttk_value;

		/*
		 * This action doesn't require any credential checks since
		 * probes will not activate in user contexts to which the
		 * enabling user does not have permissions.
		 */
		if (!dtrace_inscratch(dest, size, mstate)) {
			*flags |= CPU_DTRACE_BADADDR;
			*illval = regs[rd];
			break;
		}

		DTRACE_CPUFLAG_SET(CPU_DTRACE_NOFAULT);
		dtrace_copyin(tupregs[0].dttk_value, dest, size, flags);
		DTRACE_CPUFLAG_CLEAR(CPU_DTRACE_NOFAULT);
		break;
	}

	case DIF_SUBR_COPYINSTR: {
		uintptr_t	dest = mstate->dtms_scratch_ptr;
		uint64_t	size = state->dts_options[DTRACEOPT_STRSIZE];

		if (nargs > 1 && tupregs[1].dttk_value < size)
			size = tupregs[1].dttk_value + 1;

		/*
		 * This action doesn't require any credential checks since
		 * probes will not activate in user contexts to which the
		 * enabling user does not have permissions.
		 */
		if (!DTRACE_INSCRATCH(mstate, size)) {
			DTRACE_CPUFLAG_SET(CPU_DTRACE_NOSCRATCH);
			regs[rd] = 0;
			break;
		}

		DTRACE_CPUFLAG_SET(CPU_DTRACE_NOFAULT);
		dtrace_copyinstr(tupregs[0].dttk_value, dest, size, flags);
		DTRACE_CPUFLAG_CLEAR(CPU_DTRACE_NOFAULT);

		((char *)dest)[size - 1] = '\0';
		mstate->dtms_scratch_ptr += size;
		regs[rd] = dest;
		break;
	}

#if 0 /* FIXME */
	case DIF_SUBR_MSGSIZE:
	case DIF_SUBR_MSGDSIZE: {
		uintptr_t	baddr = tupregs[0].dttk_value, daddr;
		uintptr_t	wptr, rptr;
		size_t		count = 0;
		int		cont = 0;

		while (baddr != NULL && !(*flags & CPU_DTRACE_FAULT)) {

			if (!dtrace_canload(baddr, sizeof(mblk_t), mstate,
			    vstate)) {
				regs[rd] = 0;
				break;
			}

			wptr = dtrace_loadptr(baddr +
			    offsetof(mblk_t, b_wptr));

			rptr = dtrace_loadptr(baddr +
			    offsetof(mblk_t, b_rptr));

			if (wptr < rptr) {
				*flags |= CPU_DTRACE_BADADDR;
				*illval = tupregs[0].dttk_value;
				break;
			}

			daddr = dtrace_loadptr(baddr +
			    offsetof(mblk_t, b_datap));

			baddr = dtrace_loadptr(baddr +
			    offsetof(mblk_t, b_cont));

			/*
			 * We want to prevent against denial-of-service here,
			 * so we're only going to search the list for
			 * dtrace_msgdsize_max mblks.
			 */
			if (cont++ > dtrace_msgdsize_max) {
				*flags |= CPU_DTRACE_ILLOP;
				break;
			}

			if (subr == DIF_SUBR_MSGDSIZE) {
				if (dtrace_load8(daddr +
				    offsetof(dblk_t, db_type)) != M_DATA)
					continue;
			}

			count += wptr - rptr;
		}

		if (!(*flags & CPU_DTRACE_FAULT))
			regs[rd] = count;

		break;
	}
#endif

	case DIF_SUBR_PROGENYOF: {
		pid_t			pid = tupregs[0].dttk_value;
		struct task_struct	*p;
		int			rval = 0;

		for (p = current; p != NULL; p = p->real_parent) {
			if (p->pid == pid) {
				rval = 1;
				break;
			}

			if (p == p->real_parent)
				break;
		}

		regs[rd] = rval;
		break;
	}

	case DIF_SUBR_SPECULATION:
		regs[rd] = dtrace_speculation(state);
		break;

	case DIF_SUBR_COPYOUT: {
		uintptr_t	kaddr = tupregs[0].dttk_value;
		uintptr_t	uaddr = tupregs[1].dttk_value;
		uint64_t	size = tupregs[2].dttk_value;

		if (!dtrace_destructive_disallow &&
		    dtrace_priv_proc_control(state) &&
		    !dtrace_istoxic(kaddr, size) &&
		    dtrace_canload(kaddr, size, mstate, vstate)) {
			DTRACE_CPUFLAG_SET(CPU_DTRACE_NOFAULT);
			dtrace_copyout(kaddr, uaddr, size, flags);
			DTRACE_CPUFLAG_CLEAR(CPU_DTRACE_NOFAULT);
		}
		break;
	}

	case DIF_SUBR_COPYOUTSTR: {
		uintptr_t	kaddr = tupregs[0].dttk_value;
		uintptr_t	uaddr = tupregs[1].dttk_value;
		uint64_t	size = tupregs[2].dttk_value;

		if (!dtrace_destructive_disallow &&
		    dtrace_priv_proc_control(state) &&
		    !dtrace_istoxic(kaddr, size) &&
		    dtrace_strcanload(kaddr, size, mstate, vstate)) {
			DTRACE_CPUFLAG_SET(CPU_DTRACE_NOFAULT);
			dtrace_copyoutstr(kaddr, uaddr, size, flags);
			DTRACE_CPUFLAG_CLEAR(CPU_DTRACE_NOFAULT);
		}
		break;
	}

	case DIF_SUBR_STRLEN: {
		size_t		sz;
		uintptr_t	addr = (uintptr_t)tupregs[0].dttk_value;

		sz = dtrace_strlen((char *)addr,
				   state->dts_options[DTRACEOPT_STRSIZE]);

		if (!dtrace_canload(addr, sz + 1, mstate, vstate)) {
			regs[rd] = 0;
			break;
		}

		regs[rd] = sz;

		break;
	}

	case DIF_SUBR_STRCHR:
	case DIF_SUBR_STRRCHR: {
		/*
		 * We're going to iterate over the string looking for the
		 * specified character.  We will iterate until we have reached
		 * the string length or we have found the character.  If this
		 * is DIF_SUBR_STRRCHR, we will look for the last occurrence
		 * of the specified character instead of the first.
		 */
		uintptr_t	saddr = tupregs[0].dttk_value;
		uintptr_t	addr = tupregs[0].dttk_value;
		uintptr_t	limit = addr +
					state->dts_options[DTRACEOPT_STRSIZE];
		char		c, target = (char)tupregs[1].dttk_value;

		for (regs[rd] = 0; addr < limit; addr++) {
			if ((c = dtrace_load8(addr)) == target) {
				regs[rd] = addr;

				if (subr == DIF_SUBR_STRCHR)
					break;
			}

			if (c == '\0')
				break;
		}

		if (!dtrace_canload(saddr, addr - saddr, mstate, vstate)) {
			regs[rd] = 0;
			break;
		}

		break;
	}

	case DIF_SUBR_STRSTR:
	case DIF_SUBR_INDEX:
	case DIF_SUBR_RINDEX: {
		/*
		 * We're going to iterate over the string looking for the
		 * specified string.  We will iterate until we have reached
		 * the string length or we have found the string.  (Yes, this
		 * is done in the most naive way possible -- but considering
		 * that the string we're searching for is likely to be
		 * relatively short, the complexity of Rabin-Karp or similar
		 * hardly seems merited.)
		 */
		char		*addr = (char *)(uintptr_t)
							tupregs[0].dttk_value;
		char		*substr = (char *)(uintptr_t)
							tupregs[1].dttk_value;
		uint64_t	size = state->dts_options[DTRACEOPT_STRSIZE];
		size_t		len = dtrace_strlen(addr, size);
		size_t		sublen = dtrace_strlen(substr, size);
		char		*limit = addr + len, *orig = addr;
		int		notfound = subr == DIF_SUBR_STRSTR ? 0 : -1;
		int		inc = 1;

		regs[rd] = notfound;

		if (!dtrace_canload((uintptr_t)addr, len + 1, mstate, vstate)) {
			regs[rd] = 0;
			break;
		}

		if (!dtrace_canload((uintptr_t)substr, sublen + 1, mstate,
				    vstate)) {
			regs[rd] = 0;
			break;
		}

		/*
		 * strstr() and index()/rindex() have similar semantics if
		 * both strings are the empty string: strstr() returns a
		 * pointer to the (empty) string, and index() and rindex()
		 * both return index 0 (regardless of any position argument).
		 */
		if (sublen == 0 && len == 0) {
			if (subr == DIF_SUBR_STRSTR)
				regs[rd] = (uintptr_t)addr;
			else
				regs[rd] = 0;
			break;
		}

		if (subr != DIF_SUBR_STRSTR) {
			if (subr == DIF_SUBR_RINDEX) {
				limit = orig - 1;
				addr += len;
				inc = -1;
			}

			/*
			 * Both index() and rindex() take an optional position
			 * argument that denotes the starting position.
			 */
			if (nargs == 3) {
				int64_t	pos = (int64_t)tupregs[2].dttk_value;

				/*
				 * If the position argument to index() is
				 * negative, Perl implicitly clamps it at
				 * zero.  This semantic is a little surprising
				 * given the special meaning of negative
				 * positions to similar Perl functions like
				 * substr(), but it appears to reflect a
				 * notion that index() can start from a
				 * negative index and increment its way up to
				 * the string.  Given this notion, Perl's
				 * rindex() is at least self-consistent in
				 * that it implicitly clamps positions greater
				 * than the string length to be the string
				 * length.  Where Perl completely loses
				 * coherence, however, is when the specified
				 * substring is the empty string ("").  In
				 * this case, even if the position is
				 * negative, rindex() returns 0 -- and even if
				 * the position is greater than the length,
				 * index() returns the string length.  These
				 * semantics violate the notion that index()
				 * should never return a value less than the
				 * specified position and that rindex() should
				 * never return a value greater than the
				 * specified position.  (One assumes that
				 * these semantics are artifacts of Perl's
				 * implementation and not the results of
				 * deliberate design -- it beggars belief that
				 * even Larry Wall could desire such oddness.)
				 * While in the abstract one would wish for
				 * consistent position semantics across
				 * substr(), index() and rindex() -- or at the
				 * very least self-consistent position
				 * semantics for index() and rindex() -- we
				 * instead opt to keep with the extant Perl
				 * semantics, in all their broken glory.  (Do
				 * we have more desire to maintain Perl's
				 * semantics than Perl does?  Probably.)
				 */
				if (subr == DIF_SUBR_RINDEX) {
					if (pos < 0) {
						if (sublen == 0)
							regs[rd] = 0;
						break;
					}

					if (pos > len)
						pos = len;
				} else {
					if (pos < 0)
						pos = 0;

					if (pos >= len) {
						if (sublen == 0)
							regs[rd] = len;
						break;
					}
				}

				addr = orig + pos;
			}
		}

		for (regs[rd] = notfound; addr != limit; addr += inc) {
			if (dtrace_strncmp(addr, substr, sublen) == 0) {
				if (subr != DIF_SUBR_STRSTR) {
					/*
					 * As D index() and rindex() are
					 * modeled on Perl (and not on awk),
					 * we return a zero-based (and not a
					 * one-based) index.  (For you Perl
					 * weenies: no, we're not going to add
					 * $[ -- and shouldn't you be at a con
					 * or something?)
					 */
					regs[rd] = (uintptr_t)(addr - orig);
					break;
				}

				ASSERT(subr == DIF_SUBR_STRSTR);
				regs[rd] = (uintptr_t)addr;
				break;
			}
		}

		break;
	}

	case DIF_SUBR_STRTOK: {
		uintptr_t	addr = tupregs[0].dttk_value;
		uintptr_t	tokaddr = tupregs[1].dttk_value;
		uint64_t	size = state->dts_options[DTRACEOPT_STRSIZE];
		uintptr_t	limit, toklimit = tokaddr + size;
		uint8_t		c = 0, tokmap[32];	/* 256 / 8 */
		char		*dest = (char *)mstate->dtms_scratch_ptr;
		int		i;

		/*
		 * Check both the token buffer and (later) the input buffer,
		 * since both could be non-scratch addresses.
		 */
		if (!dtrace_strcanload(tokaddr, size, mstate, vstate)) {
			regs[rd] = 0;
			break;
		}

		if (!DTRACE_INSCRATCH(mstate, size)) {
			DTRACE_CPUFLAG_SET(CPU_DTRACE_NOSCRATCH);
			regs[rd] = 0;
			break;
		}

		if (addr == (uintptr_t)NULL) {
			/*
			 * If the address specified is NULL, we use our saved
			 * strtok pointer from the mstate.  Note that this
			 * means that the saved strtok pointer is _only_
			 * valid within multiple enablings of the same probe --
			 * it behaves like an implicit clause-local variable.
			 */
			addr = mstate->dtms_strtok;
		} else {
			/*
			 * If the user-specified address is non-NULL we must
			 * access check it.  This is the only time we have
			 * a chance to do so, since this address may reside
			 * in the string table of this clause-- future calls
			 * (when we fetch addr from mstate->dtms_strtok)
			 * would fail this access check.
			 */
			if (!dtrace_strcanload(addr, size, mstate, vstate)) {
				regs[rd] = 0;
				break;
			}
		}

		/*
		 * First, zero the token map, and then process the token
		 * string -- setting a bit in the map for every character
		 * found in the token string.
		 */
		for (i = 0; i < sizeof(tokmap); i++)
			tokmap[i] = 0;

		for (; tokaddr < toklimit; tokaddr++) {
			if ((c = dtrace_load8(tokaddr)) == '\0')
				break;

			ASSERT((c >> 3) < sizeof(tokmap));
			tokmap[c >> 3] |= (1 << (c & 0x7));
		}

		for (limit = addr + size; addr < limit; addr++) {
			/*
			 * We're looking for a character that is _not_ contained
			 * in the token string.
			 */
			if ((c = dtrace_load8(addr)) == '\0')
				break;

			if (!(tokmap[c >> 3] & (1 << (c & 0x7))))
				break;
		}

		if (c == '\0') {
			/*
			 * We reached the end of the string without finding
			 * any character that was not in the token string.
			 * We return NULL in this case, and we set the saved
			 * address to NULL as well.
			 */
			regs[rd] = 0;
			mstate->dtms_strtok = (uintptr_t)NULL;
			break;
		}

		/*
		 * From here on, we're copying into the destination string.
		 */
		for (i = 0; addr < limit && i < size - 1; addr++) {
			if ((c = dtrace_load8(addr)) == '\0')
				break;

			if (tokmap[c >> 3] & (1 << (c & 0x7)))
				break;

			ASSERT(i < size);
			dest[i++] = c;
		}

		ASSERT(i < size);
		dest[i] = '\0';
		regs[rd] = (uintptr_t)dest;
		mstate->dtms_scratch_ptr += size;
		mstate->dtms_strtok = addr;
		break;
	}

	case DIF_SUBR_SUBSTR: {
		uintptr_t	s = tupregs[0].dttk_value;
		uint64_t	size = state->dts_options[DTRACEOPT_STRSIZE];
		char		*d = (char *)mstate->dtms_scratch_ptr;
		int64_t		index = (int64_t)tupregs[1].dttk_value;
		int64_t		remaining = (int64_t)tupregs[2].dttk_value;
		size_t		len = dtrace_strlen((char *)s, size);
		int64_t		i = 0;

		if (!dtrace_canload(s, len + 1, mstate, vstate)) {
			regs[rd] = 0;
			break;
		}

		if (!DTRACE_INSCRATCH(mstate, size)) {
			DTRACE_CPUFLAG_SET(CPU_DTRACE_NOSCRATCH);
			regs[rd] = 0;
			break;
		}

		if (nargs <= 2)
			remaining = (int64_t)size;

		if (index < 0) {
			index += len;

			if (index < 0 && index + remaining > 0) {
				remaining += index;
				index = 0;
			}
		}

		if (index >= len || index < 0) {
			remaining = 0;
		} else if (remaining < 0) {
			remaining += len - index;
		} else if (index + remaining > size) {
			remaining = size - index;
		}

		for (i = 0; i < remaining; i++) {
			if ((d[i] = dtrace_load8(s + index + i)) == '\0')
				break;
		}

		d[i] = '\0';

		mstate->dtms_scratch_ptr += size;
		regs[rd] = (uintptr_t)d;
		break;
	}

	case DIF_SUBR_GETMAJOR:
		regs[rd] = MAJOR(tupregs[0].dttk_value);
		break;

	case DIF_SUBR_GETMINOR:
		regs[rd] = MINOR(tupregs[0].dttk_value);
		break;

#if 0 /* FIXME */
	case DIF_SUBR_DDI_PATHNAME: {
		/*
		 * This one is a galactic mess.  We are going to roughly
		 * emulate ddi_pathname(), but it's made more complicated
		 * by the fact that we (a) want to include the minor name and
		 * (b) must proceed iteratively instead of recursively.
		 */
		uintptr_t dest = mstate->dtms_scratch_ptr;
		uint64_t size = state->dts_options[DTRACEOPT_STRSIZE];
		char *start = (char *)dest, *end = start + size - 1;
		uintptr_t daddr = tupregs[0].dttk_value;
		int64_t minor = (int64_t)tupregs[1].dttk_value;
		char *s;
		int i, len, depth = 0;

		/*
		 * Due to all the pointer jumping we do and context we must
		 * rely upon, we just mandate that the user must have kernel
		 * read privileges to use this routine.
		 */
		if ((mstate->dtms_access & DTRACE_ACCESS_KERNEL) == 0) {
			*flags |= CPU_DTRACE_KPRIV;
			*illval = daddr;
			regs[rd] = 0;
		}

		if (!DTRACE_INSCRATCH(mstate, size)) {
			DTRACE_CPUFLAG_SET(CPU_DTRACE_NOSCRATCH);
			regs[rd] = 0;
			break;
		}

		*end = '\0';

		/*
		 * We want to have a name for the minor.  In order to do this,
		 * we need to walk the minor list from the devinfo.  We want
		 * to be sure that we don't infinitely walk a circular list,
		 * so we check for circularity by sending a scout pointer
		 * ahead two elements for every element that we iterate over;
		 * if the list is circular, these will ultimately point to the
		 * same element.  You may recognize this little trick as the
		 * answer to a stupid interview question -- one that always
		 * seems to be asked by those who had to have it laboriously
		 * explained to them, and who can't even concisely describe
		 * the conditions under which one would be forced to resort to
		 * this technique.  Needless to say, those conditions are
		 * found here -- and probably only here.  Is this the only use
		 * of this infamous trick in shipping, production code?  If it
		 * isn't, it probably should be...
		 */
		if (minor != -1) {
			uintptr_t maddr = dtrace_loadptr(daddr +
			    offsetof(struct dev_info, devi_minor));

			uintptr_t next = offsetof(struct ddi_minor_data, next);
			uintptr_t name = offsetof(struct ddi_minor_data,
			    d_minor) + offsetof(struct ddi_minor, name);
			uintptr_t dev = offsetof(struct ddi_minor_data,
			    d_minor) + offsetof(struct ddi_minor, dev);
			uintptr_t scout;

			if (maddr != NULL)
				scout = dtrace_loadptr(maddr + next);

			while (maddr != NULL && !(*flags & CPU_DTRACE_FAULT)) {
				uint64_t m;
#ifdef _LP64
				m = dtrace_load64(maddr + dev) & MAXMIN64;
#else
				m = dtrace_load32(maddr + dev) & MAXMIN;
#endif
				if (m != minor) {
					maddr = dtrace_loadptr(maddr + next);

					if (scout == NULL)
						continue;

					scout = dtrace_loadptr(scout + next);

					if (scout == NULL)
						continue;

					scout = dtrace_loadptr(scout + next);

					if (scout == NULL)
						continue;

					if (scout == maddr) {
						*flags |= CPU_DTRACE_ILLOP;
						break;
					}

					continue;
				}

				/*
				 * We have the minor data.  Now we need to
				 * copy the minor's name into the end of the
				 * pathname.
				 */
				s = (char *)dtrace_loadptr(maddr + name);
				len = dtrace_strlen(s, size);

				if (*flags & CPU_DTRACE_FAULT)
					break;

				if (len != 0) {
					if ((end -= (len + 1)) < start)
						break;

					*end = ':';
				}

				for (i = 1; i <= len; i++)
					end[i] = dtrace_load8((uintptr_t)s++);
				break;
			}
		}

		while (daddr != NULL && !(*flags & CPU_DTRACE_FAULT)) {
			ddi_node_state_t devi_state;

			devi_state = dtrace_load32(daddr +
			    offsetof(struct dev_info, devi_node_state));

			if (*flags & CPU_DTRACE_FAULT)
				break;

			if (devi_state >= DS_INITIALIZED) {
				s = (char *)dtrace_loadptr(daddr +
				    offsetof(struct dev_info, devi_addr));
				len = dtrace_strlen(s, size);

				if (*flags & CPU_DTRACE_FAULT)
					break;

				if (len != 0) {
					if ((end -= (len + 1)) < start)
						break;

					*end = '@';
				}

				for (i = 1; i <= len; i++)
					end[i] = dtrace_load8((uintptr_t)s++);
			}

			/*
			 * Now for the node name...
			 */
			s = (char *)dtrace_loadptr(daddr +
			    offsetof(struct dev_info, devi_node_name));

			daddr = dtrace_loadptr(daddr +
			    offsetof(struct dev_info, devi_parent));

			/*
			 * If our parent is NULL (that is, if we're the root
			 * node), we're going to use the special path
			 * "devices".
			 */
			if (daddr == NULL)
				s = "devices";

			len = dtrace_strlen(s, size);
			if (*flags & CPU_DTRACE_FAULT)
				break;

			if ((end -= (len + 1)) < start)
				break;

			for (i = 1; i <= len; i++)
				end[i] = dtrace_load8((uintptr_t)s++);
			*end = '/';

			if (depth++ > dtrace_devdepth_max) {
				*flags |= CPU_DTRACE_ILLOP;
				break;
			}
		}

		if (end < start)
			DTRACE_CPUFLAG_SET(CPU_DTRACE_NOSCRATCH);

		if (daddr == NULL) {
			regs[rd] = (uintptr_t)end;
			mstate->dtms_scratch_ptr += size;
		}

		break;
	}
#endif

	case DIF_SUBR_STRJOIN: {
		char		*d = (char *)mstate->dtms_scratch_ptr;
		uint64_t	size = state->dts_options[DTRACEOPT_STRSIZE];
		uintptr_t	s1 = tupregs[0].dttk_value;
		uintptr_t	s2 = tupregs[1].dttk_value;
		int		i = 0;

		if (!dtrace_strcanload(s1, size, mstate, vstate) ||
		    !dtrace_strcanload(s2, size, mstate, vstate)) {
			regs[rd] = 0;
			break;
		}

		if (!DTRACE_INSCRATCH(mstate, size)) {
			DTRACE_CPUFLAG_SET(CPU_DTRACE_NOSCRATCH);
			regs[rd] = 0;
			break;
		}

		for (;;) {
			if (i >= size) {
				DTRACE_CPUFLAG_SET(CPU_DTRACE_NOSCRATCH);
				regs[rd] = 0;
				break;
			}

			if ((d[i++] = dtrace_load8(s1++)) == '\0') {
				i--;
				break;
			}
		}

		for (;;) {
			if (i >= size) {
				DTRACE_CPUFLAG_SET(CPU_DTRACE_NOSCRATCH);
				regs[rd] = 0;
				break;
			}

			if ((d[i++] = dtrace_load8(s2++)) == '\0')
				break;
		}

		if (i < size) {
			mstate->dtms_scratch_ptr += i;
			regs[rd] = (uintptr_t)d;
		}

		break;
	}

	case DIF_SUBR_LLTOSTR: {
		int64_t		i = (int64_t)tupregs[0].dttk_value;
		int64_t		val = i < 0 ? i * -1 : i;
		uint64_t	size = 22;	/* room for 2^64 in dec */
		char		*end = (char *)mstate->dtms_scratch_ptr + size
									- 1;

		if (!DTRACE_INSCRATCH(mstate, size)) {
			DTRACE_CPUFLAG_SET(CPU_DTRACE_NOSCRATCH);
			regs[rd] = 0;
			break;
		}

		/*
		 * GCC on Linux introduces calls to functions that are not
		 * linked into the kernel image, so we need to use the do_div()
		 * function instead.  It modifies the first argument in place
		 * (replaces it with the quotient), and returns the remainder.
		 *
		 * Was:
		 *	for (*end-- = '\0'; val; val /= 10)
		 *		*end-- = '0' + (val % 10);
		 */
		for (*end-- = '\0'; val; )
			*end-- = '0' + do_div(val, 10);

		if (i == 0)
			*end-- = '0';

		if (i < 0)
			*end-- = '-';

		regs[rd] = (uintptr_t)end + 1;
		mstate->dtms_scratch_ptr += size;
		break;
	}

	case DIF_SUBR_HTONS:
	case DIF_SUBR_NTOHS:
#ifdef __BIG_ENDIAN
		regs[rd] = (uint16_t)tupregs[0].dttk_value;
#else
		regs[rd] = DT_BSWAP_16((uint16_t)tupregs[0].dttk_value);
#endif
		break;


	case DIF_SUBR_HTONL:
	case DIF_SUBR_NTOHL:
#ifdef __BIG_ENDIAN
		regs[rd] = (uint32_t)tupregs[0].dttk_value;
#else
		regs[rd] = DT_BSWAP_32((uint32_t)tupregs[0].dttk_value);
#endif
		break;


	case DIF_SUBR_HTONLL:
	case DIF_SUBR_NTOHLL:
#ifdef __BIG_ENDIAN
		regs[rd] = (uint64_t)tupregs[0].dttk_value;
#else
		regs[rd] = DT_BSWAP_64((uint64_t)tupregs[0].dttk_value);
#endif
		break;


	case DIF_SUBR_DIRNAME:
	case DIF_SUBR_BASENAME: {
		char		*dest = (char *)mstate->dtms_scratch_ptr;
		uint64_t	size = state->dts_options[DTRACEOPT_STRSIZE];
		uintptr_t	src = tupregs[0].dttk_value;
		int		i, j, len = dtrace_strlen((char *)src, size);
		int		lastbase = -1, firstbase = -1, lastdir = -1;
		int		start, end;

		if (!dtrace_canload(src, len + 1, mstate, vstate)) {
			regs[rd] = 0;
			break;
		}

		if (!DTRACE_INSCRATCH(mstate, size)) {
			DTRACE_CPUFLAG_SET(CPU_DTRACE_NOSCRATCH);
			regs[rd] = 0;
			break;
		}

		/*
		 * The basename and dirname for a zero-length string is
		 * defined to be "."
		 */
		if (len == 0) {
			len = 1;
			src = (uintptr_t)".";
		}

		/*
		 * Start from the back of the string, moving back toward the
		 * front until we see a character that isn't a slash.  That
		 * character is the last character in the basename.
		 */
		for (i = len - 1; i >= 0; i--) {
			if (dtrace_load8(src + i) != '/')
				break;
		}

		if (i >= 0)
			lastbase = i;

		/*
		 * Starting from the last character in the basename, move
		 * towards the front until we find a slash.  The character
		 * that we processed immediately before that is the first
		 * character in the basename.
		 */
		for (; i >= 0; i--) {
			if (dtrace_load8(src + i) == '/')
				break;
		}

		if (i >= 0)
			firstbase = i + 1;

		/*
		 * Now keep going until we find a non-slash character.  That
		 * character is the last character in the dirname.
		 */
		for (; i >= 0; i--) {
			if (dtrace_load8(src + i) != '/')
				break;
		}

		if (i >= 0)
			lastdir = i;

		ASSERT(!(lastbase == -1 && firstbase != -1));
		ASSERT(!(firstbase == -1 && lastdir != -1));

		if (lastbase == -1) {
			/*
			 * We didn't find a non-slash character.  We know that
			 * the length is non-zero, so the whole string must be
			 * slashes.  In either the dirname or the basename
			 * case, we return '/'.
			 */
			ASSERT(firstbase == -1);
			firstbase = lastbase = lastdir = 0;
		}

		if (firstbase == -1) {
			/*
			 * The entire string consists only of a basename
			 * component.  If we're looking for dirname, we need
			 * to change our string to be just "."; if we're
			 * looking for a basename, we'll just set the first
			 * character of the basename to be 0.
			 */
			if (subr == DIF_SUBR_DIRNAME) {
				ASSERT(lastdir == -1);
				src = (uintptr_t)".";
				lastdir = 0;
			} else {
				firstbase = 0;
			}
		}

		if (subr == DIF_SUBR_DIRNAME) {
			if (lastdir == -1) {
				/*
				 * We know that we have a slash in the name --
				 * or lastdir would be set to 0, above.  And
				 * because lastdir is -1, we know that this
				 * slash must be the first character.  (That
				 * is, the full string must be of the form
				 * "/basename".)  In this case, the last
				 * character of the directory name is 0.
				 */
				lastdir = 0;
			}

			start = 0;
			end = lastdir;
		} else {
			ASSERT(subr == DIF_SUBR_BASENAME);
			ASSERT(firstbase != -1 && lastbase != -1);
			start = firstbase;
			end = lastbase;
		}

		for (i = start, j = 0; i <= end && j < size - 1; i++, j++)
			dest[j] = dtrace_load8(src + i);

		dest[j] = '\0';
		regs[rd] = (uintptr_t)dest;
		mstate->dtms_scratch_ptr += size;
		break;
	}

	case DIF_SUBR_CLEANPATH: {
		char		*dest = (char *)mstate->dtms_scratch_ptr, c;
		uint64_t	size = state->dts_options[DTRACEOPT_STRSIZE];
		uintptr_t	src = tupregs[0].dttk_value;
		int		i = 0, j = 0;

		if (!dtrace_strcanload(src, size, mstate, vstate)) {
			regs[rd] = 0;
			break;
		}

		if (!DTRACE_INSCRATCH(mstate, size)) {
			DTRACE_CPUFLAG_SET(CPU_DTRACE_NOSCRATCH);
			regs[rd] = 0;
			break;
		}

		/*
		 * Move forward, loading each character.
		 */
		do {
			c = dtrace_load8(src + i++);
next:
			if (j + 5 >= size)	/* 5 = strlen("/..c\0") */
				break;

			if (c != '/') {
				dest[j++] = c;
				continue;
			}

			c = dtrace_load8(src + i++);

			if (c == '/') {
				/*
				 * We have two slashes -- we can just advance
				 * to the next character.
				 */
				goto next;
			}

			if (c != '.') {
				/*
				 * This is not "." and it's not ".." -- we can
				 * just store the "/" and this character and
				 * drive on.
				 */
				dest[j++] = '/';
				dest[j++] = c;
				continue;
			}

			c = dtrace_load8(src + i++);

			if (c == '/') {
				/*
				 * This is a "/./" component.  We're not going
				 * to store anything in the destination buffer;
				 * we're just going to go to the next component.
				 */
				goto next;
			}

			if (c != '.') {
				/*
				 * This is not ".." -- we can just store the
				 * "/." and this character and continue
				 * processing.
				 */
				dest[j++] = '/';
				dest[j++] = '.';
				dest[j++] = c;
				continue;
			}

			c = dtrace_load8(src + i++);

			if (c != '/' && c != '\0') {
				/*
				 * This is not ".." -- it's "..[mumble]".
				 * We'll store the "/.." and this character
				 * and continue processing.
				 */
				dest[j++] = '/';
				dest[j++] = '.';
				dest[j++] = '.';
				dest[j++] = c;
				continue;
			}

			/*
			 * This is "/../" or "/..\0".  We need to back up
			 * our destination pointer until we find a "/".
			 */
			i--;
			while (j != 0 && dest[--j] != '/')
				continue;

			if (c == '\0')
				dest[++j] = '/';
		} while (c != '\0');

		dest[j] = '\0';
		regs[rd] = (uintptr_t)dest;
		mstate->dtms_scratch_ptr += size;
		break;
	}

	case DIF_SUBR_LINK_NTOP: {
		struct dtrace_hwtype_alen {
			int hwtype;
			size_t hwalen;
		} hwinfo[] = {
			{ ARPHRD_ETHER, ETH_ALEN },
			{ ARPHRD_INFINIBAND, INFINIBAND_ALEN },
			{ -1, 0 }
		};
/*
 * Captures the maximum hardware address length among all the supported
 * hardware types. Please update this macro when adding a new hardware type.
 */
#define DTRACE_MAX_HWTYPE_ALEN (ETH_ALEN > INFINIBAND_ALEN ? \
				ETH_ALEN : INFINIBAND_ALEN)
		uintptr_t src = tupregs[1].dttk_value;
		int type = tupregs[0].dttk_value;
		uint8_t hwaddr[DTRACE_MAX_HWTYPE_ALEN];
		char *base;
		size_t size, len;
		int i;

		for (i = 0; hwinfo[i].hwtype != -1; i++) {
			if (type == hwinfo[i].hwtype)
				break;
		}
		if (hwinfo[i].hwtype == -1) {
			DTRACE_CPUFLAG_SET(CPU_DTRACE_ILLOP);
			regs[rd] = 0;
			break;
		}
		len = hwinfo[i].hwalen;

		/*
		 * Safely load the hardware address.
		 */
		if (!dtrace_canload(src, len, mstate, vstate)) {
			regs[rd] = 0;
			break;
		}
		dtrace_bcopy((void *)src, hwaddr, len);

		/*
		 * Check if a hardware address string will fit in scratch.
		 * For every byte we need 3 characters (including ':').
		 */
		size = len * 3;
		if (!DTRACE_INSCRATCH(mstate, size)) {
			DTRACE_CPUFLAG_SET(CPU_DTRACE_NOSCRATCH);
			regs[rd] = 0;
			break;
		}
		base = (char *)mstate->dtms_scratch_ptr;

		/*
		 * Build the Hardware address string by working through the
		 * address from the beginning. Given a hardware address
		 * {0xa0, 0xaa, 0xff, 0xc, 0, 1, 2} of length 6, it will build
		 * a0:aa:ff:0c:00:01:02.
		 */
		for (i = 0; i < len; i++) {
			if (hwaddr[i] < 16) {
				*base++ = '0';
				*base++ = dtrace_hexdigits[hwaddr[i]];
			} else {
				*base++ = dtrace_hexdigits[hwaddr[i] / 16];
				*base++ = dtrace_hexdigits[hwaddr[i] % 16];
			}

			if (i < len - 1)
				*base++ = ':';
		}
		*base++ = '\0';
		regs[rd] = mstate->dtms_scratch_ptr;
		mstate->dtms_scratch_ptr += size;
#undef DTRACE_MAX_HWTYPE_ALEN
		break;
	}

	case DIF_SUBR_INET_NTOA:
	case DIF_SUBR_INET_NTOA6:
	case DIF_SUBR_INET_NTOP: {
		uintptr_t src;
		size_t	size;
		int	af, argi, i;
		char	*base, *end;

		if (subr == DIF_SUBR_INET_NTOP) {
			af = (int)tupregs[0].dttk_value;
			argi = 1;
		} else {
			af = subr == DIF_SUBR_INET_NTOA ? AF_INET: AF_INET6;
			argi = 0;
		}

		src = tupregs[argi].dttk_value;
		if (af == AF_INET) {
			ipaddr_t	ip4;
			uint8_t		*ptr8, val;

			/*
			 * Safely load the IPv4 address.
			 */
			if (!dtrace_canload(src, 4, mstate, vstate)) {
				regs[rd] = 0;
				break;
			}
			ip4 = dtrace_load32(src);

			/*
			 * Check an IPv4 string will fit in scratch.
			 */
			size = INET_ADDRSTRLEN;
			if (!DTRACE_INSCRATCH(mstate, size)) {
				DTRACE_CPUFLAG_SET(CPU_DTRACE_NOSCRATCH);
				regs[rd] = 0;
				break;
			}
			base = (char *)mstate->dtms_scratch_ptr;
			end = (char *)mstate->dtms_scratch_ptr + size - 1;

			/*
			 * Stringify as a dotted decimal quad.
			 */
			*end-- = '\0';
			ptr8 = (uint8_t *)&ip4;
			for (i = 3; i >= 0; i--) {
				val = ptr8[i];

				if (val == 0) {
					*end-- = '0';
				} else {
					for (; val; val /= 10) {
						*end-- = '0' + (val % 10);
					}
				}

				if (i > 0)
					*end-- = '.';
			}
			ASSERT(end + 1 >= base);
#if IS_ENABLED(CONFIG_IPV6)
		} else if (af == AF_INET6) {
			in6_addr_t	ip6;
			int		firstzero, tryzero, numzero, v6end;
			uint16_t	val;

			/*
			 * Stringify using RFC 1884 convention 2 - 16 bit
			 * hexadecimal values with a zero-run compression.
			 * Lower case hexadecimal digits are used.
			 * 	eg, fe80::214:4fff:fe0b:76c8.
			 * The IPv4 embedded form is returned for inet_ntop,
			 * just the IPv4 string is returned for inet_ntoa6.
			 */

			/*
			 * Safely load the IPv6 address.
			 */
			if (!dtrace_canload(src, sizeof(in6_addr_t), mstate,
					    vstate)) {
				regs[rd] = 0;
				break;
			}
			dtrace_bcopy((void *)src, (void *)(uintptr_t)&ip6,
				     sizeof(in6_addr_t));

			/*
			 * Check an IPv6 string will fit in scratch.
			 */
			size = INET6_ADDRSTRLEN;
			if (!DTRACE_INSCRATCH(mstate, size)) {
				DTRACE_CPUFLAG_SET(CPU_DTRACE_NOSCRATCH);
				regs[rd] = 0;
				break;
			}
			base = (char *)mstate->dtms_scratch_ptr;
			end = (char *)mstate->dtms_scratch_ptr + size - 1;
			*end-- = '\0';

			/*
			 * Find the longest run of 16 bit zero values
			 * for the single allowed zero compression - "::".
			 */
			firstzero = -1;
			tryzero = -1;
			numzero = 1;
			for (i = 0; i < sizeof(in6_addr_t); i++) {
				if (ip6.s6_addr[i] == 0 &&
				    tryzero == -1 && i % 2 == 0) {
					tryzero = i;
					continue;
				}

				if (tryzero != -1 &&
				    (ip6.s6_addr[i] != 0 ||
				    i == sizeof(in6_addr_t) - 1)) {

					if (i - tryzero <= numzero) {
						tryzero = -1;
						continue;
					}

					firstzero = tryzero;
					numzero = i - i % 2 - tryzero;
					tryzero = -1;

					if (ip6.s6_addr[i] == 0 &&
					    i == sizeof(in6_addr_t) - 1)
						numzero += 2;
				}
			}
			ASSERT(firstzero + numzero <= sizeof(in6_addr_t));

			/*
			 * Check for an IPv4 embedded address.
			 */
			v6end = sizeof(in6_addr_t) - 2;
			if (ipv6_addr_type(&ip6) &
			    (IPV6_ADDR_COMPATv4 | IPV6_ADDR_MAPPED)) {
				for (i = sizeof(in6_addr_t) - 1;
				    i >= DTRACE_V4MAPPED_OFFSET; i--) {
					ASSERT(end >= base);

					val = ip6.s6_addr[i];

					if (val == 0) {
						*end-- = '0';
					} else {
						for (; val; val /= 10) {
							*end-- = '0' + val % 10;
						}
					}

					if (i > DTRACE_V4MAPPED_OFFSET)
						*end-- = '.';
				}

				if (subr == DIF_SUBR_INET_NTOA6)
					goto inetout;

				/*
				 * Set v6end to skip the IPv4 address that
				 * we have already stringified.
				 */
				v6end = 10;
			}

			/*
			 * Build the IPv6 string by working through the
			 * address in reverse.
			 */
			for (i = v6end; i >= 0; i -= 2) {
				ASSERT(end >= base);

				if (i == firstzero + numzero - 2) {
					*end-- = ':';
					*end-- = ':';
					i -= numzero - 2;
					continue;
				}

				if (i < 14 && i != firstzero - 2)
					*end-- = ':';

				val = (ip6.s6_addr[i] << 8) +
				    ip6.s6_addr[i + 1];

				if (val == 0) {
					*end-- = '0';
				} else {
					for (; val; val /= 16) {
						*end-- = \
						    dtrace_hexdigits[val % 16];
					}
				}
			}
			ASSERT(end + 1 >= base);
#endif
		} else {
			/*
			 * The user didn't use AH_INET or AH_INET6.
			 */
			DTRACE_CPUFLAG_SET(CPU_DTRACE_ILLOP);
			regs[rd] = 0;
			break;
		}

#if IS_ENABLED(CONFIG_IPV6)
inetout:
#endif
		regs[rd] = (uintptr_t)end + 1;
		mstate->dtms_scratch_ptr += size;
		break;
	}

	case DIF_SUBR_D_PATH: {
		struct path	*path = (struct path *)tupregs[0].dttk_value;
		char		*dest = (char *)mstate->dtms_scratch_ptr;
		char		*ptr;
		uint64_t	size = state->dts_options[DTRACEOPT_STRSIZE];
		unsigned int	fd;
		struct files_struct
				*files = current->files;
		struct fdtable	*fdt;

		if (!dtrace_canload((uintptr_t)path, sizeof(struct path),
				    mstate, vstate)) {
			regs[rd] = 0;
			break;
		}

		if (!DTRACE_INSCRATCH(mstate, size)) {
			DTRACE_CPUFLAG_SET(CPU_DTRACE_NOSCRATCH);
			regs[rd] = 0;
			break;
		}

		if (spin_is_locked(&files->file_lock) ||
		    !spin_trylock(&files->file_lock)) {
			regs[rd] = 0;
			break;
		}

		fdt = files->fdt;

		/*
		 * We (currently) limit the d_path() subroutine to paths that
		 * relate to open files in the current task.
		 */
		for (fd = 0; fd < fdt->max_fds; fd++) {
			if (fdt->fd[fd] && &fdt->fd[fd]->f_path == path)
				break;
		}

		spin_unlock(&files->file_lock);

		if (fd >= fdt->max_fds) {
			*flags |= CPU_DTRACE_BADADDR;
			*illval = (uintptr_t)path;
			regs[rd] = 0;
			break;
		}

		ptr = d_path(path, dest, size);
		if (ptr < 0) {
			regs[rd] = 0;
			break;
		}

		regs[rd] = (uintptr_t)ptr;
		mstate->dtms_scratch_ptr += size;
		break;
	}

	}
}

/*
 * Emulate the execution of DTrace IR instructions specified by the given DIF
 * object.  This function is deliberately void fo assertions as all of the
 * necessary checks are handled by a call to dtrace_difo_validate().
 */
uint64_t dtrace_dif_emulate(dtrace_difo_t *difo, dtrace_mstate_t *mstate,
			    dtrace_vstate_t *vstate, dtrace_state_t *state)
{
	const dif_instr_t	*text = difo->dtdo_buf;
	const uint_t		textlen = difo->dtdo_len;
	const char		*strtab = difo->dtdo_strtab;
	const uint64_t		*inttab = difo->dtdo_inttab;

	uint64_t		rval = 0;
	dtrace_statvar_t	*svar;
	dtrace_dstate_t		*dstate = &vstate->dtvs_dynvars;
	dtrace_difv_t		*v;
	volatile uint16_t	*flags = &this_cpu_core->cpuc_dtrace_flags;
	volatile uintptr_t	*illval = &this_cpu_core->cpuc_dtrace_illval;

	dtrace_key_t		tupregs[DIF_DTR_NREGS + 2];
						/* +2 for thread and id */
	uint64_t		regs[DIF_DIR_NREGS];
	uint64_t		*tmp;

	uint8_t			cc_n = 0, cc_z = 0, cc_v = 0, cc_c = 0;
	int64_t			cc_r;
	uint_t			pc = 0, id, opc = 0;
	uint8_t			ttop = 0;
	dif_instr_t		instr;
	uint_t			r1, r2, rd;

	dt_dbg_dif("    DIF %p emulation (text %p, %d instructions)...\n",
		   difo, text, textlen);

	/*
	 * We stash the current DIF object into the machine state: we need it
	 * for subsequent access checking.
	 */
	mstate->dtms_difo = difo;

	regs[DIF_REG_R0] = 0;			/* %r0 is fixed at zero */

	while (pc < textlen && !(*flags & CPU_DTRACE_FAULT)) {
		opc = pc;

		instr = text[pc++];
		r1 = DIF_INSTR_R1(instr);
		r2 = DIF_INSTR_R2(instr);
		rd = DIF_INSTR_RD(instr);

		dt_dbg_dif("      Executing opcode %02x (%02x, %02x, %02x)\n",
			   DIF_INSTR_OP(instr), r1, r2, rd);

		switch (DIF_INSTR_OP(instr)) {
		case DIF_OP_OR:
			regs[rd] = regs[r1] | regs[r2];
			break;
		case DIF_OP_XOR:
			regs[rd] = regs[r1] ^ regs[r2];
			break;
		case DIF_OP_AND:
			regs[rd] = regs[r1] & regs[r2];
			break;
		case DIF_OP_SLL:
			regs[rd] = regs[r1] << regs[r2];
			break;
		case DIF_OP_SRL:
			regs[rd] = regs[r1] >> regs[r2];
			break;
		case DIF_OP_SUB:
			regs[rd] = regs[r1] - regs[r2];
			break;
		case DIF_OP_ADD:
			regs[rd] = regs[r1] + regs[r2];
			break;
		case DIF_OP_MUL:
			regs[rd] = regs[r1] * regs[r2];
			break;
		case DIF_OP_SDIV:
			if (regs[r2] == 0) {
				regs[rd] = 0;
				*flags |= CPU_DTRACE_DIVZERO;
			} else {
				int	neg = 0;

				/*
				 * We cannot simply do a 64-bit division, since
				 * gcc translates it into a call to a function
				 * that is not linked into the kernel.
				 *
				 * regs[rd] = (int64_t)regs[r1] /
				 *	      (int64_t)regs[r2];
				 */
				if ((int64_t)regs[r1] < 0) {
					neg = !neg;
					regs[r1] = -(int64_t)regs[r1];
				}
				if ((int64_t)regs[r2] < 0) {
					neg = !neg;
					regs[r2] = -(int64_t)regs[r2];
				}
				regs[rd] = regs[r1];
				do_div(regs[rd], regs[r2]);

				if (neg)
					regs[rd] = -(int64_t)regs[rd];
			}
			break;

		case DIF_OP_UDIV:
			if (regs[r2] == 0) {
				regs[rd] = 0;
				*flags |= CPU_DTRACE_DIVZERO;
			} else {
				/*
				 * We cannot simply do a 64-bit division, since
				 * gcc translates it into a call to a function
				 * that is not linked into the kernel.
				 *
				 * regs[rd] = regs[r1] / regs[r2];
				 */
				regs[rd] = regs[r1];
				do_div(regs[rd], regs[r2]);
			}
			break;

		case DIF_OP_SREM:
			if (regs[r2] == 0) {
				regs[rd] = 0;
				*flags |= CPU_DTRACE_DIVZERO;
			} else {
				int	neg = 0;

				/*
				 * We cannot simply do a 64-bit division, since
				 * gcc translates it into a call to a function
				 * that is not linked into the kernel.
				 *
				 * regs[rd] = (int64_t)regs[r1] %
				 *	      (int64_t)regs[r2];
				 */
				if ((int64_t)regs[r1] < 0) {
					neg = !neg;
					regs[r1] = -(int64_t)regs[r1];
				}
				if ((int64_t)regs[r2] < 0) {
					neg = !neg;
					regs[r2] = -(int64_t)regs[r2];
				}
				regs[rd] = regs[r1];
				regs[rd] = do_div(regs[rd], regs[r2]);

				if (neg)
					regs[rd] = -(int64_t)regs[rd];
			}
			break;

		case DIF_OP_UREM:
			if (regs[r2] == 0) {
				regs[rd] = 0;
				*flags |= CPU_DTRACE_DIVZERO;
			} else {
				/*
				 * We cannot simply do a 64-bit division, since
				 * gcc translates it into a call to a function
				 * that is not linked into the kernel.
				 *
				 * regs[rd] = regs[r1] % regs[r2];
				 */
				regs[rd] = regs[r1];
				regs[rd] = do_div(regs[rd], regs[r2]);
			}
			break;

		case DIF_OP_NOT:
			regs[rd] = ~regs[r1];
			break;
		case DIF_OP_MOV:
			regs[rd] = regs[r1];
			break;
		case DIF_OP_CMP:
			cc_r = regs[r1] - regs[r2];
			cc_n = cc_r < 0;
			cc_z = cc_r == 0;
			cc_v = 0;
			cc_c = regs[r1] < regs[r2];
			break;
		case DIF_OP_TST:
			cc_n = cc_v = cc_c = 0;
			cc_z = regs[r1] == 0;
			break;
		case DIF_OP_BA:
			pc = DIF_INSTR_LABEL(instr);
			break;
		case DIF_OP_BE:
			if (cc_z)
				pc = DIF_INSTR_LABEL(instr);
			break;
		case DIF_OP_BNE:
			if (cc_z == 0)
				pc = DIF_INSTR_LABEL(instr);
			break;
		case DIF_OP_BG:
			if ((cc_z | (cc_n ^ cc_v)) == 0)
				pc = DIF_INSTR_LABEL(instr);
			break;
		case DIF_OP_BGU:
			if ((cc_c | cc_z) == 0)
				pc = DIF_INSTR_LABEL(instr);
			break;
		case DIF_OP_BGE:
			if ((cc_n ^ cc_v) == 0)
				pc = DIF_INSTR_LABEL(instr);
			break;
		case DIF_OP_BGEU:
			if (cc_c == 0)
				pc = DIF_INSTR_LABEL(instr);
			break;
		case DIF_OP_BL:
			if (cc_n ^ cc_v)
				pc = DIF_INSTR_LABEL(instr);
			break;
		case DIF_OP_BLU:
			if (cc_c)
				pc = DIF_INSTR_LABEL(instr);
			break;
		case DIF_OP_BLE:
			if (cc_z | (cc_n ^ cc_v))
				pc = DIF_INSTR_LABEL(instr);
			break;
		case DIF_OP_BLEU:
			if (cc_c | cc_z)
				pc = DIF_INSTR_LABEL(instr);
			break;
		case DIF_OP_RLDSB:
#ifdef FIXME_OPENSOLARIS_BUG
			if (!dtrace_canstore(regs[r1], 1, mstate, vstate)) {
#else
			if (!dtrace_canload(regs[r1], 1, mstate, vstate)) {
#endif
				*flags |= CPU_DTRACE_KPRIV;
				*illval = regs[r1];
				break;
			}
			/*FALLTHROUGH*/
		case DIF_OP_LDSB:
			regs[rd] = (int8_t)dtrace_load8(regs[r1]);
			break;
		case DIF_OP_RLDSH:
			if (!dtrace_canstore(regs[r1], 2, mstate, vstate)) {
				*flags |= CPU_DTRACE_KPRIV;
				*illval = regs[r1];
				break;
			}
			/*FALLTHROUGH*/
		case DIF_OP_LDSH:
			regs[rd] = (int16_t)dtrace_load16(regs[r1]);
			break;
		case DIF_OP_RLDSW:
			if (!dtrace_canstore(regs[r1], 4, mstate, vstate)) {
				*flags |= CPU_DTRACE_KPRIV;
				*illval = regs[r1];
				break;
			}
			/*FALLTHROUGH*/
		case DIF_OP_LDSW:
			regs[rd] = (int32_t)dtrace_load32(regs[r1]);
			break;
		case DIF_OP_RLDUB:
			if (!dtrace_canstore(regs[r1], 1, mstate, vstate)) {
				*flags |= CPU_DTRACE_KPRIV;
				*illval = regs[r1];
				break;
			}
			/*FALLTHROUGH*/
		case DIF_OP_LDUB:
			regs[rd] = dtrace_load8(regs[r1]);
			break;
		case DIF_OP_RLDUH:
			if (!dtrace_canstore(regs[r1], 2, mstate, vstate)) {
				*flags |= CPU_DTRACE_KPRIV;
				*illval = regs[r1];
				break;
			}
			/*FALLTHROUGH*/
		case DIF_OP_LDUH:
			regs[rd] = dtrace_load16(regs[r1]);
			break;
		case DIF_OP_RLDUW:
			if (!dtrace_canstore(regs[r1], 4, mstate, vstate)) {
				*flags |= CPU_DTRACE_KPRIV;
				*illval = regs[r1];
				break;
			}
			/*FALLTHROUGH*/
		case DIF_OP_LDUW:
			regs[rd] = dtrace_load32(regs[r1]);
			break;
		case DIF_OP_RLDX:
			if (!dtrace_canstore(regs[r1], 8, mstate, vstate)) {
				*flags |= CPU_DTRACE_KPRIV;
				*illval = regs[r1];
				break;
			}
			/*FALLTHROUGH*/
		case DIF_OP_LDX:
			regs[rd] = dtrace_load64(regs[r1]);
			break;
		case DIF_OP_ULDSB:
			regs[rd] = (int8_t)dtrace_fuword8(
						(void *)(uintptr_t)regs[r1]);
			break;
		case DIF_OP_ULDSH:
			regs[rd] = (int16_t)dtrace_fuword16(
						(void *)(uintptr_t)regs[r1]);
			break;
		case DIF_OP_ULDSW:
			regs[rd] = (int32_t)dtrace_fuword32(
						(void *)(uintptr_t)regs[r1]);
			break;
		case DIF_OP_ULDUB:
			regs[rd] = dtrace_fuword8((void *)(uintptr_t)regs[r1]);
			break;
		case DIF_OP_ULDUH:
			regs[rd] = dtrace_fuword16(
						(void *)(uintptr_t)regs[r1]);
			break;
		case DIF_OP_ULDUW:
			regs[rd] = dtrace_fuword32(
						(void *)(uintptr_t)regs[r1]);
			break;
		case DIF_OP_ULDX:
			regs[rd] = dtrace_fuword64(
						(void *)(uintptr_t)regs[r1]);
			break;
		case DIF_OP_RET:
			rval = regs[rd];
			pc = textlen;
			break;
		case DIF_OP_NOP:
			break;
		case DIF_OP_SETX:
			regs[rd] = inttab[DIF_INSTR_INTEGER(instr)];
			break;
		case DIF_OP_SETS:
			regs[rd] = (uint64_t)(uintptr_t)
					(strtab + DIF_INSTR_STRING(instr));
			break;
		case DIF_OP_SCMP: {
			size_t		sz = state->dts_options[
							DTRACEOPT_STRSIZE];
			uintptr_t	s1 = regs[r1];
			uintptr_t	s2 = regs[r2];

			if (s1 != (uintptr_t)NULL &&
			    !dtrace_strcanload(s1, sz, mstate, vstate))
				break;
			if (s2 != (uintptr_t)NULL &&
			    !dtrace_strcanload(s2, sz, mstate, vstate))
				break;

			cc_r = dtrace_strncmp((char *)s1, (char *)s2, sz);

			cc_n = cc_r < 0;
			cc_z = cc_r == 0;
			cc_v = cc_c = 0;
			break;
		}
		case DIF_OP_LDGA:
		    regs[rd] = dtrace_dif_variable(mstate, state, r1,
						   regs[r2]);
			break;
		case DIF_OP_LDGS:
			id = DIF_INSTR_VAR(instr);

			if (id >= DIF_VAR_OTHER_UBASE) {
				uintptr_t	a;

				id -= DIF_VAR_OTHER_UBASE;
				svar = vstate->dtvs_globals[id];
				ASSERT(svar != NULL);
				v = &svar->dtsv_var;

				if (!(v->dtdv_type.dtdt_flags & DIF_TF_BYREF)) {
					regs[rd] = svar->dtsv_data;
					break;
				}

				a = (uintptr_t)svar->dtsv_data;

				/*
				 * If the 0th byte is set to UINT8_MAX then
				 * this is to be treated as a reference to a
				 * NULL variable.
				 */
				if (*(uint8_t *)a == UINT8_MAX)
					regs[rd] = 0;
				else
					regs[rd] = a + sizeof(uint64_t);

				break;
			}

			regs[rd] = dtrace_dif_variable(mstate, state, id, 0);
			break;

		case DIF_OP_STGS:
			id = DIF_INSTR_VAR(instr);

			ASSERT(id >= DIF_VAR_OTHER_UBASE);
			id -= DIF_VAR_OTHER_UBASE;

			svar = vstate->dtvs_globals[id];
			ASSERT(svar != NULL);
			v = &svar->dtsv_var;

			if (v->dtdv_type.dtdt_flags & DIF_TF_BYREF) {
				uintptr_t	a = (uintptr_t)svar->dtsv_data;

				ASSERT(a != 0);
				ASSERT(svar->dtsv_size != 0);

				if (regs[rd] == 0) {
					*(uint8_t *)a = UINT8_MAX;
					break;
				} else {
					*(uint8_t *)a = 0;
					a += sizeof(uint64_t);
				}

				if (!dtrace_vcanload(
					(void *)(uintptr_t)regs[rd],
					&v->dtdv_type, mstate, vstate))
					break;

				dtrace_vcopy((void *)(uintptr_t)regs[rd],
					     (void *)a, &v->dtdv_type);
				break;
			}

			svar->dtsv_data = regs[rd];
			break;

		case DIF_OP_LDTA:
			/*
			 * There are no DTrace built-in thread-local arrays at
			 * present.  This opcode is saved for future work.
			 */
			*flags |= CPU_DTRACE_ILLOP;
			regs[rd] = 0;
			break;

		case DIF_OP_LDLS:
			id = DIF_INSTR_VAR(instr);

			if (id < DIF_VAR_OTHER_UBASE) {
				/*
				 * For now, this has no meaning.
				 */
				regs[rd] = 0;
				break;
			}

			id -= DIF_VAR_OTHER_UBASE;

			ASSERT(id < vstate->dtvs_nlocals);
			ASSERT(vstate->dtvs_locals != NULL);

			svar = vstate->dtvs_locals[id];
			ASSERT(svar != NULL);
			v = &svar->dtsv_var;

			if (v->dtdv_type.dtdt_flags & DIF_TF_BYREF) {
				uintptr_t	a = (uintptr_t)svar->dtsv_data;
				size_t		sz = v->dtdv_type.dtdt_size;

				sz += sizeof(uint64_t);
				ASSERT(svar->dtsv_size == NR_CPUS * sz);
				a += smp_processor_id() * sz;

				if (*(uint8_t *)a == UINT8_MAX) {
					/*
					 * If the 0th byte is set to UINT8_MAX
					 * then this is to be treated as a
					 * reference to a NULL variable.
					 */
					regs[rd] = 0;
				} else
					regs[rd] = a + sizeof(uint64_t);

				break;
			}

			ASSERT(svar->dtsv_size == NR_CPUS * sizeof(uint64_t));
			tmp = (uint64_t *)(uintptr_t)svar->dtsv_data;
			regs[rd] = tmp[smp_processor_id()];
			break;

		case DIF_OP_STLS:
			id = DIF_INSTR_VAR(instr);

			ASSERT(id >= DIF_VAR_OTHER_UBASE);
			id -= DIF_VAR_OTHER_UBASE;
			ASSERT(id < vstate->dtvs_nlocals);

			ASSERT(vstate->dtvs_locals != NULL);
			svar = vstate->dtvs_locals[id];
			ASSERT(svar != NULL);
			v = &svar->dtsv_var;

			if (v->dtdv_type.dtdt_flags & DIF_TF_BYREF) {
				uintptr_t	a = (uintptr_t)svar->dtsv_data;
				size_t		sz = v->dtdv_type.dtdt_size;

				sz += sizeof(uint64_t);
				ASSERT(svar->dtsv_size == NR_CPUS * sz);
				a += smp_processor_id() * sz;

				if (regs[rd] == 0) {
					*(uint8_t *)a = UINT8_MAX;
					break;
				} else {
					*(uint8_t *)a = 0;
					a += sizeof(uint64_t);
				}

				if (!dtrace_vcanload(
						(void *)(uintptr_t)regs[rd],
						&v->dtdv_type, mstate, vstate))
					break;

				dtrace_vcopy((void *)(uintptr_t)regs[rd],
					     (void *)a, &v->dtdv_type);
				break;
			}

			ASSERT(svar->dtsv_size == NR_CPUS * sizeof(uint64_t));
			tmp = (uint64_t *)(uintptr_t)svar->dtsv_data;
			tmp[smp_processor_id()] = regs[rd];
			break;

		case DIF_OP_LDTS: {
			dtrace_dynvar_t	*dvar;
			dtrace_key_t	*key;

			id = DIF_INSTR_VAR(instr);
			ASSERT(id >= DIF_VAR_OTHER_UBASE);
			id -= DIF_VAR_OTHER_UBASE;
			v = &vstate->dtvs_tlocals[id];

			key = &tupregs[DIF_DTR_NREGS];
			key[0].dttk_value = (uint64_t)id;
			key[0].dttk_size = 0;
			DTRACE_TLS_THRKEY(key[1].dttk_value);
			key[1].dttk_size = 0;

			dvar = dtrace_dynvar(dstate, 2, key, sizeof(uint64_t),
					     DTRACE_DYNVAR_NOALLOC, mstate,
					     vstate);

			if (dvar == NULL) {
				regs[rd] = 0;
				break;
			}

			if (v->dtdv_type.dtdt_flags & DIF_TF_BYREF)
				regs[rd] = (uint64_t)(uintptr_t)dvar->dtdv_data;
			else
				regs[rd] = *((uint64_t *)dvar->dtdv_data);

			break;
		}

		case DIF_OP_STTS: {
			dtrace_dynvar_t	*dvar;
			dtrace_key_t	*key;

			id = DIF_INSTR_VAR(instr);
			ASSERT(id >= DIF_VAR_OTHER_UBASE);
			id -= DIF_VAR_OTHER_UBASE;

			key = &tupregs[DIF_DTR_NREGS];
			key[0].dttk_value = (uint64_t)id;
			key[0].dttk_size = 0;
			DTRACE_TLS_THRKEY(key[1].dttk_value);
			key[1].dttk_size = 0;
			v = &vstate->dtvs_tlocals[id];

			dvar = dtrace_dynvar(dstate, 2, key,
				v->dtdv_type.dtdt_size > sizeof(uint64_t)
					?  v->dtdv_type.dtdt_size
					: sizeof(uint64_t),
				regs[rd]
					? DTRACE_DYNVAR_ALLOC
					: DTRACE_DYNVAR_DEALLOC,
				mstate, vstate);

			/*
			 * Given that we're storing to thread-local data,
			 * we need to flush our predicate cache.
			 */
			current->predcache = 0;

			if (dvar == NULL)
				break;

			if (v->dtdv_type.dtdt_flags & DIF_TF_BYREF) {
				if (!dtrace_vcanload(
						(void *)(uintptr_t)regs[rd],
						&v->dtdv_type, mstate, vstate))
					break;

				dtrace_vcopy((void *)(uintptr_t)regs[rd],
					     dvar->dtdv_data, &v->dtdv_type);
			} else
				*((uint64_t *)dvar->dtdv_data) = regs[rd];

			break;
		}

		case DIF_OP_SRA:
			regs[rd] = (int64_t)regs[r1] >> regs[r2];
			break;

		case DIF_OP_CALL:
			dtrace_dif_subr(DIF_INSTR_SUBR(instr), rd, regs,
					tupregs, ttop, mstate, state);
			break;

		case DIF_OP_PUSHTR:
			if (ttop == DIF_DTR_NREGS) {
				*flags |= CPU_DTRACE_TUPOFLOW;
				break;
			}

			if (r1 == DIF_TYPE_STRING)
				/*
				 * If this is a string type and the size is 0,
				 * we'll use the system-wide default string
				 * size.  Note that we are _not_ looking at
				 * the value of the DTRACEOPT_STRSIZE option;
				 * had this been set, we would expect to have
				 * a non-zero size value in the "pushtr".
				 */
				tupregs[ttop].dttk_size =
					dtrace_strlen(
						(char *)(uintptr_t)regs[rd],
						regs[r2]
						    ? regs[r2]
						    : dtrace_strsize_default
					) + 1;
			else
				tupregs[ttop].dttk_size = regs[r2];

			tupregs[ttop++].dttk_value = regs[rd];
			break;

		case DIF_OP_PUSHTV:
			if (ttop == DIF_DTR_NREGS) {
				*flags |= CPU_DTRACE_TUPOFLOW;
				break;
			}

			tupregs[ttop].dttk_value = regs[rd];
			tupregs[ttop++].dttk_size = 0;
			break;

		case DIF_OP_POPTS:
			if (ttop != 0)
				ttop--;
			break;

		case DIF_OP_FLUSHTS:
			ttop = 0;
			break;

		case DIF_OP_LDGAA:
		case DIF_OP_LDTAA: {
			dtrace_dynvar_t	*dvar;
			dtrace_key_t	*key = tupregs;
			uint_t		nkeys = ttop;

			id = DIF_INSTR_VAR(instr);
			ASSERT(id >= DIF_VAR_OTHER_UBASE);
			id -= DIF_VAR_OTHER_UBASE;

			key[nkeys].dttk_value = (uint64_t)id;
			key[nkeys++].dttk_size = 0;

			if (DIF_INSTR_OP(instr) == DIF_OP_LDTAA) {
				DTRACE_TLS_THRKEY(key[nkeys].dttk_value);
				key[nkeys++].dttk_size = 0;
				v = &vstate->dtvs_tlocals[id];
			} else
				v = &vstate->dtvs_globals[id]->dtsv_var;

			dvar = dtrace_dynvar(dstate, nkeys, key,
			v->dtdv_type.dtdt_size > sizeof(uint64_t) ?
			v->dtdv_type.dtdt_size : sizeof(uint64_t),
			DTRACE_DYNVAR_NOALLOC, mstate, vstate);

			if (dvar == NULL) {
				regs[rd] = 0;
				break;
			}

			if (v->dtdv_type.dtdt_flags & DIF_TF_BYREF)
				regs[rd] = (uint64_t)(uintptr_t)dvar->dtdv_data;
			else
				regs[rd] = *((uint64_t *)dvar->dtdv_data);

			break;
		}

		case DIF_OP_STGAA:
		case DIF_OP_STTAA: {
			dtrace_dynvar_t	*dvar;
			dtrace_key_t	*key = tupregs;
			uint_t		nkeys = ttop;

			id = DIF_INSTR_VAR(instr);
			ASSERT(id >= DIF_VAR_OTHER_UBASE);
			id -= DIF_VAR_OTHER_UBASE;

			key[nkeys].dttk_value = (uint64_t)id;
			key[nkeys++].dttk_size = 0;

			if (DIF_INSTR_OP(instr) == DIF_OP_STTAA) {
				DTRACE_TLS_THRKEY(key[nkeys].dttk_value);
				key[nkeys++].dttk_size = 0;
				v = &vstate->dtvs_tlocals[id];
			} else
				v = &vstate->dtvs_globals[id]->dtsv_var;

			dvar = dtrace_dynvar(dstate, nkeys, key,
				v->dtdv_type.dtdt_size > sizeof(uint64_t)
					?  v->dtdv_type.dtdt_size
					: sizeof(uint64_t),
				regs[rd] ? DTRACE_DYNVAR_ALLOC
					 : DTRACE_DYNVAR_DEALLOC,
				mstate, vstate);

			if (dvar == NULL)
				break;

			if (v->dtdv_type.dtdt_flags & DIF_TF_BYREF) {
				if (!dtrace_vcanload(
						(void *)(uintptr_t)regs[rd],
						&v->dtdv_type, mstate, vstate))
					break;

				dtrace_vcopy((void *)(uintptr_t)regs[rd],
					     dvar->dtdv_data, &v->dtdv_type);
			} else
				*((uint64_t *)dvar->dtdv_data) = regs[rd];

			break;
		}

		case DIF_OP_ALLOCS: {
			uintptr_t	ptr =
					P2ROUNDUP(mstate->dtms_scratch_ptr, 8);
			size_t		size = ptr - mstate->dtms_scratch_ptr +
					       regs[r1];

			/*
			 * Rounding up the user allocation size could have
			 * overflowed large, bogus allocations (like -1ULL) to
			 * 0.
			 */
			if (size < regs[r1] ||
			    !DTRACE_INSCRATCH(mstate, size)) {
				DTRACE_CPUFLAG_SET(CPU_DTRACE_NOSCRATCH);
				regs[rd] = 0;
				break;
			}

			dtrace_bzero((void *) mstate->dtms_scratch_ptr, size);
			mstate->dtms_scratch_ptr += size;
			regs[rd] = ptr;
			break;
		}

		case DIF_OP_COPYS:
			if (!dtrace_canstore(regs[rd], regs[r2], mstate,
					     vstate)) {
				*flags |= CPU_DTRACE_BADADDR;
				*illval = regs[rd];
				break;
			}

			if (!dtrace_canload(regs[r1], regs[r2], mstate, vstate))
				break;

			dtrace_bcopy((void *)(uintptr_t)regs[r1],
				     (void *)(uintptr_t)regs[rd],
				     (size_t)regs[r2]);
			break;

		case DIF_OP_STB:
			if (!dtrace_canstore(regs[rd], 1, mstate, vstate)) {
				*flags |= CPU_DTRACE_BADADDR;
				*illval = regs[rd];
				break;
			}

			*((uint8_t *)(uintptr_t)regs[rd]) = (uint8_t)regs[r1];
			break;

		case DIF_OP_STH:
			if (!dtrace_canstore(regs[rd], 2, mstate, vstate)) {
				*flags |= CPU_DTRACE_BADADDR;
				*illval = regs[rd];
				break;
			}

			if (regs[rd] & 1) {
				*flags |= CPU_DTRACE_BADALIGN;
				*illval = regs[rd];
				break;
			}

			*((uint16_t *)(uintptr_t)regs[rd]) = (uint16_t)regs[r1];
			break;

		case DIF_OP_STW:
			if (!dtrace_canstore(regs[rd], 4, mstate, vstate)) {
				*flags |= CPU_DTRACE_BADADDR;
				*illval = regs[rd];
				break;
			}

			if (regs[rd] & 3) {
				*flags |= CPU_DTRACE_BADALIGN;
				*illval = regs[rd];
				break;
			}

			*((uint32_t *)(uintptr_t)regs[rd]) = (uint32_t)regs[r1];
			break;

		case DIF_OP_STX:
			if (!dtrace_canstore(regs[rd], 8, mstate, vstate)) {
				*flags |= CPU_DTRACE_BADADDR;
				*illval = regs[rd];
				break;
			}

			if (regs[rd] & 7) {
				*flags |= CPU_DTRACE_BADALIGN;
				*illval = regs[rd];
				break;
			}

			*((uint64_t *)(uintptr_t)regs[rd]) = regs[r1];
			break;
		}
	}


	if (!(*flags & CPU_DTRACE_FAULT)) {
		dt_dbg_dif("    DIF %p completed, rval = %llx (flags %x)\n",
			   difo, rval, *flags);
		return rval;
	}

	dt_dbg_dif("    DIF %p emulation failed (flags %x)\n",  difo, *flags);

	mstate->dtms_fltoffs = opc * sizeof(dif_instr_t);
	mstate->dtms_present |= DTRACE_MSTATE_FLTOFFS;

	return 0;
}
