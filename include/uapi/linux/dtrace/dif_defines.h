/*
 * Licensed under the Universal Permissive License v 1.0 as shown at
 * http://oss.oracle.com/licenses/upl.
 *
 * Copyright (c) 2009, 2017, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * Note: The contents of this file are private to the implementation of the
 * DTrace subsystem and are subject to change at any time without notice.
 */

#ifndef _LINUX_DTRACE_DIF_DEFINES_H
#define _LINUX_DTRACE_DIF_DEFINES_H

#include <linux/dtrace/universal.h>

/*
 * The following definitions describe the DTrace Intermediate Format (DIF), a a
 * RISC-like instruction set and program encoding used to represent predicates
 * and actions that can be bound to DTrace probes.  The constants below defining
 * the number of available registers are suggested minimums; the compiler should
 * use DTRACEIOC_CONF to dynamically obtain the number of registers provided by
 * the current DTrace implementation.
 */

#define DIF_VERSION_1	1
#define DIF_VERSION_2	2
#define DIF_VERSION	DIF_VERSION_2
#define	DIF_DIR_NREGS	8		/* number of DIF integer registers */
#define	DIF_DTR_NREGS	8		/* number of DIF tuple registers */

#define DIF_OP_OR	1		/* or   r1, r2, rd */
#define DIF_OP_XOR	2		/* xor  r1, r2, rd */
#define DIF_OP_AND	3		/* and  r1, r2, rd */
#define DIF_OP_SLL	4		/* sll  r1, r2, rd */
#define DIF_OP_SRL	5		/* srl  r1, r2, rd */
#define DIF_OP_SUB	6		/* sub  r1, r2, rd */
#define DIF_OP_ADD	7		/* add  r1, r2, rd */
#define DIF_OP_MUL	8		/* mul  r1, r2, rd */
#define DIF_OP_SDIV	9		/* sdiv r1, r2, rd */
#define DIF_OP_UDIV	10		/* udiv r1, r2, rd */
#define DIF_OP_SREM	11		/* srem r1, r2, rd */
#define DIF_OP_UREM	12		/* urem r1, r2, rd */
#define DIF_OP_NOT	13		/* not  r1, rd */
#define DIF_OP_MOV	14		/* mov  r1, rd */
#define DIF_OP_CMP	15		/* cmp  r1, r2 */
#define DIF_OP_TST	16		/* tst  r1 */
#define DIF_OP_BA	17		/* ba   label */
#define DIF_OP_BE	18		/* be   label */
#define DIF_OP_BNE	19		/* bne  label */
#define DIF_OP_BG	20		/* bg   label */
#define DIF_OP_BGU	21		/* bgu  label */
#define DIF_OP_BGE	22		/* bge  label */
#define DIF_OP_BGEU	23		/* bgeu label */
#define DIF_OP_BL	24		/* bl   label */
#define DIF_OP_BLU	25		/* blu  label */
#define DIF_OP_BLE	26		/* ble  label */
#define DIF_OP_BLEU	27		/* bleu label */
#define DIF_OP_LDSB	28		/* ldsb [r1], rd */
#define DIF_OP_LDSH	29		/* ldsh [r1], rd */
#define DIF_OP_LDSW	30		/* ldsw [r1], rd */
#define DIF_OP_LDUB	31		/* ldub [r1], rd */
#define DIF_OP_LDUH	32		/* lduh [r1], rd */
#define DIF_OP_LDUW	33		/* lduw [r1], rd */
#define DIF_OP_LDX	34		/* ldx  [r1], rd */
#define DIF_OP_RET	35		/* ret  rd */
#define DIF_OP_NOP	36		/* nop */
#define DIF_OP_SETX	37		/* setx intindex, rd */
#define DIF_OP_SETS	38		/* sets strindex, rd */
#define DIF_OP_SCMP	39		/* scmp r1, r2 */
#define DIF_OP_LDGA	40		/* ldga var, ri, rd */
#define DIF_OP_LDGS	41		/* ldgs var, rd */
#define DIF_OP_STGS	42		/* stgs var, rs */
#define DIF_OP_LDTA	43		/* ldta var, ri, rd */
#define DIF_OP_LDTS	44		/* ldts var, rd */
#define DIF_OP_STTS	45		/* stts var, rs */
#define DIF_OP_SRA	46		/* sra  r1, r2, rd */
#define DIF_OP_CALL	47		/* call subr, rd */
#define DIF_OP_PUSHTR	48		/* pushtr type, rs, rr */
#define DIF_OP_PUSHTV	49		/* pushtv type, rs, rv */
#define DIF_OP_POPTS	50		/* popts */
#define DIF_OP_FLUSHTS	51		/* flushts */
#define DIF_OP_LDGAA	52		/* ldgaa var, rd */
#define DIF_OP_LDTAA	53		/* ldtaa var, rd */
#define DIF_OP_STGAA	54		/* stgaa var, rs */
#define DIF_OP_STTAA	55		/* sttaa var, rs */
#define DIF_OP_LDLS	56		/* ldls var, rd */
#define DIF_OP_STLS	57		/* stls var, rs */
#define DIF_OP_ALLOCS	58		/* allocs r1, rd */
#define DIF_OP_COPYS	59		/* copys  r1, r2, rd */
#define DIF_OP_STB	60		/* stb  r1, [rd] */
#define DIF_OP_STH	61		/* sth  r1, [rd] */
#define DIF_OP_STW	62		/* stw  r1, [rd] */
#define DIF_OP_STX	63		/* stx  r1, [rd] */
#define DIF_OP_ULDSB	64		/* uldsb [r1], rd */
#define DIF_OP_ULDSH	65		/* uldsh [r1], rd */
#define DIF_OP_ULDSW	66		/* uldsw [r1], rd */
#define DIF_OP_ULDUB	67		/* uldub [r1], rd */
#define DIF_OP_ULDUH	68		/* ulduh [r1], rd */
#define DIF_OP_ULDUW	69		/* ulduw [r1], rd */
#define DIF_OP_ULDX	70		/* uldx  [r1], rd */
#define DIF_OP_RLDSB	71		/* rldsb [r1], rd */
#define DIF_OP_RLDSH	72		/* rldsh [r1], rd */
#define DIF_OP_RLDSW	73		/* rldsw [r1], rd */
#define DIF_OP_RLDUB	74		/* rldub [r1], rd */
#define DIF_OP_RLDUH	75		/* rlduh [r1], rd */
#define DIF_OP_RLDUW	76		/* rlduw [r1], rd */
#define DIF_OP_RLDX	77		/* rldx  [r1], rd */
#define DIF_OP_XLATE	78		/* xlate xlrindex, rd */
#define DIF_OP_XLARG	79		/* xlarg xlrindex, rd */

#define	DIF_INTOFF_MAX		0xffff	/* highest integer table offset */
#define	DIF_STROFF_MAX		0xffff	/* highest string table offset */
#define	DIF_REGISTER_MAX	0xff	/* highest register number */
#define	DIF_VARIABLE_MAX	0xffff	/* highest variable identifier */
#define	DIF_SUBROUTINE_MAX	0xffff	/* highest subroutine code */

#define	DIF_VAR_ARRAY_MIN	0x0000	/* lowest numbered array variable */
#define	DIF_VAR_ARRAY_UBASE	0x0080	/* lowest user-defined array */
#define	DIF_VAR_ARRAY_MAX	0x00ff	/* highest numbered array variable */

#define	DIF_VAR_OTHER_MIN	0x0100	/* lowest numbered scalar or assc */
#define	DIF_VAR_OTHER_UBASE	0x0500	/* lowest user-defined scalar or assc */
#define	DIF_VAR_OTHER_MAX	0xffff	/* highest numbered scalar or assc */

#define DIF_VAR_ARGS		0x0000
#define DIF_VAR_REGS		0x0001
#define DIF_VAR_UREGS		0x0002
#define DIF_VAR_CURTHREAD	0x0100
#define DIF_VAR_TIMESTAMP	0x0101
#define DIF_VAR_VTIMESTAMP	0x0102
#define DIF_VAR_IPL		0x0103
#define DIF_VAR_EPID		0x0104
#define DIF_VAR_ID		0x0105
#define DIF_VAR_ARG0		0x0106
#define DIF_VAR_ARG1		0x0107
#define DIF_VAR_ARG2		0x0108
#define DIF_VAR_ARG3		0x0109
#define DIF_VAR_ARG4		0x010a
#define DIF_VAR_ARG5		0x010b
#define DIF_VAR_ARG6		0x010c
#define DIF_VAR_ARG7		0x010d
#define DIF_VAR_ARG8		0x010e
#define DIF_VAR_ARG9		0x010f
#define DIF_VAR_STACKDEPTH	0x0110
#define DIF_VAR_CALLER		0x0111
#define DIF_VAR_PROBEPROV	0x0112
#define DIF_VAR_PROBEMOD	0x0113
#define DIF_VAR_PROBEFUNC	0x0114
#define DIF_VAR_PROBENAME	0x0115
#define DIF_VAR_PID		0x0116
#define DIF_VAR_TID		0x0117
#define DIF_VAR_EXECNAME	0x0118
#define DIF_VAR_ZONENAME	0x0119
#define DIF_VAR_WALLTIMESTAMP	0x011a
#define DIF_VAR_USTACKDEPTH	0x011b
#define DIF_VAR_UCALLER		0x011c
#define DIF_VAR_PPID		0x011d
#define DIF_VAR_UID		0x011e
#define DIF_VAR_GID		0x011f
#define DIF_VAR_ERRNO		0x0120
#define DIF_VAR_CURCPU		0x0121

#define DIF_SUBR_RAND			0
#define DIF_SUBR_MUTEX_OWNED		1
#define DIF_SUBR_MUTEX_OWNER		2
#define DIF_SUBR_MUTEX_TYPE_ADAPTIVE	3
#define DIF_SUBR_MUTEX_TYPE_SPIN	4
#define DIF_SUBR_RW_READ_HELD		5
#define DIF_SUBR_RW_WRITE_HELD		6
#define DIF_SUBR_RW_ISWRITER		7
#define DIF_SUBR_COPYIN			8
#define DIF_SUBR_COPYINSTR		9
#define DIF_SUBR_SPECULATION		10
#define DIF_SUBR_PROGENYOF		11
#define DIF_SUBR_STRLEN			12
#define DIF_SUBR_COPYOUT		13
#define DIF_SUBR_COPYOUTSTR		14
#define DIF_SUBR_ALLOCA			15
#define DIF_SUBR_BCOPY			16
#define DIF_SUBR_COPYINTO		17
#define DIF_SUBR_MSGDSIZE		18
#define DIF_SUBR_MSGSIZE		19
#define DIF_SUBR_GETMAJOR		20
#define DIF_SUBR_GETMINOR		21
#define DIF_SUBR_DDI_PATHNAME		22
#define DIF_SUBR_STRJOIN		23
#define DIF_SUBR_LLTOSTR		24
#define DIF_SUBR_BASENAME		25
#define DIF_SUBR_DIRNAME		26
#define DIF_SUBR_CLEANPATH		27
#define DIF_SUBR_STRCHR			28
#define DIF_SUBR_STRRCHR		29
#define DIF_SUBR_STRSTR			30
#define DIF_SUBR_STRTOK			31
#define DIF_SUBR_SUBSTR			32
#define DIF_SUBR_INDEX			33
#define DIF_SUBR_RINDEX			34
#define DIF_SUBR_HTONS			35
#define DIF_SUBR_HTONL			36
#define DIF_SUBR_HTONLL			37
#define DIF_SUBR_NTOHS			38
#define DIF_SUBR_NTOHL			39
#define DIF_SUBR_NTOHLL			40
#define DIF_SUBR_INET_NTOP		41
#define DIF_SUBR_INET_NTOA		42
#define DIF_SUBR_INET_NTOA6		43
#define DIF_SUBR_D_PATH			44
#define DIF_SUBR_LINK_NTOP		45

#define DIF_SUBR_MAX			45

typedef uint32_t	dif_instr_t;

#define DIF_INSTR_OP(i)			(((i) >> 24) & 0xff)
#define DIF_INSTR_R1(i)			(((i) >> 16) & 0xff)
#define DIF_INSTR_R2(i)			(((i) >>  8) & 0xff)
#define DIF_INSTR_RD(i)			((i) & 0xff)
#define DIF_INSTR_RS(i)			((i) & 0xff)
#define DIF_INSTR_LABEL(i)		((i) & 0xffffff)
#define DIF_INSTR_VAR(i)		(((i) >>  8) & 0xffff)
#define DIF_INSTR_INTEGER(i)		(((i) >>  8) & 0xffff)
#define DIF_INSTR_STRING(i)		(((i) >>  8) & 0xffff)
#define DIF_INSTR_SUBR(i)		(((i) >>  8) & 0xffff)
#define DIF_INSTR_TYPE(i)		(((i) >> 16) & 0xff)
#define DIF_INSTR_XLREF(i)		(((i) >>  8) & 0xffff)
#define DIF_INSTR_FMT(op, r1, r2, d) \
			(((op) << 24) | ((r1) << 16) | ((r2) << 8) | (d))

#define DIF_INSTR_NOT(r1, d)		(DIF_INSTR_FMT(DIF_OP_NOT, r1, 0, d))
#define DIF_INSTR_MOV(r1, d)		(DIF_INSTR_FMT(DIF_OP_MOV, r1, 0, d))
#define DIF_INSTR_CMP(op, r1, r2)	(DIF_INSTR_FMT(op, r1, r2, 0))
#define DIF_INSTR_TST(r1)		(DIF_INSTR_FMT(DIF_OP_TST, r1, 0, 0))
#define DIF_INSTR_BRANCH(op, label)	(((op) << 24) | (label))
#define DIF_INSTR_LOAD(op, r1, d)	(DIF_INSTR_FMT(op, r1, 0, d))
#define DIF_INSTR_STORE(op, r1, d)	(DIF_INSTR_FMT(op, r1, 0, d))
#define DIF_INSTR_SETX(i, d)		((DIF_OP_SETX << 24) | ((i) << 8) | (d))
#define DIF_INSTR_SETS(s, d)		((DIF_OP_SETS << 24) | ((s) << 8) | (d))
#define DIF_INSTR_RET(d)		(DIF_INSTR_FMT(DIF_OP_RET, 0, 0, d))
#define DIF_INSTR_NOP			(DIF_OP_NOP << 24)
#define DIF_INSTR_LDA(op, v, r, d)	(DIF_INSTR_FMT(op, v, r, d))
#define DIF_INSTR_LDV(op, v, d)		(((op) << 24) | ((v) << 8) | (d))
#define DIF_INSTR_STV(op, v, rs)	(((op) << 24) | ((v) << 8) | (rs))
#define DIF_INSTR_CALL(s, d)		((DIF_OP_CALL << 24) | ((s) << 8) | (d))
#define DIF_INSTR_PUSHTS(op, t, r2, rs)	(DIF_INSTR_FMT(op, t, r2, rs))
#define DIF_INSTR_POPTS			(DIF_OP_POPTS << 24)
#define DIF_INSTR_FLUSHTS		(DIF_OP_FLUSHTS << 24)
#define DIF_INSTR_ALLOCS(r1, d)		(DIF_INSTR_FMT(DIF_OP_ALLOCS, r1, 0, d))
#define DIF_INSTR_COPYS(r1, r2, d)	(DIF_INSTR_FMT(DIF_OP_COPYS, r1, r2, d))
#define DIF_INSTR_XLATE(op, r, d)	(((op) << 24) | ((r) << 8) | (d))

#define DIF_REG_R0		0

/*
 * A DTrace Intermediate Format Type (DIF Type) is used to represent the types
 * of variables, function and associative array arguments, and the return type
 * for each DIF object (shown below).  It contains a description of the type,
 * its size in bytes, and a module identifier.
 */

#define DIF_TYPE_CTF		0
#define DIF_TYPE_STRING		1

#define DIF_TF_BYREF		0x1

/*
 * A DTrace Intermediate Format variable record is used to describe each of the
 * variables referenced by a given DIF object.  It contains an integer variable
 * identifier along with variable scope and properties, as shown below.  The
 * size of this structure must be sizeof (int) aligned.
 */

#define DIFV_KIND_ARRAY		0
#define DIFV_KIND_SCALAR	1

#define DIFV_SCOPE_GLOBAL	0
#define DIFV_SCOPE_THREAD	1
#define DIFV_SCOPE_LOCAL	2

#define DIFV_F_REF		0x1
#define DIFV_F_MOD		0x2

struct dtrace_diftype;
struct dtrace_difv;

#endif /* _LINUX_DTRACE_DIF_DEFINES_H */
