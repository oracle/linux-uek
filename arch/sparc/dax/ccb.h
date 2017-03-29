/*
 * Copyright (c) 2017, Oracle and/or its affiliates. All rights reserved.
 *
 * This work is licensed under the terms of the GNU GPL, version 2.
 */

#ifndef	_CCB_H
#define	_CCB_H

/* CCB address types */
#define	CCB_AT_IMM		0	/* immediate */
#define	CCB_AT_VA		3	/* virtual address */
#ifdef __KERNEL__
#define	CCB_AT_VA_ALT		1	/* only kernel can use
					 * secondary context
					 */
#define	CCB_AT_RA		2	/* only kernel can use real address */
#endif /* __KERNEL__ */

#define	CCB_AT_COMPL_MASK	0x3
#define	CCB_AT_SRC0_MASK	0x7
#define	CCB_AT_SRC1_MASK	0x7
#define	CCB_AT_DST_MASK		0x7
#define	CCB_AT_TBL_MASK		0x3

#define	CCB_AT_COMPL_SHIFT	32
#define	CCB_AT_SRC0_SHIFT	34

/* CCB header sync flags */
#define	CCB_SYNC_SERIAL		BIT(0)
#define	CCB_SYNC_COND		BIT(1)
#define	CCB_SYNC_LONGCCB	BIT(2)

#define	CCB_SYNC_FLG_SHIFT	24
#define	CCB_HDR_SHIFT		32

#define	CCB_DW1_INTR_SHIFT	59

#define	DAX_BUF_LIMIT_FLOW_CTL	2
#define	DAX_EXT_OP_ENABLE	1

/* CCB L3 output allocation */
#define	CCB_OUTPUT_ALLOC_NONE	0	/* do not allocate in L3 */
#define	CCB_OUTPUT_ALLOC_HARD	1	/* allocate in L3 of running cpu */
#define	CCB_OUTPUT_ALLOC_SOFT	2	/* allocate to whichever L3 owns */
					/* line, else L3 of running cpu */

#define	CCB_LOCAL_ADDR_SHIFT	6
#define	CCB_LOCAL_ADDR(x, mask)	(((x) & mask) >> CCB_LOCAL_ADDR_SHIFT)

#define	CCB_DWORD_CTL		0
#define	CCB_DWORD_COMPL		1

#define	QUERY_DWORD_INPUT	2
#define	QUERY_DWORD_DAC		3
#define	QUERY_DWORD_SEC_INPUT	4
#define	QUERY_DWORD_OUTPUT	6
#define	QUERY_DWORD_TBL		7


#define	BIT_MASK64(_hi, _lo)	(((u64)((~(u64)0)>>(63-(_hi)))) & \
	((u64)((~(u64)0)<<(_lo))))

#define	CCB_GET(s, dword)	(((dword) & CCB_##s##_MASK) >> CCB_##s##_SHIFT)

#define	CCB_SET(s, val, dword)				\
	((dword) = ((dword) & ~CCB_##s##_MASK) |	\
	((((val) << CCB_##s##_SHIFT)) & CCB_##s##_MASK))

#define	CCB_QUERY_INPUT_VA_MASK		BIT_MASK64(53, 0)
#define	CCB_QUERY_INPUT_VA_SHIFT	0

#define	CCB_QUERY_INPUT_PA_MASK		BIT_MASK64(55, 0)
#define	CCB_QUERY_INPUT_PA_SHIFT	0

#define	CCB_QUERY_SEC_INPUT_VA_MASK	CCB_QUERY_INPUT_VA_MASK
#define	CCB_QUERY_SEC_INPUT_VA_SHIFT	CCB_QUERY_INPUT_VA_SHIFT

#define	CCB_QUERY_SEC_INPUT_PA_MASK	CCB_QUERY_INPUT_PA_MASK
#define	CCB_QUERY_SEC_INPUT_PA_SHIFT	CCB_QUERY_INPUT_PA_SHIFT

#define	CCB_COMPL_VA(dw)		CCB_GET(COMPL_VA, (dw))

#define	CCB_QUERY_INPUT_VA(dw)	CCB_GET(QUERY_INPUT_VA, (dw))
#define	CCB_QUERY_SEC_INPUT_VA(dw)	CCB_GET(QUERY_SEC_INPUT_VA, (dw))
#define	CCB_QUERY_OUTPUT_VA(dw)	CCB_GET(QUERY_OUTPUT_VA, (dw))
#define	CCB_QUERY_TBL_VA(dw)		CCB_GET(QUERY_TBL_VA, (dw))

#define	CCB_SET_COMPL_PA(pa, dw)	CCB_SET(COMPL_PA, (pa), (dw))

#define	CCB_SET_QUERY_INPUT_PA(pa, dw)	CCB_SET(QUERY_INPUT_PA, (pa), (dw))
#define	CCB_SET_QUERY_SEC_INPUT_PA(pa, dw)	\
	CCB_SET(QUERY_SEC_INPUT_PA, (pa), (dw))
#define	CCB_SET_QUERY_OUTPUT_PA(pa, dw)	CCB_SET(QUERY_OUTPUT_PA, (pa), (dw))
#define	CCB_SET_QUERY_TBL_PA(pa, dw)	CCB_SET(QUERY_TBL_PA, (pa), (dw))

/* max number of VA bits that can be specified in CCB */
#define	CCB_VA_NBITS			54

#define CCB_VA_SIGN_EXTEND(va) va

#define CCB_COMPL_PA_MASK		BIT_MASK64(55, 6)
#define CCB_COMPL_PA_SHIFT		0

/*
 * Query CCB opcodes
 */
#define	CCB_QUERY_OPCODE_SYNC_NOP	0x0
#define	CCB_QUERY_OPCODE_EXTRACT	0x1
#define	CCB_QUERY_OPCODE_SCAN_VALUE	0x2
#define	CCB_QUERY_OPCODE_SCAN_RANGE	0x3
#define	CCB_QUERY_OPCODE_TRANSLATE	0x4
#define	CCB_QUERY_OPCODE_SELECT		0x5
#define	CCB_QUERY_OPCODE_INV_SCAN_VALUE	0x12
#define	CCB_QUERY_OPCODE_INV_SCAN_RANGE	0x13
#define	CCB_QUERY_OPCODE_INV_TRANSLATE	0x14

/* Query primary input formats */
#define	CCB_QUERY_IFMT_FIX_BYTE		0	/* to 16 bytes */
#define	CCB_QUERY_IFMT_FIX_BIT		1	/* to 15 bits */
#define	CCB_QUERY_IFMT_VAR_BYTE		2	/* separate length stream */
#define	CCB_QUERY_IFMT_FIX_BYTE_RLE	4	/* to 16 bytes + RL stream */
#define	CCB_QUERY_IFMT_FIX_BIT_RLE	5	/* to 15 bits + RL stream */
#define	CCB_QUERY_IFMT_FIX_BYTE_HUFF	8	/* to 16 bytes */
#define	CCB_QUERY_IFMT_FIX_BIT_HUFF	9	/* to 15 bits */
#define	CCB_QUERY_IFMT_VAR_BYTE_HUFF	10	/* separate length stream */
#define	CCB_QUERY_IFMT_FIX_BYTE_RLE_HUFF 12	/* to 16 bytes + RL stream */
#define	CCB_QUERY_IFMT_FIX_BIT_RLE_HUFF	13	/* to 15 bits + RL stream */

/* Query secondary input size */
#define	CCB_QUERY_SZ_ONEBIT		0
#define	CCB_QUERY_SZ_TWOBIT		1
#define	CCB_QUERY_SZ_FOURBIT		2
#define	CCB_QUERY_SZ_EIGHTBIT		3

/* Query secondary input encoding */
#define	CCB_QUERY_SIE_LESS_ONE		0
#define	CCB_QUERY_SIE_ACTUAL		1

/* Query output formats */
#define	CCB_QUERY_OFMT_BYTE_ALIGN	0
#define	CCB_QUERY_OFMT_16B		1
#define	CCB_QUERY_OFMT_BIT_VEC		2
#define	CCB_QUERY_OFMT_ONE_IDX		3

/* Query operand size constants */
#define	CCB_QUERY_OPERAND_DISABLE	31

/* Query Data Access Control input length format */
#define	CCB_QUERY_ILF_SYMBOL		0
#define	CCB_QUERY_ILF_BYTE		1
#define	CCB_QUERY_ILF_BIT		2

/* Completion area cmd_status */
#define	CCB_CMD_STAT_NOT_COMPLETED	0
#define	CCB_CMD_STAT_COMPLETED		1
#define	CCB_CMD_STAT_FAILED		2
#define	CCB_CMD_STAT_KILLED		3
#define	CCB_CMD_STAT_NOT_RUN		4
#define	CCB_CMD_STAT_NO_OUTPUT		5

/* Completion area err_mask of user visible errors */
#define	CCB_CMD_ERR_BOF			0x1	/* buffer overflow */
#define	CCB_CMD_ERR_DECODE		0x2	/* CCB decode error */
#define	CCB_CMD_ERR_POF			0x3	/* page overflow */
#define	CCB_CMD_ERR_RSVD1		0x4	/* Reserved */
#define	CCB_CMD_ERR_RSVD2		0x5	/* Reserved */
#define	CCB_CMD_ERR_KILL		0x7	/* command was killed */
#define	CCB_CMD_ERR_TO			0x8	/* command timeout */
#define	CCB_CMD_ERR_MCD			0x9	/* MCD error */
#define	CCB_CMD_ERR_DATA_FMT		0xA	/* data format error */
#define	CCB_CMD_ERR_OTHER		0xF	/* error not visible to user */

struct ccb_hdr {
	u32	ccb_ver:4;	/* must be set to 0 for M7 HW */
	u32	sync_flags:4;
	u32	opcode:8;
	u32	rsvd:3;
	u32	at_tbl:2;	/* IMM/RA(kernel)/VA*/
	u32	at_dst:3;	/* IMM/RA(kernel)/VA*/
	u32	at_src1:3;	/* IMM/RA(kernel)/VA*/
	u32	at_src0:3;	/* IMM/RA(kernel)/VA*/
#ifdef __KERNEL__
	u32	at_cmpl:2;	/* IMM/RA(kernel)/VA*/
#else
	u32	rsvd2:2;	/* only kernel can specify at_cmpl */
#endif /* __KERNEL__ */
};

struct ccb_addr {
	u64	adi:4;
	u64	rsvd:4;
	u64	addr:50;	/* [55:6] of 64B aligned address */
					/* if VA, [55:54] must be 0 */
	u64	rsvd2:6;
};

struct ccb_byte_addr {
	u64	adi:4;
	u64	rsvd:4;
	u64	addr:56;	/* [55:0] of byte aligned address */
					/* if VA, [55:54] must be 0 */
};

struct ccb_tbl_addr {
	u64	adi:4;
	u64	rsvd:4;
	u64	addr:50;	/* [55:6] of 64B aligned address */
					/* if VA, [55:54] must be 0 */
	u64	rsvd2:4;
	u64	vers:2;		/* version number */
};

struct ccb_cmpl_addr {
	u64	adi:4;
	u64	intr:1;		/* Interrupt not supported */
#ifdef __KERNEL__
	u64	rsvd:3;
	u64	addr:50;	/* [55:6] of 64B aligned address */
					/* if VA, [55:54] must be 0 */
	u64	rsvd2:6;
#else
	u64	rsvd:59;	/* Only kernel can specify completion */
					/* address in CCB.  User must use */
					/* offset to mmapped kernel memory. */
#endif /* __KERNEL__ */
};

struct ccb_sync_nop_ctl {
	struct ccb_hdr	hdr;
	u32		ext_op:1;	/* extended op flag */
	u32		rsvd:31;
};

/*
 * CCB_QUERY_OPCODE_SYNC_NOP
 */
struct ccb_sync_nop {
	struct ccb_sync_nop_ctl	ctl;
	struct ccb_cmpl_addr	completion;
	u64			rsvd[6];
};

/*
 * Query CCB definitions
 */

struct ccb_extract_ctl {
	struct ccb_hdr	hdr;
	u32	src0_fmt:4;
	u32	src0_sz:5;
	u32	src0_off:3;
	u32	src1_enc:1;
	u32	src1_off:3;
	u32	src1_sz:2;
	u32	output_fmt:2;
	u32	output_sz:2;
	u32	pad_dir:1;
	u32	rsvd:9;
};

struct ccb_data_acc_ctl {
	u64	flow_ctl:2;
	u64	pipeline_targ:2;
	u64	output_buf_sz:20;
	u64	rsvd:8;
	u64	output_alloc:2;
	u64	rsvd2:4;
	u64	input_len_fmt:2;
	u64	input_cnt:24;
};

/*
 * CCB_QUERY_OPCODE_EXTRACT
 */
struct ccb_extract {
	struct ccb_extract_ctl	control;
	struct ccb_cmpl_addr	completion;
	struct ccb_byte_addr	src0;
	struct ccb_data_acc_ctl	data_acc_ctl;
	struct ccb_byte_addr	src1;
	u64			rsvd;
	struct ccb_addr		output;
	struct ccb_tbl_addr	tbl;
};

struct ccb_scan_bound {
	u32	upper;
	u32	lower;
};

/*
 * CCB_QUERY_OPCODE_SCAN_VALUE
 * CCB_QUERY_OPCODE_SCAN_RANGE
 */
struct ccb_scan {
	struct ccb_extract_ctl	control;
	struct ccb_cmpl_addr	completion;
	struct ccb_byte_addr	src0;
	struct ccb_data_acc_ctl	data_acc_ctl;
	struct ccb_byte_addr	src1;
	struct ccb_scan_bound	bound_msw;
	struct ccb_addr		output;
	struct ccb_tbl_addr	tbl;
};

/*
 * Scan Value/Range words 8-15 required when L or U operand size > 4 bytes.
 */
struct ccb_scan_ext {
	struct ccb_scan_bound	bound_msw2;
	struct ccb_scan_bound	bound_msw3;
	struct ccb_scan_bound	bound_msw4;
	u64		rsvd[5];
};

struct ccb_translate_ctl {
	struct ccb_hdr	hdr;
	u32	src0_fmt:4;
	u32	src0_sz:5;
	u32	src0_off:3;
	u32	src1_enc:1;
	u32	src1_off:3;
	u32	src1_sz:2;
	u32	output_fmt:2;
	u32	output_sz:2;
	u32	rsvd:1;
	u32	test_val:9;
};

/*
 * CCB_QUERY_OPCODE_TRANSLATE
 */
struct ccb_translate {
	struct ccb_translate_ctl	control;
	struct ccb_cmpl_addr		completion;
	struct ccb_byte_addr		src0;
	struct ccb_data_acc_ctl		data_acc_ctl;
	struct ccb_byte_addr		src1;
	u64				rsvd;
	struct ccb_addr			dst;
	struct ccb_tbl_addr		vec_addr;
};

struct ccb_select_ctl {
	struct ccb_hdr	hdr;
	u32		src0_fmt:4;
	u32		src0_sz:5;
	u32		src0_off:3;
	u32		rsvd:1;
	u32		src1_off:3;
	u32		rsvd2:2;
	u32		output_fmt:2;
	u32		output_sz:2;
	u32		pad_dir:1;
	u32		rsvd3:9;
};

/*
 * CCB_QUERY_OPCODE_SELECT
 */
struct ccb_select {
	struct ccb_select_ctl	control;
	struct ccb_cmpl_addr	completion;
	struct ccb_byte_addr	src0;
	struct ccb_data_acc_ctl	data_acc_ctl;
	struct ccb_byte_addr	src1;
	u64			rsvd;
	struct ccb_addr		output;
	struct ccb_tbl_addr	tbl;
};

union ccb {
	struct ccb_sync_nop	sync_nop;
	struct ccb_extract	extract;
	struct ccb_scan		scan;
	struct ccb_scan_ext	scan_ext;
	struct ccb_translate	translate;
	struct ccb_select	select;
	u64			dwords[8];
};

struct ccb_completion_area {
	u8	cmd_status;	/* user may mwait on this address */
	u8	err_mask;	/* user visible error notification */
	u8	rsvd[2];	/* reserved */
	u32	rsvd2;		/* reserved */
	u32	output_sz;	/* Bytes of output */
	u32	rsvd3;		/* reserved */
	u64	run_time;	/* run time in OCND2 cycles */
	u64	run_stats;	/* nothing reported in version 1.0 */
	u32	n_processed;	/* input elements processed */
	u32	rsvd4[5];	/* reserved */
	u64	command_rv;	/* command return value */
	u64	rsvd5[8];	/* reserved */
};

#endif	/* _CCB_H */
