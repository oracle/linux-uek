/*
 * Copyright (C) 2018 Cavium, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of version 2 of the GNU General Public License
 * as published by the Free Software Foundation.
 */

#ifndef __BCH_REGS_H
#define __BCH_REGS_H

#define BCH_NR_VF	1

union bch_cmd {
	u64 u[4];
	struct fields {
	    struct {
#if defined(__BIG_ENDIAN_BITFIELD)
		u64 ecc_gen:2;
		u64 reserved_36_61:26;
		u64 ecc_level:4;
		u64 reserved_12_31:20;
		u64 size:12;
#else
		u64 size:12;
		u64 reserved_12_31:20;
		u64 ecc_level:4;
		u64 reserved_36_61:26;
		u64 ecc_gen:2;
#endif
	    } cword;
	    struct {
#if defined(__BIG_ENDIAN_BITFIELD)
		u64 reserved_58_63:6;
		u64 fw:1;
		u64 nc:1;
		u64 reserved_49_55:7;
		u64 ptr:49;
#else
		u64 ptr:49;
		u64 reserved_49_55:7;
		u64 nc:1;
		u64 fw:1;
		u64 reserved_58_63:6;
#endif
	    } oword;
	    struct {
#if defined(__BIG_ENDIAN_BITFIELD)
		u64 reserved_57_63:7;
		u64 nc:1;
		u64 reserved_49_55:7;
		u64 ptr:49;
#else
		u64 ptr:49;
		u64 reserved_49_55:7;
		u64 nc:1;
		u64 reserved_57_63:7;
#endif
	    } iword;
	    struct {
#if defined(__BIG_ENDIAN_BITFIELD)
		u64 reserved_49_63:15;
		u64 ptr:49;
#else
		u64 ptr:49;
		u64 reserved_49_63:15;
#endif
	    } rword;
	} s;
};

enum ecc_gen {
	eg_correct,
	eg_copy,
	eg_gen,
	eg_copy3,
};

/** Response from BCH instruction */
union bch_resp {
	uint16_t  u16;
	struct {
#ifdef __BIG_ENDIAN_BITFIELD
		uint16_t	done:1;		/** Block is done */
		uint16_t	uncorrectable:1;/** too many bits flipped */
		uint16_t	erased:1;	/** Block is erased */
		uint16_t	zero:6;		/** Always zero, ignore */
		uint16_t	num_errors:7;	/** Number of errors in block */
#else
		uint16_t	num_errors:7;	/** Number of errors in block */
		uint16_t	zero:6;		/** Always zero, ignore */
		uint16_t	erased:1;	/** Block is erased */
		uint16_t	uncorrectable:1;/** too many bits flipped */
		uint16_t	done:1;		/** Block is done */
#endif
	} s;
};

union bch_vqx_ctl {
	u64 u;
	struct {
#if defined(__BIG_ENDIAN_BITFIELD)
		u64 reserved_22_63:42;
		u64 early_term:4;
		u64 one_cmd:1;
		u64 erase_disable:1;
		u64 reserved_6_15:10;
		u64 max_read:4;
		u64 cmd_be:1;
		u64 reserved_0:1;
#else /* Little Endian */
		u64 reserved_0:1;
		u64 cmd_be:1;
		u64 max_read:4;
		u64 reserved_6_15:10;
		u64 erase_disable:1;
		u64 one_cmd:1;
		u64 early_term:4;
		u64 reserved_22_63:42;
#endif
	} s;
};

union bch_vqx_cmd_buf {
	u64 u;
	struct {
#if defined(__BIG_ENDIAN_BITFIELD)
		u64 reserved_48_63:16;
		u64 ldwb:1;
		u64 dfb:1;
		u64 size:13;
		u64 reserved_0_32:33;
#else /* Little Endian */
		u64 reserved_0_32:33;
		u64 size:13;
		u64 dfb:1;
		u64 ldwb:1;
		u64 reserved_48_63:16;
#endif
	} s;
};

/* keep queue state indexed, even though just one supported here,
 * for later generalization to similarly-shaped queues on other Cavium devices
 */
enum {QID_BCH, QID_MAX};
struct bch_q {
	struct device *dev;
	int index;
	u16 max_depth;
	u16 pool_size_m1;
	u64 *base_vaddr;
	dma_addr_t base_paddr;
};
extern struct bch_q cavium_bch_q[QID_MAX];

/* with one dma-mapped area, virt<->phys conversions by +/- (vaddr-paddr) */
static inline dma_addr_t qphys(int qid, void *v)
{
	struct bch_q *q = &cavium_bch_q[qid];
	int off = (u8 *)v - (u8 *)q->base_vaddr;

	return q->base_paddr + off;
}
#define cavm_ptr_to_phys(v) qphys(QID_BCH, (v))

static inline void *qvirt(int qid, dma_addr_t p)
{
	struct bch_q *q = &cavium_bch_q[qid];
	int off = p - q->base_paddr;

	return q->base_vaddr + off;
}
#define cavm_phys_to_ptr(p) qvirt(QID_BCH, (p))

/* plenty for interleaved r/w on two planes with 16k page, ecc_size 1k */
/* QDEPTH >= 16, as successive chunks must align on 128-byte boundaries */
#define QDEPTH	256	/* u64s in a command queue chunk, incl next-pointer */
#define NQS	1	/* linked chunks in the chain */

int cavm_cmd_queue_initialize(struct device *dev,
	int queue_id, int max_depth, int fpa_pool, int pool_size);
int cavm_cmd_queue_shutdown(int queue_id);

/**
 * Write an arbitrary number of command words to a command queue.
 * This is a generic function; the fixed number of command word
 * functions yield higher performance.
 *
 * Could merge with crypto version for FPA use on cn83xx
 */
static inline int cavm_cmd_queue_write(int queue_id,
	bool use_locking, int cmd_count, const uint64_t *cmds)
{
	int ret = 0;
	uint64_t *cmd_ptr;
	struct bch_q *qptr = &cavium_bch_q[queue_id];

	if (unlikely((cmd_count < 1) || (cmd_count > 32)))
		return -EINVAL;
	if (unlikely(cmds == NULL))
		return -EINVAL;

	cmd_ptr = qptr->base_vaddr;

	while (cmd_count > 0) {
		int slot = qptr->index % (QDEPTH * NQS);

		if (slot % QDEPTH != QDEPTH - 1) {
			cmd_ptr[slot] = *cmds++;
			cmd_count--;
		}

		qptr->index++;
	}

	wmb();	/* flush commands before ringing bell */

	return ret;
}

#endif /*__BCH_REGS_H*/
