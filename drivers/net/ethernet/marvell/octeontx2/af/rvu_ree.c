// SPDX-License-Identifier: GPL-2.0
/* Marvell OcteonTx2 RVU Admin Function driver
 *
 * Copyright (C) 2020 Marvell Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include "rvu.h"
#include "rvu_reg.h"

/* Maximum number of REE blocks */
#define MAX_REE_BLKS		2

/* Graph maximum number of entries, each of 8B */
#define REE_GRAPH_CNT		(16 * 1024 * 1024)

/* Prefix Block size 1K of 16B entries
 * maximum number of blocks for a single ROF is 128
 */
#define REE_PREFIX_PTR_LEN	1024
#define REE_PREFIX_CNT		(128 * 1024)

/* Rule DB entries are held in memory */
#define REE_RULE_DB_ALLOC_SIZE	(4 * 1024 * 1024)
#define REE_RULE_DB_ALLOC_SHIFT	22
#define REE_RULE_DB_BLOCK_CNT	64

/* Rule DB incremental */
#define REE_RULE_DBI_SIZE	(16 * 6)

/* Administrative instruction queue size */
#define REE_AQ_SIZE		128

enum ree_cmp_ops {
	REE_CMP_EQ,	/* Equal to data*/
	REE_CMP_GEQ,	/* Equal or greater than data */
	REE_CMP_LEQ,	/* Equal or less than data */
	REE_CMP_KEY_FIELDS_MAX,
};

enum ree_rof_types {
	REE_ROF_TYPE_0	= 0, /* Legacy */
	REE_ROF_TYPE_1	= 1, /* Check CSR EQ */
	REE_ROF_TYPE_2	= 2, /* Check CSR GEQ */
	REE_ROF_TYPE_3	= 3, /* Check CSR LEQ */
	REE_ROF_TYPE_4	= 4, /* Not relevant */
	REE_ROF_TYPE_5	= 5, /* Check CSR checksum only for internal memory */
	REE_ROF_TYPE_6	= 6, /* Internal memory */
	REE_ROF_TYPE_7	= 7, /* External memory */
};

struct ree_rule_db_entry {
#if defined(__BIG_ENDIAN_BITFIELD)
	u64 addr		: 32;
	u64 pad			: 24;
	u64 type		:  8;
#else
	u64 type		:  8;
	u64 pad			: 24;
	u64 addr		: 32;
#endif
	u64 value;
};

static void ree_reex_enable(struct rvu *rvu, struct rvu_block *block)
{
	u64 reg;

	/* Set GO bit */
	reg = rvu_read64(rvu, block->addr, REE_AF_REEXM_CTRL);
	reg |= REE_AF_REEXM_CTRL_GO;
	rvu_write64(rvu, block->addr, REE_AF_REEXM_CTRL, reg);
}

static void ree_reex_force_clock(struct rvu *rvu, struct rvu_block *block,
				 bool force_on)
{
	u64 reg;

	/* Force ON or OFF for SCLK / RXPCLK */
	reg = rvu_read64(rvu, block->addr, REE_AF_CMD_CTL);
	if (force_on)
		reg = reg | REE_AF_FORCE_CCLK | REE_AF_FORCE_CSCLK;
	else
		reg = reg & ~(REE_AF_FORCE_CCLK | REE_AF_FORCE_CSCLK);
	rvu_write64(rvu, block->addr, REE_AF_CMD_CTL, reg);
}

static int ree_graceful_disable_control(struct rvu *rvu,
					struct rvu_block *block, bool apply)
{
	u64 val, mask;
	int err;

	/* Graceful Disable is available on all queues 0..35
	 * 0 = Queue is not gracefully-disabled (apply is false)
	 * 1 = Queue was gracefully-disabled (apply is true)
	 */
	mask = GENMASK(35, 0);

	/* Check what is graceful disable status */
	val = rvu_read64(rvu, block->addr, REE_AF_GRACEFUL_DIS_STATUS) & mask;
	if (apply & val)
		return REE_AF_ERR_Q_IS_GRACEFUL_DIS;
	else if (!apply & !val)
		return REE_AF_ERR_Q_NOT_GRACEFUL_DIS;

	/* Apply Graceful Enable or Disable on all queues 0..35 */
	if (apply)
		val = GENMASK(35, 0);
	else
		val = 0;

	rvu_write64(rvu, block->addr, REE_AF_GRACEFUL_DIS_CTL, val);

	/* Poll For graceful disable if it is applied or not on all queues */
	/* This might take time */
	err = rvu_poll_reg(rvu, block->addr, REE_AF_GRACEFUL_DIS_STATUS, mask,
			   !apply);
	if (err) {
		dev_err(rvu->dev, "REE graceful disable control failed");
		return err;
	}
	return 0;
}

static int ree_reex_programming(struct rvu *rvu, struct rvu_block *block,
				u8 incremental)
{
	int err;

	if (!incremental) {
		/* REEX Set & Clear MAIN_CSR init */
		rvu_write64(rvu, block->addr, REE_AF_REEXM_CTRL,
			    REE_AF_REEXM_CTRL_INIT);
		rvu_write64(rvu, block->addr, REE_AF_REEXM_CTRL, 0x0);

		/* REEX Poll MAIN_CSR INIT_DONE */
		err = rvu_poll_reg(rvu, block->addr, REE_AF_REEXM_STATUS,
				   REE_AF_REEXM_STATUS_INIT_DONE, false);
		if (err) {
			dev_err(rvu->dev, "REE poll reexm status failed");
			return err;
		}

		/* REEX Set Mem Init Mode */
		rvu_write64(rvu, block->addr, REE_AF_REEXR_CTRL,
			    (REE_AF_REEXR_CTRL_INIT |
			     REE_AF_REEXR_CTRL_MODE_IM_L1_L2));

		/* REEX Set & Clear Mem Init */
		rvu_write64(rvu, block->addr, REE_AF_REEXR_CTRL,
			    REE_AF_REEXR_CTRL_MODE_IM_L1_L2);

		/* REEX Poll all RTRU DONE 3 bits */
		err = rvu_poll_reg(rvu, block->addr, REE_AF_REEXR_STATUS,
				   (REE_AF_REEXR_STATUS_IM_INIT_DONE |
				    REE_AF_REEXR_STATUS_L1_CACHE_INIT_DONE |
				    REE_AF_REEXR_STATUS_L2_CACHE_INIT_DONE),
				    false);
		if (err) {
			dev_err(rvu->dev, "REE for cache done failed");
			return err;
		}
	} else {
		/* REEX Set Mem Init Mode */
		rvu_write64(rvu, block->addr, REE_AF_REEXR_CTRL,
			    (REE_AF_REEXR_CTRL_INIT |
			     REE_AF_REEXR_CTRL_MODE_L1_L2));

		/* REEX Set & Clear Mem Init */
		rvu_write64(rvu, block->addr, REE_AF_REEXR_CTRL,
			    REE_AF_REEXR_CTRL_MODE_L1_L2);

		/* REEX Poll all RTRU DONE 2 bits */
		err = rvu_poll_reg(rvu, block->addr, REE_AF_REEXR_STATUS,
				   (REE_AF_REEXR_STATUS_L1_CACHE_INIT_DONE |
				    REE_AF_REEXR_STATUS_L2_CACHE_INIT_DONE),
				    false);
		if (err) {
			dev_err(rvu->dev, "REE cache & init done failed");
			return err;
		}
	}

	/* Before 1st time en-queue, set REEX RTRU.GO bit to 1 */
	rvu_write64(rvu, block->addr, REE_AF_REEXR_CTRL, REE_AF_REEXR_CTRL_GO);
	return 0;
}

static int ree_aq_verify_type6_completion(struct rvu *rvu,
					  struct rvu_block *block)
{
	u64 val;
	int err;

	/* Poll on Done count until it is 1 to see that last instruction
	 * is completed. Then write this value to DONE_ACK to decrement
	 * the value of Done count
	 * Note that no interrupts are used for this counters
	 */
	err = rvu_poll_reg(rvu, block->addr, REE_AF_AQ_DONE,
			   0x1, false);
	if (err) {
		dev_err(rvu->dev, "REE AFAQ done failed");
		return err;
	}
	val = rvu_read64(rvu, block->addr, REE_AF_AQ_DONE);
	rvu_write64(rvu, block->addr, REE_AF_AQ_DONE_ACK, val);
	return 0;
}

static void ree_aq_inst_enq(struct rvu *rvu, struct rvu_block *block,
			    struct ree_rsrc *ree, dma_addr_t head, u32 size,
			    int doneint)
{
	struct admin_queue *aq = block->aq;
	struct ree_af_aq_inst_s inst;

	/* Fill instruction */
	memset(&inst, 0, sizeof(struct ree_af_aq_inst_s));
	inst.length = size;
	inst.rof_ptr_addr = (u64)head;
	inst.doneint = doneint;
	/* Copy instruction to AF AQ head */
	memcpy(aq->inst->base + (ree->aq_head * aq->inst->entry_sz),
	       &inst, aq->inst->entry_sz);
	/* Sync into memory */
	wmb();
	/* SW triggers HW AQ.DOORBELL */
	rvu_write64(rvu, block->addr, REE_AF_AQ_DOORBELL, 1);
	/* Move Head to next cell in AF AQ.
	 * HW CSR gives only AF AQ tail address
	 */
	ree->aq_head++;
	if (ree->aq_head >= aq->inst->qsize)
		ree->aq_head = 0;
}

static int ree_reex_memory_alloc(struct rvu *rvu, struct rvu_block *block,
				 struct ree_rsrc *ree, int db_len,
				 int is_incremental)
{
	int alloc_len, err, i;

	/* Allocate Graph Memory 128MB. This is an IOVA base address
	 * for the memory image of regular expressions graphs.
	 * Software is filling this memory with graph instructions (type 7)
	 * and HW uses this as external memory for graph search.
	 */
	if (!ree->graph_ctx) {
		err = qmem_alloc(rvu->dev, &ree->graph_ctx, REE_GRAPH_CNT,
				 sizeof(u64));
		if (err)
			return err;
		/* Update Graph address in DRAM */
		rvu_write64(rvu, block->addr, REE_AF_EM_BASE,
			    (u64)ree->graph_ctx->iova);
	}

	/* If not incremental programming, clear Graph Memory
	 * before programming
	 */
	if (!is_incremental)
		memset(ree->graph_ctx->base, 0, REE_GRAPH_CNT * sizeof(u64));

	/* Allocate buffers to hold ROF data. Each buffer holds maximum length
	 * of 16384 Bytes, which is 1K instructions block. These blocks are
	 * pointed to by REE_AF_AQ_INST_S:ROF_PTR_ADDR. Multiple blocks are
	 * allocated for concurrent work with HW
	 */
	if (!ree->prefix_ctx) {
		err = qmem_alloc(rvu->dev, &ree->prefix_ctx, REE_PREFIX_CNT,
				 sizeof(struct ree_rof_s));
		if (err) {
			qmem_free(rvu->dev, ree->graph_ctx);
			ree->graph_ctx = NULL;
			return err;
		}
	}

	/* Allocate memory to hold incremental programming checksum reference
	 * data which later be retrieved via mbox by the application
	 */
	if (!ree->ruledbi) {
		ree->ruledbi = kmalloc_array(REE_RULE_DBI_SIZE, sizeof(void *),
					     GFP_KERNEL);
		if (!ree->ruledbi) {
			qmem_free(rvu->dev, ree->graph_ctx);
			ree->graph_ctx = NULL;
			qmem_free(rvu->dev, ree->prefix_ctx);
			ree->prefix_ctx = NULL;
			return REE_AF_ERR_RULE_DBI_ALLOC_FAILED;
		}
	}
	/* Allocate memory to hold ROF instructions. ROF instructions are
	 * passed from application by multiple mbox messages. Once the last
	 * instruction is passed, they are programmed to REE.
	 * ROF instructions are kept in memory for future retrieve by
	 * application in order to make incremental programming
	 */
	if (!ree->ruledb) {
		ree->ruledb = kmalloc_array(REE_RULE_DB_BLOCK_CNT,
					    sizeof(void *), GFP_KERNEL);
		if (!ree->ruledb) {
			qmem_free(rvu->dev, ree->graph_ctx);
			ree->graph_ctx = NULL;
			qmem_free(rvu->dev, ree->prefix_ctx);
			ree->prefix_ctx = NULL;
			kfree(ree->ruledbi);
			ree->ruledbi = NULL;
			return REE_AF_ERR_RULE_DB_ALLOC_FAILED;
		}
		ree->ruledb_blocks = 0;
	}
	alloc_len = ree->ruledb_blocks * REE_RULE_DB_ALLOC_SIZE;
	while (alloc_len < db_len) {
		if (ree->ruledb_blocks >= REE_RULE_DB_BLOCK_CNT) {
			/* No need to free memory here since it is just
			 * indication of rule DB that is too big.
			 * Unlike previous allocation that happens only once,
			 * this allocation can happen along time if larger
			 * ROF files are sent
			 */
			return REE_AF_ERR_RULE_DB_TOO_BIG;
		}
		ree->ruledb[ree->ruledb_blocks] =
			kmalloc(REE_RULE_DB_ALLOC_SIZE, GFP_KERNEL);
		if (!ree->ruledb[ree->ruledb_blocks]) {
			for (i = 0; i < ree->ruledb_blocks; i++)
				kfree(ree->ruledb[i]);
			qmem_free(rvu->dev, ree->graph_ctx);
			ree->graph_ctx = NULL;
			qmem_free(rvu->dev, ree->prefix_ctx);
			ree->prefix_ctx = NULL;
			kfree(ree->ruledbi);
			ree->ruledbi = NULL;
			kfree(ree->ruledb);
			ree->ruledb = NULL;
			return REE_AF_ERR_RULE_DB_BLOCK_ALLOC_FAILED;
		}
		ree->ruledb_blocks += 1;
		alloc_len += REE_RULE_DB_ALLOC_SIZE;
	}

	return 0;
}

static
int ree_reex_cksum_compare(struct rvu *rvu, int blkaddr,
			   struct ree_rule_db_entry **rule_db,
			   int *rule_db_len, enum ree_cmp_ops cmp)
{
	u64 offset;
	u64 reg;

	/* ROF instructions have 3 fields: type, address and data.
	 * Instructions of type 1,2,3 and 5 are compared against CSR values.
	 * The address of the CSR is calculated from the instruction address.
	 * The CSR value is compared against instruction data.
	 * REE AF REEX comparison registers are in 2 sections: main and rtru.
	 * Main CSR base address is 0x8000, rtru CSR base address is 0x8200
	 * Instruction address bits 16 to 18 indicate the block from which one
	 * can take the base address. Main is 0x0000, RTRU is 0x0001
	 * Low 5 bits indicate the offset, one should multiply it by 8.
	 * The address is calculated as follows:
	 * - Base address is 0x8000
	 * - bits 16 to 18 are multiplied by 0x200
	 * - Low 5 bits are multiplied by 8
	 */
	offset = REE_AF_REEX_CSR_BLOCK_BASE_ADDR +
		((((*rule_db)->addr & REE_AF_REEX_CSR_BLOCK_ID_MASK) >>
		  REE_AF_REEX_CSR_BLOCK_ID_SHIFT) *
		 REE_AF_REEX_CSR_BLOCK_ID) +
		(((*rule_db)->addr & REE_AF_REEX_CSR_INDEX_MASK) *
		 REE_AF_REEX_CSR_INDEX);
	reg = rvu_read64(rvu, blkaddr, offset);
	switch (cmp) {
	case REE_CMP_EQ:
		if (reg != (*rule_db)->value) {
			dev_err(rvu->dev, "REE addr %llx data %llx neq %llx",
				offset, reg, (*rule_db)->value);
			return REE_AF_ERR_RULE_DB_EQ_BAD_VALUE;
		}
		break;
	case REE_CMP_GEQ:
		if (reg < (*rule_db)->value) {
			dev_err(rvu->dev, "REE addr %llx data %llx ngeq %llx",
				offset, reg, (*rule_db)->value);
			return REE_AF_ERR_RULE_DB_GEQ_BAD_VALUE;
		}
		break;
	case REE_CMP_LEQ:
		if (reg > (*rule_db)->value) {
			dev_err(rvu->dev, "REE addr %llx data %llx nleq %llx",
				offset, reg, (*rule_db)->value);
			return REE_AF_ERR_RULE_DB_LEQ_BAD_VALUE;
		}
		break;
	default:
		dev_err(rvu->dev, "REE addr %llx data %llx default %llx",
			offset, reg, (*rule_db)->value);
		return REE_AF_ERR_RULE_UNKNOWN_VALUE;
	}

	(*rule_db)++;
	*rule_db_len -= sizeof(struct ree_rule_db_entry);
	return 0;
}

static
void ree_reex_prefix_write(void **prefix_ptr,
			   struct ree_rule_db_entry **rule_db,
			   int *rule_db_len, int *count)
{
	struct ree_rof_s rof_entry;

	while ((*rule_db)->type == REE_ROF_TYPE_6) {
		rof_entry.typ = (*rule_db)->type;
		rof_entry.addr = (*rule_db)->addr;
		rof_entry.data = (*rule_db)->value;
		memcpy((*prefix_ptr), (void *)(&rof_entry),
		       sizeof(struct ree_rof_s));
		/* AF AQ prefix block to copy to */
		(*prefix_ptr) += sizeof(struct ree_rof_s);
		/* Location in ROF DB that was parsed by now */
		(*rule_db)++;
		/* Length of ROF DB left to handle*/
		(*rule_db_len) -= sizeof(struct ree_rule_db_entry);
		/* Number of type 6 rows that were parsed */
		(*count)++;
	}
}

static
void ree_reex_graph_write(struct ree_rsrc *ree,
			  struct ree_rule_db_entry **rule_db, int *rule_db_len)
{
	u32 offset;

	while ((*rule_db)->type == REE_ROF_TYPE_7) {
		offset = ((*rule_db)->addr & 0xFFFFFF) << 3;
		memcpy(ree->graph_ctx->base + offset,
		       &(*rule_db)->value, sizeof((*rule_db)->value));
		(*rule_db)++;
		*rule_db_len -= sizeof(struct ree_rule_db_entry);
	}
}

static
int ree_rof_data_validation(struct rvu *rvu, int blkaddr,
			    struct ree_rsrc *ree, int *db_block,
			    struct ree_rule_db_entry **rule_db_ptr,
			    int *rule_db_len)
{
	int err;

	/* Parse ROF data */
	while (*rule_db_len > 0) {
		switch ((*rule_db_ptr)->type) {
		case REE_ROF_TYPE_1:
			err = ree_reex_cksum_compare(rvu, blkaddr, rule_db_ptr,
						     rule_db_len, REE_CMP_EQ);
			if (err < 0)
				return err;
			break;
		case REE_ROF_TYPE_2:
			err = ree_reex_cksum_compare(rvu, blkaddr, rule_db_ptr,
						     rule_db_len, REE_CMP_GEQ);
			if (err < 0)
				return err;
			break;
		case REE_ROF_TYPE_3:
			err = ree_reex_cksum_compare(rvu, blkaddr, rule_db_ptr,
						     rule_db_len, REE_CMP_LEQ);
			if (err < 0)
				return err;
			break;
		case REE_ROF_TYPE_4:
			/* Type 4 handles internal memory */
			(*rule_db_ptr)++;
			(*rule_db_len) -= sizeof(struct ree_rof_s);
			break;
		case REE_ROF_TYPE_5:
			err = ree_reex_cksum_compare(rvu, blkaddr, rule_db_ptr,
						     rule_db_len, REE_CMP_EQ);
			if (err < 0)
				return err;
			break;
		case REE_ROF_TYPE_6:
		case REE_ROF_TYPE_7:
			return 0;
		default:
			/* Other types not supported */
			(*rule_db_ptr)++;
			*rule_db_len -= sizeof(struct ree_rof_s);
			break;
		}
		/* If rule DB is larger than 4M there is a need
		 * to move between db blocks of 4M
		 */
		if ((uint64_t)(*rule_db_ptr) -
					  (uint64_t)ree->ruledb[(*db_block)] >=
			 REE_RULE_DB_ALLOC_SIZE) {
			(*db_block)++;
			*rule_db_ptr = ree->ruledb[(*db_block)];
		}
	}
	return 0;
}

static
int ree_rof_data_enq(struct rvu *rvu, struct rvu_block *block,
		     struct ree_rsrc *ree,
		     struct ree_rule_db_entry **rule_db_ptr,
		     int *rule_db_len, int *db_block)
{
	void *prefix_ptr = ree->prefix_ctx->base;
	int size, num_of_entries = 0;
	dma_addr_t head;

	/* Parse ROF data */
	while (*rule_db_len > 0) {
		switch ((*rule_db_ptr)->type) {
		case REE_ROF_TYPE_1:
		case REE_ROF_TYPE_2:
		case REE_ROF_TYPE_3:
		case REE_ROF_TYPE_4:
		case REE_ROF_TYPE_5:
			break;
		case REE_ROF_TYPE_6:
			ree_reex_prefix_write(&prefix_ptr, rule_db_ptr,
					      rule_db_len, &num_of_entries);
			break;
		case REE_ROF_TYPE_7:
			ree_reex_graph_write(ree, rule_db_ptr, rule_db_len);
			break;
		default:
			/* Other types not supported */
			(*rule_db_ptr)++;
			(*rule_db_len) -= sizeof(struct ree_rof_s);
			break;
		}
		/* If rule DB is larger than 4M there is a need
		 * to move between db blocks of 4M
		 */
		if ((uint64_t)(*rule_db_ptr) -
					  (uint64_t)ree->ruledb[(*db_block)] >=
			 REE_RULE_DB_ALLOC_SIZE) {
			(*db_block)++;
			*rule_db_ptr = ree->ruledb[(*db_block)];
		}
		/* If there are no more prefix and graph data
		 * en-queue prefix data and continue with data validation
		 */
		if (((*rule_db_ptr)->type != REE_ROF_TYPE_6) &&
		    ((*rule_db_ptr)->type != REE_ROF_TYPE_7))
			break;
	}

	/* Block is filled with 1K instructions
	 * En-queue to AF AQ all available blocks
	 */
	head = ree->prefix_ctx->iova;
	while (num_of_entries > 0) {
		if (num_of_entries > REE_PREFIX_PTR_LEN) {
			size = REE_PREFIX_PTR_LEN * sizeof(struct ree_rof_s);
			ree_aq_inst_enq(rvu, block, ree, head, size, false);
			head += REE_PREFIX_PTR_LEN * sizeof(struct ree_rof_s);
		} else {
			size = num_of_entries * sizeof(struct ree_rof_s);
			ree_aq_inst_enq(rvu, block, ree, head, size, true);
		}
		num_of_entries -= REE_PREFIX_PTR_LEN;
	}
	/* Verify completion of type 6 */
	return ree_aq_verify_type6_completion(rvu, block);
}

static
int ree_rule_db_prog(struct rvu *rvu, struct rvu_block *block,
		     struct ree_rsrc *ree, int inc)
{
	struct ree_rule_db_entry *rule_db_ptr;
	int rule_db_len, err = 0, db_block = 0;
	u64 reg;

	/* If it is incremental programming, stop fetching new instructions */
	if (inc) {
		err = ree_graceful_disable_control(rvu, block, true);
		if (err)
			return err;
	}

	/* Force Clock ON
	 * Force bits should be set throughout REEX programming, whether full
	 * or incremental
	 */
	ree_reex_force_clock(rvu, block, true);

	/* Reinitialize REEX block for programming */
	err = ree_reex_programming(rvu, block, inc);
	if (err)
		return err;

	/* Parse ROF data - validation part*/
	rule_db_len = ree->ruledb_len;
	rule_db_ptr = (struct ree_rule_db_entry *)ree->ruledb[0];
	db_block = 0;
	err = ree_rof_data_validation(rvu, block->addr, ree, &db_block,
				      &rule_db_ptr, &rule_db_len);
	if (err)
		return err;

	/* Parse ROF data - data part*/
	err = ree_rof_data_enq(rvu, block, ree, &rule_db_ptr, &rule_db_len,
			       &db_block);
	if (err)
		return err;

	/* Parse ROF data - validation part*/
	err = ree_rof_data_validation(rvu, block->addr, ree, &db_block,
				      &rule_db_ptr, &rule_db_len);
	if (err)
		return err;

	/* REEX Programming DONE: clear GO bit */
	reg = rvu_read64(rvu, block->addr, REE_AF_REEXR_CTRL);
	reg = reg & ~(REE_AF_REEXR_CTRL_GO);
	rvu_write64(rvu, block->addr, REE_AF_REEXR_CTRL, reg);

	ree_reex_enable(rvu, block);

	/* Force Clock OFF */
	ree_reex_force_clock(rvu, block, false);

	/* If it is incremental programming, resume fetching instructions */
	if (inc) {
		err = ree_graceful_disable_control(rvu, block, false);
		if (err)
			return err;
	}

	return 0;
}

int rvu_mbox_handler_ree_rule_db_prog(struct rvu *rvu,
				      struct ree_rule_db_prog_req_msg *req,
				      struct msg_rsp *rsp)
{
	int blkaddr, db_block = 0, blkid = 0, err;
	struct rvu_block *block;
	struct ree_rsrc *ree;

	blkaddr = req->blkaddr;
	if (!is_block_implemented(rvu->hw, blkaddr))
		return REE_AF_ERR_BLOCK_NOT_IMPLEMENTED;
	if (blkaddr == BLKADDR_REE1)
		blkid = 1;

	block = &rvu->hw->block[blkaddr];
	ree = &rvu->hw->ree[blkid];

	/* If this is the first block of ROF */
	if (!req->offset) {
		if (req->total_len >
				REE_RULE_DB_ALLOC_SIZE * REE_RULE_DB_BLOCK_CNT)
			return REE_AF_ERR_RULE_DB_TOO_BIG;

		/* Initialize Programming memory */
		err = ree_reex_memory_alloc(rvu, block, ree, req->total_len,
					    req->is_incremental);
		if (err)
			return err;
		/* Programming overwrites existing rule db
		 * Incremental programming overwrites both rule db and rule dbi
		 */
		ree->ruledb_len = 0;
		if (!req->is_incremental)
			ree->ruledbi_len = 0;
	}

	/* Copy rof data from mbox to ruledb.
	 * Rule db is later used for programming
	 */
	if (ree->ruledb_len + req->len >
			ree->ruledb_blocks * REE_RULE_DB_ALLOC_SIZE)
		return REE_AF_ERR_RULE_DB_WRONG_LENGTH;
	if (ree->ruledb_len != req->offset)
		return REE_AF_ERR_RULE_DB_WRONG_OFFSET;
	/* All messages should be in block size, apart for last one */
	if (req->len < REE_RULE_DB_REQ_BLOCK_SIZE && !req->is_last)
		return REE_AF_ERR_RULE_DB_SHOULD_FILL_REQUEST;
	/* Each mbox is 32KB each ruledb block is 4096KB
	 * Single mbox shouldn't spread over blocks
	 */
	db_block = ree->ruledb_len >> REE_RULE_DB_ALLOC_SHIFT;
	if (db_block >= ree->ruledb_blocks)
		return REE_AF_ERR_RULE_DB_BLOCK_TOO_BIG;
	memcpy((void *)((u64)ree->ruledb[db_block] + ree->ruledb_len),
	       req->rule_db, req->len);
	ree->ruledb_len += req->len;
	/* ROF file is sent in chunks
	 * wait for last chunk to start programming
	 */
	if (!req->is_last)
		return 0;

	if (req->total_len != ree->ruledb_len)
		return REE_AF_ERR_RULE_DB_PARTIAL;

	if (!req->is_incremental || req->is_dbi) {
		err = ree_rule_db_prog(rvu, block, ree, req->is_incremental);
		if (err)
			return err;
	}

	if (req->is_dbi) {
		memcpy(ree->ruledbi,
		       ree->ruledb[db_block] +
				req->total_len - REE_RULE_DBI_SIZE,
		       REE_RULE_DBI_SIZE);
		ree->ruledbi_len = REE_RULE_DBI_SIZE;
	}

	return 0;
}

int
rvu_mbox_handler_ree_rule_db_get(struct rvu *rvu,
				 struct ree_rule_db_get_req_msg *req,
				 struct ree_rule_db_get_rsp_msg *rsp)
{
	int blkaddr, len, blkid = 0, db_block;
	struct ree_rsrc *ree;

	blkaddr = req->blkaddr;
	if (!is_block_implemented(rvu->hw, blkaddr))
		return REE_AF_ERR_BLOCK_NOT_IMPLEMENTED;
	if (blkaddr == BLKADDR_REE1)
		blkid = 1;
	ree = &rvu->hw->ree[blkid];

	/* In case no programming or incremental programming was done yet */
	if ((req->is_dbi && ree->ruledbi_len == 0) ||
	    (!req->is_dbi && ree->ruledb_len == 0)) {
		rsp->len = 0;
		return 0;
	}

	/* ROF file is sent in chunks
	 * Verify that offset is inside db range
	 */
	if (req->is_dbi) {
		if (ree->ruledbi_len < req->offset)
			return REE_AF_ERR_RULE_DB_INC_OFFSET_TOO_BIG;
		len = ree->ruledbi_len - req->offset;
	} else {
		if (ree->ruledb_len < req->offset)
			return REE_AF_ERR_RULE_DB_OFFSET_TOO_BIG;
		len = ree->ruledb_len - req->offset;
	}

	/* Check if this is the last chunk of db */
	if (len < REE_RULE_DB_RSP_BLOCK_SIZE) {
		rsp->is_last = true;
		rsp->len = len;
	} else {
		rsp->is_last = false;
		rsp->len = REE_RULE_DB_RSP_BLOCK_SIZE;
	}

	/* Copy DB chunk to response */
	if (req->is_dbi) {
		memcpy(rsp->rule_db, ree->ruledbi + req->offset, rsp->len);
	} else {
		db_block = req->offset >> 22;
		memcpy(rsp->rule_db, ree->ruledb[db_block] + req->offset,
		       rsp->len);
	}

	return 0;
}

int
rvu_mbox_handler_ree_rule_db_len_get(struct rvu *rvu, struct ree_req_msg *req,
				     struct ree_rule_db_len_rsp_msg *rsp)
{
	int blkaddr, blkid = 0;

	blkaddr = req->blkaddr;
	if (!is_block_implemented(rvu->hw, blkaddr))
		return REE_AF_ERR_BLOCK_NOT_IMPLEMENTED;
	if (blkaddr == BLKADDR_REE1)
		blkid = 1;
	rsp->len = rvu->hw->ree[blkid].ruledb_len;
	rsp->inc_len = rvu->hw->ree[blkid].ruledbi_len;
	return 0;
}

int rvu_mbox_handler_ree_config_lf(struct rvu *rvu,
				   struct ree_lf_req_msg *req,
				   struct msg_rsp *rsp)
{
	u16 pcifunc = req->hdr.pcifunc;
	int lf, blkaddr, num_lfs;
	struct rvu_block *block;
	u64 val;

	blkaddr = req->blkaddr;
	if (!is_block_implemented(rvu->hw, blkaddr))
		return REE_AF_ERR_BLOCK_NOT_IMPLEMENTED;
	block = &rvu->hw->block[blkaddr];

	/* Need to translate REE LF slot to global number
	 * VFs use local numbering from 0 to number of LFs - 1
	 */
	lf = rvu_get_lf(rvu, block, pcifunc, req->lf);
	if (lf < 0)
		return REE_AF_ERR_LF_INVALID;

	num_lfs = rvu_get_rsrc_mapcount(rvu_get_pfvf(rvu, req->hdr.pcifunc),
					blkaddr);
	if (lf >= num_lfs)
		return REE_AF_ERR_LF_NO_MORE_RESOURCES;

	/* LF instruction buffer size and priority are configured by AF.
	 * Priority value can be 0 or 1
	 */
	if (req->pri > 1)
		return REE_AF_ERR_LF_WRONG_PRIORITY;
	if (req->size > REE_AF_QUE_SBUF_CTL_MAX_SIZE)
		return REE_AF_ERR_LF_SIZE_TOO_BIG;
	val =  req->size;
	val =  val << REE_AF_QUE_SBUF_CTL_SIZE_SHIFT;
	val +=  req->pri;
	rvu_write64(rvu, blkaddr, REE_AF_QUE_SBUF_CTL(lf), val);

	return 0;
}

int rvu_mbox_handler_ree_rd_wr_register(struct rvu *rvu,
					struct ree_rd_wr_reg_msg *req,
					struct ree_rd_wr_reg_msg *rsp)
{
	int blkaddr;

	blkaddr = req->blkaddr;
	if (!is_block_implemented(rvu->hw, blkaddr))
		return REE_AF_ERR_BLOCK_NOT_IMPLEMENTED;
	rsp->reg_offset = req->reg_offset;
	rsp->ret_val = req->ret_val;
	rsp->is_write = req->is_write;

	switch (req->reg_offset) {
	case REE_AF_REEXM_MAX_MATCH:
	break;

	default:
		/* Access to register denied */
		return REE_AF_ERR_ACCESS_DENIED;
	}

	if (req->is_write)
		rvu_write64(rvu, blkaddr, req->reg_offset, req->val);
	else
		rsp->val = rvu_read64(rvu, blkaddr, req->reg_offset);

	return 0;
}

static int ree_aq_inst_alloc(struct rvu *rvu, struct admin_queue **ad_queue,
			     int qsize, int inst_size, int res_size)
{
	struct admin_queue *aq;
	int err;

	*ad_queue = devm_kzalloc(rvu->dev, sizeof(*aq), GFP_KERNEL);
	if (!*ad_queue)
		return -ENOMEM;
	aq = *ad_queue;

	/* Allocate memory for instructions i.e AQ */
	err = qmem_alloc(rvu->dev, &aq->inst, qsize, inst_size);
	if (err) {
		devm_kfree(rvu->dev, aq);
		return err;
	}

	/* REE AF AQ does not have result and lock is not used */
	aq->res = NULL;

	return 0;
}

static irqreturn_t rvu_ree_af_ras_intr_handler(int irq, void *ptr)
{
	struct rvu_block *block = ptr;
	struct rvu *rvu = block->rvu;
	int blkaddr = block->addr;
	u64 intr;

	if (blkaddr < 0)
		return IRQ_NONE;

	intr = rvu_read64(block->rvu, blkaddr, REE_AF_RAS);
	if (intr & REE_AF_RAS_DAT_PSN)
		dev_err(rvu->dev, "REE: Poison received on a NCB data response\n");
	if (intr & REE_AF_RAS_LD_CMD_PSN)
		dev_err(rvu->dev, "REE: Poison received on a NCB instruction response\n");
	if (intr & REE_AF_RAS_LD_REEX_PSN)
		dev_err(rvu->dev, "REE: Poison received on a REEX response\n");

	/* Clear interrupts */
	rvu_write64(rvu, blkaddr, REE_AF_RAS, intr);
	return IRQ_HANDLED;
}

static irqreturn_t rvu_ree_af_rvu_intr_handler(int irq, void *ptr)
{
	struct rvu_block *block = ptr;
	struct rvu *rvu = block->rvu;
	int blkaddr = block->addr;
	u64 intr;

	blkaddr = rvu_get_blkaddr(rvu, BLKTYPE_REE, 0);
	if (blkaddr < 0)
		return IRQ_NONE;

	intr = rvu_read64(rvu, blkaddr, REE_AF_RVU_INT);
	if (intr & REE_AF_RVU_INT_UNMAPPED_SLOT)
		dev_err(rvu->dev, "REE: Unmapped slot error\n");

	/* Clear interrupts */
	rvu_write64(rvu, blkaddr, REE_AF_RVU_INT, intr);
	return IRQ_HANDLED;
}

static irqreturn_t rvu_ree_af_aq_intr_handler(int irq, void *ptr)
{
	struct rvu_block *block = ptr;
	struct rvu *rvu = block->rvu;
	int blkaddr = block->addr;
	u64 intr;

	blkaddr = rvu_get_blkaddr(rvu, BLKTYPE_REE, 0);
	if (blkaddr < 0)
		return IRQ_NONE;

	intr = rvu_read64(rvu, blkaddr, REE_AF_AQ_INT);

	if (intr & REE_AF_AQ_INT_DOVF)
		dev_err(rvu->dev, "REE: DOORBELL overflow\n");
	if (intr & REE_AF_AQ_INT_IRDE)
		dev_err(rvu->dev, "REE: Instruction NCB read response error\n");
	if (intr & REE_AF_AQ_INT_PRDE)
		dev_err(rvu->dev, "REE: Payload NCB read response error\n");
	if (intr & REE_AF_AQ_INT_PLLE)
		dev_err(rvu->dev, "REE: Payload length error\n");

	/* Clear interrupts */
	rvu_write64(rvu, blkaddr, REE_AF_AQ_INT, intr);
	return IRQ_HANDLED;
}

void rvu_ree_unregister_interrupts_block(struct rvu *rvu, int blkaddr)
{
	int i, offs;

	if (!is_block_implemented(rvu->hw, blkaddr))
		return;

	offs = rvu_read64(rvu, blkaddr, REE_PRIV_AF_INT_CFG) & 0x7FF;
	if (!offs) {
		dev_warn(rvu->dev,
			 "Failed to get REE_AF_INT vector offsets");
		return;
	}

	/* Disable all REE AF interrupts */
	rvu_write64(rvu, blkaddr, REE_AF_RAS_ENA_W1C, 0x1);
	rvu_write64(rvu, blkaddr, REE_AF_RVU_INT_ENA_W1C, 0x1);
	rvu_write64(rvu, blkaddr, REE_AF_AQ_DONE_INT_ENA_W1C, 0x1);
	rvu_write64(rvu, blkaddr, REE_AF_AQ_INT_ENA_W1C, 0x1);

	for (i = 0; i < REE_AF_INT_VEC_CNT; i++)
		if (rvu->irq_allocated[offs + i]) {
			free_irq(pci_irq_vector(rvu->pdev, offs + i), rvu);
			rvu->irq_allocated[offs + i] = false;
		}
}

void rvu_ree_unregister_interrupts(struct rvu *rvu)
{
	rvu_ree_unregister_interrupts_block(rvu, BLKADDR_REE0);
	rvu_ree_unregister_interrupts_block(rvu, BLKADDR_REE1);
}

static int rvu_ree_af_request_irq(struct rvu_block *block,
				  int offset, irq_handler_t handler,
				  const char *name)
{
	int ret = 0;
	struct rvu *rvu = block->rvu;

	WARN_ON(rvu->irq_allocated[offset]);
	rvu->irq_allocated[offset] = false;
	sprintf(&rvu->irq_name[offset * NAME_SIZE], name);
	ret = request_irq(pci_irq_vector(rvu->pdev, offset), handler, 0,
			  &rvu->irq_name[offset * NAME_SIZE], block);
	if (ret)
		dev_warn(block->rvu->dev, "Failed to register %s irq\n", name);
	else
		rvu->irq_allocated[offset] = true;

	return rvu->irq_allocated[offset];
}

int rvu_ree_register_interrupts_block(struct rvu *rvu, int blkaddr)
{
	struct rvu_hwinfo *hw = rvu->hw;
	struct rvu_block *block;
	int offs, ret = 0;

	if (!is_block_implemented(rvu->hw, blkaddr))
		return 0;

	block = &hw->block[blkaddr];

	/* Read interrupt vector */
	offs = rvu_read64(rvu, blkaddr, REE_PRIV_AF_INT_CFG) & 0x7FF;
	if (!offs) {
		dev_warn(rvu->dev,
			 "Failed to get REE_AF_INT vector offsets");
		return 0;
	}

	/* Register and enable RAS interrupt */
	ret = rvu_ree_af_request_irq(block, offs + REE_AF_INT_VEC_RAS,
				     rvu_ree_af_ras_intr_handler,
				     "REEAF RAS");
	if (!ret)
		goto err;
	rvu_write64(rvu, blkaddr, REE_AF_RAS_ENA_W1S, ~0ULL);

	/* Register and enable RVU interrupt */
	ret = rvu_ree_af_request_irq(block, offs + REE_AF_INT_VEC_RVU,
				     rvu_ree_af_rvu_intr_handler,
				     "REEAF RVU");
	if (!ret)
		goto err;
	rvu_write64(rvu, blkaddr, REE_AF_RVU_INT_ENA_W1S, ~0ULL);

	/* QUE DONE */
	/* Interrupt for QUE DONE is not required, software is polling
	 * DONE count to get indication that all instructions are completed
	 */

	/* Register and enable AQ interrupt */
	ret = rvu_ree_af_request_irq(block, offs + REE_AF_INT_VEC_AQ,
				     rvu_ree_af_aq_intr_handler,
				     "REEAF RVU");
	if (!ret)
		goto err;
	rvu_write64(rvu, blkaddr, REE_AF_AQ_INT_ENA_W1S, ~0ULL);

	return 0;
err:
	rvu_ree_unregister_interrupts(rvu);
	return ret;
}

int rvu_ree_register_interrupts(struct rvu *rvu)
{
	int ret;

	ret = rvu_ree_register_interrupts_block(rvu, BLKADDR_REE0);
	if (ret)
		return ret;

	return rvu_ree_register_interrupts_block(rvu, BLKADDR_REE1);
}

static int rvu_ree_init_block(struct rvu *rvu, int blkaddr)
{
	struct rvu_hwinfo *hw = rvu->hw;
	struct rvu_block *block;
	struct ree_rsrc *ree;
	int err, blkid = 0;
	u64 val;

	if (!is_block_implemented(rvu->hw, blkaddr))
		return 0;

	block = &hw->block[blkaddr];
	if (blkaddr == BLKADDR_REE1)
		blkid = 1;
	ree = &rvu->hw->ree[blkid];

	/* Administrative instruction queue allocation */
	err = ree_aq_inst_alloc(rvu, &block->aq,
				REE_AQ_SIZE,
				sizeof(struct ree_af_aq_inst_s),
				0);
	if (err)
		return err;

	/* Administrative instruction queue address */
	rvu_write64(rvu, block->addr, REE_AF_AQ_SBUF_ADDR,
		    (u64)block->aq->inst->iova);

	/* Move head to start only when a new AQ is allocated and configured.
	 * Otherwise head is wrap around
	 */
	ree->aq_head = 0;

	/* Administrative queue instruction buffer size, in units of 128B
	 * (8 * REE_AF_AQ_INST_S)
	 */
	val = REE_AQ_SIZE >> 3;
	rvu_write64(rvu, block->addr, REE_AF_AQ_SBUF_CTL,
		    (val << REE_AF_AQ_SBUF_CTL_SIZE_SHIFT));

	/* Enable instruction queue */
	rvu_write64(rvu, block->addr, REE_AF_AQ_ENA, 0x1);

	/* Force Clock ON
	 * Force bits should be set throughout the REEX Initialization
	 */
	ree_reex_force_clock(rvu, block, true);

	/* REEX MAIN_CSR configuration */
	rvu_write64(rvu, block->addr, REE_AF_REEXM_MAX_MATCH,
		    REE_AF_REEXM_MAX_MATCH_MAX);
	rvu_write64(rvu, block->addr, REE_AF_REEXM_MAX_PRE_CNT,
		    REE_AF_REEXM_MAX_PRE_CNT_COUNT);
	rvu_write64(rvu, block->addr, REE_AF_REEXM_MAX_PTHREAD_CNT,
		    REE_AF_REEXM_MAX_PTHREAD_COUNT);
	rvu_write64(rvu, block->addr, REE_AF_REEXM_MAX_LATENCY_CNT,
		    REE_AF_REEXM_MAX_LATENCY_COUNT);

	/* REEX Set & Clear MAIN_CSR init */
	rvu_write64(rvu, block->addr, REE_AF_REEXM_CTRL, 0x1);
	rvu_write64(rvu, block->addr, REE_AF_REEXM_CTRL, 0x0);

	/* REEX Poll MAIN_CSR INIT_DONE */
	err = rvu_poll_reg(rvu, block->addr, REE_AF_REEXM_STATUS,
			   BIT_ULL(0), false);
	if (err) {
		dev_err(rvu->dev, "REE reexm poll for init done failed");
		return err;
	}

	/* Force Clock OFF */
	ree_reex_force_clock(rvu, block, false);

	return 0;
}

int rvu_ree_init(struct rvu *rvu)
{
	struct rvu_hwinfo *hw = rvu->hw;
	int err;

	hw->ree = devm_kcalloc(rvu->dev, MAX_REE_BLKS, sizeof(struct ree_rsrc),
			       GFP_KERNEL);
	if (!hw->ree)
		return -ENOMEM;

	err = rvu_ree_init_block(rvu, BLKADDR_REE0);
	if (err)
		return err;
	return rvu_ree_init_block(rvu, BLKADDR_REE1);
}

void rvu_ree_freemem_block(struct rvu *rvu, int blkaddr, int blkid)
{
	struct rvu_hwinfo *hw = rvu->hw;
	struct rvu_block *block;
	struct ree_rsrc *ree;
	int i = 0;

	if (!is_block_implemented(rvu->hw, blkaddr))
		return;

	block = &hw->block[blkaddr];
	ree  = &hw->ree[blkid];

	rvu_aq_free(rvu, block->aq);
	if (ree->graph_ctx)
		qmem_free(rvu->dev, ree->graph_ctx);
	if (ree->prefix_ctx)
		qmem_free(rvu->dev, ree->prefix_ctx);
	if (ree->ruledb) {
		for (i = 0; i < ree->ruledb_blocks; i++)
			kfree(ree->ruledb[i]);
		kfree(ree->ruledb);
	}
	kfree(ree->ruledbi);
}

void rvu_ree_freemem(struct rvu *rvu)
{
	rvu_ree_freemem_block(rvu, BLKADDR_REE0, 0);
	rvu_ree_freemem_block(rvu, BLKADDR_REE1, 1);
}
