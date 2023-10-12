/* SPDX-License-Identifier: GPL-2.0 */
/* Marvell RVU AF REE extension
 *
 * Copyright (C) 2023 Marvell.
 *
 */

#define MBOX_EBLOCK_REE_MESSAGES					\
/* REE mbox IDs (range 0xE00 - 0xFFF) */				\
M(REE_CONFIG_LF,	0xE01, ree_config_lf, ree_lf_req_msg,		\
				msg_rsp)				\
M(REE_RD_WR_REGISTER,	0xE02, ree_rd_wr_register, ree_rd_wr_reg_msg,	\
				ree_rd_wr_reg_msg)			\
M(REE_RULE_DB_PROG,	0xE03, ree_rule_db_prog,			\
				ree_rule_db_prog_req_msg,		\
				msg_rsp)				\
M(REE_RULE_DB_LEN_GET,	0xE04, ree_rule_db_len_get, ree_req_msg,	\
				ree_rule_db_len_rsp_msg)		\
M(REE_RULE_DB_GET,	0xE05, ree_rule_db_get,				\
				ree_rule_db_get_req_msg,		\
				ree_rule_db_get_rsp_msg)		\

/* REE mailbox error codes
 * Range 1001 - 1100.
 */
enum ree_af_status {
	REE_AF_ERR_RULE_UNKNOWN_VALUE		= -1001,
	REE_AF_ERR_LF_NO_MORE_RESOURCES		= -1002,
	REE_AF_ERR_LF_INVALID			= -1003,
	REE_AF_ERR_ACCESS_DENIED		= -1004,
	REE_AF_ERR_RULE_DB_PARTIAL		= -1005,
	REE_AF_ERR_RULE_DB_EQ_BAD_VALUE		= -1006,
	REE_AF_ERR_RULE_DB_BLOCK_ALLOC_FAILED	= -1007,
	REE_AF_ERR_BLOCK_NOT_IMPLEMENTED	= -1008,
	REE_AF_ERR_RULE_DB_INC_OFFSET_TOO_BIG	= -1009,
	REE_AF_ERR_RULE_DB_OFFSET_TOO_BIG	= -1010,
	REE_AF_ERR_Q_IS_GRACEFUL_DIS		= -1011,
	REE_AF_ERR_Q_NOT_GRACEFUL_DIS		= -1012,
	REE_AF_ERR_RULE_DB_ALLOC_FAILED		= -1013,
	REE_AF_ERR_RULE_DB_TOO_BIG		= -1014,
	REE_AF_ERR_RULE_DB_GEQ_BAD_VALUE	= -1015,
	REE_AF_ERR_RULE_DB_LEQ_BAD_VALUE	= -1016,
	REE_AF_ERR_RULE_DB_WRONG_LENGTH		= -1017,
	REE_AF_ERR_RULE_DB_WRONG_OFFSET		= -1018,
	REE_AF_ERR_RULE_DB_BLOCK_TOO_BIG	= -1019,
	REE_AF_ERR_RULE_DB_SHOULD_FILL_REQUEST	= -1020,
	REE_AF_ERR_RULE_DBI_ALLOC_FAILED	= -1021,
	REE_AF_ERR_LF_WRONG_PRIORITY		= -1022,
	REE_AF_ERR_LF_SIZE_TOO_BIG		= -1023,
	REE_AF_ERR_GRAPH_ADDRESS_TOO_BIG	= -1024,
	REE_AF_ERR_BAD_RULE_TYPE		= -1025,
};

/* REE mbox message formats */

struct ree_req_msg {
	struct mbox_msghdr hdr;
	u32 blkaddr;
};

struct ree_lf_req_msg {
	struct mbox_msghdr hdr;
	u32 blkaddr;
	u32 size;
	u8 lf;
	u8 pri;
};

struct ree_rule_db_prog_req_msg {
	struct mbox_msghdr	hdr;
/* Rule DB passed in MBOX and is copied to internal REE DB
 * This size should be power of 2 to fit into rule DB internal blocks
 */
#define REE_RULE_DB_REQ_BLOCK_SIZE (MBOX_SIZE >> 1)
	u8 rule_db[REE_RULE_DB_REQ_BLOCK_SIZE];
	u32 blkaddr;		/* REE0 or REE1 */
	u32 total_len;		/* Total len of rule db */
	u32 offset;		/* Offset of current rule db block */
	u16 len;		/* Length of rule db block */
	u8 is_last;		/* Is this the last block */
	u8 is_incremental;	/* Is incremental flow */
	u8 is_dbi;		/* Is rule db incremental */
};

struct ree_rule_db_get_req_msg {
	struct mbox_msghdr hdr;
	u32 blkaddr;
	u32 offset;	/* Retrieve db from this offset */
	u8 is_dbi;	/* Is request for rule db incremental */
};

struct ree_rd_wr_reg_msg {
	struct mbox_msghdr hdr;
	u64 reg_offset;
	u64 *ret_val;
	u64 val;
	u32 blkaddr;
	u8 is_write;
};

struct ree_rule_db_len_rsp_msg {
	struct mbox_msghdr hdr;
	u32 blkaddr;
	u32 len;
	u32 inc_len;
};

struct ree_rule_db_get_rsp_msg {
	struct mbox_msghdr hdr;
#define REE_RULE_DB_RSP_BLOCK_SIZE (MBOX_DOWN_TX_SIZE - SZ_1K)
	u8 rule_db[REE_RULE_DB_RSP_BLOCK_SIZE];
	u32 total_len;		/* Total len of rule db */
	u32 offset;		/* Offset of current rule db block */
	u16 len;		/* Length of rule db block */
	u8 is_last;		/* Is this the last block */
};

#define M(_name, _id, fn_name, req, rsp)				\
int rvu_mbox_handler_ ## fn_name(struct rvu *, struct req *, struct rsp *);
MBOX_EBLOCK_REE_MESSAGES
#undef M
