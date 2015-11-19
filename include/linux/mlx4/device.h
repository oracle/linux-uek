/*
 * Copyright (c) 2006, 2007 Cisco Systems, Inc.  All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *	- Redistributions of source code must retain the above
 *	  copyright notice, this list of conditions and the following
 *	  disclaimer.
 *
 *	- Redistributions in binary form must reproduce the above
 *	  copyright notice, this list of conditions and the following
 *	  disclaimer in the documentation and/or other materials
 *	  provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef MLX4_DEVICE_H
#define MLX4_DEVICE_H

#include <linux/pci.h>
#include <linux/completion.h>
#include <linux/netdevice.h>
#include <linux/radix-tree.h>

#include <asm/atomic.h>

#include <linux/mlx4/driver.h>

enum {
	MLX4_FLAG_MSI_X		= 1 << 0,
	MLX4_FLAG_OLD_PORT_CMDS	= 1 << 1,
	MLX4_FLAG_MASTER	= 1 << 2,
	MLX4_FLAG_MFUNC		= 1 << 3,
	MLX4_FLAG_SRIOV		= 1 << 4,
};

enum {
	MLX4_MAX_PORTS		= 2,
	MLX4_MAX_PORT_PKEYS	= 128,
};

/* base qkey for use in sriov tunnel-qp/proxy-cp communication.
 * These qkeys must not be allowed for general use. This is a 64k range,
 * and to test for violation, we use the mask (protect against future chg).
 */
#define MLX4_RESERVED_QKEY_BASE  (0xFFFF0000)
#define MLX4_RESERVED_QKEY_MASK  (0xFFFF0000)

enum {
	MLX4_BOARD_ID_LEN = 64
};

enum {
	MLX4_MAX_NUM_PF		= 16,
	MLX4_MAX_NUM_VF		= 64,
	MLX4_MFUNC_MAX		= 80,
	MLX4_MFUNC_EQ_NUM	= 4,
	MLX4_MFUNC_MAX_EQES     = 8,
	MLX4_MFUNC_EQE_MASK     = (MLX4_MFUNC_MAX_EQES - 1)
};

enum {
	MLX4_DEV_CAP_FLAG_RC		= 1 <<  0,
	MLX4_DEV_CAP_FLAG_UC		= 1 <<  1,
	MLX4_DEV_CAP_FLAG_UD		= 1 <<  2,
	MLX4_DEV_CAP_FLAG_XRC		= 1 <<  3,
	MLX4_DEV_CAP_FLAG_SRQ		= 1 <<  6,
	MLX4_DEV_CAP_FLAG_IPOIB_CSUM	= 1 <<  7,
	MLX4_DEV_CAP_FLAG_BAD_PKEY_CNTR	= 1 <<  8,
	MLX4_DEV_CAP_FLAG_BAD_QKEY_CNTR	= 1 <<  9,
	MLX4_DEV_CAP_FLAG_DPDP		= 1 << 12,
	MLX4_DEV_CAP_FLAG_RAW_ETY	= 1 << 13,
	MLX4_DEV_CAP_FLAG_BLH		= 1 << 15,
	MLX4_DEV_CAP_FLAG_MEM_WINDOW	= 1 << 16,
	MLX4_DEV_CAP_FLAG_APM		= 1 << 17,
	MLX4_DEV_CAP_FLAG_ATOMIC	= 1 << 18,
	MLX4_DEV_CAP_FLAG_RAW_MCAST	= 1 << 19,
	MLX4_DEV_CAP_FLAG_UD_AV_PORT	= 1 << 20,
	MLX4_DEV_CAP_FLAG_UD_MCAST	= 1 << 21,
	MLX4_DEV_CAP_FLAG_IBOE		= 1 << 30,
	MLX4_DEV_CAP_FLAG_FC_T11	= 1 << 31
};

enum {
	MLX4_BMME_FLAG_LOCAL_INV	= 1 <<  6,
	MLX4_BMME_FLAG_REMOTE_INV	= 1 <<  7,
	MLX4_BMME_FLAG_TYPE_2_WIN	= 1 <<  9,
	MLX4_BMME_FLAG_RESERVED_LKEY	= 1 << 10,
	MLX4_BMME_FLAG_FAST_REG_WR	= 1 << 11,
};

enum mlx4_event {
	MLX4_EVENT_TYPE_COMP		   = 0x00,
	MLX4_EVENT_TYPE_PATH_MIG	   = 0x01,
	MLX4_EVENT_TYPE_COMM_EST	   = 0x02,
	MLX4_EVENT_TYPE_SQ_DRAINED	   = 0x03,
	MLX4_EVENT_TYPE_SRQ_QP_LAST_WQE	   = 0x13,
	MLX4_EVENT_TYPE_SRQ_LIMIT	   = 0x14,
	MLX4_EVENT_TYPE_CQ_ERROR	   = 0x04,
	MLX4_EVENT_TYPE_WQ_CATAS_ERROR	   = 0x05,
	MLX4_EVENT_TYPE_EEC_CATAS_ERROR	   = 0x06,
	MLX4_EVENT_TYPE_PATH_MIG_FAILED	   = 0x07,
	MLX4_EVENT_TYPE_WQ_INVAL_REQ_ERROR = 0x10,
	MLX4_EVENT_TYPE_WQ_ACCESS_ERROR	   = 0x11,
	MLX4_EVENT_TYPE_SRQ_CATAS_ERROR	   = 0x12,
	MLX4_EVENT_TYPE_LOCAL_CATAS_ERROR  = 0x08,
	MLX4_EVENT_TYPE_PORT_CHANGE	   = 0x09,
	MLX4_EVENT_TYPE_EQ_OVERFLOW	   = 0x0f,
	MLX4_EVENT_TYPE_ECC_DETECT	   = 0x0e,
	MLX4_EVENT_TYPE_CMD		   = 0x0a,
	MLX4_EVENT_TYPE_CLIENT_REREGISTER  = 0x16,
	MLX4_EVENT_TYPE_VEP_UPDATE	   = 0x19,
	MLX4_EVENT_TYPE_COMM_CHANNEL	   = 0x18,
	MLX4_EVENT_TYPE_MAC_UPDATE	   = 0x20,
	MLX4_EVENT_TYPE_SW_EVENT	   = 0x3f, /* TBD add check that future HW does not use this value */
	MLX4_EVENT_TYPE_FLR_EVENT	   = 0x1c,
	MLX4_EVENT_TYPE_PORT_MGMT_CHANGE   = 0x1d,
	MLX4_EVENT_TYPE_NONE		   = 0xff,
};

enum sw_event_sub_type{
	PKEY_UPDATE_AVIAL = 0,
 	GUID_CHANGE_AVIAL = 1,
	LID_CHANGE_AVIAL = 2,
	CLIENT_REREGISTER_AVIAL = 3,
	FUNCTION_BOOT = 4,
	FUNCTION_SHUTDOWN = 5,
};

enum {
	MLX4_PORT_CHANGE_SUBTYPE_DOWN	= 1,
	MLX4_PORT_CHANGE_SUBTYPE_ACTIVE	= 4
};

enum slave_port_state {
	SLAVE_PORT_DOWN = 0,
	SLAVE_PENDING_UP,
	SLAVE_PORT_UP,
};

enum slave_port_gen_event {
	SLAVE_PORT_GEN_EVENT_DOWN = 0,
	SLAVE_PORT_GEN_EVENT_UP,
	SLAVE_PORT_GEN_EVENT_NONE,
};
enum slave_port_state_event {
	MLX4_PORT_STATE_DEV_EVENT_PORT_DOWN,
	MLX4_PORT_STATE_DEV_EVENT_PORT_UP,
	MLX4_PORT_STATE_IB_PORT_STATE_EVENT_GID_VALID,
	MLX4_PORT_STATE_IB_EVENT_GID_INVALID,
};

enum {
	MLX4_PERM_LOCAL_READ	= 1 << 10,
	MLX4_PERM_LOCAL_WRITE	= 1 << 11,
	MLX4_PERM_REMOTE_READ	= 1 << 12,
	MLX4_PERM_REMOTE_WRITE	= 1 << 13,
	MLX4_PERM_ATOMIC	= 1 << 14
};

enum {
	MLX4_OPCODE_NOP			= 0x00,
	MLX4_OPCODE_SEND_INVAL		= 0x01,
	MLX4_OPCODE_RDMA_WRITE		= 0x08,
	MLX4_OPCODE_RDMA_WRITE_IMM	= 0x09,
	MLX4_OPCODE_SEND		= 0x0a,
	MLX4_OPCODE_SEND_IMM		= 0x0b,
	MLX4_OPCODE_LSO			= 0x0e,
	MLX4_OPCODE_BIG_LSO		= 0x2e,
	MLX4_OPCODE_RDMA_READ		= 0x10,
	MLX4_OPCODE_ATOMIC_CS		= 0x11,
	MLX4_OPCODE_ATOMIC_FA		= 0x12,
	MLX4_OPCODE_MASKED_ATOMIC_CS	= 0x14,
	MLX4_OPCODE_MASKED_ATOMIC_FA	= 0x15,
	MLX4_OPCODE_BIND_MW		= 0x18,
	MLX4_OPCODE_FMR			= 0x19,
	MLX4_OPCODE_LOCAL_INVAL		= 0x1b,
	MLX4_OPCODE_CONFIG_CMD		= 0x1f,

	MLX4_RECV_OPCODE_RDMA_WRITE_IMM	= 0x00,
	MLX4_RECV_OPCODE_SEND		= 0x01,
	MLX4_RECV_OPCODE_SEND_IMM	= 0x02,
	MLX4_RECV_OPCODE_SEND_INVAL	= 0x03,

	MLX4_CQE_OPCODE_ERROR		= 0x1e,
	MLX4_CQE_OPCODE_RESIZE		= 0x16,
};

enum {
	MLX4_STAT_RATE_OFFSET	= 5
};

enum mlx4_protocol {
	MLX4_PROT_IB_IPV6 = 0,
	MLX4_PROT_ETH,
	MLX4_PROT_IB_IPV4,
	MLX4_PROT_FCOE
};

enum {
	MLX4_MTT_FLAG_PRESENT		= 1
};

enum mlx4_qp_region {
	MLX4_QP_REGION_FW = 0,
	MLX4_QP_REGION_ETH_ADDR,
	MLX4_QP_REGION_FC_ADDR,
	MLX4_NUM_QP_REGION
};

enum mlx4_port_type {
	MLX4_PORT_TYPE_NONE	= 0,
	MLX4_PORT_TYPE_IB	= 1,
	MLX4_PORT_TYPE_ETH	= 2,
	MLX4_PORT_TYPE_AUTO	= 3
};

enum mlx4_special_vlan_idx {
	MLX4_NO_VLAN_IDX        = 0,
	MLX4_VLAN_MISS_IDX,
	MLX4_VLAN_REGULAR
};
#define MLX4_LEAST_ATTACHED_VECTOR	0xffffffff

enum mlx4_steer_type {
	MLX4_MC_STEER = 0,
	MLX4_UC_STEER,
	MLX4_NUM_STEERS
};

enum {
	MLX4_CUNTERS_DISABLED,
	MLX4_CUNTERS_BASIC,
	MLX4_CUNTERS_EXT
};

enum mlx4_mr_state {
	MLX4_MR_DISABLED = 0,
	MLX4_MR_EN_HW,
	MLX4_MR_EN_SW
};

enum mlx4_mr_flags {
	MLX4_MR_FLAG_NONE = 0,
	MLX4_MR_FLAG_FMR  = 1
};

static inline u64 mlx4_fw_ver(u64 major, u64 minor, u64 subminor)
{
	return (major << 32) | (minor << 16) | subminor;
}

struct mlx4_caps {
	u64			fw_ver;
	u32			function;
	u32			pf_num;
	u32			num_ports;
	u32			vl_cap[MLX4_MAX_PORTS + 1];
	u32			ib_mtu_cap[MLX4_MAX_PORTS + 1];
	__be32			ib_port_def_cap[MLX4_MAX_PORTS + 1];
	u64			def_mac[MLX4_MAX_PORTS + 1];
	u32			eth_mtu_cap[MLX4_MAX_PORTS + 1];
	u32			gid_table_len[MLX4_MAX_PORTS + 1];
	u32			pkey_table_len[MLX4_MAX_PORTS + 1];
	u32			pkey_table_max_len[MLX4_MAX_PORTS + 1];
	u32			trans_type[MLX4_MAX_PORTS + 1];
	u32			vendor_oui[MLX4_MAX_PORTS + 1];
	u32			wavelength[MLX4_MAX_PORTS + 1];
	u64			trans_code[MLX4_MAX_PORTS + 1];
	u32			local_ca_ack_delay;
	u32			num_uars;
	u32			uar_page_size;
	u32			bf_reg_size;
	u32			bf_regs_per_page;
	u32			max_sq_sg;
	u32			max_rq_sg;
	u32			num_qps;
	u32			max_wqes;
	u32			max_sq_desc_sz;
	u32			max_rq_desc_sz;
	u32			max_qp_init_rdma;
	u32			max_qp_dest_rdma;
	u32			sqp_start;
	u32			tunnel_qpn;
	u32			num_srqs;
	u32			max_srq_wqes;
	u32			max_srq_sge;
	u32			reserved_srqs;
	u32			num_cqs;
	u32			max_cqes;
	u32			reserved_cqs;
	u32			num_eqs;
	u32			reserved_eqs;
	u32			num_comp_vectors;
	u32			num_mpts;
	u32			num_mtt_segs;
	u32			mtts_per_seg;
	u32			fmr_reserved_mtts;
	u32			reserved_mtts;
	u32			reserved_mrws;
	u32			reserved_uars;
	u32			num_mgms;
	u32			num_amgms;
	u32			reserved_mcgs;
	u32			num_qp_per_mgm;
	u32			num_pds;
	u32			reserved_pds;
	u32			mtt_entry_sz;
	u32			reserved_xrcds;
	u32			max_xrcds;
	u32			max_msg_sz;
	u32			page_size_cap;
	u64			flags;
	u32			bmme_flags;
	u32			reserved_lkey;
	u16			stat_rate_support;
	u32			udp_rss;
	u32			loopback_support;
	u32			vep_uc_steering;
	u32			vep_mc_steering;
	u32			wol;
	u8			port_width_cap[MLX4_MAX_PORTS + 1];
	u32			max_gso_sz;
	u32                     reserved_qps_cnt[MLX4_NUM_QP_REGION];
	u32			reserved_qps;
	u32                     reserved_qps_base[MLX4_NUM_QP_REGION];
	u32                     log_num_macs;
	u32                     log_num_vlans;
	u32                     log_num_prios;
	u32	port_type[MLX4_MAX_PORTS + 1];
	u8			supported_type[MLX4_MAX_PORTS + 1];
	u8			sqp_demux;
	u32	port_mask[MLX4_MAX_PORTS + 1];
	u32	possible_type[MLX4_MAX_PORTS + 1];
	u8			counters_mode;
	u32			max_basic_counters;
	u32			max_ext_counters;
	u32			mc_promisc_mode;
	u32			mad_demux;
	u32			dmpt_entry_sz;
	u64			mtt_base;
	u64			dmpt_base;
	u64			fmr_dmpt_base;
	u32			fmr_dmpt_base_idx;
	u32			fmr_num_mpts;
	u64                     fmr_mtt_base;
	u32			fmr_mtt_base_idx;
	u32			fmr_num_mtt_segs;
	u8			fmr_log_page_size;
	u8			qinq;
	u32			vep_num;
	u16			clp_ver;
	u16			poolsz;
	u32			cqe_size;
} __attribute__((packed));

struct mlx4_buf_list {
	void		       *buf;
	dma_addr_t		map;
};

struct mlx4_buf {
	struct mlx4_buf_list	direct;
	struct mlx4_buf_list   *page_list;
	int			nbufs;
	int			npages;
	int			page_shift;
};

struct mlx4_mtt {
	u32			first_seg;
	int			order;
	int			page_shift;
};

enum {
	MLX4_DB_PER_PAGE = PAGE_SIZE / 4
};

struct mlx4_db_pgdir {
	struct list_head	list;
	DECLARE_BITMAP(order0, MLX4_DB_PER_PAGE);
	DECLARE_BITMAP(order1, MLX4_DB_PER_PAGE / 2);
	unsigned long	       *bits[2];
	__be32		       *db_page;
	dma_addr_t		db_dma;
};

struct mlx4_ib_user_db_page;

struct mlx4_db {
	__be32			*db;
	union {
		struct mlx4_db_pgdir		*pgdir;
		struct mlx4_ib_user_db_page	*user_page;
	}			u;
	dma_addr_t		dma;
	int			index;
	int			order;
};

struct mlx4_hwq_resources {
	struct mlx4_db		db;
	struct mlx4_mtt		mtt;
	struct mlx4_buf		buf;
};

struct mlx4_mr {
	struct mlx4_mtt		mtt;
	u64			iova;
	u64			size;
	u32			key;
	u32			pd;
	u32			access;
	int			enabled;
	enum mlx4_mr_flags	flags;
};

struct mlx4_fmr {
	struct mlx4_mr		mr;
	struct mlx4_mpt_entry  *mpt;
	__be64		       *mtts;
	dma_addr_t		dma_handle;
	int			max_pages;
	int			max_maps;
	int			maps;
	u8			page_shift;
};

struct mlx4_uar {
	unsigned long		pfn;
	int			index;
	struct list_head	bf_list;
	unsigned		free_bf_bmap;
	void __iomem	       *map;
	void __iomem	       *bf_map;
};

struct mlx4_bf {
	unsigned long		offset;
	int			buf_size;
	struct mlx4_uar	       *uar;
	void __iomem	       *reg;
};

struct mlx4_cq {
	void (*comp)		(struct mlx4_cq *);
	void (*event)		(struct mlx4_cq *, enum mlx4_event);

	struct mlx4_uar	       *uar;

	u32			cons_index;

	__be32		       *set_ci_db;
	__be32		       *arm_db;
	int			arm_sn;

	int			cqn;
	unsigned		vector;

	atomic_t		refcount;
	struct completion	free;
};

struct mlx4_qp {
	void (*event)		(struct mlx4_qp *, enum mlx4_event);

	int			qpn;

	atomic_t		refcount;
	struct completion	free;
};

struct mlx4_srq {
	void (*event)		(struct mlx4_srq *, enum mlx4_event);

	int			srqn;
	int			max;
	int			max_gs;
	int			wqe_shift;

	atomic_t		refcount;
	struct completion	free;
};

struct mlx4_av {
	__be32			port_pd;
	u8			reserved1;
	u8			g_slid;
	__be16			dlid;
	u8			reserved2;
	u8			gid_index;
	u8			stat_rate;
	u8			hop_limit;
	__be32			sl_tclass_flowlabel;
	u8			dgid[16];
};

struct mlx4_eth_av {
	__be32		port_pd;
	u8		reserved1;
	u8		smac_idx;
	u16		reserved2;
	u8		reserved3;
	u8		gid_index;
	u8		stat_rate;
	u8		hop_limit;
	__be32		sl_tclass_flowlabel;
	u8		dgid[16];
	u32		reserved4[2];
	__be16		vlan;
	u8		mac[6];
};

union mlx4_ext_av {
	struct mlx4_av		ib;
	struct mlx4_eth_av	eth;
};

struct mlx4_counters {
	__be32	counter_mode;
	__be32	num_ifc;
	u32	reserved[2];
	__be64	rx_frames;
	__be64	rx_bytes;
	__be64	tx_frames;
	__be64	tx_bytes;
};

struct mlx4_counters_ext {
	__be32	counter_mode;
	__be32	num_ifc;
	u32	reserved[2];
	__be64	rx_uni_frames;
	__be64	rx_uni_bytes;
	__be64	rx_mcast_frames;
	__be64	rx_mcast_bytes;
	__be64	rx_bcast_frames;
	__be64	rx_bcast_bytes;
	__be64	rx_nobuf_frames;
	__be64	rx_nobuf_bytes;
	__be64	rx_err_frames;
	__be64	rx_err_bytes;
	__be64	tx_uni_frames;
	__be64	tx_uni_bytes;
	__be64	tx_mcast_frames;
	__be64	tx_mcast_bytes;
	__be64	tx_bcast_frames;
	__be64	tx_bcast_bytes;
	__be64	tx_nobuf_frames;
	__be64	tx_nobuf_bytes;
	__be64	tx_err_frames;
	__be64	tx_err_bytes;
};

struct mlx4_dev {
	struct pci_dev	       *pdev;
	unsigned long		flags;
	unsigned long		num_slaves;
	struct mlx4_caps	caps;
	struct radix_tree_root	qp_table_tree;
	struct radix_tree_root	srq_table_tree;
	u32			rev_id;
	char			board_id[MLX4_BOARD_ID_LEN];
	int			sr_iov;
	int			is_internal_sma;
	u8                      gids_per_func;
};

struct mlx4_init_port_param {
	int			set_guid0;
	int			set_node_guid;
	int			set_si_guid;
	u16			mtu;
	int			port_width_cap;
	u16			vl_cap;
	u16			max_gid;
	u16			max_pkey;
	u64			guid0;
	u64			node_guid;
	u64			si_guid;
};

static inline void mlx4_query_steer_cap(struct mlx4_dev *dev, int *log_mac,
					int *log_vlan, int *log_prio)
{
	*log_mac = dev->caps.log_num_macs;
	*log_vlan = dev->caps.log_num_vlans;
	*log_prio = dev->caps.log_num_prios;
}

struct mlx4_stat_out_mbox {
	/* Received frames with a length of 64 octets */
	__be64 R64_prio_0;
	__be64 R64_prio_1;
	__be64 R64_prio_2;
	__be64 R64_prio_3;
	__be64 R64_prio_4;
	__be64 R64_prio_5;
	__be64 R64_prio_6;
	__be64 R64_prio_7;
	__be64 R64_novlan;
	/* Received frames with a length of 127 octets */
	__be64 R127_prio_0;
	__be64 R127_prio_1;
	__be64 R127_prio_2;
	__be64 R127_prio_3;
	__be64 R127_prio_4;
	__be64 R127_prio_5;
	__be64 R127_prio_6;
	__be64 R127_prio_7;
	__be64 R127_novlan;
	/* Received frames with a length of 255 octets */
	__be64 R255_prio_0;
	__be64 R255_prio_1;
	__be64 R255_prio_2;
	__be64 R255_prio_3;
	__be64 R255_prio_4;
	__be64 R255_prio_5;
	__be64 R255_prio_6;
	__be64 R255_prio_7;
	__be64 R255_novlan;
	/* Received frames with a length of 511 octets */
	__be64 R511_prio_0;
	__be64 R511_prio_1;
	__be64 R511_prio_2;
	__be64 R511_prio_3;
	__be64 R511_prio_4;
	__be64 R511_prio_5;
	__be64 R511_prio_6;
	__be64 R511_prio_7;
	__be64 R511_novlan;
	/* Received frames with a length of 1023 octets */
	__be64 R1023_prio_0;
	__be64 R1023_prio_1;
	__be64 R1023_prio_2;
	__be64 R1023_prio_3;
	__be64 R1023_prio_4;
	__be64 R1023_prio_5;
	__be64 R1023_prio_6;
	__be64 R1023_prio_7;
	__be64 R1023_novlan;
	/* Received frames with a length of 1518 octets */
	__be64 R1518_prio_0;
	__be64 R1518_prio_1;
	__be64 R1518_prio_2;
	__be64 R1518_prio_3;
	__be64 R1518_prio_4;
	__be64 R1518_prio_5;
	__be64 R1518_prio_6;
	__be64 R1518_prio_7;
	__be64 R1518_novlan;
	/* Received frames with a length of 1522 octets */
	__be64 R1522_prio_0;
	__be64 R1522_prio_1;
	__be64 R1522_prio_2;
	__be64 R1522_prio_3;
	__be64 R1522_prio_4;
	__be64 R1522_prio_5;
	__be64 R1522_prio_6;
	__be64 R1522_prio_7;
	__be64 R1522_novlan;
	/* Received frames with a length of 1548 octets */
	__be64 R1548_prio_0;
	__be64 R1548_prio_1;
	__be64 R1548_prio_2;
	__be64 R1548_prio_3;
	__be64 R1548_prio_4;
	__be64 R1548_prio_5;
	__be64 R1548_prio_6;
	__be64 R1548_prio_7;
	__be64 R1548_novlan;
	/* Received frames with a length of 1548 < octets < MTU */
	__be64 R2MTU_prio_0;
	__be64 R2MTU_prio_1;
	__be64 R2MTU_prio_2;
	__be64 R2MTU_prio_3;
	__be64 R2MTU_prio_4;
	__be64 R2MTU_prio_5;
	__be64 R2MTU_prio_6;
	__be64 R2MTU_prio_7;
	__be64 R2MTU_novlan;
	/* Received frames with a length of MTU< octets and good CRC */
	__be64 RGIANT_prio_0;
	__be64 RGIANT_prio_1;
	__be64 RGIANT_prio_2;
	__be64 RGIANT_prio_3;
	__be64 RGIANT_prio_4;
	__be64 RGIANT_prio_5;
	__be64 RGIANT_prio_6;
	__be64 RGIANT_prio_7;
	__be64 RGIANT_novlan;
	/* Received broadcast frames with good CRC */
	__be64 RBCAST_prio_0;
	__be64 RBCAST_prio_1;
	__be64 RBCAST_prio_2;
	__be64 RBCAST_prio_3;
	__be64 RBCAST_prio_4;
	__be64 RBCAST_prio_5;
	__be64 RBCAST_prio_6;
	__be64 RBCAST_prio_7;
	__be64 RBCAST_novlan;
	/* Received multicast frames with good CRC */
	__be64 MCAST_prio_0;
	__be64 MCAST_prio_1;
	__be64 MCAST_prio_2;
	__be64 MCAST_prio_3;
	__be64 MCAST_prio_4;
	__be64 MCAST_prio_5;
	__be64 MCAST_prio_6;
	__be64 MCAST_prio_7;
	__be64 MCAST_novlan;
	/* Received unicast not short or GIANT frames with good CRC */
	__be64 RTOTG_prio_0;
	__be64 RTOTG_prio_1;
	__be64 RTOTG_prio_2;
	__be64 RTOTG_prio_3;
	__be64 RTOTG_prio_4;
	__be64 RTOTG_prio_5;
	__be64 RTOTG_prio_6;
	__be64 RTOTG_prio_7;
	__be64 RTOTG_novlan;

	/* Count of total octets of received frames, includes framing characters */
	__be64 RTTLOCT_prio_0;
	/* Count of total octets of received frames, not including framing
	   characters */
	__be64 RTTLOCT_NOFRM_prio_0;
	/* Count of Total number of octets received
	   (only for frames without errors) */
	__be64 ROCT_prio_0;

	__be64 RTTLOCT_prio_1;
	__be64 RTTLOCT_NOFRM_prio_1;
	__be64 ROCT_prio_1;

	__be64 RTTLOCT_prio_2;
	__be64 RTTLOCT_NOFRM_prio_2;
	__be64 ROCT_prio_2;

	__be64 RTTLOCT_prio_3;
	__be64 RTTLOCT_NOFRM_prio_3;
	__be64 ROCT_prio_3;

	__be64 RTTLOCT_prio_4;
	__be64 RTTLOCT_NOFRM_prio_4;
	__be64 ROCT_prio_4;

	__be64 RTTLOCT_prio_5;
	__be64 RTTLOCT_NOFRM_prio_5;
	__be64 ROCT_prio_5;

	__be64 RTTLOCT_prio_6;
	__be64 RTTLOCT_NOFRM_prio_6;
	__be64 ROCT_prio_6;

	__be64 RTTLOCT_prio_7;
	__be64 RTTLOCT_NOFRM_prio_7;
	__be64 ROCT_prio_7;

	__be64 RTTLOCT_novlan;
	__be64 RTTLOCT_NOFRM_novlan;
	__be64 ROCT_novlan;

	/* Count of Total received frames including bad frames */
	__be64 RTOT_prio_0;
	/* Count of  Total number of received frames with 802.1Q encapsulation */
	__be64 R1Q_prio_0;
	__be64 reserved1;

	__be64 RTOT_prio_1;
	__be64 R1Q_prio_1;
	__be64 reserved2;

	__be64 RTOT_prio_2;
	__be64 R1Q_prio_2;
	__be64 reserved3;

	__be64 RTOT_prio_3;
	__be64 R1Q_prio_3;
	__be64 reserved4;

	__be64 RTOT_prio_4;
	__be64 R1Q_prio_4;
	__be64 reserved5;

	__be64 RTOT_prio_5;
	__be64 R1Q_prio_5;
	__be64 reserved6;

	__be64 RTOT_prio_6;
	__be64 R1Q_prio_6;
	__be64 reserved7;

	__be64 RTOT_prio_7;
	__be64 R1Q_prio_7;
	__be64 reserved8;

	__be64 RTOT_novlan;
	__be64 R1Q_novlan;
	__be64 reserved9;

	/* Total number of Successfully Received Control Frames */
	__be64 RCNTL;
	__be64 reserved10;
	__be64 reserved11;
	__be64 reserved12;
	/* Count of received frames with a length/type field  value between 46
	   (42 for VLANtagged frames) and 1500 (also 1500 for VLAN-tagged frames),
	   inclusive */
	__be64 RInRangeLengthErr;
	/* Count of received frames with length/type field between 1501 and 1535
	   decimal, inclusive */
	__be64 ROutRangeLengthErr;
	/* Count of received frames that are longer than max allowed size for
	   802.3 frames (1518/1522) */
	__be64 RFrmTooLong;
	/* Count frames received with PCS error */
	__be64 PCS;

	/* Transmit frames with a length of 64 octets */
	__be64 T64_prio_0;
	__be64 T64_prio_1;
	__be64 T64_prio_2;
	__be64 T64_prio_3;
	__be64 T64_prio_4;
	__be64 T64_prio_5;
	__be64 T64_prio_6;
	__be64 T64_prio_7;
	__be64 T64_novlan;
	__be64 T64_loopbk;
	/* Transmit frames with a length of 65 to 127 octets. */
	__be64 T127_prio_0;
	__be64 T127_prio_1;
	__be64 T127_prio_2;
	__be64 T127_prio_3;
	__be64 T127_prio_4;
	__be64 T127_prio_5;
	__be64 T127_prio_6;
	__be64 T127_prio_7;
	__be64 T127_novlan;
	__be64 T127_loopbk;
	/* Transmit frames with a length of 128 to 255 octets */
	__be64 T255_prio_0;
	__be64 T255_prio_1;
	__be64 T255_prio_2;
	__be64 T255_prio_3;
	__be64 T255_prio_4;
	__be64 T255_prio_5;
	__be64 T255_prio_6;
	__be64 T255_prio_7;
	__be64 T255_novlan;
	__be64 T255_loopbk;
	/* Transmit frames with a length of 256 to 511 octets */
	__be64 T511_prio_0;
	__be64 T511_prio_1;
	__be64 T511_prio_2;
	__be64 T511_prio_3;
	__be64 T511_prio_4;
	__be64 T511_prio_5;
	__be64 T511_prio_6;
	__be64 T511_prio_7;
	__be64 T511_novlan;
	__be64 T511_loopbk;
	/* Transmit frames with a length of 512 to 1023 octets */
	__be64 T1023_prio_0;
	__be64 T1023_prio_1;
	__be64 T1023_prio_2;
	__be64 T1023_prio_3;
	__be64 T1023_prio_4;
	__be64 T1023_prio_5;
	__be64 T1023_prio_6;
	__be64 T1023_prio_7;
	__be64 T1023_novlan;
	__be64 T1023_loopbk;
	/* Transmit frames with a length of 1024 to 1518 octets */
	__be64 T1518_prio_0;
	__be64 T1518_prio_1;
	__be64 T1518_prio_2;
	__be64 T1518_prio_3;
	__be64 T1518_prio_4;
	__be64 T1518_prio_5;
	__be64 T1518_prio_6;
	__be64 T1518_prio_7;
	__be64 T1518_novlan;
	__be64 T1518_loopbk;
	/* Counts transmit frames with a length of 1519 to 1522 bytes */
	__be64 T1522_prio_0;
	__be64 T1522_prio_1;
	__be64 T1522_prio_2;
	__be64 T1522_prio_3;
	__be64 T1522_prio_4;
	__be64 T1522_prio_5;
	__be64 T1522_prio_6;
	__be64 T1522_prio_7;
	__be64 T1522_novlan;
	__be64 T1522_loopbk;
	/* Transmit frames with a length of 1523 to 1548 octets */
	__be64 T1548_prio_0;
	__be64 T1548_prio_1;
	__be64 T1548_prio_2;
	__be64 T1548_prio_3;
	__be64 T1548_prio_4;
	__be64 T1548_prio_5;
	__be64 T1548_prio_6;
	__be64 T1548_prio_7;
	__be64 T1548_novlan;
	__be64 T1548_loopbk;
	/* Counts transmit frames with a length of 1549 to MTU bytes */
	__be64 T2MTU_prio_0;
	__be64 T2MTU_prio_1;
	__be64 T2MTU_prio_2;
	__be64 T2MTU_prio_3;
	__be64 T2MTU_prio_4;
	__be64 T2MTU_prio_5;
	__be64 T2MTU_prio_6;
	__be64 T2MTU_prio_7;
	__be64 T2MTU_novlan;
	__be64 T2MTU_loopbk;
	/* Transmit frames with a length greater than MTU octets and a good CRC. */
	__be64 TGIANT_prio_0;
	__be64 TGIANT_prio_1;
	__be64 TGIANT_prio_2;
	__be64 TGIANT_prio_3;
	__be64 TGIANT_prio_4;
	__be64 TGIANT_prio_5;
	__be64 TGIANT_prio_6;
	__be64 TGIANT_prio_7;
	__be64 TGIANT_novlan;
	__be64 TGIANT_loopbk;
	/* Transmit broadcast frames with a good CRC */
	__be64 TBCAST_prio_0;
	__be64 TBCAST_prio_1;
	__be64 TBCAST_prio_2;
	__be64 TBCAST_prio_3;
	__be64 TBCAST_prio_4;
	__be64 TBCAST_prio_5;
	__be64 TBCAST_prio_6;
	__be64 TBCAST_prio_7;
	__be64 TBCAST_novlan;
	__be64 TBCAST_loopbk;
	/* Transmit multicast frames with a good CRC */
	__be64 TMCAST_prio_0;
	__be64 TMCAST_prio_1;
	__be64 TMCAST_prio_2;
	__be64 TMCAST_prio_3;
	__be64 TMCAST_prio_4;
	__be64 TMCAST_prio_5;
	__be64 TMCAST_prio_6;
	__be64 TMCAST_prio_7;
	__be64 TMCAST_novlan;
	__be64 TMCAST_loopbk;
	/* Transmit good frames that are neither broadcast nor multicast */
	__be64 TTOTG_prio_0;
	__be64 TTOTG_prio_1;
	__be64 TTOTG_prio_2;
	__be64 TTOTG_prio_3;
	__be64 TTOTG_prio_4;
	__be64 TTOTG_prio_5;
	__be64 TTOTG_prio_6;
	__be64 TTOTG_prio_7;
	__be64 TTOTG_novlan;
	__be64 TTOTG_loopbk;

	/* total octets of transmitted frames, including framing characters */
	__be64 TTTLOCT_prio_0;
	/* total octets of transmitted frames, not including framing characters */
	__be64 TTTLOCT_NOFRM_prio_0;
	/* ifOutOctets */
	__be64 TOCT_prio_0;

	__be64 TTTLOCT_prio_1;
	__be64 TTTLOCT_NOFRM_prio_1;
	__be64 TOCT_prio_1;

	__be64 TTTLOCT_prio_2;
	__be64 TTTLOCT_NOFRM_prio_2;
	__be64 TOCT_prio_2;

	__be64 TTTLOCT_prio_3;
	__be64 TTTLOCT_NOFRM_prio_3;
	__be64 TOCT_prio_3;

	__be64 TTTLOCT_prio_4;
	__be64 TTTLOCT_NOFRM_prio_4;
	__be64 TOCT_prio_4;

	__be64 TTTLOCT_prio_5;
	__be64 TTTLOCT_NOFRM_prio_5;
	__be64 TOCT_prio_5;

	__be64 TTTLOCT_prio_6;
	__be64 TTTLOCT_NOFRM_prio_6;
	__be64 TOCT_prio_6;

	__be64 TTTLOCT_prio_7;
	__be64 TTTLOCT_NOFRM_prio_7;
	__be64 TOCT_prio_7;

	__be64 TTTLOCT_novlan;
	__be64 TTTLOCT_NOFRM_novlan;
	__be64 TOCT_novlan;

	__be64 TTTLOCT_loopbk;
	__be64 TTTLOCT_NOFRM_loopbk;
	__be64 TOCT_loopbk;

	/* Total frames transmitted with a good CRC that are not aborted  */
	__be64 TTOT_prio_0;
	/* Total number of frames transmitted with 802.1Q encapsulation */
	__be64 T1Q_prio_0;
	__be64 reserved13;

	__be64 TTOT_prio_1;
	__be64 T1Q_prio_1;
	__be64 reserved14;

	__be64 TTOT_prio_2;
	__be64 T1Q_prio_2;
	__be64 reserved15;

	__be64 TTOT_prio_3;
	__be64 T1Q_prio_3;
	__be64 reserved16;

	__be64 TTOT_prio_4;
	__be64 T1Q_prio_4;
	__be64 reserved17;

	__be64 TTOT_prio_5;
	__be64 T1Q_prio_5;
	__be64 reserved18;

	__be64 TTOT_prio_6;
	__be64 T1Q_prio_6;
	__be64 reserved19;

	__be64 TTOT_prio_7;
	__be64 T1Q_prio_7;
	__be64 reserved20;

	__be64 TTOT_novlan;
	__be64 T1Q_novlan;
	__be64 reserved21;

	__be64 TTOT_loopbk;
	__be64 T1Q_loopbk;
	__be64 reserved22;

	/* Received frames with a length greater than MTU octets and a bad CRC */
	__be32 RJBBR;
	/* Received frames with a bad CRC that are not runts, jabbers,
	   or alignment errors */
	__be32 RCRC;
	/* Received frames with SFD with a length of less than 64 octets and a
	   bad CRC */
	__be32 RRUNT;
	/* Received frames with a length less than 64 octets and a good CRC */
	__be32 RSHORT;
	/* Total Number of Received Packets Dropped */
	__be32 RDROP;
	/* Drop due to overflow  */
	__be32 RdropOvflw;
	/* Drop due to overflow */
	__be32 RdropLength;
	/* Total of good frames. Does not include frames received with
	   frame-too-long, FCS, or length errors */
	__be32 RTOTFRMS;
	/* Total dropped Xmited packets */
	__be32 TDROP;
};

struct mlx4_func_stat_out_mbox {
	__be64 etherStatsDropEvents;
	__be64 etherStatsOctets;
	__be64 etherStatsPkts;
	__be64 etherStatsBroadcastPkts;
	__be64 etherStatsMulticastPkts;
	__be64 etherStatsCRCAlignErrors;
	__be64 etherStatsUndersizePkts;
	__be64 etherStatsOversizePkts;
	__be64 etherStatsFragments;
	__be64 etherStatsJabbers;
	__be64 etherStatsCollisions;
	__be64 etherStatsPkts64Octets;
	__be64 etherStatsPkts65to127Octets;
	__be64 etherStatsPkts128to255Octets;
	__be64 etherStatsPkts256to511Octets;
	__be64 etherStatsPkts512to1023Octets;
	__be64 etherStatsPkts1024to1518Octets;
};

struct mlx4_mpt_entry {
	__be32 flags;
	__be32 qpn;
	__be32 key;
	__be32 pd_flags;
	__be64 start;
	__be64 length;
	__be32 lkey;
	__be32 win_cnt;
	u8	reserved1;
	u8	flags2;
	u8	reserved2;
	u8	mtt_rep;
	__be64 mtt_seg;
	__be32 mtt_sz;
	__be32 entity_size;
	__be32 first_byte_offset;
} __attribute__((packed));


/*
 * Must be packed because start is 64 bits but only aligned to 32 bits.
 */
struct mlx4_eq_context {
	__be32			flags;
	u16			reserved1[3];
	__be16			page_offset;
	u8			log_eq_size;
	u8			reserved2[4];
	u8			eq_period;
	u8			reserved3;
	u8			eq_max_count;
	u8			reserved4[3];
	u8			intr;
	u8			log_page_size;
	u8			reserved5[2];
	u8			mtt_base_addr_h;
	__be32			mtt_base_addr_l;
	u32			reserved6[2];
	__be32			consumer_index;
	__be32			producer_index;
	u32			reserved7[4];
};

struct mlx4_cq_context {
	__be32			flags;
	u16			reserved1[3];
	__be16			page_offset;
	__be32			logsize_usrpage;
	__be16			cq_period;
	__be16			cq_max_count;
	u8			reserved2[3];
	u8			comp_eqn;
	u8			log_page_size;
	u8			reserved3[2];
	u8			mtt_base_addr_h;
	__be32			mtt_base_addr_l;
	__be32			last_notified_index;
	__be32			solicit_producer_index;
	__be32			consumer_index;
	__be32			producer_index;
	u32			reserved4[2];
	__be64			db_rec_addr;
};

struct mlx4_srq_context {
	__be32			state_logsize_srqn;
	u8			logstride;
	u8			reserved1;
	__be16			xrc_domain;
	__be32			pg_offset_cqn;
	u32			reserved2;
	u8			log_page_size;
	u8			reserved3[2];
	u8			mtt_base_addr_h;
	__be32			mtt_base_addr_l;
	__be32			pd;
	__be16			limit_watermark;
	__be16			wqe_cnt;
	u16			reserved4;
	__be16			wqe_counter;
	u32			reserved5;
	__be64			db_rec_addr;
};

struct mlx4_eth_common_counters {
	/* bad packets received		*/
	unsigned long	rx_errors;
	/* packet transmit problems	*/
	unsigned long	tx_errors;
	/* multicast packets received	*/
	unsigned long	multicast;
	unsigned long	rx_length_errors;
	/* receiver ring buff overflow	*/
	unsigned long	rx_over_errors;
	/* recved pkt with crc error	*/
	unsigned long	rx_crc_errors;
	/* recv'r fifo overrun		*/
	unsigned long	rx_fifo_errors;
	/* receiver missed packet	*/
	unsigned long	rx_missed_errors;
	unsigned long	broadcast;

	unsigned long	iboe_tx_packets;
	unsigned long	iboe_rx_packets;
	unsigned long	iboe_tx_bytess;
	unsigned long	iboe_rx_bytess;
};

struct mlx4_wol_struct {
	__be32 flags;
	__be32 preserved1;
};

struct mlx4_enable_fmr_mbox {
	/* protocol KVM = 0, XEN = 1 */
	u8	protocol;
	/* size of protocol specific private info */
	u8	fmr_info_size;
	/* data size added by the protocol on vpm struct */
	u8	vpm_info_size;
	/* log of number of 4K pages be used in FMR ICM mappings */
	u8	log_page_size;
	/* reserved */
	__be32	reserved[2];
	/* mpt index assigned by firmware for the vf */
	__be32	base_mpt_entry;  /* mpts number is taken from QUERY_HCA */
	/* protocol specific private info */
	u8	fmr_info[0];
};

int mlx4_DUMP_ETH_STATS(struct mlx4_dev *dev, u8 port, u8 reset,
			   struct mlx4_eth_common_counters *stats);

#define mlx4_foreach_port(port, dev, type)				\
	for ((port) = 1; (port) <= (dev)->caps.num_ports; (port)++)	\
		if ((type) == (dev)->caps.port_mask[(port)])

#define mlx4_foreach_ib_transport_port(port, dev)                         \
	for ((port) = 1; (port) <= (dev)->caps.num_ports; (port)++)       \
		if (((dev)->caps.port_mask[port] == MLX4_PORT_TYPE_IB) || \
			((dev)->caps.flags & MLX4_DEV_CAP_FLAG_IBOE))


static inline int mlx4_is_master(struct mlx4_dev *dev)
{
	return dev->flags & MLX4_FLAG_MASTER;
}

static inline int mlx4_is_mfunc(struct mlx4_dev *dev)
{
	return dev->flags & (MLX4_FLAG_MFUNC | MLX4_FLAG_MASTER);
}

static inline int mlx4_is_qp_reserved(struct mlx4_dev *dev, u32 qpn)
{
	return (qpn < dev->caps.tunnel_qpn + 8 +
		16 * MLX4_MFUNC_MAX * !!mlx4_is_master(dev));
}

static inline int mlx4_is_guest_proxy(struct mlx4_dev *dev, int slave, u32 qpn)
{
	int base = dev->caps.tunnel_qpn + 8 + slave * 8;

	if (qpn >= base && qpn < base + 8)
		return 1;

	return 0;
}

int mlx4_buf_alloc(struct mlx4_dev *dev, int size, int max_direct,
		   struct mlx4_buf *buf, gfp_t gfp);
void mlx4_buf_free(struct mlx4_dev *dev, int size, struct mlx4_buf *buf);
static inline void *mlx4_buf_offset(struct mlx4_buf *buf, int offset)
{
	if (BITS_PER_LONG == 64 || buf->nbufs == 1)
		return buf->direct.buf + offset;
	else
		return buf->page_list[offset >> PAGE_SHIFT].buf +
			(offset & (PAGE_SIZE - 1));
}

static inline u32 key_to_hw_index(u32 key)
{
	return (key << 24) | (key >> 8);
}

static inline u32 key_to_mpt_index(struct mlx4_dev *dev, u32 key)
{
	return key_to_hw_index(key) & (dev->caps.num_mpts - 1);
}

int mlx4_pd_alloc(struct mlx4_dev *dev, u32 *pdn);
void mlx4_pd_free(struct mlx4_dev *dev, u32 pdn);

int mlx4_xrcd_alloc(struct mlx4_dev *dev, u32 *xrcdn);
void mlx4_xrcd_free(struct mlx4_dev *dev, u32 xrcdn);

int mlx4_uar_alloc(struct mlx4_dev *dev, struct mlx4_uar *uar);
void mlx4_uar_free(struct mlx4_dev *dev, struct mlx4_uar *uar);
int mlx4_bf_alloc(struct mlx4_dev *dev, struct mlx4_bf *bf);
void mlx4_bf_free(struct mlx4_dev *dev, struct mlx4_bf *bf);

int mlx4_mtt_init(struct mlx4_dev *dev, int npages, int page_shift,
		  struct mlx4_mtt *mtt, enum mlx4_mr_flags flags);
void mlx4_mtt_cleanup(struct mlx4_dev *dev, struct mlx4_mtt *mtt,
		      enum mlx4_mr_flags flags);
u64 mlx4_mtt_addr(struct mlx4_dev *dev, struct mlx4_mtt *mtt);

int mlx4_mr_reserve_range(struct mlx4_dev *dev, int cnt, int align, u32 *base_mridx);
void mlx4_mr_release_range(struct mlx4_dev *dev, u32 base_mridx, int cnt);
int mlx4_mr_alloc_reserved(struct mlx4_dev *dev, u32 mridx, u32 pd,
			   u64 iova, u64 size, u32 access, int npages,
			   int page_shift, struct mlx4_mr *mr);
int mlx4_mr_alloc(struct mlx4_dev *dev, u32 pd, u64 iova, u64 size, u32 access,
		  int npages, int page_shift, struct mlx4_mr *mr);
void mlx4_mr_free_reserved(struct mlx4_dev *dev, struct mlx4_mr *mr);
void mlx4_mr_free(struct mlx4_dev *dev, struct mlx4_mr *mr);
int mlx4_mr_enable(struct mlx4_dev *dev, struct mlx4_mr *mr);
int mlx4_write_mtt(struct mlx4_dev *dev, struct mlx4_mtt *mtt,
		   int start_index, int npages, u64 *page_list);
int mlx4_buf_write_mtt(struct mlx4_dev *dev, struct mlx4_mtt *mtt,
		       struct mlx4_buf *buf, gfp_t gfp);

int mlx4_db_alloc(struct mlx4_dev *dev, struct mlx4_db *db, int order,
		  gfp_t gfp);
void mlx4_db_free(struct mlx4_dev *dev, struct mlx4_db *db);

int mlx4_alloc_hwq_res(struct mlx4_dev *dev, struct mlx4_hwq_resources *wqres,
		       int size, int max_direct);
void mlx4_free_hwq_res(struct mlx4_dev *mdev, struct mlx4_hwq_resources *wqres,
		       int size);

int mlx4_cq_alloc(struct mlx4_dev *dev, int nent, struct mlx4_mtt *mtt,
		  struct mlx4_uar *uar, u64 db_rec, struct mlx4_cq *cq,
		  unsigned vector, int collapsed);
void mlx4_cq_free(struct mlx4_dev *dev, struct mlx4_cq *cq);

int mlx4_qp_reserve_range(struct mlx4_dev *dev, int cnt, int align, int *base);
void mlx4_qp_release_range(struct mlx4_dev *dev, int base_qpn, int cnt);

int mlx4_qp_alloc(struct mlx4_dev *dev, int qpn, struct mlx4_qp *qp,
		  gfp_t gfp);
void mlx4_qp_free(struct mlx4_dev *dev, struct mlx4_qp *qp);

int mlx4_srq_alloc(struct mlx4_dev *dev, u32 pdn, u32 cqn, u16 xrcd,
		   struct mlx4_mtt *mtt, u64 db_rec, struct mlx4_srq *srq);
void mlx4_srq_free(struct mlx4_dev *dev, struct mlx4_srq *srq);
int mlx4_srq_arm(struct mlx4_dev *dev, struct mlx4_srq *srq, int limit_watermark);
int mlx4_srq_query(struct mlx4_dev *dev, struct mlx4_srq *srq, int *limit_watermark);

int mlx4_SET_PORT_general(struct mlx4_interface *intf, struct mlx4_dev *dev,
		u8 port, int mtu, u8 *pptx, u8 *pprx);

int mlx4_SET_PORT_qpn_calc(struct mlx4_dev *dev, u8 port, u32 base_qpn,
			   u8 promisc);

int mlx4_INIT_PORT(struct mlx4_dev *dev, int port);
int mlx4_CLOSE_PORT(struct mlx4_dev *dev, int port);

int mlx4_multicast_attach(struct mlx4_dev *dev, struct mlx4_qp *qp, u8 gid[16],
			  int block_mcast_loopback, enum mlx4_protocol prot);
int mlx4_multicast_detach(struct mlx4_dev *dev, struct mlx4_qp *qp, u8 gid[16],
				enum mlx4_protocol prot);

int mlx4_multicast_promisc_add(struct mlx4_dev *dev, u32 qpn, u8 port);
int mlx4_multicast_promisc_remove(struct mlx4_dev *dev, u32 qpn, u8 port);
int mlx4_unicast_promisc_add(struct mlx4_dev *dev, u32 qpn, u8 port);
int mlx4_unicast_promisc_remove(struct mlx4_dev *dev, u32 qpn, u8 port);
int mlx4_SET_MCAST_FLTR(struct mlx4_dev *dev, u8 port, u64 mac, u64 clear, u8 mode);

int mlx4_register_mac(struct mlx4_dev *dev, u8 port, u64 mac, int *qpn, u8 wrap);
void mlx4_unregister_mac(struct mlx4_dev *dev, u8 port, int qpn);
int mlx4_replace_mac(struct mlx4_dev *dev, u8 port, int qpn, u64 new_mac, u8 wrap);
int mlx4_find_cached_vlan(struct mlx4_dev *dev, u8 port, u16 vid, int *idx);
int mlx4_register_vlan(struct mlx4_dev *dev, u8 port, u16 vlan, int *index);
void mlx4_unregister_vlan(struct mlx4_dev *dev, u8 port, int index);

int mlx4_map_phys_fmr_fbo(struct mlx4_dev *dev, struct mlx4_fmr *fmr,
			  u64 *page_list, int npages, u64 iova, u32 fbo,
			  u32 len, u32 *lkey, u32 *rkey, int same_key);
int mlx4_set_fmr_pd(struct mlx4_fmr *fmr, u32 pd);
int mlx4_map_phys_fmr(struct mlx4_dev *dev, struct mlx4_fmr *fmr, u64 *page_list,
		      int npages, u64 iova, u32 *lkey, u32 *rkey);
int mlx4_fmr_alloc_reserved(struct mlx4_dev *dev, u32 mridx, u32 pd,
			    u32 access, int max_pages, int max_maps,
			    u8 page_shift, struct mlx4_fmr *fmr);
int mlx4_fmr_alloc(struct mlx4_dev *dev, u32 pd, u32 access, int max_pages,
		   int max_maps, u8 page_shift, struct mlx4_fmr *fmr);
int mlx4_fmr_enable(struct mlx4_dev *dev, struct mlx4_fmr *fmr);
void mlx4_fmr_unmap(struct mlx4_dev *dev, struct mlx4_fmr *fmr,
		    u32 *lkey, u32 *rkey);
int mlx4_fmr_free_reserved(struct mlx4_dev *dev, struct mlx4_fmr *fmr);
int mlx4_fmr_free(struct mlx4_dev *dev, struct mlx4_fmr *fmr);
int mlx4_SYNC_TPT(struct mlx4_dev *dev);
int mlx4_query_diag_counters(struct mlx4_dev *mlx4_dev, int array_length,
			     u8 op_modifier, u32 in_offset[], u32 counter_out[]);
int mlx4_test_interrupts(struct mlx4_dev *dev);
int mlx4_QUERY_PORT(struct mlx4_dev *dev, void *outbox, u8 port);
void mlx4_get_fc_t11_settings(struct mlx4_dev *dev, int *enable_pre_t11, int *t11_supported);

int __mlx4_counter_alloc(struct mlx4_dev *dev, u32 *idx);
void __mlx4_counter_free(struct mlx4_dev *dev, u32 idx);
int mlx4_counter_alloc(struct mlx4_dev *dev, u32 *idx);
void mlx4_counter_free(struct mlx4_dev *dev, u32 idx);

int mlx4_wol_read(struct mlx4_dev *dev, struct mlx4_wol_struct *output, int port);
int mlx4_wol_write(struct mlx4_dev *dev, struct mlx4_wol_struct *input, int port);
int mlx4_GET_PKEY_TABLE(struct mlx4_dev *dev, u8 port, u8 table[]);
int mlx4_gen_pkey_eqe(struct mlx4_dev *dev, int slave, u8 port);

int mlx4_is_slave_active(struct mlx4_dev *dev, int slave);
void mlx4_sync_pkey_table(struct mlx4_dev *dev, int slave, int port, int i, int val);

int mlx4_gen_guid_change_eqe(struct mlx4_dev *dev, int slave, u8 port);
int mlx4_gen_all_sw_eqe(struct mlx4_dev *dev, u8 port, int avial);
int mlx4_get_parav_qkey(struct mlx4_dev *dev, u32 qpn, u32 *qkey);
void mlx4_gen_port_state_change_eqe(struct mlx4_dev *dev, int slave, u8 port, u8 port_subtype_change);
enum slave_port_state mlx4_get_slave_port_state(struct mlx4_dev *dev, int slave, u8 port);
int set_and_calc_slave_port_state(struct mlx4_dev *dev, int slave, u8 port, int event, enum slave_port_gen_event* gen_event);

#define MLX4_NOT_SET_GUID             cpu_to_be64(0ULL)
void mlx4_slave_handle_guid(struct mlx4_dev *dev, int slave_id, u8 port_num, __be64 cur_ag);
int mlx4_gid_idx_to_slave(struct mlx4_dev *dev, int gid_index);
#endif /* MLX4_DEVICE_H */
