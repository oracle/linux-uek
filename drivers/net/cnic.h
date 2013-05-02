/* cnic.h: Broadcom CNIC core network driver.
 *
 * Copyright (c) 2006-2011 Broadcom Corporation
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation.
 *
 * Written by: John(Zongxi) Chen (zongxic@broadcom.com)
 */


#ifndef CNIC_H
#define CNIC_H

#if !defined(__LITTLE_ENDIAN) && !defined(__BIG_ENDIAN)
	#error "Missing either LITTLE_ENDIAN or BIG_ENDIAN definition."
#endif

#ifndef DIV_ROUND_UP
#define DIV_ROUND_UP(n,d) (((n) + (d) - 1) / (d))
#endif

#ifndef ISCSI_DEF_FIRST_BURST_LEN
#define ISCSI_DEF_FIRST_BURST_LEN		65536
#endif

#ifndef ISCSI_DEF_MAX_RECV_SEG_LEN
#define ISCSI_DEF_MAX_RECV_SEG_LEN		8192
#endif

#ifndef ISCSI_DEF_MAX_BURST_LEN
#define ISCSI_DEF_MAX_BURST_LEN			262144
#endif

#ifndef rcu_dereference_protected

#define rcu_dereference_protected(p, c) \
	rcu_dereference((p))

#endif

#ifndef __rcu
#define __rcu
#endif

#ifndef RCU_INIT_POINTER
#define RCU_INIT_POINTER(p, v) \
		p = (typeof(*v) __force __rcu *)(v)
#endif

#ifndef pr_warning
#define pr_warning(fmt, ...) \
	printk(KERN_WARNING pr_fmt(fmt), ##__VA_ARGS__)
#endif

#ifndef pr_warn
#define pr_warn pr_warning
#endif

#if !defined(netdev_printk) && (LINUX_VERSION_CODE < 0x020624)

#if (LINUX_VERSION_CODE < 0x020615)
#define NET_PARENT_DEV(netdev)  ((netdev)->class_dev.dev)
#else
#define NET_PARENT_DEV(netdev)  ((netdev)->dev.parent)
#endif

#define netdev_printk(level, netdev, format, args...)		\
	dev_printk(level, NET_PARENT_DEV(netdev),	\
		   "%s: " format,				\
		   netdev_name(netdev), ##args)
#endif

#ifndef netdev_warn
#define netdev_warn(dev, format, args...)			\
	netdev_printk(KERN_WARNING, dev, format, ##args)
#endif

#define ISCSI_DEFAULT_MAX_OUTSTANDING_R2T 	(1)

/* Formerly Cstorm iSCSI EQ index (HC_INDEX_C_ISCSI_EQ_CONS) */
#define HC_INDEX_ISCSI_EQ_CONS          	6

/* Formerly Ustorm iSCSI EQ index (HC_INDEX_U_FCOE_EQ_CONS) */
#define HC_INDEX_FCOE_EQ_CONS			3

#define C_SB_ETH_TX_CQ_INDEX			5

#define HC_SP_INDEX_ETH_ISCSI_CQ_CONS		5
#define HC_SP_INDEX_ETH_ISCSI_RX_CQ_CONS	1

#define KWQ_PAGE_CNT	4
#define KCQ_PAGE_CNT	16

#define KWQ_CID 		24
#define KCQ_CID 		25

/*
 *	krnlq_context definition
 */
#define L5_KRNLQ_FLAGS	0x00000000
#define L5_KRNLQ_SIZE	0x00000000
#define L5_KRNLQ_TYPE	0x00000000
#define KRNLQ_FLAGS_PG_SZ					(0xf<<0)
#define KRNLQ_FLAGS_PG_SZ_256					(0<<0)
#define KRNLQ_FLAGS_PG_SZ_512					(1<<0)
#define KRNLQ_FLAGS_PG_SZ_1K					(2<<0)
#define KRNLQ_FLAGS_PG_SZ_2K					(3<<0)
#define KRNLQ_FLAGS_PG_SZ_4K					(4<<0)
#define KRNLQ_FLAGS_PG_SZ_8K					(5<<0)
#define KRNLQ_FLAGS_PG_SZ_16K					(6<<0)
#define KRNLQ_FLAGS_PG_SZ_32K					(7<<0)
#define KRNLQ_FLAGS_PG_SZ_64K					(8<<0)
#define KRNLQ_FLAGS_PG_SZ_128K					(9<<0)
#define KRNLQ_FLAGS_PG_SZ_256K					(10<<0)
#define KRNLQ_FLAGS_PG_SZ_512K					(11<<0)
#define KRNLQ_FLAGS_PG_SZ_1M					(12<<0)
#define KRNLQ_FLAGS_PG_SZ_2M					(13<<0)
#define KRNLQ_FLAGS_QE_SELF_SEQ					(1<<15)
#define KRNLQ_SIZE_TYPE_SIZE	((((0x28 + 0x1f) & ~0x1f) / 0x20) << 16)
#define KRNLQ_TYPE_TYPE						(0xf<<28)
#define KRNLQ_TYPE_TYPE_EMPTY					(0<<28)
#define KRNLQ_TYPE_TYPE_KRNLQ					(6<<28)

#define L5_KRNLQ_HOST_QIDX		0x00000004
#define L5_KRNLQ_HOST_FW_QIDX		0x00000008
#define L5_KRNLQ_NX_QE_SELF_SEQ 	0x0000000c
#define L5_KRNLQ_QE_SELF_SEQ_MAX	0x0000000c
#define L5_KRNLQ_NX_QE_HADDR_HI 	0x00000010
#define L5_KRNLQ_NX_QE_HADDR_LO 	0x00000014
#define L5_KRNLQ_PGTBL_PGIDX		0x00000018
#define L5_KRNLQ_NX_PG_QIDX 		0x00000018
#define L5_KRNLQ_PGTBL_NPAGES		0x0000001c
#define L5_KRNLQ_QIDX_INCR		0x0000001c
#define L5_KRNLQ_PGTBL_HADDR_HI 	0x00000020
#define L5_KRNLQ_PGTBL_HADDR_LO 	0x00000024

#define BNX2_PG_CTX_MAP			0x1a0034
#define BNX2_ISCSI_CTX_MAP		0x1a0074

#define MAX_CM_SK_TBL_SZ	256
#define MAX_COMPLETED_KCQE	64

#define MAX_ISCSI_TBL_SZ	256

#define CNIC_LOCAL_PORT_MIN	60000
#define CNIC_LOCAL_PORT_MAX	61024
#define CNIC_LOCAL_PORT_RANGE	(CNIC_LOCAL_PORT_MAX - CNIC_LOCAL_PORT_MIN)

#define KWQE_CNT (BNX2_PAGE_SIZE / sizeof(struct kwqe))
#define KCQE_CNT (BNX2_PAGE_SIZE / sizeof(struct kcqe))
#define MAX_KWQE_CNT (KWQE_CNT - 1)
#define MAX_KCQE_CNT (KCQE_CNT - 1)

#define MAX_KWQ_IDX	((KWQ_PAGE_CNT * KWQE_CNT) - 1)
#define MAX_KCQ_IDX	((KCQ_PAGE_CNT * KCQE_CNT) - 1)

#define KWQ_PG(x) (((x) & ~MAX_KWQE_CNT) >> (BNX2_PAGE_BITS - 5))
#define KWQ_IDX(x) ((x) & MAX_KWQE_CNT)

#define KCQ_PG(x) (((x) & ~MAX_KCQE_CNT) >> (BNX2_PAGE_BITS - 5))
#define KCQ_IDX(x) ((x) & MAX_KCQE_CNT)

#define BNX2X_NEXT_KCQE(x) (((x) & (MAX_KCQE_CNT - 1)) ==		\
		(MAX_KCQE_CNT - 1)) ?					\
		(x) + 2 : (x) + 1

#define BNX2X_KWQ_DATA_PG(cp, x) ((x) / (cp)->kwq_16_data_pp)
#define BNX2X_KWQ_DATA_IDX(cp, x) ((x) % (cp)->kwq_16_data_pp)
#define BNX2X_KWQ_DATA(cp, x)						\
	&(cp)->kwq_16_data[BNX2X_KWQ_DATA_PG(cp, x)][BNX2X_KWQ_DATA_IDX(cp, x)]

#define DEF_IPID_START		0x8000

#define DEF_KA_TIMEOUT		10000
#define DEF_KA_INTERVAL		300000
#define DEF_KA_MAX_PROBE_COUNT	3
#define DEF_TOS			0
#define DEF_TTL			0xfe
#define DEF_SND_SEQ_SCALE	0
#define DEF_RCV_BUF		0xffff
#define DEF_SND_BUF		0xffff
#define DEF_SEED		0
#define DEF_MAX_RT_TIME		500
#define DEF_MAX_DA_COUNT	2
#define DEF_SWS_TIMER		1000
#define DEF_MAX_CWND		0xffff

#define CNIC_ISCSI_OOO_SUPPORT		(1)

#define MAX_IOOO_BLOCK_SUPPORTED	(256)
#define MAX_OOO_RX_DESC_CNT		(BNX2_RX_DESC_CNT * 4)
#define MAX_OOO_TX_DESC_CNT		(BNX2_RX_DESC_CNT * 4)
#define MAX_BNX2_OOO_RX_DESC_CNT	(BNX2_RX_DESC_CNT * 2)
#define MAX_BNX2_OOO_TX_DESC_CNT	(BNX2_RX_DESC_CNT * 2)

#define MAX_RX_OOO_RING			(10)
#define MAX_TX_OOO_RING			(10)

#define BNX2_RXP_SCRATCH_OOO_RX_CID	(BNX2_RXP_SCRATCH + 0x31e0)
#define BNX2_RXP_SCRATCH_OOO_FLAGS	(BNX2_RXP_SCRATCH + 0x31e4)

#define RX_CATCHUP_CID			(RX_CID + 1)
#define TX_CATCHUP_CID			(TX_CID + 2)
#define BNX2_IOOO_FLAGS_ENABLE		(1<<0)
#define BNX2_IOOO_FLAGS_OVERRIDE	(1<<31)

#define TX_OOO_EST_NBD			8

#if (CNIC_ISCSI_OOO_SUPPORT)
/* packet descriptor for 1g, 10g uses skb  */
struct iooo_pkt_desc {
	struct list_head	list;
	u32			pkt_len;
	void			*buf;
	dma_addr_t		mapping;
	struct sk_buff		*skb;	/* 10g */
};

struct iooo_block {
	struct list_head	list;
	u32			id;
	u32			pkt_cnt;
	struct iooo_pkt_desc	pd_head;
};

struct bnx2_ooo_fhdr {
	u8			drop_blk_idx;
	u8			drop_size;
	u8			opcode;
	u8			blk_idx;
	u32			icid;
	u16			vlan_tag;
	u16			pkt_len;
	u16			tcp_udp_xsum;
	u16			ip_xsum;
};

struct bnx2x_ooo_fhdr {
	u8			qidx;
	u8			pl_offset;
	u8			status;
	u8			error;
	u32			rss_hash;
	u16			pkt_len;
	u16			vlan;
	u16			flags;
	u16			bd_len;
	u32			cid;
	u8			blk_idx;
	u8			opcode;
	u8			drop_size;
	u8			drop_blk_idx;
};

struct iooo_tx_ring_info {
	u32			tx_prod_bseq;
	u16			tx_prod;
	u32			tx_desc_cnt;
	u32			tx_desc_cnt_max;

	u16			*tx_cons_idx_ptr;
	u32			tx_cid_addr;
	u32			tx_bidx_addr;
	u32			tx_bseq_addr;
	u32			tx_buf_size;
	u32			tx_max_ring;
	struct iooo_pkt_desc	tx_pend_pd_head;
	u32			tx_pend_pd_cnt;
	u32			tx_total_pkt_sent;

	struct bnx2_tx_bd	*tx_desc_ring[MAX_TX_OOO_RING];
	struct iooo_pkt_desc	*tx_pkt_desc[MAX_OOO_TX_DESC_CNT];

	u16			tx_cons;
	u16			hw_tx_cons;

	dma_addr_t		tx_desc_mapping[MAX_TX_OOO_RING];
};

struct iooo_rx_ring_info {
	u32			rx_prod_bseq;
	u16			rx_prod;
	u16			rx_cons;

	u16			*rx_cons_idx_ptr;
	u32			rx_cid_addr;
	u32			rx_bidx_addr;
	u32			rx_bseq_addr;

	u32			rx_max_ring;

	u32			rx_desc_cnt;
	u32			rx_desc_cnt_max;
	u32			rx_buf_size;

	struct iooo_pkt_desc	*rx_pkt_desc[MAX_OOO_RX_DESC_CNT];
	struct bnx2_rx_bd	*rx_desc_ring[MAX_RX_OOO_RING];

	dma_addr_t		rx_desc_mapping[MAX_RX_OOO_RING];
};

struct iooo_hsi {
	u32			iscsi_cid;
	u8			blk_idx;
	u8			opcode;
	u8			drop_size;
	u8			drop_blk_idx;
};

struct iooo_hsi_bnx2x {
	u32			iscsi_cid;
	u8			drop_blk_idx;
	u8			drop_size;
	u8			opcode;
	u8			blk_idx;
};

struct iooo_mgmt {
	unsigned long		flags;
	/* Control flags */
#define IOOO_RESC_AVAIL		(0)
#define IOOO_START		(1)
	/* Runtime flags */
#define IOOO_BLK_FULL		(10)
#define IOOO_BLK_EMPTY		(11)
	/* - 1G specifics */
#define IOOO_START_HANDLER	(12)
#define IOOO_START_TX_FREE	(13)
	u16			blk_cons;
	u16			blk_prod;
	u16			blk_alloc[MAX_IOOO_BLOCK_SUPPORTED];
	struct iooo_block	blk[MAX_IOOO_BLOCK_SUPPORTED];

	struct iooo_hsi		hsi;
	struct iooo_rx_ring_info rxr;
	struct iooo_tx_ring_info txr;
	u32			pkt_buf_size;
};

#endif

struct cnic_ctx {
	u32		cid;
	void		*ctx;
	dma_addr_t	mapping;
};

#define BNX2_MAX_CID		0x2000

struct cnic_dma {
	int		num_pages;
	void		**pg_arr;
	dma_addr_t	*pg_map_arr;
	int		pgtbl_size;
	u32		*pgtbl;
	dma_addr_t	pgtbl_map;
};

struct cnic_id_tbl {
	spinlock_t	lock;
	u32		start;
	u32		max;
	u32		next;
	unsigned long	*table;
};

#define CNIC_KWQ16_DATA_SIZE	128

struct kwqe_16_data {
	u8	data[CNIC_KWQ16_DATA_SIZE];
};

struct cnic_iscsi {
	struct cnic_dma		task_array_info;
	struct cnic_dma		r2tq_info;
	struct cnic_dma		hq_info;
#if (CNIC_ISCSI_OOO_SUPPORT)
	struct iooo_block	pen;
	u32			blk_cnt;
#endif
};

struct cnic_context {
	u32			cid;
	struct kwqe_16_data	*kwqe_data;
	dma_addr_t		kwqe_data_mapping;
	wait_queue_head_t	waitq;
	int			wait_cond;
	unsigned long		timestamp;
	unsigned long		ctx_flags;
#define	CTX_FL_OFFLD_START	0
#define	CTX_FL_DELETE_WAIT	1
#define	CTX_FL_CID_ERROR	2
	u8			ulp_proto_id;
	union {
		struct cnic_iscsi	*iscsi;
	} proto;
};

struct kcq_info {
	struct cnic_dma	dma;
	struct kcqe	**kcq;

	u16		*hw_prod_idx_ptr;
	u16		sw_prod_idx;
	u16		*status_idx_ptr;
	u32		io_addr;

	u16		(*next_idx)(u16);
	u16		(*hw_idx)(u16);
};

struct l5cm_spe;

struct cnic_uio_dev {
	struct uio_info		cnic_uinfo;
	u32			uio_dev;

	int			l2_ring_size;
	void			*l2_ring;
	dma_addr_t		l2_ring_map;

	int			l2_buf_size;
	void			*l2_buf;
	dma_addr_t		l2_buf_map;

	struct cnic_dev		*dev;
	struct pci_dev		*pdev;
	struct list_head	list;
};

struct cnic_local {

	spinlock_t cnic_ulp_lock;
	void *ulp_handle[MAX_CNIC_ULP_TYPE];
	unsigned long ulp_flags[MAX_CNIC_ULP_TYPE];
#define ULP_F_INIT	0
#define ULP_F_START	1
#define ULP_F_CALL_PENDING	2
	struct cnic_ulp_ops __rcu *ulp_ops[MAX_CNIC_ULP_TYPE];

	unsigned long cnic_local_flags;
#define	CNIC_LCL_FL_KWQ_INIT		0x0
#define	CNIC_LCL_FL_L2_WAIT		0x1
#define	CNIC_LCL_FL_RINGS_INITED	0x2
#define	CNIC_LCL_FL_STOP_ISCSI		0x4

	struct cnic_dev *dev;

	struct cnic_eth_dev *ethdev;

	struct cnic_uio_dev *udev;

	int		l2_rx_ring_size;
	int		l2_single_buf_size;

	u16		*rx_cons_ptr;
	u16		*tx_cons_ptr;
	u16		rx_cons;
	u16		tx_cons;

	struct cnic_dma		kwq_info;
	struct kwqe		**kwq;

	struct cnic_dma		kwq_16_data_info;

	u16		max_kwq_idx;

	u16		kwq_prod_idx;
	u32		kwq_io_addr;

	volatile u16	*kwq_con_idx_ptr;
	u16		kwq_con_idx;

	struct kcq_info	kcq1;
	struct kcq_info	kcq2;

	union {
		void				*gen;
		struct status_block_msix	*bnx2;
#if (NEW_BNX2X_HSI >= 60)
		struct host_hc_status_block_e1x	*bnx2x_e1x;
		struct host_hc_status_block_e2	*bnx2x_e2;
		/* index values - which counter to update */
		#define SM_RX_ID		0
		#define SM_TX_ID		1
#else
		struct host_status_block	*bnx2x;
#endif
	} status_blk;

#if (NEW_BNX2X_HSI >= 60)
	struct host_sp_status_block	*bnx2x_def_status_blk;
#else
	struct host_def_status_block	*bnx2x_def_status_blk;
#endif

	u32				status_blk_num;
	u32				bnx2x_igu_sb_id;
	u32				int_num;
	u32				last_status_idx;
	struct tasklet_struct		cnic_irq_task;

	struct kcqe	*completed_kcq[MAX_COMPLETED_KCQE];

	struct cnic_sock *csk_tbl;
	struct cnic_id_tbl	csk_port_tbl;

	struct cnic_dma	conn_buf_info;
	struct cnic_dma	gbl_buf_info;

	struct cnic_iscsi	*iscsi_tbl;
	struct cnic_context	*ctx_tbl;
	struct cnic_id_tbl	cid_tbl;
	atomic_t		iscsi_conn;
	u32			iscsi_start_cid;

	u32			fcoe_init_cid;
	u32			fcoe_start_cid;
	struct cnic_id_tbl	fcoe_cid_tbl;

	u32			max_cid_space;

	/* per connection parameters */
	int			num_iscsi_tasks;
	int			num_ccells;
	int			task_array_size;
	int			r2tq_size;
	int			hq_size;
	int			num_cqs;

	struct notifier_block cm_nb;

#ifdef DECLARE_DELAYED_WORK
	struct delayed_work	delete_task;
#else
	struct work_struct	delete_task;
#endif

	struct cnic_ctx		*ctx_arr;
	int			ctx_blks;
	int			ctx_blk_size;
	unsigned long		ctx_align;
	int			cids_per_blk;

	u32			chip_id;
	int			func;
	u32			pfid;
	u8			port_mode;

	u32			shmem_base;

#if (CNIC_ISCSI_OOO_SUPPORT)
	struct iooo_mgmt	iooo_mgmr;
#endif

	struct cnic_ops		*cnic_ops;
	int			(*start_hw)(struct cnic_dev *);
	void			(*stop_hw)(struct cnic_dev *);
	void			(*setup_pgtbl)(struct cnic_dev *,
					       struct cnic_dma *);
	int			(*alloc_resc)(struct cnic_dev *);
	void			(*free_resc)(struct cnic_dev *);
	int			(*start_cm)(struct cnic_dev *);
	void			(*stop_cm)(struct cnic_dev *);
	void			(*enable_int)(struct cnic_dev *);
	void			(*disable_int_sync)(struct cnic_dev *);
	void			(*ack_int)(struct cnic_dev *);
	void			(*arm_int)(struct cnic_dev *, u32 index);
	void			(*close_conn)(struct cnic_sock *, u32 opcode);
#if (CNIC_ISCSI_OOO_SUPPORT)
	void			(*stop_ooo_hw)(struct cnic_dev *);
#endif
};

struct bnx2x_bd_chain_next {
	u32	addr_lo;
	u32	addr_hi;
	u8	reserved[8];
};

#define ISCSI_RAMROD_CMD_ID_UPDATE_CONN		(ISCSI_KCQE_OPCODE_UPDATE_CONN)
#define ISCSI_RAMROD_CMD_ID_INIT		(ISCSI_KCQE_OPCODE_INIT)

#define CDU_REGION_NUMBER_XCM_AG 2
#define CDU_REGION_NUMBER_UCM_AG 4

#if (NEW_BNX2X_HSI == 48)
static u8 calc_crc8( u32 data, u8 crc) 
{
    u8 D[32];
    u8 NewCRC[8];
    u8 C[8];
    u8 crc_res;
    u8 i;

    /* split the data into 31 bits */
    for (i = 0; i < 32; i++) {
        D[i] = (u8)(data & 1);
        data = data >> 1;
    }

    /* split the crc into 8 bits */
    for (i = 0; i < 8; i++ ) {
        C[i] = crc & 1;
        crc = crc >> 1;
    }
    
    NewCRC[0] = D[31] ^ D[30] ^ D[28] ^ D[23] ^ D[21] ^ D[19] ^ D[18] ^ D[16] ^ D[14] ^ D[12] ^ D[8] ^ D[7] ^ D[6] ^ D[0] ^ C[4] ^ C[6] ^ C[7];
    NewCRC[1] = D[30] ^ D[29] ^ D[28] ^ D[24] ^ D[23] ^ D[22] ^ D[21] ^ D[20] ^ D[18] ^ D[17] ^ D[16] ^ D[15] ^ D[14] ^ D[13] ^ D[12] ^ D[9] ^ D[6] ^ D[1] ^ D[0] ^ C[0] ^ C[4] ^ C[5] ^ C[6];
    NewCRC[2] = D[29] ^ D[28] ^ D[25] ^ D[24] ^ D[22] ^ D[17] ^ D[15] ^ D[13] ^ D[12] ^ D[10] ^ D[8] ^ D[6] ^ D[2] ^ D[1] ^ D[0] ^ C[0] ^ C[1] ^ C[4] ^ C[5];
    NewCRC[3] = D[30] ^ D[29] ^ D[26] ^ D[25] ^ D[23] ^ D[18] ^ D[16] ^ D[14] ^ D[13] ^ D[11] ^ D[9] ^ D[7] ^ D[3] ^ D[2] ^ D[1] ^ C[1] ^ C[2] ^ C[5] ^ C[6];
    NewCRC[4] = D[31] ^ D[30] ^ D[27] ^ D[26] ^ D[24] ^ D[19] ^ D[17] ^ D[15] ^ D[14] ^ D[12] ^ D[10] ^ D[8] ^ D[4] ^ D[3] ^ D[2] ^ C[0] ^ C[2] ^ C[3] ^ C[6] ^ C[7];
    NewCRC[5] = D[31] ^ D[28] ^ D[27] ^ D[25] ^ D[20] ^ D[18] ^ D[16] ^ D[15] ^ D[13] ^ D[11] ^ D[9] ^ D[5] ^ D[4] ^ D[3] ^ C[1] ^ C[3] ^ C[4] ^ C[7];
    NewCRC[6] = D[29] ^ D[28] ^ D[26] ^ D[21] ^ D[19] ^ D[17] ^ D[16] ^ D[14] ^ D[12] ^ D[10] ^ D[6] ^ D[5] ^ D[4] ^ C[2] ^ C[4] ^ C[5];
    NewCRC[7] = D[30] ^ D[29] ^ D[27] ^ D[22] ^ D[20] ^ D[18] ^ D[17] ^ D[15] ^ D[13] ^ D[11] ^ D[7] ^ D[6] ^ D[5] ^ C[3] ^ C[5] ^ C[6];

    crc_res = 0;
    for (i = 0; i < 8; i++) {
        crc_res |= (NewCRC[i] << i);
    }
    
    return crc_res;
}
#endif

#define CDU_VALID_DATA(_cid, _region, _type)	\
	(((_cid) << 8) | (((_region)&0xf)<<4) | (((_type)&0xf)))

#define CDU_CRC8(_cid, _region, _type)	\
	(calc_crc8(CDU_VALID_DATA(_cid, _region, _type), 0xff))

#define CDU_RSRVD_VALUE_TYPE_A(_cid, _region, _type)	\
	(0x80 | ((CDU_CRC8(_cid, _region, _type)) & 0x7f))

#if (NEW_BNX2X_HSI < 60)
/* iSCSI client IDs are 17, 19, 21, 23 */
#define BNX2X_ISCSI_BASE_CL_ID		17
#define BNX2X_ISCSI_CL_ID(vn)		(BNX2X_ISCSI_BASE_CL_ID + ((vn) << 1))

#define BNX2X_ISCSI_L2_CID		17
#endif

#define BNX2X_ISCSI_START_CID		18
#define BNX2X_ISCSI_NUM_CONNECTIONS	128
#define BNX2X_ISCSI_TASK_CONTEXT_SIZE	128
#define BNX2X_ISCSI_CONTEXT_MEM_SIZE	1024
#define BNX2X_ISCSI_MAX_PENDING_R2TS	4
#define BNX2X_ISCSI_R2TQE_SIZE		8
#define BNX2X_ISCSI_HQ_BD_SIZE		64
#define BNX2X_ISCSI_CONN_BUF_SIZE	64
#define BNX2X_ISCSI_GLB_BUF_SIZE	64
#define BNX2X_ISCSI_PBL_NOT_CACHED	0xff
#define BNX2X_ISCSI_PDU_HEADER_NOT_CACHED	0xff

#define BNX2X_FCOE_NUM_CONNECTIONS	1024

#define BNX2X_FCOE_L5_CID_BASE		MAX_ISCSI_TBL_SZ

#define BNX2X_CONTEXT_MEM_SIZE		1024

#define BNX2X_CHIP_NUM_57710		0x164e
#define BNX2X_CHIP_NUM_57711		0x164f
#define BNX2X_CHIP_NUM_57711E		0x1650
#define BNX2X_CHIP_NUM_57712		0x1662
#define BNX2X_CHIP_NUM_57712E		0x1663
#define BNX2X_CHIP_NUM_57713		0x1651
#define BNX2X_CHIP_NUM_57713E		0x1652
#define BNX2X_CHIP_NUM_57800		0x168a
#define BNX2X_CHIP_NUM_57810		0x168e
#define BNX2X_CHIP_NUM_57840		0x168d

#define BNX2X_CHIP_NUM(x)		(x >> 16)
#define BNX2X_CHIP_IS_57710(x)		\
	(BNX2X_CHIP_NUM(x) == BNX2X_CHIP_NUM_57710)
#define BNX2X_CHIP_IS_57711(x)		\
	(BNX2X_CHIP_NUM(x) == BNX2X_CHIP_NUM_57711)
#define BNX2X_CHIP_IS_57711E(x)		\
	(BNX2X_CHIP_NUM(x) == BNX2X_CHIP_NUM_57711E)
#define BNX2X_CHIP_IS_E1H(x)		\
	(BNX2X_CHIP_IS_57711(x) || BNX2X_CHIP_IS_57711E(x))
#define BNX2X_CHIP_IS_57712(x)		\
	(BNX2X_CHIP_NUM(x) == BNX2X_CHIP_NUM_57712)
#define BNX2X_CHIP_IS_57712E(x)		\
	(BNX2X_CHIP_NUM(x) == BNX2X_CHIP_NUM_57712E)
#define BNX2X_CHIP_IS_57713(x)		\
	(BNX2X_CHIP_NUM(x) == BNX2X_CHIP_NUM_57713)
#define BNX2X_CHIP_IS_57713E(x)		\
	(BNX2X_CHIP_NUM(x) == BNX2X_CHIP_NUM_57713E)
#define BNX2X_CHIP_IS_57800(x)		\
	(BNX2X_CHIP_NUM(x) == BNX2X_CHIP_NUM_57800)
#define BNX2X_CHIP_IS_57810(x)		\
	(BNX2X_CHIP_NUM(x) == BNX2X_CHIP_NUM_57810)
#define BNX2X_CHIP_IS_57840(x)		\
	(BNX2X_CHIP_NUM(x) == BNX2X_CHIP_NUM_57840)
#define BNX2X_CHIP_IS_E2(x)			\
	(BNX2X_CHIP_IS_57712(x) || BNX2X_CHIP_IS_57712E(x) || \
	 BNX2X_CHIP_IS_57713(x) || BNX2X_CHIP_IS_57713E(x))
#define BNX2X_CHIP_IS_E3(x)			\
	(BNX2X_CHIP_IS_57800(x) || BNX2X_CHIP_IS_57810(x) || \
	 BNX2X_CHIP_IS_57840(x))
#define BNX2X_CHIP_IS_E2_PLUS(x) (BNX2X_CHIP_IS_E2(x) || BNX2X_CHIP_IS_E3(x))

#define BNX2X_RX_DESC_CNT		(BNX2_PAGE_SIZE / sizeof(struct eth_rx_bd))
#define BNX2X_MAX_RX_DESC_CNT		(BNX2X_RX_DESC_CNT - 2)
#define BNX2X_RCQ_DESC_CNT		(BNX2_PAGE_SIZE / sizeof(union eth_rx_cqe))
#define BNX2X_MAX_RCQ_DESC_CNT		(BNX2X_RCQ_DESC_CNT - 1)

#define BNX2X_NEXT_RCQE(x) (((x) & BNX2X_MAX_RCQ_DESC_CNT) ==		\
		(BNX2X_MAX_RCQ_DESC_CNT - 1)) ?				\
		(x) + 2 : (x) + 1

#if (NEW_BNX2X_HSI >= 60)
#define BNX2X_DEF_SB_ID			HC_SP_SB_ID
#else
#define BNX2X_DEF_SB_ID			16
#endif

#if (NEW_BNX2X_HSI < 60)
#define BNX2X_ISCSI_RX_SB_INDEX_NUM					\
		((HC_INDEX_DEF_U_ETH_ISCSI_RX_CQ_CONS << \
		  USTORM_ETH_ST_CONTEXT_CONFIG_CQE_SB_INDEX_NUMBER_SHIFT) & \
		 USTORM_ETH_ST_CONTEXT_CONFIG_CQE_SB_INDEX_NUMBER)
#endif

#define BNX2X_SHMEM_MF_BLK_OFFSET	0x7e4

#define BNX2X_SHMEM_ADDR(base, field)	(base + \
					 offsetof(struct shmem_region, field))

#define BNX2X_SHMEM2_ADDR(base, field)	(base + \
					 offsetof(struct shmem2_region, field))

#define BNX2X_SHMEM2_HAS(base, field)				\
		((base) &&		 			\
		 (CNIC_RD(dev, BNX2X_SHMEM2_ADDR(base, size)) >	\
		  offsetof(struct shmem2_region, field)))

#define BNX2X_MF_CFG_ADDR(base, field)				\
			((base) + offsetof(struct mf_cfg, field))

#ifndef ETH_MAX_RX_CLIENTS_E2
#define ETH_MAX_RX_CLIENTS_E2 		ETH_MAX_RX_CLIENTS_E1H
#endif

#if (NEW_BNX2X_HSI >= 60)
#define CNIC_PORT(cp)			((cp)->pfid & 1)
#else
#define CNIC_PORT(cp)			((cp)->func % PORT_MAX)
#endif

#define CNIC_FUNC(cp)			((cp)->func)
#define CNIC_PATH(cp)			(!BNX2X_CHIP_IS_E2_PLUS(cp->chip_id) ? \
					 0 : (CNIC_FUNC(cp) & 1))
#define CNIC_E1HVN(cp)			((cp)->pfid >> 1)

#define BNX2X_HW_CID(cp, x)		((CNIC_PORT(cp) << 23) | \
					 (CNIC_E1HVN(cp) << 17) | (x))

#define BNX2X_SW_CID(x)			((x) & 0x1ffff)

#define BNX2X_CL_QZONE_ID(cp, cli)					\
		(BNX2X_CHIP_IS_E2_PLUS(cp->chip_id) ? cli :		\
		 cli + (CNIC_PORT(cp) * ETH_MAX_RX_CLIENTS_E1H))

#ifndef MAX_STAT_COUNTER_ID
#define MAX_STAT_COUNTER_ID						\
	(BNX2X_CHIP_IS_E1H((cp)->chip_id) ? MAX_STAT_COUNTER_ID_E1H :	\
	 ((BNX2X_CHIP_IS_E2_PLUS((cp)->chip_id)) ? MAX_STAT_COUNTER_ID_E2 :\
	  MAX_STAT_COUNTER_ID_E1))
#endif

#define CNIC_SUPPORTS_FCOE(cp)					\
	(BNX2X_CHIP_IS_E2_PLUS((cp)->chip_id) &&		\
	 !((cp)->ethdev->drv_state & CNIC_DRV_STATE_NO_FCOE))

#define TCP_TSTORM_OOO_MASK			(3<<4)
#if (NEW_BNX2X_HSI == 60)
#define TCP_TSTORM_OOO_DROP_AND_PROC_ACK	(0<<4)
#define TCP_TSTORM_OOO_SEND_PURE_ACK		(1<<4)
#define TCP_TSTORM_OOO_SUPPORTED		(2<<4)
#endif

#define CNIC_RAMROD_TMO				(HZ / 4)
#endif

