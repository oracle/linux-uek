/* cnic_if.h: Broadcom CNIC core network driver.
 *
 * Copyright (c) 2006 - 2012 Broadcom Corporation
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation.
 *
 */


#ifndef CNIC_IF_H
#define CNIC_IF_H

#include "bnx2x/bnx2x_mfw_req.h"

#define CNIC_MODULE_VERSION	"2.5.12e"
#define CNIC_MODULE_RELDATE	"Aug 22, 2012"

#define CNIC_ULP_RDMA		0
#define CNIC_ULP_ISCSI		1
#define CNIC_ULP_FCOE		2
#define CNIC_ULP_L4		3
#define MAX_CNIC_ULP_TYPE_EXT	3
#define MAX_CNIC_ULP_TYPE	4

#ifndef VLAN_TAG_PRESENT
#define VLAN_TAG_PRESENT	0x1000
#endif

struct kwqe {
	u32 kwqe_op_flag;

#define KWQE_QID_SHIFT		8
#define KWQE_OPCODE_MASK	0x00ff0000
#define KWQE_OPCODE_SHIFT	16
#define KWQE_OPCODE(x)		((x & KWQE_OPCODE_MASK) >> KWQE_OPCODE_SHIFT)
#define KWQE_LAYER_MASK			0x70000000
#define KWQE_LAYER_SHIFT		28
#define KWQE_FLAGS_LAYER_MASK_L2	(2<<28)
#define KWQE_FLAGS_LAYER_MASK_L3	(3<<28)
#define KWQE_FLAGS_LAYER_MASK_L4	(4<<28)
#define KWQE_FLAGS_LAYER_MASK_L5_RDMA	(5<<28)
#define KWQE_FLAGS_LAYER_MASK_L5_ISCSI	(6<<28)
#define KWQE_FLAGS_LAYER_MASK_L5_FCOE	(7<<28)

	u32 kwqe_info0;
	u32 kwqe_info1;
	u32 kwqe_info2;
	u32 kwqe_info3;
	u32 kwqe_info4;
	u32 kwqe_info5;
	u32 kwqe_info6;
};

struct kwqe_16 {
	u32 kwqe_info0;
	u32 kwqe_info1;
	u32 kwqe_info2;
	u32 kwqe_info3;
};

struct kcqe {
	u32 kcqe_info0;
	u32 kcqe_info1;
	u32 kcqe_info2;
	u32 kcqe_info3;
	u32 kcqe_info4;
	u32 kcqe_info5;
	u32 kcqe_info6;
	u32 kcqe_op_flag;
		#define KCQE_RAMROD_COMPLETION		(0x1<<27) /* Everest */
		#define KCQE_FLAGS_LAYER_MASK		(0x7<<28)
		#define KCQE_FLAGS_LAYER_MASK_MISC	(0<<28)
		#define KCQE_FLAGS_LAYER_MASK_L2	(2<<28)
		#define KCQE_FLAGS_LAYER_MASK_L3	(3<<28)
		#define KCQE_FLAGS_LAYER_MASK_L4	(4<<28)
		#define KCQE_FLAGS_LAYER_MASK_L5_RDMA	(5<<28)
		#define KCQE_FLAGS_LAYER_MASK_L5_ISCSI	(6<<28)
		#define KCQE_FLAGS_LAYER_MASK_L5_FCOE	(7<<28)
		#define KCQE_FLAGS_NEXT 		(1<<31)
		#define KCQE_FLAGS_OPCODE_MASK		(0xff<<16)
		#define KCQE_FLAGS_OPCODE_SHIFT		(16)
		#define KCQE_OPCODE(op)			\
		(((op) & KCQE_FLAGS_OPCODE_MASK) >> KCQE_FLAGS_OPCODE_SHIFT)
};

#define MAX_CNIC_CTL_DATA	64
#define MAX_DRV_CTL_DATA	64

#define CNIC_CTL_STOP_CMD			1
#define CNIC_CTL_START_CMD			2
#define CNIC_CTL_COMPLETION_CMD			3
#define CNIC_CTL_STOP_ISCSI_CMD			4
#define CNIC_CTL_FCOE_STATS_GET_CMD		5
#define CNIC_CTL_ISCSI_STATS_GET_CMD		6

#define DRV_CTL_IO_WR_CMD		0x101
#define DRV_CTL_IO_RD_CMD		0x102
#define DRV_CTL_CTX_WR_CMD		0x103
#define DRV_CTL_CTXTBL_WR_CMD		0x104
#define DRV_CTL_RET_L5_SPQ_CREDIT_CMD	0x105
#define DRV_CTL_START_L2_CMD		0x106
#define DRV_CTL_STOP_L2_CMD		0x107
#define DRV_CTL_GET_OOO_CQE		0x108
#define DRV_CTL_SEND_OOO_PKT		0x109
#define DRV_CTL_COMP_OOO_TX_PKTS	0x10a
#define DRV_CTL_REUSE_OOO_PKT		0x10b
#define DRV_CTL_RET_L2_SPQ_CREDIT_CMD	0x10c
#define DRV_CTL_ISCSI_STOPPED_CMD	0x10d
#define DRV_CTL_ULP_REGISTER_CMD	0x10e
#define DRV_CTL_ULP_UNREGISTER_CMD	0x10f
#if defined(__VMKLNX__)
#define DRV_CTL_START_NPAR_CMD		0x110
#define DRV_CTL_STOP_NPAR_CMD		0x111
#endif

struct cnic_ctl_completion {
	u32	cid;
	u8	opcode;
	u8	error;
};

struct drv_ctl_spq_credit {
	u32	credit_count;
};

struct cnic_ctl_info {
	int	cmd;
	union {
		struct cnic_ctl_completion comp;
		char bytes[MAX_CNIC_CTL_DATA];
	} data;
};

struct drv_ctl_io {
	u32		cid_addr;
	u32		offset;
	u32		data;
	dma_addr_t	dma_addr;
};

struct drv_ctl_l2_ring {
	u32		client_id;
	u32		cid;
};

enum {
	OOO_BD_CQE,
	OOO_RAMROD_CQE
};

enum {
	OOO_OPCODE_ADD_PEN,
	OOO_OPCODE_ADD_NEW,
	OOO_OPCODE_ADD_RIGHT,
	OOO_OPCODE_ADD_LEFT,
	OOO_OPCODE_JOIN,
	OOO_OPCODE_NOP
};

struct cnic_ooo_cqe {
	u32 cqe_type; /* OOO_BD_CQE or OOO_RAMROD_CQE */
	union {
		struct {
                        u32		raw_data[4]; /* iSCSI CQE data */
			struct sk_buff 	*pkt_desc;
		} cqe;

		struct {
			struct {
				__le32	lo;
				__le32	hi;
			} data;
		} ramrod_data;
	} u;
};


struct drv_ctl_ooo_cqe {
	struct cnic_ooo_cqe *cqe;
};

struct drv_ctl_send_ooo_pkt {
	struct sk_buff *skb;
};

struct drv_ctl_ooo_pkt {
	struct sk_buff *skb;
};

struct drv_ctl_register_data {
	int ulp_type;
	struct fcoe_capabilities fcoe_features;
};

struct drv_ctl_info {
	int	cmd;
	union {
		struct drv_ctl_spq_credit credit;
		struct drv_ctl_io io;
		struct drv_ctl_l2_ring ring;
		int ulp_type;
		struct drv_ctl_register_data register_data;
		char bytes[MAX_DRV_CTL_DATA];
		struct drv_ctl_ooo_cqe ooo_cqe;
		struct drv_ctl_ooo_pkt pkt_desc;
	} data;
};

struct cnic_ops {
	struct module	*cnic_owner;
	/* Calls to these functions are protected by RCU.  When
	 * unregistering, we wait for any calls to complete before
	 * continuing.
	 */
	int		(*cnic_handler)(void *, void *);
	int		(*cnic_ctl)(void *, struct cnic_ctl_info *);
};

#define MAX_CNIC_VEC	8

struct cnic_irq {
	unsigned int	vector;
	void		*status_blk;
	u32		status_blk_num;
	u32		status_blk_num2;
	u32		irq_flags;
#define CNIC_IRQ_FL_MSIX		0x00000001
};

struct cnic_eth_dev {
	u32		version;
#define CNIC_ETH_DEV_VER 0x12340008 /* Change this when the structure changes */

	struct module	*drv_owner;
	u32		drv_state;
#define CNIC_DRV_STATE_REGD		0x00000001
#define CNIC_DRV_STATE_USING_MSIX	0x00000002
#define CNIC_DRV_STATE_NO_ISCSI_OOO	0x00000004
#define CNIC_DRV_STATE_NO_ISCSI		0x00000008
#define CNIC_DRV_STATE_NO_FCOE		0x00000010
#define CNIC_DRV_STATE_HANDLES_IRQ	0x00000020
	u32		chip_id;
	u32		max_kwqe_pending;
	struct pci_dev	*pdev;
	void __iomem	*io_base;
#if defined(RHEL_RELEASE_CODE)
#if RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(5,5)
	void __iomem	*io_base2;
#endif
#endif

	u32		ctx_tbl_offset;
	u32		ctx_tbl_len;
	int		ctx_blk_size;
	u32		starting_cid;
	u32		max_iscsi_conn;
	u32		max_fcoe_conn;
	u32		max_rdma_conn;

	u32		fcoe_init_cid;
	u32		fcoe_wwn_port_name_hi;
	u32		fcoe_wwn_port_name_lo;
	u32		fcoe_wwn_node_name_hi;
	u32		fcoe_wwn_node_name_lo;

	u16		iscsi_l2_client_id;
	u16		iscsi_l2_cid;
	u8		iscsi_mac[ETH_ALEN];

	int		num_irq;
	struct cnic_irq	irq_arr[MAX_CNIC_VEC];
	int		(*drv_register_cnic)(struct net_device *,
					     struct cnic_ops *, void *);
	int		(*drv_unregister_cnic)(struct net_device *);
	int		(*drv_submit_kwqes_32)(struct net_device *,
					       struct kwqe *[], u32);
	int		(*drv_submit_kwqes_16)(struct net_device *,
					       struct kwqe_16 *[], u32);
	int		(*drv_ctl)(struct net_device *, struct drv_ctl_info *);
	unsigned long	reserved1[2];

#if defined(__VMKLNX__)
	u32		mf_mode;
	u32		e1hov_tag;
#if defined(BNX2X_ESX_CNA)
	struct vlan_group       **cna_vlgrp;
#endif
#endif
	union drv_info_to_mcp	*addr_drv_info_to_mcp;
};

struct cnic_sockaddr {
	union {
		struct sockaddr_in	v4;
		struct sockaddr_in6	v6;
	} local;
	union {
		struct sockaddr_in	v4;
		struct sockaddr_in6	v6;
	} remote;
};

struct cnic_sock {
	struct cnic_dev *dev;
	void	*context;
	u32	src_ip[4];
	u32	dst_ip[4];
	u16	src_port;
	u16	dst_port;
	u16	vlan_id;
	unsigned char old_ha[6];
	unsigned char ha[6];
	u32	mtu;
	u32	cid;
	u32	l5_cid;
	u32	pg_cid;
	int	ulp_type;

	u32	ka_timeout;
	u32	ka_interval;
	u8	ka_max_probe_count;
	u8	tos;
	u8	ttl;
	u8	snd_seq_scale;
	u32	rcv_buf;
	u32	snd_buf;
	u32	seed;

	unsigned long	tcp_flags;
#define SK_TCP_NO_DELAY_ACK	0x1
#define SK_TCP_KEEP_ALIVE	0x2
#define SK_TCP_NAGLE		0x4
#define SK_TCP_TIMESTAMP	0x8
#define SK_TCP_SACK		0x10
#define SK_TCP_SEG_SCALING	0x20

	unsigned long	flags;
#define SK_F_INUSE		0
#define SK_F_OFFLD_COMPLETE	1
#define SK_F_OFFLD_SCHED	2
#define SK_F_PG_OFFLD_COMPLETE	3
#define SK_F_CONNECT_START	4
#define SK_F_IPV6		5
#define SK_F_CLOSING		7
#define SK_F_HW_ERR		8

	atomic_t ref_count;
	u32 state;
	struct kwqe kwqe1;
	struct kwqe kwqe2;
	struct kwqe kwqe3;

	u32 iface_num;
};

struct cnic_dev {
	u32		version;
#define CNIC_DEV_VER 0xcdef0005 /* Change this when the structure changes */

	struct net_device	*netdev;
	struct pci_dev		*pcidev;
	void __iomem		*regview;
	struct list_head	list;

	int (*register_device)(struct cnic_dev *dev, int ulp_type,
			       void *ulp_ctx);
	int (*unregister_device)(struct cnic_dev *dev, int ulp_type);
	int (*submit_kwqes)(struct cnic_dev *dev, struct kwqe *wqes[],
				u32 num_wqes);
	int (*submit_kwqes_16)(struct cnic_dev *dev, struct kwqe_16 *wqes[],
				u32 num_wqes);

	int (*cm_create)(struct cnic_dev *, int, u32, u32, struct cnic_sock **,
			 void *, u32);
	int (*cm_destroy)(struct cnic_sock *);
	int (*cm_connect)(struct cnic_sock *, struct cnic_sockaddr *);
	int (*cm_abort)(struct cnic_sock *);
	int (*cm_close)(struct cnic_sock *);
	struct cnic_dev *(*cm_select_dev)(struct sockaddr_in *, int ulp_type);
	int (*iscsi_nl_msg_recv)(struct cnic_dev *dev, u32 msg_type,
				 char *data, u16 data_size);
	unsigned long	flags;
#define CNIC_F_CNIC_UP		1
#define CNIC_F_BNX2_CLASS	3
#define CNIC_F_BNX2X_CLASS	4
#define CNIC_F_ISCSI_OOO_ENABLE	8
	atomic_t	ref_count;
	u8		mac_addr[6];

	int		max_iscsi_conn;
	int		max_fcoe_conn;
	int		max_rdma_conn;

	union drv_info_to_mcp	*stats_addr;
	struct fcoe_capabilities	*fcoe_cap;

	void		*cnic_priv;

#if defined(__VMKLNX__)
	u64		fcoe_wwnn;
	u64		fcoe_wwpn;

	u32		pmtu_fails;
	u32		mf_mode;
	u32		e1hov_tag;

#if defined(BNX2X_ESX_CNA)
	struct vlan_group       **cna_vlgrp;
#endif
#endif
};

#define CNIC_WR(dev, off, val)		writel(val, dev->regview + off)
#define CNIC_WR16(dev, off, val)	writew(val, dev->regview + off)
#define CNIC_WR8(dev, off, val)		writeb(val, dev->regview + off)
#define CNIC_RD(dev, off)		readl(dev->regview + off)
#define CNIC_RD16(dev, off)		readw(dev->regview + off)

struct cnic_ulp_ops {
	u32		version;
#define CNIC_ULP_OPS_VER 0x57770007 /* Change this when the structure changes */

	/* Calls to these functions are protected by RCU.  When
	 * unregistering, we wait for any calls to complete before
	 * continuing.
	 */

	void (*cnic_init)(struct cnic_dev *dev);
	void (*cnic_exit)(struct cnic_dev *dev);
	void (*cnic_start)(void *ulp_ctx);
	void (*cnic_stop)(void *ulp_ctx);
	void (*indicate_kcqes)(void *ulp_ctx, struct kcqe *cqes[],
				u32 num_cqes);
	void (*indicate_netevent)(void *ulp_ctx, unsigned long event, u16 vid);
	void (*cm_connect_complete)(struct cnic_sock *);
	void (*cm_close_complete)(struct cnic_sock *);
	void (*cm_abort_complete)(struct cnic_sock *);
	void (*cm_remote_close)(struct cnic_sock *);
	void (*cm_remote_abort)(struct cnic_sock *);
	int (*iscsi_nl_send_msg)(void *ulp_ctx, u32 msg_type,
				 char *data, u16 data_size, u32 iface_num);
	int (*cnic_get_stats)(void *ulp_ctx);
	struct module *owner;
	atomic_t ref_count;
};

extern int cnic_register_driver2(int ulp_type, struct cnic_ulp_ops *ulp_ops);

extern int cnic_unregister_driver2(int ulp_type);

extern struct cnic_eth_dev *bnx2_cnic_probe2(struct net_device *dev);
extern struct cnic_eth_dev *bnx2x_cnic_probe2(struct net_device *dev);

#endif
