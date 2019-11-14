/*
 * Copyright (C) 2016 Cavium, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of version 2 of the GNU General Public License
 * as published by the Free Software Foundation.
 */

#ifndef OCTEONTX_H
#define OCTEONTX_H

#include <linux/netdevice.h>
#include <linux/ioctl.h>

#include "octeontx_mbox.h"

#define OCTTX_MAX_NODES	1 /* Maximum number of CPU devices/nodes */

#define get_gmid(x) (x)

struct octeontx_pf_vf {
	bool			in_use;
	u16			domain_id;
	u16			subdomain_id;
	u32			gmid;

	void __iomem		*reg_base;
	struct octeontx_master_com_t *master;
	void			*master_data;
};

struct octeontx_master_com_t {
	int (*send_message)(struct mbox_hdr *hdr,
			    union mbox_data *req,
			    union mbox_data *resp,
			    void *master_data,
			    void *add_data);
	int (*receive_message)(struct mbox_hdr *hdr,
			       union mbox_data *req,
			       union mbox_data *resp,
			       void *master_data,
			       void *add_data);
	int (*reset_domain)(void *master_data);
};

struct wqe_s {
	u64 work0;
	u64 *work1;
};

#define OCTTX_IOC_MAGIC	0xF2

/* THUNDERX SMC definitons */
/* X1 - gpio_num, X2 - sp, X3 - cpu, X4 - ttbr0 */
#define THUNDERX_INSTALL_GPIO_INT       0xc2000801
/* X1 - gpio_num */
#define THUNDERX_REMOVE_GPIO_INT        0xc2000802

struct intr_hand {
	u64	mask;
	char	name[50];
	u64	coffset;
	u64	soffset;
	irqreturn_t (*handler)(int, void *);
};

struct octtx_gpio_usr_data {
	u64	isr_base;
	u64	sp;
	u64	cpu;
	u64	gpio_num;
};

#define OCTTX_IOC_SET_GPIO_HANDLER \
	_IOW(OCTTX_IOC_MAGIC, 1, struct octtx_gpio_usr_data)

#define OCTTX_IOC_CLR_GPIO_HANDLER \
	_IO(OCTTX_IOC_MAGIC, 2)

enum domain_type {
	APP_NET = 0,
	HOST_NET
};

/* Port statistics */
struct octtx_port_stats {
	u64	rxpkts;
	u64	rxbytes;
	u64	rxdrop;
	u64	rxerr;
	u64	rxucast;
	u64	rxbcast;
	u64	rxmcast;
	u64	txpkts;
	u64	txbytes;
	u64	txdrop;
	u64	txerr;
	u64	txucast;
	u64	txbcast;
	u64	txmcast;
};

/* Domain network (BGX) port */
#define OCTTX_MAX_BGX_PORTS 16 /* Maximum BGX ports per System */

/* Same as in BGX_CMR_CONFIG[lmac_type] */
#define OCTTX_BGX_LMAC_TYPE_SGMII  0
#define OCTTX_BGX_LMAC_TYPE_XAUI   1
#define OCTTX_BGX_LMAC_TYPE_RXAUI  2
#define OCTTX_BGX_LMAC_TYPE_10GR   3
#define OCTTX_BGX_LMAC_TYPE_40GR   4
#define OCTTX_BGX_LMAC_TYPE_QSGMII 6

struct octtx_bgx_port {
	struct list_head list;
	struct kobject kobj;
	int	domain_id;
	int	dom_port_idx; /* Domain-local index of BGX port */
	int	glb_port_idx; /* System global index of BGX port */
	int	node; /* CPU node */
	int	bgx; /* Node-local BGX device index */
	int	lmac; /* BGX-local port/LMAC number/index */
	int	lmac_type; /* OCTTX_BGX_LMAC_TYPE_nnn */
	int	base_chan; /* Node-local base channel (PKI_CHAN_E) */
	int	num_chans;
	int	pkind; /* PKI port number */
	int	link_up; /* Last retrieved link status */
	struct octtx_port_stats stats;
	struct kobj_attribute sysfs_stats;
};

/* Domain internal (LBK) port */
#define LBK_PORT_INVAL     0xFF
/* Number of LBK1/LBK2 port */
#define LBK_PORT_PN_MAX        4
/* Number of LBK0 ports */
#define LBK_PORT_PP_MAX        BIT(4)
/* Index of LBK1/LBK2 port */
#define LBK_PORT_PN_BASE_IDX   16
/* Base port index of lbk0 port */
#define LBK_PORT_PP_BASE_IDX   0
#define LBK_PORT_PP_LOOP_BASE_IDX   56
#define LBK0_DEVICE   0
#define LBK1_DEVICE   1
#define OCTTX_MAX_LBK_PORTS    (LBK_PORT_PN_MAX + LBK_PORT_PP_MAX)

struct octtx_lbk_port {
	struct list_head list;
	struct kobject kobj;
	int	domain_id;
	int	dom_port_idx; /* Domain-local index of LBK port */
	int	glb_port_idx; /* System global index of LBK port */
	int	node; /* CPU node */
	int	ilbk; /* Node-local index of ingress LBK device */
	int	olbk; /* Node-local index of egress LBK device */
	int	ilbk_base_chan; /* Node-local base channel (PKI_CHAN_E) */
	int	ilbk_num_chans;
	int	olbk_base_chan; /* Node-local base channel (PKI_CHAN_E) */
	int	olbk_num_chans;
	int	pkind; /* PKI port number */
	void	*vnic; /* NIC port descriptor */
};

/* LBK port/peer global indexes: (8-bit peer << 8) | 8-bit port. */
#define LBK_PORT_GIDX_FULL_GEN(_i, _k) (((_i) << 4) | (_k))
#define LBK_PORT_GIDX_PRIM(_p) ((_p)->glb_port_idx & 0x1FF)
#define LBK_PORT_GIDX_ANY -1

enum octtx_coprocessor {
	OCTTX_SSO,
	OCTTX_SSOW,
	OCTTX_FPA,
	OCTTX_PKI,
	OCTTX_PKO,
	OCTTX_TIM,
	OCTTX_CPT,
	OCTTX_DPI,
	OCTTX_ZIP,
	OCTTX_COPROCESSOR_CNT
};

extern atomic64_t octtx_vf_reset[];

/* Domain internal (SDP) port */
#define OCTTX_MAX_SDP_PORTS 1 /* Maximum SDP ports per System */

struct octtx_sdp_port {
	struct list_head list;
	int	domain_id;
	int	dom_port_idx; /* Domain-local index of SDP port */
	int	glb_port_idx; /* System global index of SDP port */
	int	node; /* CPU node */
	int	sdp; /* Node-local SDP device index */
	int	lmac; /* BGX-local port/LMAC number/index */
	int	lmac_type; /* OCTTX_BGX_LMAC_TYPE_nnn */
	int	base_chan; /* Node-local base channel (PKI_CHAN_E) */
	int	num_chans;
	int	pkind; /* PKI port number */
	int	link_up; /* Last retrieved link status */
};
#endif
