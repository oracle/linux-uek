/* SPDX-License-Identifier: GPL-2.0 */
/* Marvell CNF20KA BPHY CPRI Ethernet Driver
 *
 * Copyright (C) 2025 Marvell.
 *
 */

#include <linux/cdev.h>

#define DEVICE_NAME	"cnf20k_cpri_dev"
#define DRV_NAME	"cnf20k_cpri"
#define DRV_STRING	"cnf20K_cpri_driver"

#define CHIP_ID			4
#define	PCI_CFG_REG_BAR_NUM	2

#define CNF20K_BPHY_CPRI_MAX_INTF	12

#define MAX_NUM_BPHY_CHIPLET		2
#define CPRI_ETH_PAYLOAD_SIZE_MIN	64
#define CPRI_ETH_PAYLOAD_SIZE_MAX	1536
#define CPRI_ETH_PKT_HDR_SIZE		128
#define CNF20K_BPHY_CPRI_MAX_MHAB	3
#define CNF20K_BPHY_CPRI_MAX_LMAC	2
#define MAX_CPRI_INST			5

#define RX_GP_INT_CPRI_ETH		32
#define NUM_VECTORS			4

#define MAX_NUM_HALF_BPHY_CHIPLET	1
#define CNF20K_HALF_BPHY_CPRI_MAX_MHAB	5

#define CNF20K_BPHY_CPRI_WQE_SIZE	128

#define CPRI_ETH_PKT_SIZE (CPRI_ETH_PKT_HDR_SIZE + CPRI_ETH_PAYLOAD_SIZE_MAX)

#define CNF20K_CPRI_RX_INTR_MASK(a)             ((1 << (a)))
#define CNF20K_CPRI_RX_INTR_SHIFT(a)            (1 + (a))

/* Each entry increments by cnt 0x68, 1 unit = 16 bytes */
#define CNF20K_CIRC_BUF_ENTRY(a)                ((a) / 0x68)

/* BPHY definitions */
#define PCI_DEVID_RVU_BPHY_CPRI_PF	0xA0F4

#define RVU_FUNC_BLKADDR_SHIFT          20
#define CNF20K_FUNC_BLKADDR_MASK        0xFFULL

#define BPHY_BLKADDR_MASK		0x3F

#define CPRI_REG_BASE	0x850210000000
#define CPRI_REG_SIZE	(4UL << 30)

#define ETH_ADDR_LEN      6 /**Number of octects in ethernet address*/

/* ioctl base */

#define OTX2_CPRI_IOCTL_BASE 0xCC

/* Implicit Ready notification from User space to Kernel,Kernel
 * in response returns PF_FUNC number corresponding to kernel PF driver
 * This ioctl would be first message sent from User application to
 * Kernel BPHY NDEV PF driver to obtain PF_FUNC number.
 */

#define OTX2_CPRI_IOCTL_READY_NOTIF _IOR(OTX2_CPRI_IOCTL_BASE, 0x01, uint64_t)

/* CPRI interface configurations from User space to Kernel */
#define OTX2_CPRI_IOCTL_INTF_CFG _IOW(OTX2_CPRI_IOCTL_BASE, 0x02, uint64_t)

#define OTX2_CPRI_IOCTL_LINK_EVENT  _IOW(OTX2_CPRI_IOCTL_BASE, 0x03, \
					 struct bphy_netdev_cpri_link_event)

struct cnf20k_cpri_pkt_dl_wqe_hdr {
	u64 lane_id	: 1;
	u64 reserved1	: 2;
	u64 mhab_id	: 3;
	u64 reserved2	: 2;
	u64 pkt_length	: 11;
	u64 reserved3	: 45;
	u64 w1;
};

struct cnf20k_cpri_pkt_ul_wqe_hdr {
	u64 lane_id             : 1;
	u64 reserved1           : 2;
	u64 mhab_id             : 3;
	u64 reserved2           : 2;
	u64 pkt_length          : 11;
	u64 reserved3           : 5;
	u64 fcserr              : 1;
	u64 rsp_ferr            : 1;
	u64 rsp_nferr           : 1;
	u64 reserved4           : 37;
	u64 w1;
};

/* char driver private data */
struct cnf20k_cdev_priv {
	struct device			*dev;
	struct cdev			cdev;
	dev_t				devt;
	int				is_open;
	int				irq;
	struct mutex			mutex_lock;     /* mutex */
	spinlock_t			lock;           /* irq lock */
	void __iomem			*reg_base;
	void __iomem			*cpri_reg_base;
	struct pci_dev			*pdev;
	int				odp_intf_cfg;
	int				flags;
	u8				hw_version;
#define ODP_INTF_CFG_RFOE               BIT(0)
#define ODP_INTF_CFG_CPRI               BIT(1)
};

enum cnf10k_cpri_state {
	CNF20K_CPRI_INTF_DOWN = 1,
};

struct cnf20k_cpri_stats {
	/* Rx */
	u64				rx_frames;
	u64				rx_octets;
	u64				rx_err;
	u64				bad_crc;
	u64				oversize;
	u64				undersize;
	u64				fifo_ovr;
	u64				rx_dropped;
	u64				malformed;
	u64				rx_bad_octets;
	/* Tx */
	u64				tx_frames;
	u64				tx_octets;
	u64				tx_dropped;
	/* stats lock */
	spinlock_t			lock;
};

/* cpri dl cbuf cfg */
struct cnf20k_dl_cbuf_cfg {
	int                             num_entries;
	u64                             cbuf_iova_addr;
	void __iomem                    *cbuf_virt_addr;
	/* sw */
	u64                             sw_wr_ptr;
	/* dl lock */
	spinlock_t                      lock;
};

/* cpri ul cbuf cfg */
struct cnf20k_ul_cbuf_cfg {
	int                             num_entries;
	u64                             cbuf_iova_addr;
	void __iomem                    *cbuf_virt_addr;
	/* sw */
	int                             sw_rd_ptr;
	/* ul monitoring related */
	u64                             ul_fifo_ovr_cnt;
	u64                             ul_recovery_cnt;
	bool                            flush;
	/* ul lock */
	spinlock_t                      lock;
};

/* CPRI support */
struct cnf20k_cpri_drv_ctx {
	u8                              cpri_num;
	u8                              lmac_id;
	int                             valid;
	u8				node_id;
	void                            *debugfs;
	struct net_device               *netdev;
	struct cnf20k_cpri_ndev_priv    *priv;
};

/* @struct BPHY_NETDEV_CPRI_IF_s
 * @brief Communication interface structure defnition to be used by BPHY
 *        and NETDEV applications for CPRI Interface.
 */
struct cnf20k_bphy_ndev_cpri_intf_cfg {
	u8	is_configured;    /* flag config status */
	u8	cpri_id;          /* Half capacity : 0-4,Full capacity: 0-2*/
	u8	ul_gp_int_num;    /* UL GP INT NUM */
	u8	ul_int_threshold; /* UL INT THRESHOLD */
	u8	active_lane_mask; /* Lmac Id mask mac 0 or 1 */
	u8	num_ul_buf;       /* Num UL Buffers Buffer size is 1664 */
	u8	num_dl_buf;       /* Num DL Buffers Buffer size is 1664 */
	u8	eth_addr[2][ETH_ADDR_LEN];
	/**Reserved*/
	u64	reserved[4];

};

/* hardware specific information */
struct bphy_hw_params_cnf20k {
	u32 chip_ver;	/* (version << 4) | revision */
	u32 gmid;
	u32 msix_offset[MAX_NUM_BPHY_CHIPLET];
	u32 reserved[12];       /* reserved for future extension */
};

/**
 * @struct BPHY_CPRI_NETDEV_COMM_INTF_CFG_s
 * @brief Main Communication interface structure definition to be used
 *        by BPHY and NETDEV applications for CPRI Interface.
 *
 */
struct cnf20k_bphy_cpri_netdev_comm_intf_cfg {
	/**< BPHY Hardware parameters */
	struct bphy_hw_params_cnf20k hw_params;
	u8 bphy_chiplet_mask;
	/**< CPRI Interface Configuration */
	struct cnf20k_bphy_ndev_cpri_intf_cfg
	cpri_if_cfg[MAX_NUM_BPHY_CHIPLET][MAX_CPRI_INST];
	u64 reserved[4];
};

struct cnf20k_cpri_common_cfg {
	struct cnf20k_dl_cbuf_cfg       dl_cfg;
	struct cnf20k_ul_cbuf_cfg       ul_cfg;
	u8                              refcnt;
};

/* cpri netdev priv */
struct cnf20k_cpri_ndev_priv {
	u8                              cpri_num;
	u8                              lmac_id;
	struct net_device               *netdev;
	struct pci_dev                  *pdev;
	struct cnf20k_cdev_priv		*cdev_priv;
	u32                             msg_enable;
	void __iomem                    *cpri_reg_base;
	struct iommu_domain             *iommu_domain;
	struct cnf20k_cpri_common_cfg   *cpri_common;
	struct napi_struct              napi;
	unsigned long                   state;
	struct cnf20k_cpri_stats        stats;
	u8                              mac_addr[ETH_ALEN];
	/* priv lock */
	spinlock_t                      lock;
	int                             if_type;
	u8                              link_state;
	unsigned long                   last_tx_jiffies;
	unsigned long                   last_rx_jiffies;
	unsigned long                   last_tx_dropped_jiffies;
	unsigned long                   last_rx_dropped_jiffies;
	u8				node_id;
	u8				ul_int_threshold;
};

struct bphy_netdev_cpri_link_event {
	u8	chiplet_id;
	u8	rpm_id;
	u8	lmac_id;
	u8	cpri_port_index;
	u8	link_state;
};

void cnf20k_cpri_set_ethtool_ops(struct net_device *netdev);
void cnf20k_cpri_update_stats(struct cnf20k_cpri_ndev_priv *priv);
