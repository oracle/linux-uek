// SPDX-License-Identifier: GPL-2.0
/* Marvell CNF20KA BPHY CPRI Ethernet Driver
 *
 * Copyright (C) 2025 Marvell.
 *
 */

#include <linux/module.h>
#include <linux/types.h>
#include <linux/init.h>
#include <linux/pci.h>
#include <linux/vmalloc.h>
#include <linux/pagemap.h>
#include <linux/delay.h>
#include <linux/netdevice.h>
#include <linux/interrupt.h>
#include <linux/tcp.h>
#include <linux/ipv6.h>
#include <linux/slab.h>
#include <net/checksum.h>
#include <net/ip6_checksum.h>
#include <linux/ethtool.h>
#include <linux/if_vlan.h>
#include <linux/cpu.h>
#include <linux/smp.h>
#include <linux/pm_qos.h>
#include <linux/pm_runtime.h>
#include <linux/aer.h>
#include <linux/prefetch.h>
#include <linux/suspend.h>
#include <linux/cdev.h>
#include <linux/iommu.h>
#include <linux/pci_ids.h>

#include "cnf20k_cpri.h"
#include "bphy_common.h"
#include "cnf10k_bphy_netdev_comm_if.h"
#include "cnf10k_bphy_hw.h"

/*	Theory of Operation
 *
 *      I.   General
 *
 *      The BPHY CPRI netdev driver facilitates Ethernet packet communication
 *      over CPRI MHAB interfaces. This implementation is based on a PCI driver,
 *      which is responsible for managing CPRI Ethernet UL (uplink) and DL
 *      (downlink) buffer configurations and setting up the required resources.
 *
 *      Unlike previous approaches where a user-space ODP application configured
 *      the UL/DL buffers and PSM GPINT interrupt setup via ioctl, the current
 *      driver handles all such initialization internally. This makes the system
 *      more self-contained and kernel-managed.
 *
 *      II.  Driver Operation
 *
 *      This driver registers a PCI device and sets up character devices to
 *      support optional ioctl interfaces. During initialization, it
 *      configures the Ethernet UL/DL circular buffers for each CPRI MHAB
 *      instance, sets up Rx GPINT (PSM) interrupts, and initializes the
 *      netdev instances.
 *
 *      Each netdev instance corresponds to a unique CPRI MHAB and Lane ID.
 *      The driver allocates and maps the packet memory (DDR), configures
 *      the circular buffer structures in the UL/DL direction, and sets up
 *      the GPINT configuration using CPRDX_AF_ETH_UL_INT_PSM_MSG_W0 and
 *      CPRDX_AF_ETH_UL_INT_PSM_MSG_W0 registers internally.
 *
 *      III. Transmit
 *
 *      The driver transmit routine selects the appropriate DL circular
 *      buffer ring based on the MHAB ID. If a free buffer entry is available,
 *      it populates the WQE (Work Queue Entry) header and copies the packet
 *      data into the DL buffer.It then updates the DL_WR_DOORBELL register
 *      with the number of packets written,triggering hardware processing.
 *
 *      IV.  Receive
 *
 *      The driver receives Rx notifications via PSM GPINT interrupts.
 *      Upon receiving an interrupt, it invokes the NAPI handler for the
 *      corresponding netdev.The handler reads UL_SW_RD_PTR and UL_NXT_WR_PTR
 *      from the UL circular buffer to determine the number of packets to
 *      process. For each packet, the driver allocates an skb, copies the
 *      packet data,and hands it off to the networking stack.
 *      It then updates the UL_RD_DOORBELL register with the number of
 *      packets processed.
 *
 *      V.   Miscellaneous
 *
 *      Ethtool:
 *      The driver supports ethtool statistics for each netdev instance,
 *      reporting packet counts and error stats for monitoring and
 *      diagnostics.
 *
 */

struct cnf20k_cpri_drv_ctx cnf20k_cpri_drv_ctx[CNF20K_BPHY_CPRI_MAX_INTF];
static struct class *cnf20k_cpri_class;

struct msix_entry msix_entries[4];

void __iomem *cnf20k_cpri_reg_base;

static inline u64 cnf20k_get_cpri_regaddr(u64 offset, u8 cpri_num)
{
	u64 mab_addr_did;

	switch (cpri_num) {
	case 0:
		mab_addr_did = 0x90;
		break;
	case 1:
		mab_addr_did = 0x91;
		break;
	case 2:
		mab_addr_did = 0x92;
		break;
	case 3:
		mab_addr_did = 0x93;
		break;
	case 4:
		mab_addr_did = 0x94;
		break;
	default:
		break;
	}

	offset &= ~(CNF20K_FUNC_BLKADDR_MASK << RVU_FUNC_BLKADDR_SHIFT);
	offset |= (mab_addr_did << RVU_FUNC_BLKADDR_SHIFT);
	return offset;
}

static inline u64 bphy_get_regaddr(u8 node_id, u64 offset)
{
	u64 blkaddr;

	switch (node_id) {
	case 0:
		blkaddr = 0x20;
		break;
	case 1:
		blkaddr = 0x28;
		break;
	default:
		break;
	}

	offset &= ~(BPHY_BLKADDR_MASK << RVU_FUNC_BLKADDR_SHIFT);
	offset |= (blkaddr << RVU_FUNC_BLKADDR_SHIFT);

	return offset;
}

static void cnf20k_cpri_rx_napi_schedule(int cpri_num, u32 status, int node_id)
{
	struct cnf20k_cpri_drv_ctx *drv_ctx;
	struct cnf20k_cpri_ndev_priv *priv;
	u64 offset = 0;
	u64 regval;
	int idx;

	for (idx = 0; idx < CNF20K_BPHY_CPRI_MAX_INTF; idx++) {
		drv_ctx = &cnf20k_cpri_drv_ctx[idx];
		/* ignore lmac, one UL interrupt/cpri */
		if (!(drv_ctx->valid && drv_ctx->cpri_num == cpri_num))
			continue;
		/* check if i/f down, napi disabled */
		if (!(drv_ctx->node_id == node_id))
			continue;

		priv = netdev_priv(drv_ctx->netdev);
		if (test_bit(CNF20K_CPRI_INTF_DOWN, &priv->state))
			continue;
		/* clear intr enable bit, re-enable in napi handler */
		if (node_id == 0 || node_id == 1) {
			regval = 1 << CNF20K_CPRI_RX_INTR_SHIFT(cpri_num);
			offset = PSM_CNF20K_INT_GP_ENA_W1C(1);
			offset = bphy_get_regaddr(node_id, offset);
			writeq(regval, priv->cdev_priv->reg_base + offset);
		} else {
			pr_info("node_id not matching matches\n");
		}
		/* schedule napi */
		napi_schedule(&priv->napi);
		/* napi scheduled per MHAB, return */
		return;
	}
}

static int cpri_polling_thread(void *data)
{
	while (!kthread_should_stop()) {
		for (int cpri_num = 0; cpri_num < 5; cpri_num++) {
			u64 offset =
			cnf20k_get_cpri_regaddr(0x280, cpri_num);
			u64 status = readq(cnf20k_cpri_reg_base + offset);

			if (status & BIT(0)) {
				cnf20k_cpri_rx_napi_schedule(cpri_num,
							     status, 0);
				writeq(BIT(0),
				       cnf20k_cpri_reg_base + offset);
			}
		}
		cpu_relax();
	}

	return 0;
}

void cnf20k_cpri_update_stats(struct cnf20k_cpri_ndev_priv *priv)
{
	struct cnf20k_cpri_stats *dev_stats = &priv->stats;
	u64 offset = 0;

	if (!priv) {
		pr_err("update_stats: priv is NULL\n");
		return;
	}

	offset = cnf20k_get_cpri_regaddr(offset, priv->cpri_num);

	dev_stats->rx_frames += readq(cnf20k_cpri_reg_base +
			CNF20K_CPRIX_ETH_UL_GPKTS_CNT(priv->node_id,
						      priv->lmac_id)
						      + offset);
	dev_stats->rx_octets += readq(cnf20k_cpri_reg_base +
			CNF20K_CPRIX_ETH_UL_GOCT_CNT(priv->node_id,
						     priv->lmac_id)
						     + offset);
	dev_stats->rx_err += readq(cnf20k_cpri_reg_base +
				   CNF20K_CPRIX_ETH_UL_ERR_CNT(priv->node_id,
							       priv->lmac_id)
							       + offset);
	dev_stats->bad_crc += readq(cnf20k_cpri_reg_base +
				    CNF20K_CPRIX_ETH_BAD_CRC_CNT(priv->node_id,
								 priv->lmac_id)
								 + offset);
	dev_stats->oversize += readq(cnf20k_cpri_reg_base +
				     CNF20K_CPRIX_ETH_UL_OSIZE_CNT(priv->node_id,
								   priv->lmac_id)
								   + offset);
	dev_stats->undersize += readq(cnf20k_cpri_reg_base +
				      CNF20K_CPRIX_ETH_UL_USIZE_CNT(priv->node_id,
								    priv->lmac_id)
								    + offset);
	dev_stats->fifo_ovr += readq(cnf20k_cpri_reg_base +
				     CNF20K_CPRIX_ETH_UL_FIFO_ORUN_CNT(priv->node_id,
								       priv->lmac_id)
								       + offset);
	dev_stats->malformed += readq(cnf20k_cpri_reg_base +
				      CNF20K_CPRIX_ETH_UL_MALFORMED_CNT(priv->node_id,
									priv->lmac_id)
									+ offset);
	dev_stats->rx_bad_octets += readq(cnf20k_cpri_reg_base +
					  CNF20K_CPRIX_ETH_UL_BOCT_CNT(priv->node_id,
								       priv->lmac_id)
								       + offset);
	dev_stats->tx_frames += readq(cnf20k_cpri_reg_base +
				      CNF20K_CPRIX_ETH_DL_GPKTS_CNT(priv->node_id,
								    priv->lmac_id)
								    + offset);
	dev_stats->tx_octets += readq(cnf20k_cpri_reg_base +
				      CNF20K_CPRIX_ETH_DL_GOCTETS_CNT(priv->node_id,
								      priv->lmac_id)
								      + offset);
}

static void cnf20k_cpri_get_stats64(struct net_device *netdev,
				    struct rtnl_link_stats64 *stats)
{
	struct cnf20k_cpri_ndev_priv *priv = netdev_priv(netdev);
	struct cnf20k_cpri_stats *dev_stats = &priv->stats;

	if (!priv) {
		pr_err("cnf20k_cpri_update_stats: priv is NULL\n");
		return;
	}

	cnf20k_cpri_update_stats(priv);
	stats->rx_bytes = dev_stats->rx_octets;
	stats->rx_packets = dev_stats->rx_frames;
	stats->rx_dropped = dev_stats->rx_dropped;
	stats->rx_errors = dev_stats->rx_err;
	stats->rx_crc_errors = dev_stats->bad_crc;
	stats->rx_fifo_errors = dev_stats->fifo_ovr;
	stats->rx_length_errors = dev_stats->oversize + dev_stats->undersize;
	stats->rx_frame_errors = dev_stats->malformed;
	stats->rx_errors += dev_stats->malformed;
	stats->tx_bytes = dev_stats->tx_octets;
	stats->tx_packets = dev_stats->tx_frames;
}

/* GPINT of bphy1 interrupt handler routine */
static irqreturn_t cnf20k_gpint_bphy1_intr_handler(int irq, void *dev_id)
{
	struct cnf20k_cdev_priv *cdev_priv;
	u32 status, intr_mask;
	int node_id = 1;
	u64 offset = 0;
	int cpri_num;

	cdev_priv = (struct cnf20k_cdev_priv *)dev_id;
	offset =  bphy_get_regaddr(node_id, offset);
	offset |= PSM_CNF20K_INT_GP_SUM_W1C(1);
	/* clear interrupt status */
	status = readq(cdev_priv->reg_base + offset) & 0xFFFFFFFF;
	writeq(status, cdev_priv->reg_base + offset);

	pr_debug("gpint2 status = 0x%x\n", status);

	/* cpri intr processing */
	for (cpri_num = 0; cpri_num < CNF20K_HALF_BPHY_CPRI_MAX_MHAB;
		cpri_num++) {
		intr_mask = CNF20K_CPRI_RX_INTR_MASK(cpri_num);
		if (status & intr_mask) {
			/* clear UL ETH interrupt */
			offset = CNF20K_CPRIX_ETH_UL_INT(node_id);
			offset = cnf20k_get_cpri_regaddr(offset, cpri_num);
			writeq(0x1, cnf20k_cpri_reg_base + offset);
			cnf20k_cpri_rx_napi_schedule(cpri_num, status, node_id);
		}
	}

	return IRQ_HANDLED;
}

/* GPINT of bphy0 interrupt handler routine */
static irqreturn_t cnf20k_gpint_bphy0_intr_handler(int irq, void *dev_id)
{
	struct cnf20k_cdev_priv *cdev_priv;
	u32 status, intr_mask;
	int node_id = 0;
	u64 offset = 0;
	int cpri_num;

	cdev_priv = (struct cnf20k_cdev_priv *)dev_id;

	/* clear interrupt status */
	offset = bphy_get_regaddr(node_id, offset);
	offset |= PSM_CNF20K_INT_GP_SUM_W1C(1);
	status = readq(cdev_priv->reg_base + offset) & 0xFFFFFFFF;
	writeq(status, cdev_priv->reg_base + offset);

	pr_debug("gpint2 status = 0x%x\n", status);
	/* cpri intr processing */
	for (cpri_num = 0; cpri_num < CNF20K_HALF_BPHY_CPRI_MAX_MHAB;
		cpri_num++) {
		intr_mask = CNF20K_CPRI_RX_INTR_MASK(cpri_num);
		if (status & intr_mask) {
			/* clear UL ETH interrupt */
			offset = CNF20K_CPRIX_ETH_UL_INT(node_id);
			offset = cnf20k_get_cpri_regaddr(offset, cpri_num);
			writeq(0x1, cnf20k_cpri_reg_base + offset);
			cnf20k_cpri_rx_napi_schedule(cpri_num, status, node_id);
		}
	}

	return IRQ_HANDLED;
}

static void cnf20k_cpri_dl_reg_cfg2(u8 cpri_num, dma_addr_t dma_buffer_handle,
				    u8 node_id)
{
	u64 value_cfg2 = 0;
	u64 offset = 0;

	value_cfg2 |= ((u64)1 << 63);
	value_cfg2 |= ((u64)(node_id) << 62);
	value_cfg2 |= ((u64)0x0 << 60);
	value_cfg2 |= ((u64)0x0 << 59);
	value_cfg2 |= ((u64)0x0 << 56);
	value_cfg2 |= ((u64)0x7 << 53);

	dma_buffer_handle &= ~0xFF;
	value_cfg2 |= (dma_buffer_handle & 0x1fffffffffffff);

	offset = CNF20K_CPRIX_TXD_GMII_DL_CBUF_CFG2(node_id);

	offset = cnf20k_get_cpri_regaddr(offset, cpri_num);
	writeq(value_cfg2, cnf20k_cpri_reg_base + offset);
}

static void cnf20k_cpri_ul_reg_cfg2(u8 cpri_num, dma_addr_t dma_buffer_handle,
				    u8 node_id)
{
	u64 value_cfg2 = 0;
	u64 offset = 0;

	value_cfg2 |= ((u64)1 << 63);
	value_cfg2 |= ((u64)(node_id) << 62);
	value_cfg2 |= ((u64)0x0 << 60);
	value_cfg2 |= ((u64)0x0 << 59);
	value_cfg2 |= ((u64)0x0 << 56);
	value_cfg2 |= ((u64)0x7 << 53);

	dma_buffer_handle &= ~0xFF;
	value_cfg2 |= (dma_buffer_handle & 0x1fffffffffffff);

	offset = CNF20K_CPRIX_RXD_GMII_UL_CBUF_CFG2(node_id);

	offset = cnf20k_get_cpri_regaddr(offset, cpri_num);

	writeq(value_cfg2, cnf20k_cpri_reg_base + offset);
}

static void cnf20k_cpri_dl_reg_cfg1(u8 cpri_num, u8 node_id)
{
	u64 value_cfg1 = 0;
	u64 offset = 0;

	/* Set BUF_ENABLE */
	value_cfg1 |= (u64)1 << 63;

	/* This value is 16-bit and needs to be shifted to bits 31:16 */
	value_cfg1 |= (u64)0x680 << 16;
	offset = CNF20K_CPRIX_TXD_GMII_DL_CBUF_CFG1(node_id);
	offset = cnf20k_get_cpri_regaddr(offset, cpri_num);
	writeq(value_cfg1, cnf20k_cpri_reg_base + offset);
}

static void cnf20k_cpri_ul_reg_cfg1(u8 cpri_num, u8 node_id,
				    u8 ul_int_threshold)
{
	u64 value_cfg1 = 0;
	u64 offset = 0;
	/* Set BUF_ENABLE */
	value_cfg1 |= (u64)1 << 63;

	/* This buffer Size value is 16-bit and needs to be shifted
	 * to bits 31:16
	 */
	value_cfg1 |= (u64)0x680 << 16;

	/* This value is 8-bit and needs to be shifted to bits 7:0 */
	value_cfg1 |= (u64)ul_int_threshold << 0;

	offset = CNF20K_CPRIX_RXD_GMII_UL_CBUF_CFG1(node_id);
	offset = cnf20k_get_cpri_regaddr(offset, cpri_num);
	writeq(value_cfg1, cnf20k_cpri_reg_base + offset);
}

static void cnf20k_intr_fill_cfg(struct cnf20k_cpri_ndev_priv *priv,
				 struct cnf20k_bphy_ndev_cpri_intf_cfg
				 *cpri_cfg)
{
	int node_id, cpri_num, gpint;
	u64 offset = 0;
	u64 w0 = 0;

	node_id = priv->node_id;
	cpri_num = priv->cpri_num;

	gpint =  RX_GP_INT_CPRI_ETH + priv->cpri_num;

	w0 |= ((u64)(0x24 & 0x3F)) << 0;
	w0 |= ((u64)(node_id & 0x1)) << 6;
	w0 |= ((u64)(0 & 0x1)) << 7;
	w0 |= ((u64)(0xFF & 0xFF)) << 8;
	w0 |= ((u64)(0xFE & 0xFF)) << 16;
	w0 |= ((u64)(gpint & 0x3F)) << 24;
	offset = CPRDX_AF_ETH_UL_INT_PSM_MSG_W0(node_id);
	offset = cnf20k_get_cpri_regaddr(offset, cpri_num);
	writeq(w0, cnf20k_cpri_reg_base + offset);

	offset = CPRDX_AF_ETH_UL_INT_PSM_MSG_W1(node_id);
	offset = cnf20k_get_cpri_regaddr(offset, cpri_num);
	writeq(0, cnf20k_cpri_reg_base + offset);

	offset = CPRDX_AF_ETH_UL_INT_PSM_GMID(node_id);
	offset = cnf20k_get_cpri_regaddr(offset, cpri_num);
	writeq(0x7, cnf20k_cpri_reg_base + offset);
}

static void cnf20k_cpri_fill_dl_ul_cfg(struct cnf20k_cpri_ndev_priv *priv,
				       struct cnf20k_bphy_ndev_cpri_intf_cfg
				       *cpri_cfg)
{
	struct cnf20k_ul_cbuf_cfg *ul_cfg;
	struct cnf20k_dl_cbuf_cfg *dl_cfg;
	int buffer_size = 0;

	dma_addr_t raw_dma_handle;
	void *raw_cpu_buffer;
	u64 *cpu_buffer_virt_addr;
	size_t offset;

	if (!priv) {
		pr_err("priv is NULL\n");
		return;
	}

	if (!priv->pdev) {
		pr_err("pdev is NULL\n");
		return;
	}

	if (!priv->cpri_common) {
		pr_err("cpri_common is NULL\n");
		return;
	}

	/* -------- DL buffer allocation -------- */
	dl_cfg = &priv->cpri_common->dl_cfg;
	dl_cfg->num_entries = 32;
	buffer_size = CPRI_ETH_PKT_SIZE * dl_cfg->num_entries;

	raw_cpu_buffer = dma_alloc_coherent(&priv->pdev->dev,
					    buffer_size + 256,
					    &raw_dma_handle,
					    GFP_KERNEL);
	if (!raw_cpu_buffer) {
		pr_info("Cannot allocate DMACPRI_ETH_PKT_SIZE buffer\n");
		return;
	}

	/* Align the dma_handle to 256 bytes */
	offset = raw_dma_handle % 256;
	if (offset != 0)
		offset = 256 - offset;

	cpu_buffer_virt_addr = raw_cpu_buffer + offset;
	memset(cpu_buffer_virt_addr, 0, buffer_size);
	dl_cfg->cbuf_iova_addr = raw_dma_handle + offset;
	dl_cfg->cbuf_virt_addr = cpu_buffer_virt_addr;
	dl_cfg->sw_wr_ptr = 0;

	cnf20k_cpri_dl_reg_cfg1(priv->cpri_num, priv->node_id);
	cnf20k_cpri_dl_reg_cfg2(priv->cpri_num, dl_cfg->cbuf_iova_addr,
				priv->node_id);
	spin_lock_init(&dl_cfg->lock);

	/* -------- UL buffer allocation -------- */
	ul_cfg = &priv->cpri_common->ul_cfg;
	ul_cfg->num_entries = 16;
	buffer_size = ul_cfg->num_entries * CPRI_ETH_PKT_SIZE;

	raw_cpu_buffer = dma_alloc_coherent(&priv->pdev->dev,
					    buffer_size + 256,
					    &raw_dma_handle,
					    GFP_KERNEL);
	if (!raw_cpu_buffer) {
		pr_info("Cannot allocate DMA buffer\n");
		return;
	}

	/* Align dma_handle to 256 bytes */
	offset = raw_dma_handle % 256;
	if (offset != 0)
		offset = 256 - offset;

	cpu_buffer_virt_addr = raw_cpu_buffer + offset;
	memset(cpu_buffer_virt_addr, 0, buffer_size);
	ul_cfg->cbuf_iova_addr = raw_dma_handle + offset;
	ul_cfg->cbuf_virt_addr = cpu_buffer_virt_addr;
	ul_cfg->num_entries = 16;
	ul_cfg->sw_rd_ptr = 0;

	spin_lock_init(&ul_cfg->lock);
	cnf20k_cpri_ul_reg_cfg1(priv->cpri_num, priv->node_id,
				priv->ul_int_threshold);
	cnf20k_cpri_ul_reg_cfg2(priv->cpri_num, ul_cfg->cbuf_iova_addr,
				priv->node_id);
}

/* netdev ioctl */
static int cnf20k_cpri_ioctl(struct net_device *netdev, struct ifreq *req,
			     int cmd)
{
	return -EOPNOTSUPP;
}

/* netdev xmit */
static netdev_tx_t cnf20k_cpri_eth_start_xmit(struct sk_buff *skb,
					      struct net_device *netdev)
{
	struct cnf20k_cpri_ndev_priv *priv = netdev_priv(netdev);
	struct cnf20k_cpri_pkt_dl_wqe_hdr *wqe;
	struct cnf20k_dl_cbuf_cfg *dl_cfg;
	u16 nxt_rd_ptr, sw_wr_ptr;
	int tail, head, count;
	unsigned long flags;
	u64 offset = 0;
	u8 *buf_ptr;

	dl_cfg = &priv->cpri_common->dl_cfg;

	spin_lock_irqsave(&dl_cfg->lock, flags);

	if (!priv->cpri_common) {
		pr_err("priv->cpri_common is NULL!\n");
		goto exit;
	}

	if (unlikely(priv->if_type != IF_TYPE_CPRI)) {
		netif_err(priv, tx_queued, netdev,
			  "%s {cpri%d lmac%d} invalid intfmode, droppkt\n",
			  netdev->name, priv->cpri_num, priv->lmac_id);
		/* update stats */
		priv->stats.tx_dropped++;
		priv->last_tx_dropped_jiffies = jiffies;
		goto exit;
	}

	if (unlikely(!netif_carrier_ok(netdev))) {
		/* update stats */
		priv->stats.tx_dropped++;
		priv->last_tx_dropped_jiffies = jiffies;
		goto exit;
	}

	offset = CNF20K_CPRIX_TXD_GMII_DL_WR_DOORBELL(priv->node_id);
	offset = cnf20k_get_cpri_regaddr(offset, priv->cpri_num);
	/* Read CPRI(0..2)_TXD_GMII_DL_WR_DOORBELL to become 0 */

	while ((readq(priv->cpri_reg_base + offset)) & 0xFF)
		cpu_relax();

	offset = CNF20K_CPRIX_TXD_GMII_DL_NXT_RD_PTR(priv->node_id);
	offset = cnf20k_get_cpri_regaddr(offset, priv->cpri_num);
	nxt_rd_ptr = (readq(priv->cpri_reg_base + offset) & 0xFFFF);
	/* get the HW tail */
	tail = CNF20K_CIRC_BUF_ENTRY(nxt_rd_ptr);
	offset = CNF20K_CPRIX_TXD_GMII_DL_SW_WR_PTR(priv->node_id);
	offset = cnf20k_get_cpri_regaddr(offset, priv->cpri_num);
	sw_wr_ptr = (readq(priv->cpri_reg_base + offset) & 0xFFFF);
	head = CNF20K_CIRC_BUF_ENTRY(sw_wr_ptr);

	count = (head >= tail) ? dl_cfg->num_entries - (head - tail) - 1 :
		tail - head - 1;
	if (count == 0) {
		spin_unlock_irqrestore(&dl_cfg->lock, flags);
		return NETDEV_TX_BUSY;
	}

	if (unlikely(netif_msg_pktdata(priv))) {
		netdev_printk(KERN_DEBUG, priv->netdev, "Tx: skb %pS len=%d\n",
			      skb, skb->len);
		print_hex_dump(KERN_DEBUG, "", DUMP_PREFIX_OFFSET, 16, 4,
			       skb->data, skb->len, true);
	}

	buf_ptr = (u8 __force *)dl_cfg->cbuf_virt_addr +
		(CPRI_ETH_PKT_SIZE * dl_cfg->sw_wr_ptr);

	wqe = (struct cnf20k_cpri_pkt_dl_wqe_hdr *)buf_ptr;
	wqe->mhab_id = priv->cpri_num;
	wqe->lane_id = priv->lmac_id;

	/* Clear second flit (optional but clean) */
	memset(buf_ptr + sizeof(*wqe), 0,
	       CNF20K_BPHY_CPRI_WQE_SIZE - sizeof(*wqe));

	buf_ptr += CNF20K_BPHY_CPRI_WQE_SIZE;

	/* zero pad for short pkts, since there is no HW support */
	if (skb->len < 64)
		memset(buf_ptr, 0, 64);
	memcpy(buf_ptr, skb->data, skb->len);
	wqe->pkt_length = skb->len > 64 ? skb->len : 64;

	/* ensure the memory is updated before ringing doorbell */
	dma_wmb();
	offset = (CNF20K_CPRIX_TXD_GMII_DL_WR_DOORBELL(priv->node_id));
	offset = cnf20k_get_cpri_regaddr(offset, priv->cpri_num);
	writeq(1, priv->cpri_reg_base + offset);

	/* increment queue index */
	dl_cfg->sw_wr_ptr++;
	if (dl_cfg->sw_wr_ptr == dl_cfg->num_entries)
		dl_cfg->sw_wr_ptr = 0;

	priv->last_tx_jiffies = jiffies;
exit:
	dev_kfree_skb_any(skb);
	spin_unlock_irqrestore(&dl_cfg->lock, flags);
	return NETDEV_TX_OK;
}

/* netdev open */
static int cnf20k_cpri_eth_open(struct net_device *netdev)
{
	struct cnf20k_cpri_ndev_priv *priv = netdev_priv(netdev);

	napi_enable(&priv->napi);

	spin_lock(&priv->lock);
	clear_bit(CNF20K_CPRI_INTF_DOWN, &priv->state);
	if (priv->link_state == LINK_STATE_UP) {
		netif_carrier_on(netdev);
		netif_start_queue(netdev);
	}
	spin_unlock(&priv->lock);

	return 0;
}

/* netdev close */
static int cnf20k_cpri_eth_stop(struct net_device *netdev)
{
	struct cnf20k_cpri_ndev_priv *priv = netdev_priv(netdev);

	spin_lock(&priv->lock);
	set_bit(CNF20K_CPRI_INTF_DOWN, &priv->state);

	netif_stop_queue(netdev);
	netif_carrier_off(netdev);
	spin_unlock(&priv->lock);

	napi_disable(&priv->napi);

	return 0;
}

static const struct net_device_ops cnf20k_cpri_netdev_ops = {
	.ndo_open               = cnf20k_cpri_eth_open,
	.ndo_stop               = cnf20k_cpri_eth_stop,
	.ndo_start_xmit         = cnf20k_cpri_eth_start_xmit,
	.ndo_eth_ioctl          = cnf20k_cpri_ioctl,
	.ndo_set_mac_address    = eth_mac_addr,
	.ndo_validate_addr      = eth_validate_addr,
	.ndo_get_stats64        = cnf20k_cpri_get_stats64,
};

static struct net_device *cnf20k_cpri_get_netdev(int mhab_id, int lmac_id,
						 int node_id)
{
	struct net_device *netdev = NULL;
	int idx;

	for (idx = 0; idx < CNF20K_BPHY_CPRI_MAX_INTF; idx++) {
		if (cnf20k_cpri_drv_ctx[idx].cpri_num == mhab_id &&
		    cnf20k_cpri_drv_ctx[idx].lmac_id == lmac_id &&
		    cnf20k_cpri_drv_ctx[idx].node_id == node_id &&
		    cnf20k_cpri_drv_ctx[idx].valid) {
			netdev = cnf20k_cpri_drv_ctx[idx].netdev;
			break;
		}
	}

	return netdev;
}

static int cnf20k_cpri_process_rx_pkts(struct cnf20k_cpri_ndev_priv *priv,
				       int budget)
{
	int count, head, processed_pkts = 0;
	struct cnf20k_cpri_ndev_priv *priv2;
	struct cnf20k_ul_cbuf_cfg *ul_cfg;
	struct cnf20k_cpri_pkt_ul_wqe_hdr *wqe;
	struct net_device *netdev;
	u16 nxt_wr_ptr, len;
	struct sk_buff *skb;
	u64 offset = 0;
	u8 *pkt_buf;

	ul_cfg = &priv->cpri_common->ul_cfg;

	spin_lock(&ul_cfg->lock);

	offset = CNF20K_CPRIX_RXD_GMII_UL_NXT_WR_PTR(priv->node_id);
	offset = cnf20k_get_cpri_regaddr(offset, priv->cpri_num);
	nxt_wr_ptr = readq(priv->cpri_reg_base + offset) & 0xFFFF;
	/* get the HW head */
	head = CNF20K_CIRC_BUF_ENTRY(nxt_wr_ptr);

	if (ul_cfg->sw_rd_ptr > head) {
		count = ul_cfg->num_entries - ul_cfg->sw_rd_ptr;
		count += head;
	} else {
		count = head - ul_cfg->sw_rd_ptr;
	}

	if (!count && ul_cfg->flush) {
		count = ul_cfg->num_entries;
		ul_cfg->flush = false;
	}
	while (likely((processed_pkts < budget) && (processed_pkts < count))) {
		pkt_buf = (u8 __force *)ul_cfg->cbuf_virt_addr +
			(CPRI_ETH_PKT_SIZE * ul_cfg->sw_rd_ptr);
		wqe = (struct cnf20k_cpri_pkt_ul_wqe_hdr *)pkt_buf;
		netdev = cnf20k_cpri_get_netdev(wqe->mhab_id, wqe->lane_id,
						priv->node_id);
		if (!netdev) {
			pr_info("get netdev failed\n");
			goto update_processed_pkts;
		}
		if (unlikely(!netdev)) {
			priv->stats.rx_dropped++;
			priv->last_rx_dropped_jiffies = jiffies;
			goto update_processed_pkts;
		}
		priv2 = netdev_priv(netdev);
		if (wqe->fcserr || wqe->rsp_ferr || wqe->rsp_nferr) {
			priv2->stats.rx_dropped++;
			priv2->last_rx_dropped_jiffies = jiffies;
			goto update_processed_pkts;
		}
		if (unlikely(!netif_carrier_ok(netdev))) {
			net_err_ratelimited("%s {cpri%d lmac%d} link down,drop pkt\n",
					    netdev->name, priv2->cpri_num,
					    priv2->lmac_id);
			priv2->stats.rx_dropped++;
			priv2->last_rx_dropped_jiffies = jiffies;
			goto update_processed_pkts;
		}

		len = wqe->pkt_length;
		if (unlikely(netif_msg_pktdata(priv2))) {
			netdev_printk(KERN_DEBUG, priv2->netdev, "RX DATA:");
			print_hex_dump(KERN_DEBUG, "", DUMP_PREFIX_OFFSET, 16,
				       4, pkt_buf,
				       len + CNF20K_BPHY_CPRI_WQE_SIZE, true);
		}

		pkt_buf += CNF20K_BPHY_CPRI_WQE_SIZE;
		skb = netdev_alloc_skb_ip_align(netdev, len);
		if (!skb) {
			pr_info("skb is null\n");
			priv->stats.rx_dropped++;
			priv->last_rx_dropped_jiffies = jiffies;
			goto update_processed_pkts;
		}

		memcpy(skb->data, pkt_buf, len);
		skb_put(skb, len);
		skb->protocol = eth_type_trans(skb, netdev);
		netif_receive_skb(skb);
		priv2->last_rx_jiffies = jiffies;

update_processed_pkts:
		processed_pkts++;
		ul_cfg->sw_rd_ptr++;
		if (ul_cfg->sw_rd_ptr == ul_cfg->num_entries)
			ul_cfg->sw_rd_ptr = 0;
	}

	if (processed_pkts) {
		offset = CNF20K_CPRIX_RXD_GMII_UL_RD_DOORBELL(priv->node_id);
		offset = cnf20k_get_cpri_regaddr(offset, priv->cpri_num);
		writeq(processed_pkts, priv->cpri_reg_base + offset);
	}
	spin_unlock(&ul_cfg->lock);

	return processed_pkts;
}

/* napi poll routine */
static int cnf20k_cpri_napi_poll(struct napi_struct *napi, int budget)
{
	struct cnf20k_cdev_priv *cdev_priv;
	struct cnf20k_cpri_ndev_priv *priv;
	u64 intr_en, regval, offset = 0;
	int workdone = 0;

	priv = container_of(napi, struct cnf20k_cpri_ndev_priv, napi);
	cdev_priv = priv->cdev_priv;

	/* pkt processing loop */
	workdone += cnf20k_cpri_process_rx_pkts(priv, budget);
	if (workdone < budget) {
		napi_complete_done(napi, workdone);

		/* Re enable the Rx interrupts */
		if (priv->node_id == 0 || priv->node_id == 1) {
			intr_en = 1 <<
				CNF20K_CPRI_RX_INTR_SHIFT(priv->cpri_num);
			spin_lock(&cdev_priv->lock);
			offset = bphy_get_regaddr(priv->node_id, offset);
			offset |= PSM_CNF20K_INT_GP_ENA_W1S(1);
			regval = readq(priv->cdev_priv->reg_base + offset);
			regval |= intr_en;
			writeq(regval, priv->cdev_priv->reg_base + offset);
			spin_unlock(&cdev_priv->lock);
		} else {
			pr_info("node id is Mismatching\n");
		}
	}
	return workdone;
}

static void generate_cpri_mac(u8 mac[ETH_ALEN], u8 node_id,
		       u8 cpri_num, u8 lmac)
{
	mac[0] = 0x02;
	mac[1] = 0xBB;
	mac[2] = 0xCC;
	mac[3] = node_id;
	mac[4] = cpri_num;
	mac[5] = lmac;
}

static inline void msix_enable_ctrl(struct pci_dev *dev)
{
	u16 control;

	pci_read_config_word(dev, dev->msix_cap + PCI_MSIX_FLAGS, &control);
	control |= PCI_MSIX_FLAGS_ENABLE;
	pci_write_config_word(dev, dev->msix_cap + PCI_MSIX_FLAGS, control);
}

static int cnf20k_cpri_parse_and_init_intf(struct cnf20k_cdev_priv *cdev,
					   struct cnf20k_bphy_cpri_netdev_comm_intf_cfg
					   *cfg)
{
	struct cnf20k_bphy_ndev_cpri_intf_cfg *cpri_cfg;
	struct cnf20k_cpri_drv_ctx *drv_ctx = NULL;
	struct cnf20k_cpri_ndev_priv *priv, *priv2;
	int i, j, lmac, ret = 0, intf_idx;
	struct net_device *netdev;
	struct pci_dev *pdev;
	u8 mac_addr[ETH_ALEN];
	int msix_vecs = 0;
	int irq0, irq1;

	if (!cdev || !cdev->pdev) {
		pr_info("pdev is NULL — device not ready\n");
		return -ENODEV;
	}
	pdev = cdev->pdev;

	if (cfg->bphy_chiplet_mask >= 1 && cfg->bphy_chiplet_mask <= 3) {
		int max_chiplet = (cfg->bphy_chiplet_mask == 3) ?
			MAX_NUM_BPHY_CHIPLET : MAX_NUM_HALF_BPHY_CHIPLET;

		int max_mhab = (cfg->bphy_chiplet_mask == 3) ?
			CNF20K_BPHY_CPRI_MAX_MHAB :
			CNF20K_HALF_BPHY_CPRI_MAX_MHAB;

		for (i = 0; i < max_chiplet; i++) {
			for (j = 0; j < max_mhab; j++) {
				priv2 = NULL;
				cpri_cfg = &cfg->cpri_if_cfg[i][j];

				for (lmac = 0;
				     lmac < CNF20K_BPHY_CPRI_MAX_LMAC;
				     lmac++) {
					if (!(cpri_cfg->active_lane_mask &
					(1 << lmac)))
						continue;

					netdev =
					alloc_etherdev
					(sizeof(struct cnf20k_cpri_ndev_priv));
					if (!netdev) {
						dev_err(cdev->dev,
							"err allocate netdev\n");
						ret = -ENOMEM;
						goto err_exit;
					}

					priv = netdev_priv(netdev);
					memset(priv, 0, sizeof(*priv));

					if (!priv2) {
						priv->cpri_common =
						kzalloc(sizeof
						(struct cnf20k_cpri_common_cfg),
						GFP_KERNEL);
						if (!priv->cpri_common) {
							dev_err(cdev->dev,
								"kzalloc failed\n");
							free_netdev(netdev);
							ret = -ENOMEM;
							goto err_exit;
						}
						priv->cpri_common->refcnt = 1;
					} else {
						priv->cpri_common =
						priv2->cpri_common;
						++(priv->cpri_common->refcnt);
					}

					spin_lock_init(&priv->lock);
					priv->netdev = netdev;
					priv->cdev_priv = cdev;
					priv->msg_enable =
					netif_msg_init(-1, 0);
					spin_lock_init(&priv->stats.lock);
					priv->cpri_num = cpri_cfg->cpri_id;
					priv->lmac_id = lmac;
					priv->if_type = IF_TYPE_CPRI;
					priv->node_id = i;
					priv->cpri_reg_base =
					cnf20k_cpri_reg_base;
					priv->ul_int_threshold =
					cpri_cfg->ul_int_threshold;
					priv->pdev = pdev;

					if (!priv2)
						cnf20k_cpri_fill_dl_ul_cfg(priv,
									   cpri_cfg);

					cnf20k_intr_fill_cfg(priv, cpri_cfg);
					netif_napi_add(netdev, &priv->napi,
						       cnf20k_cpri_napi_poll);

					if (!priv2)
						priv2 = priv;

					intf_idx = (i *
						CNF20K_BPHY_CPRI_MAX_MHAB
						* CNF20K_BPHY_CPRI_MAX_LMAC) +
						(j * CNF20K_BPHY_CPRI_MAX_LMAC)
						+ lmac;

					snprintf(netdev->name,
						 sizeof(netdev->name),
						 "cpri%d", intf_idx);
					netdev->netdev_ops =
					&cnf20k_cpri_netdev_ops;
					cnf20k_cpri_set_ethtool_ops(netdev);
					netdev->mtu = 1500U;
					netdev->min_mtu = ETH_MIN_MTU;
					netdev->max_mtu = 1500U;
					ret = register_netdev(netdev);
					if (ret < 0) {
						dev_err(cdev->dev,
							"failed to register netdev%s\n",
							netdev->name);
						free_netdev(netdev);
						ret = -ENODEV;
						goto err_exit;
					}
					generate_cpri_mac(mac_addr,
							  priv->node_id,
							  priv->cpri_num,
							  priv->lmac_id);
					if (!is_valid_ether_addr(mac_addr))
						eth_random_addr(mac_addr);
					ether_addr_copy(priv->mac_addr,
							mac_addr);
					dev_addr_set(netdev, priv->mac_addr);
					netif_carrier_off(netdev);
					netif_stop_queue(netdev);
					set_bit(CNF20K_CPRI_INTF_DOWN,
						&priv->state);
					priv->link_state = LINK_STATE_UP;
					drv_ctx =
					&cnf20k_cpri_drv_ctx[intf_idx];
					drv_ctx->cpri_num = priv->cpri_num;
					drv_ctx->lmac_id = priv->lmac_id;
					drv_ctx->valid = 1;
					drv_ctx->node_id = priv->node_id;
					drv_ctx->netdev = netdev;
				}
			}
		}
		if (cfg->bphy_chiplet_mask == 3) {
			for (i = 0; i < NUM_VECTORS; i++)
				msix_entries[i].entry =
				cfg->hw_params.msix_offset[0] + i;
			msix_vecs = 4;
		} else if (cfg->bphy_chiplet_mask == 1) {
			msix_entries[0].entry =
			cfg->hw_params.msix_offset[0] + 1;
			msix_vecs = 1;
		} else if (cfg->bphy_chiplet_mask == 2) {
			msix_entries[0].entry =
			cfg->hw_params.msix_offset[1] + 1;
			msix_vecs = 1;
		}
		msix_enable_ctrl(pdev);
		ret = pci_enable_msix_exact(pdev, msix_entries, msix_vecs);
		if (ret < 0) {
			dev_err(&pdev->dev, "Failed to enable MSI-X: %d\n",
				ret);
			goto err_exit;
		}

		if (cfg->bphy_chiplet_mask & 1) {
			irq0 = msix_entries[1].vector;
			ret = request_irq(irq0,
					  cnf20k_gpint_bphy0_intr_handler, 0,
					  "cnf20k_gpint_bphy0_intr_handler",
					  cdev);
			if (ret) {
				dev_err(&pdev->dev,
					"Failed to request IRQ %d: %d\n",
					irq0, ret);
				goto err_exit;
			}
		}
		if (cfg->bphy_chiplet_mask & 2) {
			int msix_idx = (cfg->bphy_chiplet_mask == 3) ? 2 : 0;

			irq1 = msix_entries[msix_idx + 1].vector;
			ret = request_irq(irq1, cnf20k_gpint_bphy1_intr_handler,
					  0, "cnf20k_gpint_bphy1_intr_handler",
					  cdev);
			if (ret) {
				dev_err(&pdev->dev,
					"Failed to request IRQ %d: %d\n",
					irq1, ret);
				if (cfg->bphy_chiplet_mask & 1)
					free_irq(irq0, cdev);
				goto err_exit;
			}
		}
	} else {
		pr_info("Invalid chiplet mask: %d\n", cfg->bphy_chiplet_mask);
		return -EINVAL;
	}

	return 0;

err_exit:
	for (i = 0; i < CNF20K_BPHY_CPRI_MAX_INTF; i++) {
		drv_ctx = &cnf20k_cpri_drv_ctx[i];
		if (drv_ctx->valid) {
			netdev = drv_ctx->netdev;
			priv = netdev_priv(netdev);
			unregister_netdev(netdev);
			netif_napi_del(&priv->napi);
			if (--priv->cpri_common->refcnt == 0)
				kfree(priv->cpri_common);
			free_netdev(netdev);
			drv_ctx->valid = 0;
		}
	}
	return ret;
}

static int cnf20k_cpri_cdev_open(struct inode *inode, struct file *filp)
{
	struct cnf20k_cdev_priv *cdev;

	/* Usually, you find your private data by inode->i_cdev or
	 * container_of or some other method, depending on your driver design.
	 * For example:
	 */
	cdev = container_of(inode->i_cdev, struct cnf20k_cdev_priv, cdev);
	filp->private_data = cdev;

	return 0;
}

static void cnf20k_cpri_set_link_state(struct net_device *netdev, u8 state)
{
	struct cnf20k_cpri_ndev_priv *priv;

	priv = netdev_priv(netdev);

	spin_lock(&priv->lock);
	if (priv->link_state != state) {
		priv->link_state = state;
		if (state == LINK_STATE_DOWN) {
			netdev_info(netdev, "Link DOWN\n");
			pr_info("debug state down %s\n", __func__);
			if (netif_running(netdev)) {
				netif_carrier_off(netdev);
				netif_stop_queue(netdev);
			}
		} else {
			netdev_info(netdev, "Link UP\n");
			pr_info("debug state up %s\n", __func__);
			if (netif_running(netdev)) {
				netif_carrier_on(netdev);
				netif_start_queue(netdev);
			}
		}
	}
	spin_unlock(&priv->lock);
}

static long cnf20k_cpri_cdev_ioctl(struct file *filp, unsigned int cmd,
				   unsigned long arg)
{
	struct cnf20k_cdev_priv *cdev = filp->private_data;
	struct cnf20k_bphy_cpri_netdev_comm_intf_cfg *intf_cfg = NULL;
	int ret = 0;

	if (!cdev) {
		pr_warn("ioctl: device not opened\n");
		return -EIO;
	}

	mutex_lock(&cdev->mutex_lock);

	switch (cmd) {
	case OTX2_CPRI_IOCTL_READY_NOTIF: {
		u64 pf_func_num = 0x7800;

		if (copy_to_user((u64 __user *)arg,
				 &pf_func_num, sizeof(pf_func_num))) {
			pr_err("Failed to copy PF_FUNC num to user space\n");
			ret = -EFAULT;
		}
		pr_info("IOCTL_READY_NOTIF:PF_FUNC_NUM = %llu to user\n",
			pf_func_num);

		break;
		}

	case OTX2_CPRI_IOCTL_INTF_CFG: {
		pr_info("cnf20k_CPRI: OTX2_CPRI_IOCTL_INTF_CFG\n");

		intf_cfg = kzalloc(sizeof(*intf_cfg), GFP_KERNEL);
		if (!intf_cfg) {
			ret = -ENOMEM;
			break;
		}

		if (copy_from_user(intf_cfg, (void __user *)arg,
				   sizeof(*intf_cfg))) {
			dev_err(cdev->dev, "copy_from_user failed in INTF_CFG\n");
			ret = -EFAULT;
			break;
			}

			pr_info("%s: Received intf cfg from user\n", __func__);
			ret = cnf20k_cpri_parse_and_init_intf(cdev,
							      intf_cfg);
			if (ret < 0) {
				pr_info("initalisation of cpri itf failed\n");
				ret = -ENOMEM;
				break;
			}

			/* Enable CPRI ETH UL INT */
			for (int idx = 0; idx < MAX_NUM_BPHY_CHIPLET; idx++) {
				for (int i = 0; i < MAX_CPRI_INST; i++) {
					u64 base_offset =
					CNF20K_CPRIX_ETH_UL_INT_ENA_W1S(idx);
					u64 offset =
					cnf20k_get_cpri_regaddr(base_offset, i);
					writeq(0x1, cnf20k_cpri_reg_base +
					offset);
				}
			}

			/* Enable GPINT Rx and Tx interrupts */
			for (int idx = 0; idx < MAX_NUM_BPHY_CHIPLET; idx++) {
				u64 offset = bphy_get_regaddr(idx, 0) +
				PSM_CNF20K_INT_GP_ENA_W1S(1);
				writeq(0xFFFFFFFF, cdev->reg_base + offset);
			}

			kthread_run(cpri_polling_thread, NULL, "cpri_poll");
			break;
			}

	case OTX2_CPRI_IOCTL_LINK_EVENT: {
		struct cnf20k_cpri_drv_ctx *cnf20k_drv_ctx = NULL;
		struct bphy_netdev_cpri_link_event cfg;
		struct net_device *netdev = NULL;

		pr_info("cnf20k_CPRI: OTX2_CPRI_IOCTL_LINK_EVENT\n");

		if (copy_from_user(&cfg, (void __user *)arg, sizeof(cfg))) {
			dev_err(cdev->dev,
				"copy_from_user failed in LINK_EVENT\n");
			ret = -EFAULT;
			break;
		}

		for (int idx = 0; idx < CNF20K_BPHY_CPRI_MAX_INTF; idx++) {
			cnf20k_drv_ctx = &cnf20k_cpri_drv_ctx[idx];
			if (cnf20k_drv_ctx->valid &&
			    cnf20k_drv_ctx->cpri_num == cfg.rpm_id &&
			    cnf20k_drv_ctx->lmac_id == cfg.lmac_id) {
				netdev = cnf20k_drv_ctx->netdev;
				cnf20k_cpri_set_link_state(netdev,
							   cfg.link_state);
				break;
				}
			}
			break;
		}

	default:
		pr_warn("OTX2_CPRI: Unknown ioctl cmd: 0x%x\n", cmd);
		ret = -ENOTTY;
		break;
	}

	mutex_unlock(&cdev->mutex_lock);
	kfree(intf_cfg);
	return ret;
}

static void cnf20k_bphy_cpri_cleanup(void)
{
	struct cnf20k_cpri_drv_ctx *drv_ctx = NULL;
	struct cnf20k_cpri_ndev_priv *priv;
	struct net_device *netdev;
	u64 offset = 0;
	int i;

	for (i = 0; i < CNF20K_BPHY_CPRI_MAX_INTF; i++) {
		drv_ctx = &cnf20k_cpri_drv_ctx[i];
		if (drv_ctx->valid) {
			netdev = drv_ctx->netdev;
			priv = netdev_priv(netdev);
			unregister_netdev(netdev);
			netif_napi_del(&priv->napi);
			--(priv->cpri_common->refcnt);
			if (priv->cpri_common->refcnt == 0)
				kfree(priv->cpri_common);
			free_netdev(netdev);
			drv_ctx->valid = 0;
		}
	}

	/* Disable CPRI ETH UL INT */
	for (int idx = 0; idx < MAX_NUM_BPHY_CHIPLET ; idx++) {
		offset = CNF20K_CPRIX_ETH_UL_INT_ENA_W1C(idx);
		for (int i = 0; i < MAX_CPRI_INST ; i++) {
			offset = cnf20k_get_cpri_regaddr(offset, i);
			writeq(0x1, cnf20k_cpri_reg_base + offset);
		}
	}
}

static int cnf20k_cpri_cdev_release(struct inode *inode, struct file *filp)
{
	struct cnf20k_cdev_priv *cdev = filp->private_data;
	u64 offset;
	u32 status;

	if (!cdev)
		return -EINVAL;

	mutex_lock(&cdev->mutex_lock);

	if (cnf20k_cpri_reg_base) {
		// Disable GPINT Rx and Tx interrupts and clear interrupt status
		for (int i = 0; i < MAX_NUM_BPHY_CHIPLET; i++) {
			// Disable GPINT interrupt
			offset = bphy_get_regaddr(i, 0) +
				 PSM_CNF20K_INT_GP_ENA_W1C(1);
			writeq(0xFFFFFFFF, cdev->reg_base + offset);

			// Clear interrupt status
			offset = bphy_get_regaddr(i, 0) +
				 PSM_CNF20K_INT_GP_SUM_W1C(1);
			status = readq(cdev->reg_base + offset) & 0xFFFFFFFF;
			writeq(status, cdev->reg_base + offset);
		}

		// Clean up all CPRI devices/interfaces
		cnf20k_bphy_cpri_cleanup();
	}

	mutex_unlock(&cdev->mutex_lock);
	return 0;
}

static const struct file_operations cnf20k_cpri_cdev_fops = {
	.owner          = THIS_MODULE,
	.unlocked_ioctl = cnf20k_cpri_cdev_ioctl,
	.open           = cnf20k_cpri_cdev_open,
	.release        = cnf20k_cpri_cdev_release,
};

static const struct pci_device_id cpri_id_table[] = {
	{ PCI_DEVICE(PCI_VENDOR_ID_CAVIUM, PCI_DEVID_RVU_BPHY_CPRI_PF) },
	{ 0, }
};
MODULE_DEVICE_TABLE(pci, cpri_id_table);

static int cpri_probe(struct pci_dev *pdev, const struct pci_device_id *ent)
{
	struct cnf20k_cdev_priv *cdev_priv;
	int err = 0;
	dev_t devt;
	int bar;

	err = pci_enable_device_mem(pdev);
	if (err)
		return err;

	bar = pci_select_bars(pdev, IORESOURCE_MEM);

	err = pci_request_selected_regions(pdev, bar, DRV_NAME);
	if (err)
		return err;

	pci_set_master(pdev);

	err = dma_set_coherent_mask(&pdev->dev, DMA_BIT_MASK(48));
	if (err) {
		pr_err("Failed to set DMA mask for 48-bit addressing\n");
		return err;
	}

	/* allocate priv structure */
	cdev_priv = kzalloc(sizeof(*cdev_priv), GFP_KERNEL);
	if (!cdev_priv) {
		err = -ENOMEM;
		goto out;
	}

	pci_set_drvdata(pdev, cdev_priv);

	cdev_priv->reg_base = pcim_iomap(pdev, PCI_CFG_REG_BAR_NUM, 0);
	if (!cdev_priv->reg_base) {
		dev_err(&pdev->dev,
			"Unable to map physical function CSRs, aborting\n");
		return -ENOMEM;
	}

	/* create a character device */
	err = alloc_chrdev_region(&devt, 0, 1, DEVICE_NAME);
	if (err < 0) {
		dev_err(&pdev->dev, "failed to alloc chrdev device region\n");
		goto out_unmap_cpri_reg;
	}

	cnf20k_cpri_class = class_create(DEVICE_NAME);
	if (IS_ERR(cnf20k_cpri_class)) {
		dev_err(&pdev->dev, "couldn't create class %s\n", DEVICE_NAME);
		err = PTR_ERR(cnf20k_cpri_class);
		goto out_unregister_chrdev_region;
	}

	cdev_priv->devt = devt;
	cdev_priv->is_open = 0;
	spin_lock_init(&cdev_priv->lock);
	mutex_init(&cdev_priv->mutex_lock);
	cdev_priv->pdev = pdev;

	cdev_init(&cdev_priv->cdev, &cnf20k_cpri_cdev_fops);
	cdev_priv->cdev.owner = THIS_MODULE;

	err = cdev_add(&cdev_priv->cdev, devt, 1);
	if (err < 0) {
		dev_err(&pdev->dev, "cdev_add() failed\n");
		goto out_class_destroy;
	}

	cdev_priv->dev = device_create(cnf20k_cpri_class, &pdev->dev,
				       cdev_priv->cdev.dev, cdev_priv,
				       DEVICE_NAME);
	if (IS_ERR(cdev_priv->dev)) {
		dev_err(&pdev->dev, "device_create failed\n");
		err = PTR_ERR(cdev_priv->dev);
		goto out_cdev_del;
	}

	dev_info(&pdev->dev, "successfully registered char device, major=%d\n",
		 MAJOR(cdev_priv->cdev.dev));

	cnf20k_cpri_reg_base = ioremap(CPRI_REG_BASE, CPRI_REG_SIZE);
	if (!cnf20k_cpri_reg_base) {
		dev_err(&pdev->dev, "failed to ioremap cpri registers\n");
		err = -ENOMEM;
		goto out_unmap_io_cpri_reg;
	}

	cdev_priv->cpri_reg_base = cnf20k_cpri_reg_base;

	pr_info("probing completed\n");
	return 0;

out_unmap_io_cpri_reg:
	iounmap(cnf20k_cpri_reg_base);

out_cdev_del:
	cdev_del(&cdev_priv->cdev);

out_class_destroy:
	class_destroy(cnf20k_cpri_class);

out_unregister_chrdev_region:
	unregister_chrdev_region(devt, 1);

out_unmap_cpri_reg:
	pci_iounmap(pdev, cdev_priv->reg_base);

out:
	pci_release_selected_regions(pdev,
				     pci_select_bars(pdev, IORESOURCE_MEM));
	kfree(cdev_priv);
	pci_disable_device(pdev);
	return err;
}

static void cpri_remove(struct pci_dev *pdev)
{
	struct cnf20k_cdev_priv *cdev_priv = pci_get_drvdata(pdev);

	if (!cdev_priv)
		return;

	/* Destroy the device node */
	if (cdev_priv->dev)
		device_destroy(cnf20k_cpri_class, cdev_priv->devt);

	/* Remove the char device */
	cdev_del(&cdev_priv->cdev);

	/* Destroy the device class if this is the last device */
	if (cnf20k_cpri_class)
		class_destroy(cnf20k_cpri_class);

	/* Unmap registers mapped with pcim_iomap */
	if (cdev_priv->reg_base)
		pci_iounmap(pdev, cdev_priv->reg_base);

	/* Unmap the ioremap region if you mapped it */
	if (cnf20k_cpri_reg_base)
		iounmap(cnf20k_cpri_reg_base);

	/* Release PCI regions */
	pci_release_selected_regions(pdev,
				     pci_select_bars(pdev, IORESOURCE_MEM));

	/* Unregister the chrdev region */
	unregister_chrdev_region(cdev_priv->devt, 1);

	/* Free your private structure */
	kfree(cdev_priv);

	/* Clear driver data pointer */
	pci_set_drvdata(pdev, NULL);

	/* Disable PCI device */
	pci_disable_device(pdev);

	pr_info("cpri driver removed\n");
}

static struct pci_driver cpri_driver = {
	.name = DRV_NAME,
	.id_table = cpri_id_table,
	.probe = cpri_probe,
	.remove = cpri_remove,
};

static int __init cpri_init_module(void)
{
	int err;

	pr_info("%s: %s\n", DRV_NAME, DRV_STRING);

	err = pci_register_driver(&cpri_driver);
	if (err < 0)
		goto cpri_err;
	return 0;
cpri_err:
	pci_unregister_driver(&cpri_driver);
	return err;
}

static void __exit cpri_cleanup_module(void)
{
	pr_info("%s: Cleaning up module\n", DRV_NAME);
	pci_unregister_driver(&cpri_driver);
}

module_init(cpri_init_module);
module_exit(cpri_cleanup_module);

MODULE_AUTHOR("Viswajth Murali <viswajithm@marvell.com>");
MODULE_DESCRIPTION(DRV_STRING);
