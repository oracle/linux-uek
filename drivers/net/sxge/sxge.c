/* sxge.c: SOL ethernet driver
 *
 * Copyright (C) 2011 Oracle Corp.
 */
/* #pragma ident   "@(#)sxge.c 1.63     13/11/22 SMI" */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/init.h>
#include <linux/pci.h>
#include <linux/dma-mapping.h>
#include <linux/netdevice.h>
#include <linux/ethtool.h>
#include <linux/etherdevice.h>
#include <linux/platform_device.h>
#include <linux/delay.h>
#include <linux/bitops.h>
#include <linux/mii.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/ipv6.h>
#include <linux/log2.h>
#include <linux/jiffies.h>
#include <linux/crc32.h>
#include <linux/list.h>
#include <linux/slab.h>

#include <linux/io.h>
#include "sxge.h"

#ifdef SXGE_VF
#define	DRV_MODULE_NAME		"sxgevf"
#else
#define DRV_MODULE_NAME		"sxge"
#endif
#define DRV_MODULE_VERSION	"0.09092013"
#define DRV_MODULE_RELDATE	"September 9, 2013"

static char version[] __devinitdata =
	DRV_MODULE_NAME ".c:v" DRV_MODULE_VERSION " (" DRV_MODULE_RELDATE ")\n";

MODULE_AUTHOR("Oracle Corp (joyce.yu@oracle.com)");
#ifdef SXGE_VF
MODULE_DESCRIPTION("SXGEVF ethernet driver");
#else
MODULE_DESCRIPTION("SXGE ethernet driver");
#endif
MODULE_LICENSE("GPL");
MODULE_VERSION(DRV_MODULE_VERSION);

#ifndef	readq
static u64 readq(void __iomem *reg)
{
	return ((u64) readl(reg)) | (((u64) readl(reg + 4UL)) << 32);
}

static void writeq(u64 val, void __iomem *reg)
{
	writel(val & 0xffffffff, reg);
	writel(val >> 32, reg + 0x4UL);
}
#endif

static DEFINE_PCI_DEVICE_TABLE(sxge_pci_tbl) = {
#ifdef SXGE_VF
	{PCI_DEVICE(PCI_VENDOR_ID_SUN, 0x207b)},
#else
	{PCI_DEVICE(PCI_VENDOR_ID_SUN, 0x2078)},
	{PCI_DEVICE(PCI_VENDOR_ID_SUN, 0x207a)},
#endif
	{}
};

MODULE_DEVICE_TABLE(pci, sxge_pci_tbl);

#define SXGE_TX_TIMEOUT			(5 * HZ)

#define	SXGE_GET64(reg)			readq(sxgep->regs + (reg))
#define	SXGE_PUT64(reg, val)		writeq((val), sxgep->regs + (reg))
#define	SXGE_DBG			printk

#define SXGE_MSG_DEFAULT (NETIF_MSG_DRV | NETIF_MSG_PROBE | NETIF_MSG_LINK)

static int sxge_debug;
static int debug = -1;
module_param(debug, int, 0);
MODULE_PARM_DESC(debug, "SXGE debug level");

ulong sxge_live_migrate = 0;
module_param_named(sxge_enable_live_migrate, sxge_live_migrate, ulong, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(sxge_enable_live_migrate, "Enable Live Migrate for VMs in the sxge driver");

static void sxge_ldg_rearm(struct sxge *sxgep, struct sxge_ldg *lp, int on)
{
	u64 val = (u64) (lp->timer << LDG_IMGMT_TIMER_SHIFT);

	if (on)
		val |= LDG_IMGMT_ARM;

	SXGE_PUT64(LDG_IMGMT(lp->ldg_num), val);
}

static int sxge_ldn_irq_enable(struct sxge *sxgep, int ldn, int on)
{
	u64 val;

	if (ldn < 0 || ldn > LDN_MAX)
		return -EINVAL;

	val = SXGE_GET64(LD_MSK_GNUM(sxgep->vni, sxgep->intmgmt_nf, ldn));
	val &= ~LD_MSK_GNUM_EN_LDG_WR;
	if (on)
		val &= ~LD_MSK_GNUM_LDG_MSK;
	else
		val |= LD_MSK_GNUM_LDG_MSK;
	SXGE_PUT64(LD_MSK_GNUM(sxgep->vni, sxgep->intmgmt_nf, ldn),
				val | LD_MSK_GNUM_EN_MSK_WR);

	return 0;
}

static int sxge_enable_ldn_in_ldg(struct sxge *sxgep,
						struct sxge_ldg *lp, int on)
{
	int i;

	for (i = 0; i <= LDN_MAX; i++) {
		int err;

		if (sxgep->ldg_map[i] != lp->ldg_num)
			continue;

		err = sxge_ldn_irq_enable(sxgep, i, on);
		if (err)
			return err;
	}
	return 0;
}

static int sxge_enable_interrupts(struct sxge *sxgep, int on)
{
	int i;

	for (i = 0; i < sxgep->num_ldg; i++) {
		struct sxge_ldg *lp = &sxgep->ldg[i];
		int err;

		err = sxge_enable_ldn_in_ldg(sxgep, lp, on);
		if (err)
			return err;
	}
	for (i = 0; i < sxgep->num_ldg; i++)
		sxge_ldg_rearm(sxgep, &sxgep->ldg[i], on);

	return 0;
}

static void sxge_rx_skb_append(struct sk_buff *skb, struct page *page,
			      u32 offset, u32 size)
{
	int i = skb_shinfo(skb)->nr_frags;
	skb_frag_t *frag = &skb_shinfo(skb)->frags[i];

	frag->page = page;
	frag->page_offset = offset;
	frag->size = size;

	skb->len += size;
	skb->data_len += size;
	skb->truesize += size;

	skb_shinfo(skb)->nr_frags = i + 1;
}

static struct page *sxge_find_rxpage(struct rx_ring_info *rxringp,
				    u64 buf_index)
{
	struct page *p;

	p = rxringp->rxpage[buf_index];

	return p;
}

static void sxge_save_page_info(struct rx_ring_info *rxringp,
			struct page *page, u64 base, int idx)
{
	page->index = base;
	rxringp->rxpage[idx] = page;
	rxringp->saved_base[idx] = base;
}

static int sxge_rbr_add_page(struct sxge *sxgep, struct rx_ring_info *rxringp,
			gfp_t mask, int start_index)
{
	struct page *page;
	u64 addr;
	int i;

	page = alloc_page(mask);
	if (!page)
		return -ENOMEM;

	addr = sxgep->ops->map_page(sxgep->device, page, 0,
					PAGE_SIZE, DMA_FROM_DEVICE);

	if (rxringp->rbr_blocks_per_page > 1)
		atomic_add(rxringp->rbr_blocks_per_page - 1,
			&compound_head(page)->_count);

	for (i = 0; i < rxringp->rbr_blocks_per_page; i++) {
		__le64 *rbr = &rxringp->rbr[start_index + i];
		u64 buf_index = (u64)(start_index + i);

		sxge_save_page_info(rxringp, page, addr, start_index + i);
		*rbr = (buf_index << RBR_DESCR_INDEX_SHIFT) |
			cpu_to_le64(addr >> RBR_DESCR_ADDR_SHIFT);
		addr += rxringp->rbr_block_size;
	}

	return 0;
}

static int sxge_rbr_refill(struct sxge *sxgep, struct rx_ring_info *rxringp,
			gfp_t mask)
{
	int index = rxringp->rbr_index;

	rxringp->rbr_pending++;
	if ((rxringp->rbr_pending % rxringp->rbr_blocks_per_page) == 0) {
		int err = sxge_rbr_add_page(sxgep, rxringp, mask, index);

		if (unlikely(err)) {
			rxringp->rbr_pending--;
			return -1;
		}

		rxringp->rbr_index += rxringp->rbr_blocks_per_page;
		if (rxringp->rbr_index == rxringp->rbr_table_size)
			rxringp->rbr_index = 0;

		if (rxringp->rbr_pending >= rxringp->rbr_kick_thresh) {
			if ((rxringp->rbr_tail + rxringp->rbr_pending) >=
				rxringp->rbr_table_size) {
				rxringp->rbr_tail_wrap ^=
							RDC_KICK_RBR_TAIL_WRAP;
				rxringp->rbr_tail = rxringp->rbr_tail +
					rxringp->rbr_pending -
					rxringp->rbr_table_size;
			} else {
				rxringp->rbr_tail = rxringp->rbr_tail +
					rxringp->rbr_pending;
			}
			SXGE_PUT64(RDC_KICK(rxringp->rdc_base),
				RDC_KICK_RBR_TAIL_UP_VLD |
				rxringp->rbr_tail_wrap |
				(rxringp->rbr_tail & RDC_KICK_RBR_TAIL));
			rxringp->rbr_pending = 0;
		}
	}

	return 0;
}

static int sxge_rx_pkt_ignore(struct sxge *sxgep,
				struct rx_ring_info *rxringp, u32 pending_rcr)
{
	unsigned int index = rxringp->rcr_index;
	int num_rcr = 0;

	rxringp->rx_dropped++;
	while (1) {
		struct page *page;
		u64 buf_index, val, val_next;
		u32 index_next;

		val = le64_to_cpup(&rxringp->rcr[index]);
		if ((pending_rcr == 2) && (val & RCR_ENTRY_MULTI)) {
			index_next = NEXT_RCR(rxringp, index);
			val_next = le64_to_cpup(&rxringp->rcr[index_next]);

			if (val_next & RCR_ENTRY_MULTI)
				return num_rcr;
		}

		if (pending_rcr == 1) {
			if (val & RCR_ENTRY_MULTI)
				return num_rcr;
		}

		num_rcr++;
		if (num_rcr > pending_rcr) {
			netdev_err(sxgep->dev, "%s(): Try to process haven't "
				"RX pkt num_rcr 0x%x, pending_rcr 0x%x\n",
				__func__, num_rcr, pending_rcr);
			break;
		}

		buf_index = val & RCR_ENTRY_INDEX;
		page = sxge_find_rxpage(rxringp, buf_index);

		if (val & RCR_ENTRY_LAST_PKT_PER_BUF) {
			sxgep->ops->unmap_page(sxgep->device, page->index,
					    PAGE_SIZE, DMA_FROM_DEVICE);
			page->index = 0;
			__free_page(page);
			rxringp->rxpage[buf_index] = NULL;
			rxringp->rbr_refill_pending++;
		}

		index = NEXT_RCR(rxringp, index);
		if (!(val & RCR_ENTRY_MULTI))
			break;

	}

	if ((index == 0) &&
		(rxringp->rcr_index == (rxringp->rcr_table_size - 1))) {
		rxringp->rcr_head_wrap ^= RDC_KICK_RCR_HEAD_WRAP;
	} else if (index < rxringp->rcr_index) {
		rxringp->rcr_head_wrap ^= RDC_KICK_RCR_HEAD_WRAP;
	}
	rxringp->rcr_index = index;

	return num_rcr;
}

static int sxge_process_rx_pkt(struct napi_struct *napi, struct sxge *sxgep,
				struct rx_ring_info *rxringp, u32 pending_rcr)
{
	unsigned int index = rxringp->rcr_index;
	struct sk_buff *skb;
	int len, num_rcr;

	skb = netdev_alloc_skb(sxgep->dev, RX_SKB_ALLOC_SIZE);
	if (unlikely(!skb))
		return sxge_rx_pkt_ignore(sxgep, rxringp, pending_rcr);

	num_rcr = 0;
	while (1) {
		struct page *page;
		u32 rcr_size, append_size, index_next;
		u64 buf_index, val, val_next, off;

		val = le64_to_cpup(&rxringp->rcr[index]);
		if ((pending_rcr == 2) && (val & RCR_ENTRY_MULTI)) {
			index_next = NEXT_RCR(rxringp, index);
			val_next = le64_to_cpup(&rxringp->rcr[index_next]);

			if (val_next & RCR_ENTRY_MULTI) {
				dev_kfree_skb(skb);
				return num_rcr;
			}
		}

		if (pending_rcr == 1) {
			if (val & RCR_ENTRY_MULTI) {
				dev_kfree_skb(skb);
				return num_rcr;
			}
		}

		num_rcr++;
		if (num_rcr > pending_rcr) {
			netdev_err(sxgep->dev, "%s(): Try to process haven't "
				"RX pkt num_rcr 0x%x, pending_rcr 0x%x\n",
				 __func__, num_rcr, pending_rcr);
			break;
		}

		len = (val & RCR_ENTRY_PKT_SEG_LEN) >>
			RCR_ENTRY_PKT_SEG_LEN_SHIFT;

		buf_index = val & RCR_ENTRY_INDEX;
		page = sxge_find_rxpage(rxringp, buf_index);

		rcr_size = rxringp->rbr_sizes[(val & RCR_ENTRY_PKTBUFSZ) >>
					 RCR_ENTRY_PKTBUFSZ_SHIFT];

		off = ((val & RCR_ENTRY_SUBINDEX) >> RCR_ENTRY_SUBINDEX_SHIFT) *
			rcr_size;
		append_size = rcr_size;
		if (num_rcr == 1) {
			u64	class_code;

			class_code = (val & RCR_ENTRY_PKT_CLASS_CODE) >>
				RCR_ENTRY_PKT_CLASS_CODE_SHIFT;
			if ((class_code & CLS_CODE_TCP_UDP) &&
				!(val & RCR_ENTRY_PKT_ERR)) {
				skb->ip_summed = CHECKSUM_UNNECESSARY;
			} else
				skb_checksum_none_assert(skb);
		}

		if (!(val & RCR_ENTRY_MULTI))
			append_size = len;

		sxge_rx_skb_append(skb, page, off, append_size);
		if (val & RCR_ENTRY_LAST_PKT_PER_BUF) {
			sxgep->ops->unmap_page(sxgep->device, page->index,
					    PAGE_SIZE, DMA_FROM_DEVICE);
			page->index = 0;
			rxringp->rxpage[buf_index] = NULL;
			rxringp->rbr_refill_pending++;
		} else
			get_page(page);

		index = NEXT_RCR(rxringp, index);
		if (!(val & RCR_ENTRY_MULTI))
			break;
	}

	if ((index == 0) &&
		(rxringp->rcr_index == (rxringp->rcr_table_size - 1))) {
		rxringp->rcr_head_wrap ^= RDC_KICK_RCR_HEAD_WRAP;
	} else if (index < rxringp->rcr_index) {
		rxringp->rcr_head_wrap ^= RDC_KICK_RCR_HEAD_WRAP;
	}
	rxringp->rcr_index = index;

	skb_reserve(skb, NET_IP_ALIGN);
	__pskb_pull_tail(skb, min(skb->len, (uint) VLAN_ETH_HLEN));

	rxringp->rx_packets++;
	rxringp->rx_bytes += skb->len;

	skb->protocol = eth_type_trans(skb, sxgep->dev);
	skb_record_rx_queue(skb, rxringp->rx_channel);
	napi_gro_receive(napi, skb);

	return num_rcr;
}

static int release_tx_packet(struct sxge *sxgep, struct tx_ring_info *txringp,
				int idx)
{
	struct tx_buff_info *tb = &txringp->tx_buffs[idx];
	struct sk_buff *skb = tb->skb;
	struct tx_pkt_hdr *tp;
	u64 tx_flags;
	int i, len;

	if (!skb) {
		netdev_err(sxgep->dev, "%s(): NULL SKB\n", __func__);
		return idx;
	}

	len = skb_headlen(skb);
	txringp->tx_packets++;

	if (txringp->tdc_prsr_en != 1) {
		tp = (struct tx_pkt_hdr *) skb->data;
		tx_flags = le64_to_cpup(&tp->flags);

		txringp->tx_bytes += (((tx_flags & TXHDR_LEN) >>
			TXHDR_LEN_SHIFT) - ((tx_flags & TXHDR_PAD) / 2));
	} else {
		txringp->tx_bytes += len;
	}

	sxgep->ops->unmap_single(sxgep->device, tb->mapping,
			      len, DMA_TO_DEVICE);

	if (le64_to_cpu(txringp->descr[idx]) & TX_DESC_MARK)
		txringp->mark_pending--;

	tb->skb = NULL;
	do {
		idx = NEXT_TX(txringp, idx);
		len -= MAX_TX_DESC_LEN;
	} while (len > 0);

	for (i = 0; i < skb_shinfo(skb)->nr_frags; i++) {
		tb = &txringp->tx_buffs[idx];
		BUG_ON(tb->skb != NULL);
		sxgep->ops->unmap_page(sxgep->device, tb->mapping,
				    skb_shinfo(skb)->frags[i].size,
				    DMA_TO_DEVICE);
		txringp->tx_bytes += skb_shinfo(skb)->frags[i].size;
		idx = NEXT_TX(txringp, idx);
	}

	dev_kfree_skb(skb);

	return idx;
}

#define	SXGE_TX_WAKEUP_THRESH(txringp)		((txringp)->pending / 4)

static void sxge_tx_work(struct sxge *sxgep, struct tx_ring_info *txringp)
{
	struct netdev_queue *txq;
	u16 pkt_cnt, tmp;
	int cons, index;
	u64 cs;

	index = (txringp - sxgep->tx_rings);
	txq = netdev_get_tx_queue(sxgep->dev, index);

	cs = txringp->tx_cs;
	if (unlikely(!(cs & (TDC_CS_MK | TDC_CS_MMK))))
		goto out;

	tmp = pkt_cnt = (cs & TDC_CS_PKT_CNT) >> TDC_CS_PKT_CNT_SHIFT;
	pkt_cnt = (pkt_cnt - txringp->last_pkt_cnt) &
		(TDC_CS_PKT_CNT >> TDC_CS_PKT_CNT_SHIFT);

	txringp->last_pkt_cnt = tmp;

	cons = txringp->cons;

	while (pkt_cnt--)
		cons = release_tx_packet(sxgep, txringp, cons);

	txringp->cons = cons;
	smp_mb();

out:
	if (unlikely(netif_tx_queue_stopped(txq) &&
		(sxge_tx_avail(txringp) > SXGE_TX_WAKEUP_THRESH(txringp)))) {
		__netif_tx_lock(txq, smp_processor_id());
		if (netif_tx_queue_stopped(txq) &&
			(sxge_tx_avail(txringp) >
			SXGE_TX_WAKEUP_THRESH(txringp)))
			netif_tx_wake_queue(txq);
		__netif_tx_unlock(txq);
	}
}

static int sxge_rx_work(struct napi_struct *napi, struct sxge *sxgep,
			struct rx_ring_info *rxringp, int budget)
{
	int qlen = 0, rcr_done = 0, work_done = 0;
	struct rxdma_mailbox *mbox = rxringp->mbox;
	u64 stat = 0, kick = 0, qlen_seg = 0;
	u64 rcrhead_index;

	/* flush RCR to force the update */
	SXGE_PUT64(RDC_FLSH(rxringp->rdc_base), 0x1);

	kick = SXGE_GET64(RDC_KICK(rxringp->rdc_base));
	stat = SXGE_GET64(RDC_CTL_STAT(rxringp->rdc_base));
	rcrhead_index = (u64) rxringp->rcr_index;
	rxringp->rcr_tail_wrap = stat & RDC_CTL_STAT_TAIL_WRAP;

	netif_printk(sxgep, rx_status, KERN_DEBUG, sxgep->dev,
		"%s(chan[%d]), stat[%llx] kick[%llx]\n",
		__func__, rxringp->rx_channel, stat, kick);

	if ((rxringp->rcr_tail_wrap >> RDC_CTL_STAT_TAIL_WRAP_SHIFT) !=
		(rxringp->rcr_head_wrap >> RDC_KICK_RCR_HEAD_WRAP_SHIFT))
		qlen_seg =  rxringp->rcr_table_size - rcrhead_index +
			((stat & RDC_CTL_STAT_TAIL) >> RDC_CTL_STAT_TAIL_SHIFT);
	else
		qlen_seg = ((stat & RDC_CTL_STAT_TAIL) >>
			RDC_CTL_STAT_TAIL_SHIFT) - rcrhead_index;

	mbox->rx_dma_ctl_stat = 0;
	mbox->rbr_tail_rcr_head = 0;

	rcr_done = work_done = 0;
	qlen = (u32) qlen_seg;
	qlen = min(qlen, budget);
	while (rcr_done < qlen) {
		u32 rcr_num;

		rcr_num = sxge_process_rx_pkt(napi, sxgep, rxringp,
			qlen - rcr_done);
		if (!rcr_num)
			break;
		rcr_done += rcr_num;
		work_done++;
	}

	if (rxringp->rbr_refill_pending >= rxringp->rbr_kick_thresh) {
		unsigned int i, err, refill_pending_left = 0;

		for (i = 0; i < rxringp->rbr_refill_pending; i++) {
			err = sxge_rbr_refill(sxgep, rxringp, GFP_ATOMIC);
			if (err)
				refill_pending_left++;
		}
		if (refill_pending_left) {
			rxringp->rbr_refill_pending = refill_pending_left;
			pr_info("No memeory to refill buffers "
				"stat 0x%llx, kick 0x%llx, "
				"rcrhead_index 0x%llx\n",
				stat, kick, rcrhead_index);
		} else
			rxringp->rbr_refill_pending = 0;
	}

	if (rcr_done)
		SXGE_PUT64(RDC_KICK(rxringp->rdc_base),
			RDC_KICK_RCR_HEAD_UP_VLD | rxringp->rcr_head_wrap |
			((rxringp->rcr_index << RDC_KICK_RCR_HEAD_PT_SHIFT) &
			RDC_KICK_RCR_HEAD_PT));

	if (stat & RDC_CTL_STAT_PKTCNT_OVERFLOW)
		rxringp->rx_hw_pktcnt +=
			SXGE_GET64(RDC_PKTCNT(rxringp->rdc_base)) &
			RDC_PKTCNT_COUNT;
	if (stat & RDC_CTL_STAT_DROPCNT_OVERFLOW)
		rxringp->rx_hw_pktdrop +=
			SXGE_GET64(RDC_PKTDROP(rxringp->rdc_base)) &
			RDC_PKTDROP_COUNT;
	if (stat & RDC_CTL_STAT_RBR_EMPTY)
		rxringp->rx_rbr_empty++;

	if (!rxringp->rbr_refill_pending) {
		SXGE_PUT64(RDC_CTL_STAT(rxringp->rdc_base),
			stat & RDC_CTL_STAT_WRITE_CLEAR_INT);
	} else {
		SXGE_PUT64(RDC_CTL_STAT(rxringp->rdc_base),
			(stat & RDC_CTL_STAT_WRITE_CLEAR_INT) &
			~RDC_CTL_STAT_RBR_EMPTY);
	}

	return work_done;
}

static int sxge_poll_core(struct sxge *sxgep, struct sxge_ldg *lp, int budget)
{
	u64 v = lp->v;
	u32 tx_vec = (v >> 4) & 0xf;
	u32 rx_vec = (v & 0xf);
	int i, work_done = 0;
	u8 vni = sxgep->vni, intmgmt_nf = sxgep->intmgmt_nf;
	u64 val;

	netif_printk(sxgep, intr, KERN_DEBUG, sxgep->dev,
		"%s() v[%016llx]\n", __func__, (unsigned long long)v);

	for (i = 0; i < sxgep->num_rings; i++) {
		struct tx_ring_info *txringp = &sxgep->tx_rings[i];

		if (tx_vec & (1 << txringp->tx_channel))
			sxge_tx_work(sxgep, txringp);
		val = SXGE_GET64(LD_MSK_GNUM(vni, intmgmt_nf,
			LDN_TXDMA(txringp->tx_channel)));
		val &= ~LD_MSK_GNUM_LDG_MSK;
		SXGE_PUT64(LD_MSK_GNUM(vni, intmgmt_nf,
			LDN_TXDMA(txringp->tx_channel)),
			val | LD_MSK_GNUM_EN_MSK_WR);
	}

	for (i = 0; i < sxgep->num_rings; i++) {
		struct rx_ring_info *rxringp = &sxgep->rx_rings[i];

		if (rx_vec & (1 << rxringp->rx_channel)) {
			int this_work_done;

			this_work_done = sxge_rx_work(&lp->napi, sxgep,
							rxringp, budget);

			budget -= this_work_done;
			work_done += this_work_done;
		}
		val = SXGE_GET64(LD_MSK_GNUM(vni, intmgmt_nf,
			LDN_RXDMA(rxringp->rx_channel)));
		val &= ~LD_MSK_GNUM_LDG_MSK;
		SXGE_PUT64(LD_MSK_GNUM(vni, intmgmt_nf,
			LDN_RXDMA(rxringp->rx_channel)),
			val | LD_MSK_GNUM_EN_MSK_WR);
	}

	return work_done;
}

static int sxge_poll(struct napi_struct *napi, int budget)
{
	struct sxge_ldg *lp = container_of(napi, struct sxge_ldg, napi);
	struct sxge *sxgep = lp->sxgep;
	int work_done = 0;

	work_done = sxge_poll_core(sxgep, lp, budget);

	if (work_done < budget) {
		napi_complete(napi);
		sxge_ldg_rearm(sxgep, lp, 1);
	}
	return work_done;
}

static void sxge_log_rxchan_errors(struct sxge *sxgep,
				  struct rx_ring_info *rxringp, u64 stat)
{
	netdev_err(sxgep->dev, "RX channel %u errors ( ", rxringp->rx_channel);

	if (stat & RDC_CTL_STAT_REQ_REJECT)
		pr_cont("REQ_REJECT ");
	if (stat & RDC_CTL_STAT_RBR_TIMEOUT)
		pr_cont("RBR_TIMEOUT ");
	if (stat & RDC_CTL_STAT_RSP_DAT_ERR)
		pr_cont("RSP_DAT_ERR ");
	if (stat & RDC_CTL_STAT_RCR_ACK_ERR)
		pr_cont("RCR_ACK_ERR ");
	if (stat & RDC_CTL_STAT_RCR_SHA_PAR)
		pr_cont("RCR_SHA_PAR ");
	if (stat & RDC_CTL_STAT_RBR_PRE_PAR)
		pr_cont("RBR_PRE_PAR ");
	if (stat & RDC_CTL_STAT_RCR_UNDERFLOW)
		pr_cont("RCR_UNDERFLOW ");
	if (stat & RDC_CTL_STAT_RBR_OVERFLOW)
		pr_cont("RBR_OVERFLOW ");

	pr_cont(")\n");
}

static int sxge_rx_error(struct sxge *sxgep, struct rx_ring_info *rxringp)
{
	u64 stat, err_log;
	int err = 0;

	stat = SXGE_GET64(RDC_CTL_STAT(rxringp->rdc_base));
	err_log = SXGE_GET64(RDC_RNG_ERR_LOG(rxringp->rdc_base));

	if (stat & RDC_CTL_STAT_CHAN_FATAL)
		err = -EINVAL;

	if (err) {
		netdev_err(sxgep->dev, "RX channel %u error, "
			"stat[%llx] err_log[%llx]\n",
			rxringp->rx_channel,
			(unsigned long long) stat,
			(unsigned long long) err_log);

		sxge_log_rxchan_errors(sxgep, rxringp, stat);
		schedule_work(&sxgep->reset_task);
	}

#if 0	/* Can't clear it from the STAT reg, has to do it in the STAT_DBG */
	/* Will be fixed in the next ASIC? */
	if (stat & RDC_CTL_STAT_FIFO_ERR)
		rxringp->rx_fifo_error++;

	if (stat & RDC_CTL_STAT_RCR_SHADOW_FULL)
		rxringp->rx_rcr_shadow_full++;

	if (stat & RDC_CTL_STAT_WRITE_CLEAR_ERRS)
		SXGE_PUT64(RDC_CTL_STAT_DBG(rxringp->rdc_base), 0);
#endif

	return err;
}


static void sxge_log_txchan_errors(struct sxge *sxgep,
				   struct tx_ring_info *txringp, u64 cs)
{
	netdev_err(sxgep->dev, "TX channel %u errors ( ", txringp->tx_channel);

	if (cs & TDC_CS_REJECT_RESP_ERR)
		pr_cont("REJECT_RESP_ERR ");
	if (cs & TDC_CS_SOP_BIT_ERR)
		pr_cont("SOP_BIT_ERR ");
	if (cs & TDC_CS_PREMATURE_SOP_ERR)
		pr_cont("PREMATURE_SOP_ERR ");
	if (cs & TDC_CS_DESC_LENGTH_ERR)
		pr_cont("DESC_LENGTH_ERR ");
	if (cs & TDC_CS_DESC_NUM_PTR_ERR)
		pr_cont("DESC_NUM_PTR_ERR ");
	if (cs & TDC_CS_MBOX_ERR)
		pr_cont("MBOX_ERR ");
	if (cs & TDC_CS_PKT_SIZE_ERR)
		pr_cont("PKT_SIZE_ERR ");
	if (cs & TDC_CS_TX_RING_OFLOW)
		pr_cont("TX_RING_OFLOW ");
	if (cs & TDC_CS_PREF_BUF_PAR_ERR)
		pr_cont("PREF_BUF_PAR_ERR ");
	if (cs & TDC_CS_NACK_PREF)
		pr_cont("NACK_PREF ");
	if (cs & TDC_CS_NACK_PKT_RD)
		pr_cont("NACK_PKT_RD ");
	if (cs & TDC_CS_CONF_PART_ERR)
		pr_cont("CONF_PART_ERR ");
	if (cs & TDC_CS_PKT_PRT_ERR)
		pr_cont("PKT_PRT_ERR ");

	pr_cont(")\n");
}

static int sxge_tx_error(struct sxge *sxgep, struct tx_ring_info *txringp)
{
	u64 cs, logh, logl;

	cs = SXGE_GET64(TDC_CS(txringp->tdc_base));
	logh = SXGE_GET64(TDC_RNG_ERR_LOGH(txringp->tdc_base));
	logl = SXGE_GET64(TDC_RNG_ERR_LOGL(txringp->tdc_base));

	netdev_err(sxgep->dev, "TX channel %u error, "
		"cs[%llx] logh[%llx] logl[%llx]\n",
		txringp->tx_channel,
		(unsigned long long) cs,
		(unsigned long long) logh,
		(unsigned long long) logl);

	sxge_log_txchan_errors(sxgep, txringp, cs);
	schedule_work(&sxgep->reset_task);

	return -ENODEV;
}

static int sxge_txvmac_interrupt(struct sxge *sxgep)
{
	struct sxge_vmac_stats *vmp = &sxgep->vmac_stats;
	u64 val;

	val = SXGE_GET64(TXVMAC_STAT(sxgep->vni, sxgep->vmac));
	if (val & TXVMAC_STAT_TX_BYTE_CNT_OVL) {
		vmp->txvmac_byte_cnt_ovl++;
		vmp->txvmac_frames += SXGE_GET64(
			TXVMAC_FRM_CNT(sxgep->vni, sxgep->vmac));
	}
	if (val & TXVMAC_STAT_TX_FRAME_CNT_OVL) {
		vmp->txvmac_frame_cnt_ovl++;
		vmp->txvmac_bytes += SXGE_GET64(
			TXVMAC_BYT_CNT(sxgep->vni, sxgep->vmac));
	}

	SXGE_PUT64(TXVMAC_STAT(sxgep->vni, sxgep->vmac),
		(val & TXVMAC_STAT_SW_RST_DONE) |
		(val & TXVMAC_STAT_TX_BYTE_CNT_OVL) |
		(val & TXVMAC_STAT_TX_FRAME_CNT_OVL));

	return 0;
}

static int sxge_rxvmac_interrupt(struct sxge *sxgep)
{
	struct sxge_vmac_stats *vmp = &sxgep->vmac_stats;
	u64 val;
	u8 vni = sxgep->vni, vmac = sxgep->vmac;
	struct sxge_link_config *linkp = &sxgep->link_config;
	struct net_device *dev = sxgep->dev;

	val = SXGE_GET64(RXVMAC_STAT(sxgep->vni, sxgep->vmac));
	if (val & RXVMAC_STAT_FRAME_CNT_OVL) {
		vmp->rxvmac_frames_cnt_ovl++;
		vmp->rxvmac_frames +=
			SXGE_GET64(RXVMAC_FRM_CNT(vni, vmac));
	}
	if (val & RXVMAC_STAT_BYTE_CNT_OVL) {
		vmp->rxvmac_byte_cnt_ovl++;
		vmp->rxvmac_bytes +=
			SXGE_GET64(RXVMAC_BYT_CNT(vni, vmac));
	}
	if (val & RXVMAC_STAT_DROP_CNT_OVL) {
		vmp->rxvmac_drop_cnt_ovl++;
		vmp->rxvmac_drops +=
			SXGE_GET64(RXVMAC_DROP_CNT(vni, vmac));
	}
	if (val & RXVMAC_STAT_DROP_BYTE_OVL) {
		vmp->rxvmac_drop_byte_ovl++;
		vmp->rxvmac_drop_bytes +=
			SXGE_GET64(RXVMAC_DROPBYT_CNT(vni, vmac));
	}
	if (val & RXVMAC_STAT_MCAST_FRAME_CNT_OVL) {
		vmp->rxvmac_mcast_frame_cnt_ovl++;
		vmp->rxvmac_mcasts +=
			SXGE_GET64(RXVMAC_MCAST_CNT(vni, vmac));
	}
	if (val & RXVMAC_STAT_BCAST_FRAME_CNT_OVL) {
		vmp->rxvmac_bcast_frame_cnt_ovl++;
		vmp->rxvmac_bcasts +=
			SXGE_GET64(RXVMAC_BCAST_CNT(vni, vmac));
	}
	if (val & RXVMAC_STAT_LINK_UP) {
		vmp->rxvmac_link_up = 1;
		vmp->rxvmac_link_down = 0;
	}
	if (val & RXVMAC_STAT_LINK_DOWN) {
		vmp->rxvmac_link_down = 1;
		vmp->rxvmac_link_up = 0;
	}
	if (val & RXVMAC_STAT_LINK_STATE) {
		vmp->rxvmac_link_state = 1;
		vmp->rxvmac_link_up = 1;
		vmp->rxvmac_link_down = 0;
	} else {
		vmp->rxvmac_link_state = 0;
		vmp->rxvmac_link_up = 0;
		vmp->rxvmac_link_down = 1;
	}

	if (!netif_carrier_ok(dev) && vmp->rxvmac_link_state) {
		netif_info(sxgep, link, dev, "Link is up at %s\n",
			(linkp->active_speed == SPEED_40000 ?
			"40Gb/sec" : "10Gb/sec"));
		netif_carrier_on(dev);
	} else if (netif_carrier_ok(dev) && !vmp->rxvmac_link_state) {
		netif_warn(sxgep, link, dev, "Link is down\n");
		netif_carrier_off(dev);
	}

	SXGE_PUT64(RXVMAC_STAT(sxgep->vni, sxgep->vmac),
		(val & RXVMAC_STAT_LINK_UP) |
		(val & RXVMAC_STAT_LINK_DOWN));

	return 0;
}

static int sxge_mailbox_interrupt(struct sxge *sxgep)
{
	u64 val = SXGE_GET64(SXGE_MB_STAT);
#if 1
	netdev_info(sxgep->dev, "%s: mailbox_interrupt mb_stat 0x%llx\n",
		__func__, val);
#endif
	return 0;
}

static int sxge_vni_error(struct sxge *sxgep)
{
#if 1
	netdev_info(sxgep->dev, "%s: vni_error_interrupt\n", __func__);
#endif
	return 0;
}

static int sxge_slowpath_interrupt(struct sxge *sxgep, struct sxge_ldg *lp,
				u64 v)
{
	int i, err = 0;

	lp->v = v;

	if (v & LDSV_V1_RXDMA) {
		u32 rx_vec = (v >> 16) & 0xf;

		for (i = 0; i < sxgep->num_rings; i++) {
			struct rx_ring_info *rxringp = &sxgep->rx_rings[i];

			if (rx_vec & (1 << rxringp->rx_channel)) {
				int r = sxge_rx_error(sxgep, rxringp);
				if (r)
					err = r;
			}
		}
	}
	if (v & LDSV_V1_TXDMA) {
		u32 tx_vec = (v >> 20) & 0xf;

		for (i = 0; i < sxgep->num_rings; i++) {
			struct tx_ring_info *txringp = &sxgep->tx_rings[i];

			if (tx_vec & (1 << txringp->tx_channel)) {
				int r = sxge_tx_error(sxgep, txringp);
				if (r)
					err = r;
			}
		}
	}


	if (v & LDSV_V0_MAILBOX) {
		int r = sxge_mailbox_interrupt(sxgep);
		if (r)
			err = r;
	}

	if (v & LDSV_V0_RXVMAC) {
		int r = sxge_rxvmac_interrupt(sxgep);
		if (r)
			err = r;
	}

	if (v & LDSV_V0_TXVMAC) {
		int r = sxge_txvmac_interrupt(sxgep);
		if (r)
			err = r;
	}

	if (v & LDSV_V1_VNI_ERROR) {
		int r = sxge_vni_error(sxgep);
		if (r)
			err = r;
	}

	if (err)
		sxge_enable_interrupts(sxgep, 0);

	return err;
}

static void sxge_rxchan_intr(struct sxge *sxgep, struct rx_ring_info *rxringp,
			    int ldn)
{
#if 0
	struct rxdma_mailbox *mbox = rxringp->mbox;
	u64 stat_write, stat = le64_to_cpup(&mbox->rx_dma_ctl_stat);

	stat_write = (RDC_CTL_STAT_RCRTHRES |
		      RDC_CTL_STAT_RCRTO);

	SXGE_PUT64(RDC_CTL_STAT(rxringp->rdc_base), stat_write);
	netif_printk(sxgep, intr, KERN_DEBUG, sxgep->dev,
		"%s: rxchan_intr stat[%llx]\n",
		__func__, (unsigned long long) stat);
#endif
}

static void sxge_txchan_intr(struct sxge *sxgep, struct tx_ring_info *txringp,
			    int ldn)
{
	txringp->tx_cs = SXGE_GET64(TDC_CS(txringp->tdc_base));

	netif_printk(sxgep, intr, KERN_DEBUG, sxgep->dev, "%s() cs[%llx]\n",
		__func__, (unsigned long long)txringp->tx_cs);
}

static void __sxge_fastpath_interrupt(struct sxge *sxgep, int ldg, u64 v)
{
	u32 rx_vec, tx_vec;
	int i;

	tx_vec = (v >> 4) & 0xf;
	rx_vec = (v & 0xf);

	for (i = 0; i < sxgep->num_rings; i++) {
		struct rx_ring_info *rxringp = &sxgep->rx_rings[i];
		int ldn = LDN_RXDMA(rxringp->rx_channel);

		if (sxgep->ldg_map[ldn] != ldg)
			continue;

		SXGE_PUT64(LD_MSK_GNUM(sxgep->vni, sxgep->intmgmt_nf, ldn),
			LD_MSK_GNUM_LDG_MSK | LD_MSK_GNUM_EN_MSK_WR);
		if (rx_vec & (1 << rxringp->rx_channel))
			sxge_rxchan_intr(sxgep, rxringp, ldn);
	}

	for (i = 0; i < sxgep->num_rings; i++) {
		struct tx_ring_info *txringp = &sxgep->tx_rings[i];
		int ldn = LDN_TXDMA(txringp->tx_channel);

		if (sxgep->ldg_map[ldn] != ldg)
			continue;

		SXGE_PUT64(LD_MSK_GNUM(sxgep->vni, sxgep->intmgmt_nf, ldn),
			LD_MSK_GNUM_LDG_MSK | LD_MSK_GNUM_EN_MSK_WR);
		if (tx_vec & (1 << txringp->tx_channel))
			sxge_txchan_intr(sxgep, txringp, ldn);
	}
}

static void sxge_schedule_napi(struct sxge *sxgep, struct sxge_ldg *lp, u64 v)
{
	if (likely(napi_schedule_prep(&lp->napi))) {
		lp->v = v;
		__sxge_fastpath_interrupt(sxgep, lp->ldg_num, v);
		__napi_schedule(&lp->napi);
	}
}

static irqreturn_t sxge_interrupt(int irq, void *dev_id)
{
	struct sxge_ldg *lp = dev_id;
	struct sxge *sxgep = lp->sxgep;
	int ldg = lp->ldg_num;
	unsigned long flags;
	u64 v;

	if (netif_msg_intr(sxgep))
		printk(KERN_DEBUG KBUILD_MODNAME ": " "%s() ldg[%p](%d) ",
			__func__, lp, ldg);

	spin_lock_irqsave(&sxgep->lock, flags);

	v = SXGE_GET64(LDSV(sxgep->vni, sxgep->intmgmt_nf, ldg));

	if (netif_msg_intr(sxgep))
		pr_cont("v[%llx]\n", (unsigned long long) v);

	if (unlikely(!v)) {
		spin_unlock_irqrestore(&sxgep->lock, flags);
		return IRQ_NONE;
	}

	if (unlikely(v & (LDSV_LDSV1_MASK | LDSV_V0_TXVMAC |
		LDSV_V0_RXVMAC | LDSV_V0_MAILBOX))) {
		int err = sxge_slowpath_interrupt(sxgep, lp, v);
		if (err)
			goto out;
	}

	if (likely(v & (LDSV_V0_TXDMA | LDSV_V0_RXDMA)))
		sxge_schedule_napi(sxgep, lp, v);
	else
		sxge_ldg_rearm(sxgep, lp, 1);

out:
	spin_unlock_irqrestore(&sxgep->lock, flags);

	return IRQ_HANDLED;
}

static int sxge_alloc_rx_ring_info(struct sxge *sxgep,
				struct rx_ring_info *rxringp)
{
	rxringp->rxpage = kzalloc(MAX_RBR_RING_SIZE * sizeof(struct page *),
		GFP_KERNEL);

	if (!rxringp->rxpage)
		return -ENOMEM;

	rxringp->mbox = sxgep->ops->alloc_coherent(sxgep->device,
		sizeof(struct rxdma_mailbox),
		&rxringp->mbox_dma, GFP_KERNEL);
	if (!rxringp->mbox)
		return -ENOMEM;
	if ((unsigned long)rxringp->mbox & (64UL - 1)) {
		netdev_err(sxgep->dev, "Coherent alloc gives misaligned "
			"RXDMA mailbox %p\n", rxringp->mbox);
		return -EINVAL;
	}

	rxringp->rcr = sxgep->ops->alloc_coherent(sxgep->device,
			MAX_RCR_RING_SIZE * sizeof(__le64),
			&rxringp->rcr_dma, GFP_KERNEL);
	if (!rxringp->rcr)
		return -ENOMEM;
	if ((unsigned long)rxringp->rcr & (64UL - 1)) {
		netdev_err(sxgep->dev, "Coherent alloc gives misaligned "
			"RXDMA RCR table %p\n", rxringp->rcr);
		return -EINVAL;
	}
	rxringp->rcr_table_size = MAX_RCR_RING_SIZE;
	rxringp->rcr_index = 0;
	rxringp->rcr_head_wrap = 0;
	rxringp->rcr_tail_wrap = 0;

	rxringp->rbr = sxgep->ops->alloc_coherent(sxgep->device,
			MAX_RBR_RING_SIZE * sizeof(__le64),
			&rxringp->rbr_dma, GFP_KERNEL);
	if (!rxringp->rbr)
		return -ENOMEM;
	if ((unsigned long)rxringp->rbr & (64UL - 1)) {
		netdev_err(sxgep->dev, "Coherent alloc gives misaligned "
			"RXDMA RBR table %p\n", rxringp->rbr);
		return -EINVAL;
	}
	rxringp->rbr_table_size = MAX_RBR_RING_SIZE;
	rxringp->rbr_index = 0;
	rxringp->rbr_pending = 0;
	rxringp->rbr_tail = 0;
	rxringp->rbr_tail_wrap = 0;
	rxringp->rbr_head_wrap = 0;

	return 0;
}

static void sxge_set_max_burst(struct sxge *sxgep, struct tx_ring_info *txringp)
{
	int mtu = sxgep->dev->mtu;

	/* These values are recommended by the HW designers for fair
	 * utilization of DRR amongst the rings.
	 */
	txringp->max_burst = mtu + 32;
	if (txringp->max_burst > 4096)
		txringp->max_burst = 4096;
}

static int sxge_alloc_tx_ring_info(struct sxge *sxgep,
				  struct tx_ring_info *txringp)
{
	BUILD_BUG_ON(sizeof(struct txdma_mailbox) != 64);

	txringp->mbox = sxgep->ops->alloc_coherent(sxgep->device,
					   sizeof(struct txdma_mailbox),
					   &txringp->mbox_dma, GFP_KERNEL);
	if (!txringp->mbox)
		return -ENOMEM;
	if ((unsigned long)txringp->mbox & (64UL - 1)) {
		netdev_err(sxgep->dev, "Coherent alloc gives misaligned "
			"TXDMA mailbox %p\n", txringp->mbox);
		return -EINVAL;
	}

	txringp->descr = sxgep->ops->alloc_coherent(sxgep->device,
					    MAX_TX_RING_SIZE * sizeof(__le64),
					    &txringp->descr_dma, GFP_KERNEL);
	if (!txringp->descr)
		return -ENOMEM;
	if ((unsigned long)txringp->descr & (64UL - 1)) {
		netdev_err(sxgep->dev, "Coherent alloc gives misaligned "
			"TXDMA descr table %p\n", txringp->descr);
		return -EINVAL;
	}

	txringp->pending = MAX_TX_RING_SIZE;
	txringp->prod = 0;
	txringp->cons = 0;
	txringp->wrap_bit = 0;

	/* XXX make these configurable... XXX */
	txringp->mark_freq = txringp->pending / 64;

	sxge_set_max_burst(sxgep, txringp);

	return 0;
}

static void sxge_size_rbr(struct sxge *sxgep, struct rx_ring_info *rxringp)
{
	u16 bss;

	bss = min(PAGE_SHIFT, 15);

	rxringp->rbr_block_size = 1 << bss;
	rxringp->rbr_blocks_per_page = 1 << (PAGE_SHIFT-bss);

	rxringp->rbr_sizes[0] = 256;
	rxringp->rbr_sizes[1] = 1024;
	if (sxgep->dev->mtu > ETH_DATA_LEN) {
		switch (PAGE_SIZE) {
		case 4 * 1024:
			rxringp->rbr_sizes[2] = 4096;
			break;

		default:
			rxringp->rbr_sizes[2] = 8192;
			break;
		}
	} else {
		rxringp->rbr_sizes[2] = 2048;
	}
	rxringp->rbr_sizes[3] = rxringp->rbr_block_size;
}

static int sxge_rbr_fill(struct sxge *sxgep, struct rx_ring_info *rxringp,
			gfp_t mask)
{
	int blocks_per_page = rxringp->rbr_blocks_per_page;
	int err, index = rxringp->rbr_index;

	err = 0;
	while (index < (rxringp->rbr_table_size - blocks_per_page)) {
		err = sxge_rbr_add_page(sxgep, rxringp, mask, index);
		if (err)
			break;
		index += blocks_per_page;
	}

	rxringp->rbr_index = index;

	return err;
}

static void sxge_rbr_free(struct sxge *sxgep, struct rx_ring_info *rxringp)
{
	int i;

	for (i = 0; i < MAX_RBR_RING_SIZE; i++) {
		struct page *page;

		page = rxringp->rxpage[i];
		if (page) {
			u64 base = page->index;

			sxgep->ops->unmap_page(sxgep->device,
				base, PAGE_SIZE,
				DMA_FROM_DEVICE);
			page->index = 0;
			__free_page(page);
		}
	}

	for (i = 0; i < rxringp->rbr_table_size; i++)
		rxringp->rbr[i] = cpu_to_le64(0);
	rxringp->rbr_index = 0;
	rxringp->rbr_tail = 0;
	rxringp->rbr_tail_wrap = 0;
	rxringp->rbr_head_wrap = 0;
}

static void sxge_free_rx_ring_info(struct sxge *sxgep,
					struct rx_ring_info *rxringp)
{
	if (rxringp->mbox) {
		sxgep->ops->free_coherent(sxgep->device,
				       sizeof(struct rxdma_mailbox),
				       rxringp->mbox, rxringp->mbox_dma);
		rxringp->mbox = NULL;
	}

	if (rxringp->rcr) {
		sxgep->ops->free_coherent(sxgep->device,
				       MAX_RCR_RING_SIZE * sizeof(__le64),
				       rxringp->rcr, rxringp->rcr_dma);
		rxringp->rcr = NULL;
		rxringp->rcr_table_size = 0;
		rxringp->rcr_index = 0;
		rxringp->rcr_head_wrap = 0;
		rxringp->rcr_tail_wrap = 0;
	}

	if (rxringp->rbr) {
		sxge_rbr_free(sxgep, rxringp);

		sxgep->ops->free_coherent(sxgep->device,
				       MAX_RBR_RING_SIZE * sizeof(__le64),
				       rxringp->rbr, rxringp->rbr_dma);
		rxringp->rbr = NULL;
		rxringp->rbr_table_size = 0;
		rxringp->rbr_index = 0;
		rxringp->rbr_tail = 0;
		rxringp->rbr_tail_wrap = 0;
		rxringp->rbr_head_wrap = 0;
	}

	kfree(rxringp->rxpage);
	rxringp->rxpage = NULL;
}

static void sxge_free_tx_ring_info(struct sxge *sxgep,
	struct tx_ring_info *txringp)
{
	if (txringp->mbox) {
		sxgep->ops->free_coherent(sxgep->device,
				       sizeof(struct txdma_mailbox),
				       txringp->mbox, txringp->mbox_dma);
		txringp->mbox = NULL;
	}
	if (txringp->descr) {
		int i;

		for (i = 0; i < MAX_TX_RING_SIZE; i++) {
			if (txringp->tx_buffs[i].skb)
				(void) release_tx_packet(sxgep, txringp, i);
		}

		sxgep->ops->free_coherent(sxgep->device,
				       MAX_TX_RING_SIZE * sizeof(__le64),
				       txringp->descr, txringp->descr_dma);
		txringp->descr = NULL;
		txringp->pending = 0;
		txringp->prod = 0;
		txringp->cons = 0;
		txringp->wrap_bit = 0;
	}
}

static void sxge_free_channels(struct sxge *sxgep)
{
	int i;

	if (sxgep->rx_rings) {
		for (i = 0; i < sxgep->num_rings; i++) {
			struct rx_ring_info *rxringp = &sxgep->rx_rings[i];

			sxge_free_rx_ring_info(sxgep, rxringp);
		}
		kfree(sxgep->rx_rings);
		sxgep->rx_rings = NULL;
	}

	if (sxgep->tx_rings) {
		for (i = 0; i < sxgep->num_rings; i++) {
			struct tx_ring_info *txringp = &sxgep->tx_rings[i];

			sxge_free_tx_ring_info(sxgep, txringp);
		}
		kfree(sxgep->tx_rings);
		sxgep->tx_rings = NULL;
	}
}

static int sxge_alloc_channels(struct sxge *sxgep)
{
	int			i, j, err, ring_num = 0;
	struct rx_ring_info	*rx_rings;
	struct tx_ring_info	*tx_rings;

	err = -ENOMEM;
	dev_printk(KERN_DEBUG, sxgep->device, "num_ring = %d\n",
		sxgep->num_rings);
	rx_rings = kcalloc(sxgep->num_rings,
		sizeof(struct rx_ring_info), GFP_KERNEL);
	if (!rx_rings) {
		dev_printk(KERN_DEBUG, sxgep->device,
			"kcalloc RX RING failed\n");
		return err;
	}
		
	tx_rings = kcalloc(sxgep->num_rings,
		sizeof(struct tx_ring_info), GFP_KERNEL);
	if (!tx_rings) {
		kfree(rx_rings);
		dev_printk(KERN_DEBUG, sxgep->device,
			"kcalloc TX RING failed\n");
		return err;
	}

	smp_wmb();
	sxgep->rx_rings = rx_rings;
	smp_wmb();
	sxgep->tx_rings = tx_rings;

	netif_set_real_num_rx_queues(sxgep->dev, sxgep->num_rings);
	netif_set_real_num_tx_queues(sxgep->dev, sxgep->num_rings);

	/*
	 * Scan the RDAT table to get the VNI, DMA, VMAC numbers and calculate
	 * the register base
	 */
	for (i = 0; i < MAX_VNI_NUM; i++) {
		if (sxgep->piobar_resource[i]) {
			uint8_t piobar_vmac_resource, vmac = 0;
			uint8_t piobar_dma_resource;

			piobar_dma_resource = sxgep->piobar_resource[i];
			piobar_vmac_resource = sxgep->piobar_resource[i] >> 4;
			for (j = 0; j < 4; j++) {
				if (piobar_dma_resource & 0x1) {
					sxgep->rx_rings[ring_num].vni = i;
					sxgep->rx_rings[ring_num].rdc_base =
						RDC_BASE(i, j);
					sxgep->rx_rings[ring_num].rx_channel =
						j;
					sxgep->tx_rings[ring_num].vni = i;
					sxgep->tx_rings[ring_num].tdc_base =
						TDC_BASE(i, j);
					sxgep->tx_rings[ring_num].tx_channel =	
						j;
					switch (piobar_vmac_resource & 0xf) {
					case 0x1:
						vmac = 0;
						break;
					case 0x2:
						vmac = 1;
						break;
					case 0x4:
						vmac = 2;
						break;
					case 0x8:
						vmac = 3;
						break;
					default:
						netdev_warn(sxgep->dev, "%s: "
						    "invalid vmac assigned\n",
						    __func__);
						goto out_err;
					}
					sxgep->rx_rings[ring_num].vmac = vmac;
					sxgep->rx_rings[ring_num].vmac_base =
						VMAC_BASE(i, vmac);
					sxgep->tx_rings[ring_num].vmac = vmac;
					sxgep->tx_rings[ring_num].vmac_base =
						VMAC_BASE(i, vmac);
					sxgep->vmac = vmac;
					ring_num++;
				}
				piobar_dma_resource = piobar_dma_resource >> 1;
			}
		}
	}

	for (i = 0; i < sxgep->num_rings; i++) {
		struct rx_ring_info *rxringp = &sxgep->rx_rings[i];
		struct tx_ring_info *txringp = &sxgep->tx_rings[i];

		rxringp->sxgep = sxgep;

		/* rxings */
		err = sxge_alloc_rx_ring_info(sxgep, rxringp);
		if (err)
			goto out_err;

		sxge_size_rbr(sxgep, rxringp);
		/* Change from 16 to 1, may change it back */
		rxringp->rcr_pkt_threshold = 1;
		rxringp->rcr_timeout = 8;
		rxringp->rbr_kick_thresh = RBR_REFILL_MIN;
		if (rxringp->rbr_kick_thresh < rxringp->rbr_blocks_per_page)
			rxringp->rbr_kick_thresh = rxringp->rbr_blocks_per_page;

		err = sxge_rbr_fill(sxgep, rxringp, GFP_KERNEL);
		if (err)
			return err;

		/* txring */
		txringp->sxgep = sxgep;
		err = sxge_alloc_tx_ring_info(sxgep, txringp);
		if (err)
			goto out_err;
	}

	return 0;
out_err:
	sxge_free_channels(sxgep);
	return err;
}

static int sxge_check_eps_init(struct sxge *sxgep)
{
	uint64_t	niu_avail;

	niu_avail = SXGE_GET64(0xfe010);

	if (niu_avail != 0x1) {
		pr_warning("%s: HW is not ready\n", sxgep->dev->name);
		return -1;
	}

	return 0;
}

static int sxge_get_default_config(struct sxge *sxgep)
{
	uint64_t	addr;
	uint64_t	rdat_low, rdat_high;
	uint64_t	piobar_resource_low, piobar_resource_high;
	int		i, j;

	/* Reading RDAT */
	addr = RDAT_LOW;
	rdat_low = SXGE_GET64(addr);

	addr = RDAT_HIGH;
	rdat_high = SXGE_GET64(addr);

	piobar_resource_low = rdat_low;
	piobar_resource_high = rdat_high;

	for (i = 0; i < 8; i++) {
		sxgep->piobar_resource[i] = (uint8_t) piobar_resource_low;
		sxgep->piobar_resource[i + 8] = (uint8_t) piobar_resource_high;
		piobar_resource_low = piobar_resource_low >> 8;
		piobar_resource_high = piobar_resource_high >> 8;
	}

	sxgep->num_rings = 0;
	for (i = 0; i < MAX_VNI_NUM; i++) {
		if (sxgep->piobar_resource[i]) {
			uint8_t piobar_vmac_resource, vmac_cnt = 0;
			uint8_t piobar_dma_resource;

			sxgep->vni = i;
			piobar_dma_resource = sxgep->piobar_resource[i];
			piobar_vmac_resource = sxgep->piobar_resource[i] >> 4;
			for (j = 0; j < 4; j++) {
				if (piobar_dma_resource & 0x1)
					sxgep->num_rings++;

				if (piobar_vmac_resource & 0x1) {
					vmac_cnt++;
					sxgep->intmgmt_nf = j;
				}
				piobar_dma_resource = piobar_dma_resource >> 1;
				piobar_vmac_resource = piobar_vmac_resource >> 1;
			}
			if (!(sxgep->piobar_resource[i] & 0x0F) ||
				(vmac_cnt != 0x1)) {
				SXGE_DBG("invalid piobar_resource:"
				    "piobar_resource[0x%x] 0x%x\n",
				    i, sxgep->piobar_resource[i]);
			}
			if (sxgep->num_rings == 0)
				SXGE_DBG("invalid piobar_resource: "
				    "piobar_resource[0x%x] 0x%x\n",
				    i, sxgep->piobar_resource[i]);
		}
	}

	return 0;
}

static int sxge_tx_cs_sng_poll(struct sxge *sxgep, u32 base)
{
	int limit = 1000;

	while (--limit > 0) {
		u64 val = SXGE_GET64(TDC_CS(base));
		if (val & TDC_CS_SNG_STATE)
			return 0;
	}
	return -ENODEV;
}

static int sxge_tx_channel_stop(struct sxge *sxgep, u32 base)
{
	u64 val = SXGE_GET64(TDC_CS(base));

	val |= TDC_CS_STOP_N_GO;
	SXGE_PUT64(TDC_CS(base), val);

	return sxge_tx_cs_sng_poll(sxgep, base);
}

static int sxge_tx_cs_reset_poll(struct sxge *sxgep, u32 base)
{
	int limit = 1000;

	while (--limit > 0) {
		u64 val = SXGE_GET64(TDC_CS(base));
		if (val & TDC_CS_RST_STATE)
			return 0;
	}
	return -ENODEV;
}

static int sxge_tx_channel_reset(struct sxge *sxgep, u32 base)
{
	u64 val = SXGE_GET64(TDC_CS(base));
	int err;

	val |= TDC_CS_RST;
	SXGE_PUT64(TDC_CS(base), val);

	err = sxge_tx_cs_reset_poll(sxgep, base);
	if (!err)
		SXGE_PUT64(TDC_RING_KICK(base), 0);

	return err;
}

static int sxge_tx_channel_lpage_init(struct sxge *sxgep, u32 base)
{
	SXGE_PUT64(TDC_PG_HDL(base), 0);

	/* Need to do more? */

	return 0;
}

static int sxge_init_one_tx_channel(struct sxge *sxgep,
		struct tx_ring_info *txringp)
{
	int err;
	u32 base = txringp->tdc_base;
	u64 val, ring_len;

	err = sxge_tx_channel_stop(sxgep, base);
	if (err)
		return err;

	err = sxge_tx_channel_reset(sxgep, base);
	if (err)
		return err;

	err = sxge_tx_channel_lpage_init(sxgep, base);
	if (err)
		return err;

	SXGE_PUT64(TXC_DMA_MAX(base), txringp->max_burst);
	val = SXGE_GET64(TXC_DMA_MAX(base));
	if (val & TDC_PRSR_ENABLE)
		txringp->tdc_prsr_en = 1;
	/* Enable HW chksuming if it was set by the EPS */
	if (val & TDC_HPRSR_CSPARTIAL)
		sxgep->dev->features |= (NETIF_F_SG | NETIF_F_HW_CSUM);

	SXGE_PUT64(TDC_DMA_ENT_MSK(base), 0);

	if (txringp->descr_dma & ~(TDC_RNG_CFIG_STADDR_BASE |
				TDC_RNG_CFIG_STADDR)) {
		netdev_err(sxgep->dev, "TX ring channel %d "
			"DMA addr (%llx) is not aligned\n",
			txringp->tx_channel,
			(unsigned long long) txringp->descr_dma);
		return -EINVAL;
	}

	/* The length field in TX_RNG_CFIG is measured in 64-byte
	 * blocks.  rp->pending is the number of TX descriptors in
	 * our ring, 8 bytes each, thus we divide by 8 bytes more
	 * to get the proper value the chip wants.
	 */
	ring_len = (txringp->pending / 8);

	val = ((ring_len << TDC_RNG_CFIG_LEN_SHIFT) |
		txringp->descr_dma);
	SXGE_PUT64(TDC_RNG_CFIG(base), val);

	if (((txringp->mbox_dma >> 32) & ~TDC_MBH_MBADDR) ||
		((u32)txringp->mbox_dma & ~TDC_MBL_MBADDR)) {
		netdev_err(sxgep->dev, "TX ring channel %d "
			"MBOX addr (%llx) has invalid bits\n",
			txringp->tx_channel,
			(unsigned long long) txringp->mbox_dma);
		return -EINVAL;
	}
	SXGE_PUT64(TDC_MBH(base), txringp->mbox_dma >> 32);
	SXGE_PUT64(TDC_MBL(base), txringp->mbox_dma & TDC_MBL_MBADDR);

	SXGE_PUT64(TDC_CS(base), 0);

	txringp->last_pkt_cnt = 0;

	return 0;
}

static int sxge_rx_cs_sng_poll(struct sxge *sxgep, u32 base)
{
	int limit = 1000;

	while (--limit > 0) {
		u64 val = SXGE_GET64(RDC_CTL_STAT(base));
		if (val & RDC_CTL_STAT_SNG_STATE)
			return 0;
	}
	return -ENODEV;
}

static int sxge_rx_channel_stop(struct sxge *sxgep, u32 base)
{
	u64 val = SXGE_GET64(RDC_CTL_STAT(base));

	val |= RDC_CTL_STAT_STOP_N_GO;
	SXGE_PUT64(RDC_CTL_STAT(base), val);

	return sxge_rx_cs_sng_poll(sxgep, base);
}

static int sxge_rx_cs_reset_poll(struct sxge *sxgep, u32 base)
{
	int limit = 1000;

	while (--limit > 0) {
		u64 val = SXGE_GET64(RDC_CTL_STAT(base));
		if (val & RDC_CTL_STAT_RST_STATE)
			return 0;
	}
	return -ENODEV;
}

static int sxge_rx_channel_reset(struct sxge *sxgep, u32 base)
{
	u64 val = SXGE_GET64(RDC_CTL_STAT(base));
	int err;

	val |= RDC_CTL_STAT_RST;
	SXGE_PUT64(RDC_CTL_STAT(base), val);

	err = sxge_rx_cs_reset_poll(sxgep, base);

	return err;
}

static int sxge_rx_channel_lpage_init(struct sxge *sxgep, u32 base)
{
	SXGE_PUT64(RDC_PAGE_HDL(base), 0);

	/* Anything else need to be done? */

	return 0;
}

static int sxge_compute_rdc_cfig(struct rx_ring_info *rxringp, u64 *ret)
{
	u64 val = 0;

	*ret = 0;
	switch (rxringp->rbr_block_size) {
	case 4 * 1024:
		val |= (RBR_BLKSIZE_4K << RDC_CFG_BLKSIZE_SHIFT);
		break;
	case 8 * 1024:
		val |= (RBR_BLKSIZE_8K << RDC_CFG_BLKSIZE_SHIFT);
		break;
	case 16 * 1024:
		val |= (RBR_BLKSIZE_16K << RDC_CFG_BLKSIZE_SHIFT);
		break;
	case 32 * 1024:
		val |= (RBR_BLKSIZE_32K << RDC_CFG_BLKSIZE_SHIFT);
		break;
	default:
		return -EINVAL;
	}

	val &= ~RDC_CFG_VLD2;
	switch (rxringp->rbr_sizes[2]) {
	case 2 * 1024:
		val |= (RBR_BUFSZ2_2K << RDC_CFG_BUFSZ2_SHIFT);
		break;
	case 4 * 1024:
		val |= (RBR_BUFSZ2_4K << RDC_CFG_BUFSZ2_SHIFT);
		break;
	case 8 * 1024:
		val |= (RBR_BUFSZ2_8K << RDC_CFG_BUFSZ2_SHIFT);
		break;
	case 16 * 1024:
		val |= (RBR_BUFSZ2_16K << RDC_CFG_BUFSZ2_SHIFT);
		break;

	default:
		return -EINVAL;
	}

	val &= ~RDC_CFG_VLD1;
	switch (rxringp->rbr_sizes[1]) {
	case 1 * 1024:
		val |= (RBR_BUFSZ1_1K << RDC_CFG_BUFSZ1_SHIFT);
		break;
	case 2 * 1024:
		val |= (RBR_BUFSZ1_2K << RDC_CFG_BUFSZ1_SHIFT);
		break;
	case 4 * 1024:
		val |= (RBR_BUFSZ1_4K << RDC_CFG_BUFSZ1_SHIFT);
		break;
	case 8 * 1024:
		val |= (RBR_BUFSZ1_8K << RDC_CFG_BUFSZ1_SHIFT);
		break;

	default:
		return -EINVAL;
	}

	val &= ~RDC_CFG_VLD0;
	switch (rxringp->rbr_sizes[0]) {
	case 256:
		val |= (RBR_BUFSZ0_256 << RDC_CFG_BUFSZ0_SHIFT);
		break;
	case 512:
		val |= (RBR_BUFSZ0_512 << RDC_CFG_BUFSZ0_SHIFT);
		break;
	case 1 * 1024:
		val |= (RBR_BUFSZ0_1K << RDC_CFG_BUFSZ0_SHIFT);
		break;
	case 2 * 1024:
		val |= (RBR_BUFSZ0_2K << RDC_CFG_BUFSZ0_SHIFT);
		break;

	default:
		return -EINVAL;
	}

	*ret = val;
	return 0;
}

static int sxge_init_one_rx_channel(struct sxge *sxgep,
	struct rx_ring_info *rxringp)
{
	int err, base = rxringp->rdc_base;
	u64 val;

	err = sxge_rx_channel_stop(sxgep, base);
	if (err)
		return err;

	err = sxge_rx_channel_reset(sxgep, base);
	if (err)
		return err;

	err = sxge_rx_channel_lpage_init(sxgep, base);
	if (err)
		return err;

	/* Clear interrupt mask reg to enable interrupt */
	SXGE_PUT64(RDC_ENT_MSK(base), 0);

	SXGE_PUT64(RDC_MBX_CFG(base),
		rxringp->mbox_dma & RDC_MBX_CFG_MBOX_STADDR);

	SXGE_PUT64(RDC_MBX_UPD_CFG(base),
		(RDC_MBX_UPD_CFG_ENABLE |
		((u64)rxringp->rcr_pkt_threshold & RDC_MBX_UPD_CFG_PTHRESH)));

	SXGE_PUT64(RDC_RBR_CFG(base),
		(((u64)(rxringp->rbr_table_size/8) <<
		RDC_RBR_CFG_LEN_SHIFT) |
		(rxringp->rbr_dma & RDC_RBR_CFG_STADDR)));

	err = sxge_compute_rdc_cfig(rxringp, &val);
	if (err)
		return err;
	SXGE_PUT64(RDC_CFG(base), val);

	SXGE_PUT64(RDC_RCR_CFG(base),
		(((u64)rxringp->rcr_table_size << RDC_RCR_CFG_LEN_SHIFT) |
		(rxringp->rcr_dma & RDC_RCR_CFG_STADDR)));
	SXGE_PUT64(RDC_RCR_TIMER_CFG(base),
		((u64)rxringp->rcr_pkt_threshold <<
		RDC_RCR_TIMER_CFG_PTHRESH_SHIFT) |
		RDC_RCR_TIMER_CFG_ENPTHRESH |
		RDC_RCR_TIMER_CFG_ENTIMEOUT |
		((u64)rxringp->rcr_timeout << RDC_RCR_TIMER_CFG_TIMEOUT_SHIFT));

	SXGE_PUT64(RDC_CTL_STAT(base), 0);

	rxringp->rbr_tail = (u64) rxringp->rbr_index;
	SXGE_PUT64(RDC_KICK(base),
		RDC_KICK_RBR_TAIL_UP_VLD |
		(rxringp->rbr_tail & RDC_KICK_RBR_TAIL));

	val = SXGE_GET64(RDC_CTL_STAT(base));

	return 0;
}

static void sxge_stop_one_tx_channel(struct sxge *sxgep,
	struct tx_ring_info *txringp)
{
	(void) sxge_tx_channel_stop(sxgep, txringp->tdc_base);
}

static void sxge_stop_tx_channels(struct sxge *sxgep)
{
	int i;

	for (i = 0; i < sxgep->num_rings; i++) {
		struct tx_ring_info *txringp = &sxgep->tx_rings[i];

		sxge_stop_one_tx_channel(sxgep, txringp);
	}
}

static void sxge_reset_one_tx_channel(struct sxge *sxgep,
	struct tx_ring_info *txringp)
{
	(void) sxge_tx_channel_reset(sxgep, txringp->tdc_base);
}

static void sxge_reset_tx_channels(struct sxge *sxgep)
{
	int i;

	for (i = 0; i < sxgep->num_rings; i++) {
		struct tx_ring_info *txringp = &sxgep->tx_rings[i];

		sxge_reset_one_tx_channel(sxgep, txringp);
	}
}

static int sxge_one_txvmac_reset(struct sxge *sxgep, u8 vni, u8 vmac)
{
	int limit;
	u64 val;

	/* reset txvmac */
	val = TXVMAC_CONF_SW_RST;
	SXGE_PUT64(TXVMAC_CONF(vni, vmac),  val);

	limit = 1000;
	while (--limit > 0) {
		val = SXGE_GET64(TXVMAC_STAT(vni, vmac));
		if (val & TXVMAC_STAT_SW_RST_DONE)
			break;
		udelay(10);
	}
	if (limit <= 0)
		return -ENODEV;

	return 0;
}

static int sxge_one_txvmac_init(struct sxge *sxgep, u8 vni, u8 vmac)
{
	int err;

	err = sxge_one_txvmac_reset(sxgep, vni, vmac);
	if (err)
		return err;

	/* Enable interrupt bit and Clear counter */
	/* Disable interrupt for performance */
	SXGE_PUT64(TXVMAC_STAT_MSK(vni, vmac), TXVMAC_STAT_SW_RST_DONE |
		TXVMAC_STAT_TX_BYTE_CNT_OVL |
		TXVMAC_STAT_TX_FRAME_CNT_OVL);

	SXGE_PUT64(TXVMAC_CONF(vni, vmac), 0);
	SXGE_PUT64(TXVMAC_STAT(vni, vmac), TXVMAC_STAT_SW_RST_DONE |
		TXVMAC_STAT_TX_BYTE_CNT_OVL |
		TXVMAC_STAT_TX_FRAME_CNT_OVL);

	return 0;
}

static int sxge_one_rxvmac_reset(struct sxge *sxgep, u8 vni, u8 vmac)
{
	int limit;
	u64 val;

	/* reset rxvmac */
	val = RXVMAC_CONFIG_RST;
	SXGE_PUT64(RXVMAC_CONFIG(vni, vmac), val);

	limit = 1000;
	while (--limit > 0) {
		val = SXGE_GET64(RXVMAC_CONFIG(vni, vmac));
		if (val & RXVMAC_CONFIG_RST_STATE)
			break;
		udelay(10);
	}
	if (limit <= 0)
		return -ENODEV;

	return 0;
}

static void sxge_rxvmac_promisc_enable(struct sxge *sxgep, u8 vni, u8 vmac)
{
	u64 val = SXGE_GET64(RXVMAC_CONFIG(vni, vmac));

	val |= RXVMAC_CONFIG_PROMISC_MODE;
	SXGE_PUT64(RXVMAC_CONFIG(vni, vmac), val);
}

static int sxge_one_rxvmac_enable(struct sxge *sxgep, u8 vni, u8 vmac)
{
	u64 val;

	/* Set up DMA and enable the VMAC */
	val = SXGE_GET64(RXVMAC_CONFIG(vni, vmac));

	val |= (sxgep->piobar_resource[vni] &
		SXGE_PIOBAR_RESOUCE_DMA_MASK) <<
		RXVMAC_CONFIG_DMA_VECTOR_SHIFT;
	/* Set OP code for different configuration */
	if (sxgep->num_rings == 1)
		val |= RXVMAC_CONFIG_OPCODE_1F1D;
	else if (sxgep->num_rings == 4)
		val |= RXVMAC_CONFIG_OPCODE_1F4D;
	else if (sxgep->num_rings == 2)
		val |= RXVMAC_CONFIG_OPCODE_1F2D;

	val &= ~RXVMAC_CONFIG_RST_STATE;
	SXGE_PUT64(RXVMAC_CONFIG(vni, vmac), val);

	return 0;
}

static int sxge_one_rxvmac_init(struct sxge *sxgep, u8 vni, u8 vmac)
{
	int err;
	u64 val;
	struct sxge_vmac_stats *vmp = &sxgep->vmac_stats;

	err = sxge_one_rxvmac_reset(sxgep, vni, vmac);
	if (err)
		return err;

	err = sxge_one_rxvmac_enable(sxgep, vni, vmac);
	if (err)
		return err;

	/* Enable interrupt bit only for link up/down */
	SXGE_PUT64(RXVMAC_INT_MASK(vni, vmac),
		RXVMAC_STAT_BCAST_FRAME_CNT_OVL |
		RXVMAC_STAT_MCAST_FRAME_CNT_OVL |
		RXVMAC_STAT_DROP_BYTE_OVL |
		RXVMAC_STAT_DROP_CNT_OVL | RXVMAC_STAT_BYTE_CNT_OVL |
		RXVMAC_STAT_FRAME_CNT_OVL);

	val = SXGE_GET64(RXVMAC_STAT(sxgep->vni, sxgep->vmac));
	if (val & RXVMAC_STAT_LINK_STATE) {
		vmp->rxvmac_link_state = 1;
		vmp->rxvmac_link_up = 1;
		vmp->rxvmac_link_down = 0;
	}

	return 0;
}

static void sxge_reset_rx_vmacs(struct sxge *sxgep)
{
	int i, j;
	uint8_t piobar_resource;

	for (i = 0; i < MAX_VNI_NUM; i++) {
		if (sxgep->piobar_resource[i]) {
			piobar_resource = sxgep->piobar_resource[i];
			piobar_resource = piobar_resource >>
				SXGE_PIOBAR_RESOUCE_VMAC_SHIFT;
			for (j = 0; j < 4; j++) {
				if (piobar_resource & 0x1)
					sxge_one_rxvmac_reset(sxgep, i, j);
				piobar_resource = piobar_resource >> 1;
			}
		}
	}
}

static void sxge_stop_one_rx_channel(struct sxge *sxgep,
	struct rx_ring_info *rxringp)
{
	(void) sxge_rx_channel_stop(sxgep, rxringp->rdc_base);
}

static void sxge_stop_rx_channels(struct sxge *sxgep)
{
	int i;

	for (i = 0; i < sxgep->num_rings; i++) {
		struct rx_ring_info *rxringp = &sxgep->rx_rings[i];

		sxge_stop_one_rx_channel(sxgep, rxringp);
	}
}

static void sxge_reset_one_rx_channel(struct sxge *sxgep,
	struct rx_ring_info *rxringp)
{
	u32 base = rxringp->rdc_base;

	sxge_rx_channel_reset(sxgep, base);
	SXGE_PUT64(RDC_ENT_MSK(base), RDC_ENT_MSK_ALL);
}

static void sxge_reset_rx_channels(struct sxge *sxgep)
{
	int i;

	for (i = 0; i < sxgep->num_rings; i++) {
		struct rx_ring_info *rxringp = &sxgep->rx_rings[i];

		sxge_reset_one_rx_channel(sxgep, rxringp);
	}
}

static int sxge_hosteps_mbox_reset_poll(struct sxge *sxgep)
{
	int limit = 1000;

	while (--limit > 0) {
		u64 val = SXGE_GET64(SXGE_MB_STAT);
		if (val & SXGE_MB_STAT_FUNC_RST_DONE)
			return 0;
	}
	return -ENODEV;
}

static int sxge_hosteps_mbox_reset(struct sxge *sxgep)
{
	u64 val = SXGE_GET64(SXGE_MB_STAT);
	int err;

	val |= SXGE_MB_STAT_FUNC_RST;
	SXGE_PUT64(SXGE_MB_STAT, val);

	err = sxge_hosteps_mbox_reset_poll(sxgep);

	return err;
}

static int sxge_init_hosteps_mbox(struct sxge *sxgep)
{
	int err;

	err = sxge_hosteps_mbox_reset(sxgep);
	if (err)
		return err;

	/* Disable the mbox interrupt */
	SXGE_PUT64(SXGE_MB_MSK, 0x1be);

	SXGE_PUT64(SXGE_MB_STAT, SXGE_MB_STAT_FUNC_RST_DONE);

	return 0;
}

static int sxge_init_hw(struct sxge *sxgep)
{
	int i, j, err;
	uint8_t piobar_resource;

	netif_printk(sxgep, ifup, KERN_DEBUG, sxgep->dev,
		"Initialize DMA channels\n");
	for (i = 0; i < sxgep->num_rings; i++) {
		struct tx_ring_info *txringp = &sxgep->tx_rings[i];
		struct rx_ring_info *rxringp = &sxgep->rx_rings[i];

		err = sxge_init_one_tx_channel(sxgep, txringp);
		if (err)
			return err;

		err = sxge_init_one_rx_channel(sxgep, rxringp);
		if (err)
			goto out_uninit_tx_channels;
	}

	netif_printk(sxgep, ifup, KERN_DEBUG, sxgep->dev, "Initialize VMAC\n");
	for (i = 0; i < MAX_VNI_NUM; i++) {
		if (sxgep->piobar_resource[i]) {
			piobar_resource = sxgep->piobar_resource[i];
			piobar_resource = piobar_resource >>
				SXGE_PIOBAR_RESOUCE_VMAC_SHIFT;
			for (j = 0; j < 4; j++) {
				if (piobar_resource & 0x1) {
					err = sxge_one_txvmac_init(sxgep, i, j);
					if (err)
						goto out_uninit_rx_channels;
					err = sxge_one_rxvmac_init(sxgep, i, j);
					if (err)
						goto out_uninit_rx_channels;
				}
				piobar_resource = piobar_resource >> 1;
			}
		}
	}

	netif_printk(sxgep, ifup, KERN_DEBUG, sxgep->dev, "Initialize MBOX\n");
	err = sxge_init_hosteps_mbox(sxgep);
	if (err)
		goto out_uninit_rx_vmacs;

	return 0;

out_uninit_rx_vmacs:
	netif_printk(sxgep, ifup, KERN_DEBUG, sxgep->dev, "Uninit VMAC\n");
	sxge_reset_rx_vmacs(sxgep);

out_uninit_rx_channels:
	netif_printk(sxgep, ifup, KERN_DEBUG, sxgep->dev, "Uninit RXDMA\n");
	sxge_stop_rx_channels(sxgep);
	sxge_reset_rx_channels(sxgep);

out_uninit_tx_channels:
	netif_printk(sxgep, ifup, KERN_DEBUG, sxgep->dev, "Uninit TXDMA\n");
	sxge_stop_tx_channels(sxgep);
	sxge_reset_tx_channels(sxgep);

	return err;
}

static void sxge_stop_hw(struct sxge *sxgep)
{
	netif_printk(sxgep, ifdown, KERN_DEBUG, sxgep->dev,
		"Disable interrupts\n");
	sxge_enable_interrupts(sxgep, 0);

	netif_printk(sxgep, ifdown, KERN_DEBUG, sxgep->dev, "Disable VMAC\n");
	sxge_reset_rx_vmacs(sxgep);

	netif_printk(sxgep, ifdown, KERN_DEBUG, sxgep->dev,
		"Stop TX channels\n");
	sxge_stop_tx_channels(sxgep);

	netif_printk(sxgep, ifdown, KERN_DEBUG, sxgep->dev,
		"Stop RX channels\n");
	sxge_stop_rx_channels(sxgep);

	netif_printk(sxgep, ifdown, KERN_DEBUG, sxgep->dev,
		"Reset TX channels\n");
	sxge_reset_tx_channels(sxgep);

	netif_printk(sxgep, ifdown, KERN_DEBUG, sxgep->dev,
		"Reset RX channels\n");
	sxge_reset_rx_channels(sxgep);
}

static int sxge_request_irq(struct sxge *sxgep)
{
	int i, j, err;

	for (i = 0; i < sxgep->num_ldg; i++) {
		struct sxge_ldg *lp = &sxgep->ldg[i];

		err = request_irq(lp->irq, sxge_interrupt, IRQF_SHARED,
			sxgep->dev->name, lp);
		if (err)
			goto out_free_irqs;
	}

	return 0;

out_free_irqs:
	for (j = 0; j < i; j++) {
		struct sxge_ldg *lp = &sxgep->ldg[j];

		free_irq(lp->irq, lp);
	}
	return err;
}

static void sxge_free_irq(struct sxge *sxgep)
{
	int i;

	for (i = 0; i < sxgep->num_ldg; i++) {
		struct sxge_ldg *lp = &sxgep->ldg[i];

		free_irq(lp->irq, lp);
	}
}

static void sxge_enable_napi(struct sxge *sxgep)
{
	int i;

	for (i = 0; i < sxgep->num_ldg; i++)
		napi_enable(&sxgep->ldg[i].napi);
}

static void sxge_disable_napi(struct sxge *sxgep)
{
	int i;

	for (i = 0; i < sxgep->num_ldg; i++)
		napi_disable(&sxgep->ldg[i].napi);
}

static int sxge_open(struct net_device *dev)
{
	struct sxge	*sxgep = netdev_priv(dev);
	int		err;

	/* Need ? in the sxge case ? */
	netif_carrier_off(dev);

	/* need to check if EPS has done its job */
	if (sxge_check_eps_init(sxgep) < 0) {
		netdev_err(dev, "%s(): sxge_check_eps_init fail\n", __func__);
		return -1;
	}

	/* alloc ring and buffers */
	err = sxge_alloc_channels(sxgep);
	if (err)
		goto out_err;

	err = sxge_enable_interrupts(sxgep, 0);
	if (err)
		goto out_free_channels;

	err = sxge_request_irq(sxgep);
	if (err)
		goto out_free_channels;

	sxge_enable_napi(sxgep);

	spin_lock_irq(&sxgep->lock);

	/* Init DMA, add interrupts */
	err = sxge_init_hw(sxgep);
	if (!err) {
		err = sxge_enable_interrupts(sxgep, 1);
		if (err)
			sxge_stop_hw(sxgep);
	}

	sxgep->flags |= SXGE_FLAGS_HW_INIT;

	spin_unlock_irq(&sxgep->lock);

	if (err) {
		sxge_disable_napi(sxgep);
		goto out_free_irq;
	}

	netif_tx_start_all_queues(dev);

	netif_carrier_on(dev);

	return 0;

out_free_irq:
	sxge_free_irq(sxgep);

out_free_channels:
	sxge_free_channels(sxgep);

out_err:
	return err;
}

static void sxge_full_shutdown(struct sxge *sxgep, struct net_device *dev)
{
	cancel_work_sync(&sxgep->reset_task);

	sxge_disable_napi(sxgep);
	netif_tx_stop_all_queues(dev);

	spin_lock_irq(&sxgep->lock);

	sxge_stop_hw(sxgep);

	spin_unlock_irq(&sxgep->lock);
}

static int sxge_close(struct net_device *dev)
{
	struct sxge *sxgep = netdev_priv(dev);

	/* TODO: shuddown HW, free irq, free channel */
	sxge_full_shutdown(sxgep, dev);

	sxge_free_irq(sxgep);

	sxge_free_channels(sxgep);

	return 0;
}

static void sxge_vmac_stats(struct sxge *sxgep)
{
	struct sxge_vmac_stats *vmp = &sxgep->vmac_stats;
	u8 vmac, vni;

	vni = sxgep->vni;
	vmac = sxgep->vmac;

	vmp->txvmac_frames += SXGE_GET64(TXVMAC_FRM_CNT(vni, vmac));
	vmp->txvmac_bytes += SXGE_GET64(TXVMAC_BYT_CNT(vni, vmac));

	vmp->rxvmac_frames += SXGE_GET64(RXVMAC_FRM_CNT(vni, vmac));
	vmp->rxvmac_bytes += SXGE_GET64(RXVMAC_BYT_CNT(vni, vmac));
	vmp->rxvmac_drops += SXGE_GET64(RXVMAC_DROP_CNT(vni, vmac));
	vmp->rxvmac_drop_bytes +=
		SXGE_GET64(RXVMAC_DROPBYT_CNT(vni, vmac));
	vmp->rxvmac_mcasts += SXGE_GET64(RXVMAC_MCAST_CNT(vni, vmac));
	vmp->rxvmac_bcasts += SXGE_GET64(RXVMAC_BCAST_CNT(vni, vmac));
}

static void sxge_get_rx_stats(struct sxge *sxgep)
{
	unsigned long pkts, dropped, errors, bytes;
	struct rx_ring_info *rx_rings;
	int i;

	pkts = dropped = errors = bytes = 0;
	rx_rings = ACCESS_ONCE(sxgep->rx_rings);
	if (!rx_rings)
		goto no_rings;

	for (i = 0; i < sxgep->num_rings; i++) {
		struct rx_ring_info *rxringp = &rx_rings[i];

		if (!rxringp)
			return;

		pkts += rxringp->rx_packets;
		bytes += rxringp->rx_bytes;
		dropped += rxringp->rx_dropped;
		errors += rxringp->rx_errors;
	}

no_rings:
	sxgep->dev->stats.rx_packets = pkts;
	sxgep->dev->stats.rx_bytes = bytes;
	sxgep->dev->stats.rx_dropped = dropped;
	sxgep->dev->stats.rx_errors = errors;
}

static void sxge_get_tx_stats(struct sxge *sxgep)
{
	unsigned long pkts, errors, bytes;
	struct tx_ring_info *tx_rings;
	int i;

	pkts = errors = bytes = 0;

	tx_rings = ACCESS_ONCE(sxgep->tx_rings);
	if (!tx_rings)
		goto no_rings;

	for (i = 0; i < sxgep->num_rings; i++) {
		struct tx_ring_info *txringp = &tx_rings[i];

		if (!txringp)
			return;

		pkts += txringp->tx_packets;
		bytes += txringp->tx_bytes;
		errors += txringp->tx_errors;
	}

no_rings:
	sxgep->dev->stats.tx_packets = pkts;
	sxgep->dev->stats.tx_bytes = bytes;
	sxgep->dev->stats.tx_errors = errors;
}

static struct net_device_stats *sxge_get_stats(struct net_device *dev)
{
	struct sxge *sxgep = netdev_priv(dev);

	if (netif_running(dev)) {
		sxge_get_rx_stats(sxgep);
		sxge_get_tx_stats(sxgep);
	}
	return &sxgep->dev->stats;
}

static int sxge_eps_mbx_post(struct sxge *sxgep, u64 *req, int len)
{
	int i, limit = 10000;
	u64 val = SXGE_GET64(SXGE_MB_STAT);

	if (val & SXGE_MB_STAT_OMB_FULL)
		return  -ENODEV;

	/* 0th entry is the last 64-bit word to be posted. */
	for (i = 1; i < len; i++)
		SXGE_PUT64(SXGE_OMB(i), req[i]);

	SXGE_PUT64(SXGE_OMB(0), req[0]);

	while (--limit > 0) {
		val = SXGE_GET64(SXGE_MB_STAT);

		if ((val & SXGE_MB_STAT_OMB_ACKED) ||
			(val & SXGE_MB_STAT_OMB_FAILED)) {
			sxgep->sxge_mb_stat = val;
			SXGE_PUT64(SXGE_MB_STAT, val & (SXGE_MB_STAT_OMB_ACKED |
				SXGE_MB_STAT_OMB_FAILED));
			break;
		}
		udelay(10);
	}

	if ((!limit) || (sxgep->sxge_mb_stat & SXGE_MB_STAT_OMB_FAILED))
		return -ENODEV;

	return 0;
}

static int sxge_eps_mbx_wait_response(struct sxge *sxgep)
{
	u64 val;
	int limit = 10000;

	while (--limit > 0) {
		val = SXGE_GET64(SXGE_MB_STAT);

		if (val & SXGE_MB_STAT_IMB_FULL) {
			SXGE_PUT64(SXGE_MB_STAT, val & SXGE_MB_STAT_IMB_FULL);
			return 0;
		}
		udelay(10);
	}

	return -ENODEV;
}

static int sxge_eps_mbx_check_validity(struct sxge *sxgep, u64 *tag)
{
	u64 mb_tag = *tag;
	u64 req = (mb_tag & MB_TAG_REQ) >> MB_TAG_REQ_SHIFT;
	u64 len = (mb_tag & MB_TAG_LEN) >> MB_TAG_LEN_SHIFT;

	if (len > SXGE_MB_MAX_LEN) {
		netdev_err(sxgep->dev, "%s(): len is wrong\n", __func__);
		return -EINVAL;
	}

	switch (req) {
	case SXGE_MB_REQUEST:
	case SXGE_MB_RESPONSE:
		break;
	default:
		return -EINVAL;
	}

	switch ((mb_tag & MB_TAG_TYPE) >> MB_TAG_TYPE_SHIFT) {
	case SXGE_MB_GET_L2_ADDR_CAP:
	case SXGE_MB_GET_TCAM_CAP:
	case SXGE_MB_LINK_SPEED:
		break;
	case SXGE_MB_L2_ADDR_ADD:
	case SXGE_MB_L2_ADDR_REM:
		break;
	case SXGE_MB_L2_MCAST_ADD:
	case SXGE_MB_L2_MCAST_REM:
		if (len != SXGE_MB_L2_ADDR_REQ_LEN)
			return -EINVAL;
		if (req  == SXGE_MB_REQUEST)
			return -EINVAL;
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

static int sxge_eps_mbx_process(struct sxge *sxgep, struct sxge_mb_msg *mb_msgp)
{
	struct sxge_mb_msg mb_msg;
	int i, err;

	mb_msg.msg_data[0] = SXGE_GET64(SXGE_IMB(0));

	err = sxge_eps_mbx_check_validity(sxgep, &mb_msg.msg_data[0]);
	if (err) {
		SXGE_PUT64(SXGE_IMB_ACK, SXGE_IMB_ACK_IMB_NACK);
		return -ENODEV;
	}

	mb_msg.len = (mb_msg.msg_data[0] & MB_TAG_LEN) >> MB_TAG_LEN_SHIFT;

	for (i = 1; i < mb_msg.len; i++)
		mb_msg.msg_data[i] = SXGE_GET64(SXGE_IMB(i));
	
	SXGE_PUT64(SXGE_IMB_ACK, SXGE_IMB_ACK_IMB_ACK);

	memcpy(mb_msgp, &mb_msg, sizeof(struct sxge_mb_msg));

	return 0;
}

static int sxge_eps_mbx_mcast_add(struct sxge *sxgep, u8 *addr)
{
	struct l2_address_req l2_addr_req;
	struct sxge_mb_msg mb_msg;
	u64 l2_addr;
	int err;

	l2_addr = ((u64) addr[0] << 40) | ((u64) addr[1] << 32) |
		((u64) addr[2] << 24) | ((u64) addr[3] << 16) |
		((u64) addr[4] << 8) | ((u64) addr[5]);

	l2_addr_req.mb_tag = ((u64) SXGE_MB_L2_ADDR_REQ_LEN |
		((u64) SXGE_MB_L2_MCAST_ADD << MB_TAG_TYPE_SHIFT) |
		((u64) SXGE_MB_REQUEST << MB_TAG_REQ_SHIFT) |
		((u64) 0xaabb << MB_TAG_SEQ_SHIFT));

	l2_addr_req.addr = l2_addr;
	l2_addr_req.mask  = 0;

	err = sxge_eps_mbx_post(sxgep, (uint64_t *)&l2_addr_req,
				SXGE_MB_L2_ADDR_REQ_LEN);
	if (err) {
		netdev_err(sxgep->dev, "sxge_eps_mbx_post fail\n");
		return err;
	}

	err = sxge_eps_mbx_wait_response(sxgep);
	if (err) {
		netdev_err(sxgep->dev, "sxge_eps_mbx_wait_response fail\n");
		return err;
	}

	err = sxge_eps_mbx_process(sxgep, &mb_msg);
	if (err) {
		netdev_err(sxgep->dev, "sxge_eps_mbx_process fail\n");
		return err;
	}

	return 0;
}

static int sxge_eps_mbx_l2_add(struct sxge *sxgep, u8 *addr, u64 slot)
{
	struct l2_address_req l2_addr_req;
	struct sxge_mb_msg mb_msg;
	u64 l2_addr;
	int err;

	if (slot >= (SXGE_MAX_TCAM_ENTRY_PER_FUNC * sxgep->num_rings)) {
		printk("No more Alternate MAC Address Entry Available\n");
		return -EINVAL;
	}

	l2_addr = ((u64) addr[0] << 40) | ((u64) addr[1] << 32) |
		((u64) addr[2] << 24) | ((u64) addr[3] << 16) |
		((u64) addr[4] << 8) | ((u64) addr[5]);

	l2_addr_req.mb_tag = (u64) SXGE_MB_L2_ADDR_REQ_LEN |
		((u64) SXGE_MB_L2_ADDR_ADD << MB_TAG_TYPE_SHIFT) |
		((u64) SXGE_MB_REQUEST << MB_TAG_REQ_SHIFT) |
		((u64) 0xaabb << MB_TAG_SEQ_SHIFT);

	l2_addr_req.addr = l2_addr;
	l2_addr_req.mask  = 0;
	l2_addr_req.slot = slot;

	err = sxge_eps_mbx_post(sxgep, (uint64_t *)&l2_addr_req,
				SXGE_MB_L2_ADDR_REQ_LEN);
	if (err) {
		netdev_err(sxgep->dev, "sxge_eps_mbx_post fail\n");
		return err;
	}

	err = sxge_eps_mbx_wait_response(sxgep);
	if (err) {
		netdev_err(sxgep->dev, "sxge_eps_mbx_wait_response fail\n");
		return err;
	}

	err = sxge_eps_mbx_process(sxgep, &mb_msg);
	if (err) {
		netdev_err(sxgep->dev, "sxge_eps_mbx_process fail\n");
		return err;
	}

	return 0;
}

static int sxge_eps_mbx_link_speed(struct sxge *sxgep)
{
	struct mb_cap cap;
	struct sxge_mb_msg mb_msg;
	int err;
	u64 pcs_mode;

	cap.mb_tag = (u64) SXGE_MB_CAP_LEN |
		((u64) SXGE_MB_LINK_SPEED << MB_TAG_TYPE_SHIFT) |
		((u64) SXGE_MB_REQUEST << MB_TAG_REQ_SHIFT) |
		((u64) 0xaabb << MB_TAG_SEQ_SHIFT);

	err = sxge_eps_mbx_post(sxgep, (uint64_t *) &cap,
				SXGE_MB_CAP_LEN);
	if (err) {
		netdev_err(sxgep->dev, "sxge_eps_mbx_post fail\n");
		return err;
	}

	err = sxge_eps_mbx_wait_response(sxgep);
	if (err) {
		netdev_err(sxgep->dev, "sxge_eps_mbx_wait_response fail\n");
		return err;
	}

	err = sxge_eps_mbx_process(sxgep, &mb_msg);
	if (err) {
		netdev_err(sxgep->dev, "sxge_eps_mbx_process fail\n");
		return err;
	}

	pcs_mode = (mb_msg.msg_data[SXGE_MB_40G_MODE_INDEX] &
		SXGE_MB_PCS_MODE_MASK) >> SXGE_MB_PCS_MODE_SHIFT;
	switch (pcs_mode) {
	case SXGE_MB_PCS_MODE_KR4:
		sxgep->link_config.speed = SPEED_40000;
		break;
	case SXGE_MB_PCS_MODE_X:
		sxgep->link_config.speed = SPEED_1000;
		break;
	case SXGE_MB_PCS_MODE_KX4:
		sxgep->link_config.speed = SPEED_4000;
		break;
	case SXGE_MB_PCS_MODE_KR:
		sxgep->link_config.speed = SPEED_10000;
		break;
	default:
		break;
	}

	return 0;
}

static void sxge_set_rx_mode(struct net_device *dev)
{
	struct sxge *sxgep = netdev_priv(dev);
	int alt_cnt, err;
	struct netdev_hw_addr *ha;
	unsigned long flags;

	spin_lock_irqsave(&sxgep->lock, flags);
	sxgep->flags &= ~(SXGE_FLAGS_MCAST | SXGE_FLAGS_PROMISC);
	if (dev->flags & IFF_PROMISC) {
		sxgep->flags |= SXGE_FLAGS_PROMISC;
		netdev_warn(dev, "Host driver can't put HW in this mode"
			"Please use CLI to set it\n");
	}
	if ((dev->flags & IFF_ALLMULTI) || (!netdev_mc_empty(dev)))
		sxgep->flags |= SXGE_FLAGS_MCAST;

	alt_cnt = netdev_uc_count(dev);
	if (alt_cnt > (SXGE_MAX_TCAM_ENTRY_PER_FUNC * sxgep->num_rings)) {
		alt_cnt = SXGE_MAX_TCAM_ENTRY_PER_FUNC;
		netdev_warn(dev, "Too many ucast to be set, "
			"Host can only set up to 0x%x\n",
			(SXGE_MAX_TCAM_ENTRY_PER_FUNC * sxgep->num_rings));
	}

	if (alt_cnt) {
		/* Using slot 1 and up for alternate MAC address */
		u64	slot = 1;

		if (!sxge_live_migrate) {
			netdev_for_each_uc_addr(ha, dev) {
				err = sxge_eps_mbx_l2_add(sxgep, ha->addr, slot);
				if (err)
					netdev_warn(dev,
						"Error %d adding alt mac\n",
						err);
				slot++;
			}
		} else
			netdev_warn(dev, "VM Live Migrate Enabled, "
				"Can't Support Alternate MAC address\n");
	}

	if (dev->flags & IFF_ALLMULTI) {
		/* Set promisc bit in the RXVMAC config */
		sxge_rxvmac_promisc_enable(sxgep, sxgep->vni, sxgep->vmac);
	} else if (!netdev_mc_empty(dev)) {
		netdev_for_each_mc_addr(ha, dev) {
			err = sxge_eps_mbx_mcast_add(sxgep, ha->addr);
			if (err)
				netdev_warn(dev, "Error %d ", err);
		}
	}
	spin_unlock_irqrestore(&sxgep->lock, flags);
}

static int sxge_set_mac_addr(struct net_device *dev, void *p)
{
	struct sxge *sxgep = netdev_priv(dev);
	struct sockaddr	*addr = p;
	unsigned long flags;
	int err;

	if (!is_valid_ether_addr(addr->sa_data))
		return -EINVAL;

	if (!memcmp(dev->perm_addr, addr->sa_data, ETH_ALEN))
		return 0;

	memcpy(dev->dev_addr, addr->sa_data, ETH_ALEN);

	if ((!netif_running(dev)) && (!(sxgep->flags & SXGE_FLAGS_HW_INIT)))
		return 0;

	/* set it here ? or EPS set it */
	spin_lock_irqsave(&sxgep->lock, flags);
	/* Reserve Slot 0 for Primary MAC address */
	err = sxge_eps_mbx_l2_add(sxgep, addr->sa_data, 0);
	spin_unlock_irqrestore(&sxgep->lock, flags);
	if (err)
		return -EADDRNOTAVAIL;

	return 0;
}

static int sxge_ioctl(struct net_device *dev, struct ifreq *ifr, int cmd)
{
#if 0
	struct sxge	*sxgep = netdev_priv(dev);
	int		status = 0;
#endif
	switch (cmd) {
	default:
#if 0
		netdev_warn(dev, "unknown ioctlcmd 0x%x\n", cmd);
#endif
		break;
	}
	return -EOPNOTSUPP;
}

static void sxge_netif_stop(struct sxge *sxgep)
{
	sxgep->dev->trans_start = jiffies; /* prevent tx timeout */

	sxge_disable_napi(sxgep);

	netif_tx_disable(sxgep->dev);
}

static void sxge_netif_start(struct sxge *sxgep)
{
	netif_tx_wake_all_queues(sxgep->dev);

	sxge_enable_napi(sxgep);

	sxge_enable_interrupts(sxgep, 1);
}

static void sxge_reset_task(struct work_struct *work)
{
	struct sxge	*sxgep = container_of(work, struct sxge, reset_task);
	unsigned long	flags;
	int		err;

	spin_lock_irqsave(&sxgep->lock, flags);
	if (!netif_running(sxgep->dev)) {
		spin_unlock_irqrestore(&sxgep->lock, flags);
		return;
	}

	spin_unlock_irqrestore(&sxgep->lock, flags);

	sxge_netif_stop(sxgep);

	spin_lock_irqsave(&sxgep->lock, flags);

	sxge_stop_hw(sxgep);

	spin_unlock_irqrestore(&sxgep->lock, flags);

	sxge_free_channels(sxgep);

	/* Re-init */
	err = sxge_get_default_config(sxgep);
	if (err)
		netdev_warn(sxgep->dev,
			"reset sxge_get_default_config failed\n");

	err = sxge_alloc_channels(sxgep);
	if (err) {
		netdev_err(sxgep->dev, "Failed to alloc sxge channels\n");
		return;
	}

	spin_lock_irqsave(&sxgep->lock, flags);

	err = sxge_init_hw(sxgep);
	if (!err)
		sxge_netif_start(sxgep);
	else
		netdev_err(sxgep->dev, "Failed to init hw\n");

	spin_unlock_irqrestore(&sxgep->lock, flags);
}

static void sxge_tx_timeout(struct net_device *dev)
{
	struct sxge *sxgep = netdev_priv(dev);

	dev_err(sxgep->device, "%s: Transmit timed out, resetting\n",
		dev->name);

	schedule_work(&sxgep->reset_task);
}

static void sxge_set_txd(struct tx_ring_info *txringp, int index,
			u64 mapping, u64 len, u64 mark, u64 n_frags,
			u64 ip_summed)
{
	__le64 *desc = &txringp->descr[index];

	*desc = cpu_to_le64(mark |
			(n_frags << TX_DESC_NUM_PTR_SHIFT) |
			((txringp->tdc_prsr_en & ip_summed)<<
			TX_DESC_CKSUM_EN_SHIFT) |
			(len << TX_DESC_TR_LEN_SHIFT) |
			(mapping & TX_DESC_SAD));
}

static u64 sxge_compute_tx_flags(struct sk_buff *skb, struct ethhdr *ehdr,
			u64 pad_bytes, u64 len)
{
	u16 eth_proto, eth_proto_inner;
	u64 csum_bits, l3off, ihl, ret;
	u8 ip_proto;
	int ipv6;

	eth_proto = be16_to_cpu(ehdr->h_proto);
	eth_proto_inner = eth_proto;
	if (eth_proto == ETH_P_8021Q) {
		struct vlan_ethhdr *vp = (struct vlan_ethhdr *) ehdr;
		__be16 val = vp->h_vlan_encapsulated_proto;

		eth_proto_inner = be16_to_cpu(val);
	}

	ipv6 = ihl = 0;
	switch (skb->protocol) {
	case cpu_to_be16(ETH_P_IP):
		ip_proto = ip_hdr(skb)->protocol;
		ihl = ip_hdr(skb)->ihl;
		break;
	case cpu_to_be16(ETH_P_IPV6):
		ip_proto = ipv6_hdr(skb)->nexthdr;
		ihl = (40 >> 2);
		ipv6 = 1;
		break;
	default:
		ip_proto = ihl = 0;
		break;
	}

	csum_bits = TXHDR_CSUM_NONE;
	if (skb->ip_summed == CHECKSUM_PARTIAL) {
		u64 start, stuff;

		csum_bits = (ip_proto == IPPROTO_TCP ?
				TXHDR_CSUM_TCP :
				(ip_proto == IPPROTO_UDP ?
				TXHDR_CSUM_UDP : TXHDR_CSUM_SCTP));

		start = skb_checksum_start_offset(skb) -
			(pad_bytes + sizeof(struct tx_pkt_hdr));
		stuff = start + skb->csum_offset;

		csum_bits |= (start / 2) << TXHDR_L4START_SHIFT;
		csum_bits |= (stuff / 2) << TXHDR_L4STUFF_SHIFT;
	}

	l3off = skb_network_offset(skb) -
		(pad_bytes + sizeof(struct tx_pkt_hdr));

	ret = (((pad_bytes / 2) << TXHDR_PAD_SHIFT) |
		(len << TXHDR_LEN_SHIFT) |
		((l3off / 2) << TXHDR_L3START_SHIFT) |
		(ihl << TXHDR_IHL_SHIFT) |
		((eth_proto_inner < 1536) ? TXHDR_LLC : 0) |
		((eth_proto == ETH_P_8021Q) ? TXHDR_VLAN : 0) |
		(ipv6 ? TXHDR_IP_VER : 0) |
		csum_bits);

	return ret;
}

static u64 read_rdtsc(void)
{
	u32	low;
	u32	high;
	u64	retval;
	asm volatile ("rdtsc\n" : "=a" (low), "=d" (high));

	retval = high;
	retval <<= 32;
	retval = retval | low;

	return retval;
}

void sxge_mailbox_mac_lookup_table(u8 *input_mac, u64 input_time, struct sxge *sxgep)
{
	u32	lru_index = 0;
	u32	i = 0, j = 0, k = 0, found = 0, index = 0;
	u32	done = 0, err = 0;
	u8	empty_mac[ETH_ALEN] = {0};
	unsigned long flags;

	for (i = 0 ; i < MBOX_LOOKUP_TABLE_SIZE; i++) {
		/*
		 * 1. Adding new MAC address to TCAM in unused slot
		 * 2. Adding Existing MAC addess in correct slot which
		 *    isused already.
		 * 3. Based on LRU find time and rewite the TCAM entry IF
		 *    lookup table full
		 */
		if (0 == memcmp(empty_mac, sxgep->mb_lookup_p[i].mac,
			ETH_ALEN)) {
			/*
			 * To find packets came from already saved MAC addesss
			 * in History
			 */
			for (j = 0; j < MBOX_LOOKUP_TABLE_SIZE; j++) {
				if (0 == memcmp(input_mac,
					sxgep->mb_lookup_p[j].history_mac,
					ETH_ALEN)) {
						index = j;
						found = 1;
						break;
				}
			}

			/* To Add new MAC address*/
			if (!found) {
				index = 0;
				for (k = 0; k < MBOX_LOOKUP_TABLE_SIZE; k++) {
				/* To find packets came from New MAC addesss */
					if (0 == memcmp(empty_mac,
					    sxgep->mb_lookup_p[k].history_mac,
					    ETH_ALEN)) {
						index = k;
						break;
					}

					/*To find the index for LRU */
					if (sxgep->mb_lookup_p[k].last_used <
					    sxgep->mb_lookup_p[index].last_used)
						index = k;
				}
			}

			i = index;
			memcpy(sxgep->mb_lookup_p[i].mac, input_mac, ETH_ALEN);
			memcpy(sxgep->mb_lookup_p[i].history_mac, input_mac,
				ETH_ALEN);

			sxgep->mb_lookup_p[i].last_used = input_time;
			sxgep->mb_lookup_p[i].flag = 1;

			spin_lock_irqsave(&sxgep->lock, flags);
			err = sxge_eps_mbx_l2_add(sxgep,
				sxgep->mb_lookup_p[i].history_mac, (u64)(i + 1));
			spin_unlock_irqrestore(&sxgep->lock, flags);

			if (err){
				sxgep->mb_lookup_p[i].flag = 0;
				return;
			}

			done = 1;
			break;
		}

		if (0 == memcmp(input_mac, sxgep->mb_lookup_p[i].mac,
			ETH_ALEN)) {
			sxgep->mb_lookup_p[i].last_used = input_time;
			done = 1;
			break;
		}

		if (sxgep->mb_lookup_p[i].last_used <
			sxgep->mb_lookup_p[lru_index].last_used)
			lru_index = i;
	}

	if (!done) {
		memcpy(sxgep->mb_lookup_p[lru_index].mac, input_mac, ETH_ALEN);
		memcpy(sxgep->mb_lookup_p[lru_index].history_mac, input_mac,
			ETH_ALEN);
		sxgep->mb_lookup_p[lru_index].last_used = input_time;
		spin_lock_irqsave(&sxgep->lock, flags);
		err = sxge_eps_mbx_l2_add(sxgep,
			sxgep->mb_lookup_p[lru_index].history_mac,
			(u64) (lru_index + 1));
		spin_unlock_irqrestore(&sxgep->lock, flags);
		if (err)
			return;
	}
}


void remove_lookup_table_entry_by_seconds(struct sxge *sxgep, u64 cputic)
{
	int	i;
	u32	high, tbl_entry_time_high;
	u8	empty_mac[ETH_ALEN] = {0};

	high = (u32)(cputic >> 32);

	for(i = 0; i < MBOX_LOOKUP_TABLE_SIZE; i++) {
		if (sxgep->mb_lookup_p[i].last_used == 0)
			continue;

		tbl_entry_time_high = (u32)(sxgep->mb_lookup_p[i].last_used >>
			32);
		/* more than 10 seconds */
		if ((high - tbl_entry_time_high) > 0x5) {
			sxgep->mb_lookup_p[i].flag = 0;
			memcpy(sxgep->mb_lookup_p[i].mac, empty_mac, ETH_ALEN);
		}
	}
}

static int sxge_start_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct sxge *sxgep = netdev_priv(dev);
	unsigned long align, headroom;
	struct netdev_queue *txq;
	struct tx_ring_info *txringp;
	struct tx_pkt_hdr *txhdrp;
	unsigned int len, nfg;
	struct ethhdr *ehdr;
	int prod, i, tlen;
	u64 mapping, mrk;
	u64 ip_summed = 0;
	u32 orphan = 0;

	if (sxge_live_migrate) {
		u64 cputic;

		cputic = read_rdtsc();
		remove_lookup_table_entry_by_seconds(sxgep, cputic);
	}

	i = skb_get_queue_mapping(skb);
	txringp = &sxgep->tx_rings[i];
	txq = netdev_get_tx_queue(dev, i);

	if (sxge_tx_avail(txringp) <= (skb_shinfo(skb)->nr_frags + 1)) {
		netif_tx_stop_queue(txq);
		dev_err(sxgep->device, "%s: BUG! Tx ring full when "
			"queue awake!\n", dev->name);
		txringp->tx_errors++;
		return NETDEV_TX_BUSY;
	}

	if (skb->len < ETH_ZLEN) {
		unsigned int pad_bytes = ETH_ZLEN - skb->len;

		if (skb_pad(skb, pad_bytes))
			goto out;
		skb_put(skb, pad_bytes);
	}

	if (sxge_live_migrate) {
		u8 l2_addr[ETH_ALEN];
		u64 last_used;

		memcpy(l2_addr, skb->data+6, ETH_ALEN);

		if ((memcmp(dev->perm_addr, l2_addr, ETH_ALEN) != 0) &&
			(memcmp(dev->dev_addr, l2_addr, ETH_ALEN) != 0)){
			last_used = read_rdtsc();
			sxge_mailbox_mac_lookup_table( l2_addr, last_used, sxgep);
		}
	}

	if (txringp->tdc_prsr_en != 1) {
		orphan = 1;
		netdev_warn(dev, "xmit txringp->tdc_prsr_en != 1\n");
		len = sizeof(struct tx_pkt_hdr) + 15;
		if (skb_headroom(skb) < len) {
			struct sk_buff *skb_new;

			skb_new = skb_realloc_headroom(skb, len);
			if (!skb_new) {
				txringp->tx_errors++;
				goto out_drop;
			}
			kfree_skb(skb);
			skb = skb_new;
		} else
			skb_orphan(skb);

		align = ((unsigned long) skb->data & (16 - 1));
		headroom = align + sizeof(struct tx_pkt_hdr);

		ehdr = (struct ethhdr *) skb->data;
		txhdrp = (struct tx_pkt_hdr *) skb_push(skb, headroom);

		len = skb->len - sizeof(struct tx_pkt_hdr);
		txhdrp->flags = cpu_to_le64(
				sxge_compute_tx_flags(skb, ehdr, align, len));
		txhdrp->resv = 0;
	}

	if (!orphan)
		skb_orphan(skb);

	len = skb_headlen(skb);
	mapping = sxgep->ops->map_single(sxgep->device, skb->data,
			len, DMA_TO_DEVICE);

	if (skb->ip_summed)
		ip_summed = 1;

	prod = txringp->prod;

	txringp->tx_buffs[prod].skb = skb;
	txringp->tx_buffs[prod].mapping = mapping;

	mrk = TX_DESC_SOP;
	if (++txringp->mark_counter == txringp->mark_freq) {
		txringp->mark_counter = 0;
		mrk |= TX_DESC_MARK;
		txringp->mark_pending++;
	}

	tlen = len;
	nfg = skb_shinfo(skb)->nr_frags;
	while (tlen > 0) {
		tlen -= MAX_TX_DESC_LEN;
		nfg++;
	}

	while (len > 0) {
		unsigned int this_len = len;

		if (this_len > MAX_TX_DESC_LEN)
			this_len = MAX_TX_DESC_LEN;

		sxge_set_txd(txringp, prod, mapping, this_len, mrk, nfg,
			ip_summed);
		mrk = nfg = 0;
		prod = NEXT_TX(txringp, prod);
		mapping += this_len;
		len -= this_len;
	}

	for (i = 0; i <  skb_shinfo(skb)->nr_frags; i++) {
		skb_frag_t *frag = &skb_shinfo(skb)->frags[i];

		len = frag->size;
		mapping = sxgep->ops->map_page(sxgep->device, frag->page,
					frag->page_offset, len,
					DMA_TO_DEVICE);

		txringp->tx_buffs[prod].skb = NULL;
		txringp->tx_buffs[prod].mapping = mapping;

		sxge_set_txd(txringp, prod, mapping, len, 0, 0, ip_summed);
		prod = NEXT_TX(txringp, prod);
	}

	if (prod < txringp->prod)
		txringp->wrap_bit ^= TDC_RING_KICK_WRAP;
	txringp->prod = prod;

	SXGE_PUT64(TDC_RING_KICK(txringp->tdc_base),
		txringp->wrap_bit | (prod << 3));

	if (unlikely(sxge_tx_avail(txringp) <= (MAX_SKB_FRAGS + 1))) {
		netif_tx_stop_queue(txq);
		if (sxge_tx_avail(txringp) > SXGE_TX_WAKEUP_THRESH(txringp))
			netif_tx_wake_queue(txq);
	}

out:
	return NETDEV_TX_OK;

out_drop:
	txringp->tx_errors++;
	kfree_skb(skb);
	goto out;
}

static int sxge_change_mtu(struct net_device *dev, int new_mtu)
{
	int		err = 0, orig_jumbo, new_jumbo;

	if ((new_mtu < 68) || (new_mtu > (SXGE_MAX_MTU - 22)))
		return -EINVAL;

	orig_jumbo = (dev->mtu > ETH_DATA_LEN);
	new_jumbo = (new_mtu > ETH_DATA_LEN);

	dev->mtu = new_mtu;

	if (!netif_running(dev) ||
		(orig_jumbo == new_jumbo))
		return 0;

	return err;
}

static void sxge_get_drvinfo(struct net_device *dev,
		struct ethtool_drvinfo *info)
{
	struct sxge	*sxgep = netdev_priv(dev);

	strncpy(info->driver, DRV_MODULE_NAME, 32);
	strncpy(info->version, DRV_MODULE_VERSION, 32);
	strncpy(info->bus_info, pci_name(sxgep->pdev), 32);
}

static int sxge_get_settings(struct net_device *dev, struct ethtool_cmd *cmd)
{
	struct sxge *sxgep = netdev_priv(dev);
	struct sxge_link_config *linkp;

	if (!netif_running(dev))
		return 0;

	if (sxge_eps_mbx_link_speed(sxgep))
		netdev_warn(dev, "sxge_eps_mbx_link_speed failed\n");

	linkp = &sxgep->link_config;

	linkp->active_speed = linkp->speed;
	linkp->active_duplex = DUPLEX_FULL;
	linkp->active_autoneg = 1;
	linkp->active_advertising |= ADVERTISED_Autoneg;

	memset(cmd, 0, sizeof(*cmd));
	cmd->phy_address = 0;
	cmd->supported = linkp->supported | SUPPORTED_Autoneg;
	cmd->advertising = linkp->active_advertising;
	cmd->autoneg = linkp->active_autoneg;
	ethtool_cmd_speed_set(cmd, linkp->active_speed);
	cmd->duplex = linkp->active_duplex;
	cmd->port = PORT_FIBRE;

	return 0;
}

static int sxge_set_settings(struct net_device *dev, struct ethtool_cmd *cmd)
{
	return -EINVAL;
}

static u32 sxge_get_msglevel(struct net_device *dev)
{
	struct sxge *sxgep = netdev_priv(dev);
	return sxgep->msg_enable;
}

static void sxge_set_msglevel(struct net_device *dev, u32 value)
{
	struct sxge *sxgep = netdev_priv(dev);
	sxgep->msg_enable = value;
}

static const struct {
	const char string[ETH_GSTRING_LEN];
} sxge_vmac_stat_keys[] = {
	{ "tx_frames" },
	{ "tx_bytes" },
	{ "tx_frame_cnt_ovl" },
	{ "tx_byte_cnt_ovl" },
	{ "rx_frames" },
	{ "rx_bytes" },
	{ "rx_drops" },
	{ "rx_drop_bytes" },
	{ "rx_mcasts" },
	{ "rx_bcasts" },
	{ "rx_frames_cnt_ovl" },
	{ "rx_byte_cnt_ovl" },
	{ "rx_drop_byte_ovl" },
	{ "rx_drop_cnt_ovl" },
	{ "rx_mcast_frame_cnt_ovl" },
	{ "rx_bcast_frame_cnt_ovl" },
	{ "rx_link_up" },
	{ "rx_link_down" },
	{ "rx_link_state" },
};

#define NUM_VMAC_STAT_KEYS	ARRAY_SIZE(sxge_vmac_stat_keys)

static const struct {
	const char string[ETH_GSTRING_LEN];
} sxge_rxchan_stat_keys[] = {
	{ "rx_channel" },
	{ "rx_packets" },
	{ "rx_bytes" },
	{ "rx_dropped" },
	{ "rx_errors" },
	{ "rx_hw_pktcnt" },
	{ "rx_hw_pktdrop" },
	{ "rx_rbr_empty" },
	{ "rx_fifo_error" },
	{ "rx_rcr_shadow_full" },
};

#define NUM_RXCHAN_STAT_KEYS	ARRAY_SIZE(sxge_rxchan_stat_keys)

static const struct {
	const char string[ETH_GSTRING_LEN];
} sxge_txchan_stat_keys[] = {
	{ "tx_channel" },
	{ "tx_packets" },
	{ "tx_bytes" },
	{ "tx_errors" },
};

#define NUM_TXCHAN_STAT_KEYS	ARRAY_SIZE(sxge_txchan_stat_keys)

static void sxge_get_strings(struct net_device *dev, u32 stringset, u8 *data)
{
	struct sxge *sxgep = netdev_priv(dev);
	int i;

	if (stringset != ETH_SS_STATS)
		return;

	memcpy(data, sxge_vmac_stat_keys,
	       sizeof(sxge_vmac_stat_keys));
	data += sizeof(sxge_vmac_stat_keys);

	for (i = 0; i < sxgep->num_rings; i++) {
		memcpy(data, sxge_rxchan_stat_keys,
		       sizeof(sxge_rxchan_stat_keys));
		data += sizeof(sxge_rxchan_stat_keys);
	}
	for (i = 0; i < sxgep->num_rings; i++) {
		memcpy(data, sxge_txchan_stat_keys,
		       sizeof(sxge_txchan_stat_keys));
		data += sizeof(sxge_txchan_stat_keys);
	}
}

static int sxge_get_sset_count(struct net_device *dev, int stringset)
{
	struct sxge *sxgep = netdev_priv(dev);

	if (stringset != ETH_SS_STATS)
		return -EINVAL;

	return NUM_VMAC_STAT_KEYS +
		(sxgep->num_rings * NUM_RXCHAN_STAT_KEYS) +
		(sxgep->num_rings * NUM_TXCHAN_STAT_KEYS);
}

static void sxge_get_ethtool_stats(struct net_device *dev,
				  struct ethtool_stats *stats, u64 *data)
{
	struct sxge *sxgep = netdev_priv(dev);
	int i;

	sxge_vmac_stats(sxgep);

	memcpy(data, &sxgep->vmac_stats,
	       sizeof(struct sxge_vmac_stats));
	data += (sizeof(struct sxge_vmac_stats) / sizeof(u64));

	for (i = 0; i < sxgep->num_rings; i++) {
		struct rx_ring_info *rxringp = &sxgep->rx_rings[i];

		if (!rxringp)
			return;

		rxringp->rx_hw_pktcnt +=
			SXGE_GET64(RDC_PKTCNT(rxringp->rdc_base)) &
			RDC_PKTCNT_COUNT;
		rxringp->rx_hw_pktdrop +=
			SXGE_GET64(RDC_PKTDROP(rxringp->rdc_base)) &
			RDC_PKTDROP_COUNT;

		data[0] = (u64) rxringp->rx_channel;
		data[1] = rxringp->rx_packets;
		data[2] = rxringp->rx_bytes;
		data[3] = rxringp->rx_dropped;
		data[4] = rxringp->rx_errors;
		data[5] = rxringp->rx_hw_pktcnt;
		data[6] = rxringp->rx_hw_pktdrop;
		data[7] = rxringp->rx_rbr_empty;
		data[8] = rxringp->rx_fifo_error;
		data[9] = rxringp->rx_rcr_shadow_full;
		data += 10;
	}
	for (i = 0; i < sxgep->num_rings; i++) {
		struct tx_ring_info *txringp = &sxgep->tx_rings[i];

		if (!txringp)
			return;

		data[0] = (u64) txringp->tx_channel;
		data[1] = txringp->tx_packets;
		data[2] = txringp->tx_bytes;
		data[3] = txringp->tx_errors;
		data += 4;
	}
}

static const struct ethtool_ops sxge_ethtool_ops = {
	.get_drvinfo		= sxge_get_drvinfo,
	.get_link		= ethtool_op_get_link,
	.get_msglevel		= sxge_get_msglevel,
	.set_msglevel		= sxge_set_msglevel,
	.get_settings		= sxge_get_settings,
	.set_settings		= sxge_set_settings,
	.get_strings		= sxge_get_strings,
	.get_sset_count		= sxge_get_sset_count,
	.get_ethtool_stats	= sxge_get_ethtool_stats,
};

static int sxge_ldg_assign_ldn(struct sxge *sxgep, int ldg, int ldn)
{
	u8 vni = sxgep->vni, func = sxgep->intmgmt_nf;
	u64 val;

	if (ldg < SXGE_LDG_MIN || ldg > SXGE_LDG_MAX)
		return -EINVAL;
	if (ldn < 0 || ldn > LDN_MAX)
		return -EINVAL;

	sxgep->ldg_map[ldn] = ldg;

	val = (ldg & LD_MSK_GNUM_LDG_NUM) | LD_MSK_GNUM_EN_LDG_WR;
	SXGE_PUT64(LD_MSK_GNUM(vni, func, ldn), val);

	return 0;
}

static void __devinit sxge_try_msix(struct sxge *sxgep, u8 *ldg_num_map)
{
	struct msix_entry msi_vec[SXGE_NUM_LDG];
	struct pci_dev *pdev = sxgep->pdev;
	int i, num_irqs, err;

	for (i = 0; i < SXGE_NUM_LDG; i++)
		ldg_num_map[i] = i;

	num_irqs = (sxgep->num_rings * 2) + 5;
retry:
	for (i = 0; i < num_irqs; i++) {
		msi_vec[i].vector = 0;
		msi_vec[i].entry = i;
	}

	err = pci_enable_msix(pdev, msi_vec, num_irqs);
	if (err < 0) {
		sxgep->flags &= ~SXGE_FLAGS_MSIX;
		return;
	}
	if (err > 0) {
		num_irqs = err;
		goto retry;
	}

	sxgep->flags |= SXGE_FLAGS_MSIX;
	for (i = 0; i < num_irqs; i++)
		sxgep->ldg[i].irq = msi_vec[i].vector;
	sxgep->num_ldg = num_irqs;
}

static int __devinit sxge_ldg_init(struct sxge *sxgep)
{
	u8 ldg_num_map[SXGE_NUM_LDG];
	int i, err, ldg_rotor;

	sxgep->num_ldg = 1;
	sxgep->ldg[0].irq = sxgep->dev->irq;

	sxge_try_msix(sxgep, ldg_num_map);

	for (i = 0; i < sxgep->num_ldg; i++) {
		struct sxge_ldg *lp = &sxgep->ldg[i];

		netif_napi_add(sxgep->dev, &lp->napi, sxge_poll, 64);

		lp->sxgep = sxgep;
		lp->ldg_num = ldg_num_map[i];
		lp->timer = 2; /* XXX */

		/* SID ? */
	}

	/*
	 * LDG assignment ordering
	 *
	 *	RX DMA channels
	 *	TX DMA channels
	 *	Mailbox
	 *	RX VMAC
	 *	TX VMAC
	 *	VNI error
	 */
	ldg_rotor = 0;

	for (i = 0; i < sxgep->num_rings; i++) {
		err = sxge_ldg_assign_ldn(sxgep,
		    ldg_num_map[ldg_rotor], LDN_RXDMA(i));
		if (err)
			return err;
		ldg_rotor++;
		if (ldg_rotor == sxgep->num_ldg)
			ldg_rotor = 0;
	}

	for (i = 0; i < sxgep->num_rings; i++) {
		err = sxge_ldg_assign_ldn(sxgep,
		    ldg_num_map[ldg_rotor], LDN_TXDMA(i));
		if (err)
			return err;
		ldg_rotor++;
		if (ldg_rotor == sxgep->num_ldg)
			ldg_rotor = 0;
	}

	ldg_rotor++;
	if (ldg_rotor == sxgep->num_ldg)
		ldg_rotor = 0;
	err = sxge_ldg_assign_ldn(sxgep, ldg_num_map[ldg_rotor], LDN_MAILBOX);
	if (err)
		return err;

	ldg_rotor++;
	if (ldg_rotor == sxgep->num_ldg)
		ldg_rotor = 0;
	err = sxge_ldg_assign_ldn(sxgep, ldg_num_map[ldg_rotor], LDN_RXVMAC);
	if (err)
		return err;

	ldg_rotor++;
	if (ldg_rotor == sxgep->num_ldg)
		ldg_rotor = 0;
	err = sxge_ldg_assign_ldn(sxgep, ldg_num_map[ldg_rotor], LDN_TXVMAC);
	if (err)
		return err;

	ldg_rotor++;
	if (ldg_rotor == sxgep->num_ldg)
		ldg_rotor = 0;
	err = sxge_ldg_assign_ldn(sxgep, ldg_num_map[ldg_rotor], LDN_VNI_ERROR);
	if (err)
		return err;

	return 0;
}

static void __devexit sxge_ldg_free(struct sxge *sxgep)
{
	if (sxgep->flags & SXGE_FLAGS_MSIX)
		pci_disable_msix(sxgep->pdev);
}

static int __devinit sxge_get_invariants(struct sxge *sxgep)
{
	int			i, err = 0;
	struct net_device	*dev = sxgep->dev;
	unsigned char		mac_addr[6];
	u64			val;

	if (sxge_get_default_config(sxgep) < 0) {
		netdev_warn(sxgep->dev, "sxge_get_default_config fail\n");
		return -1;
	}

	val = SXGE_GET64(0xf00b8);
	mac_addr[5] = (u8)(val & 0xff);
	mac_addr[4] = (u8)((val >> 8) & 0xff);
	mac_addr[3] = (u8)((val >> 16) & 0xff);
	mac_addr[2] = (u8)((val >> 24) & 0xff);
	mac_addr[1] = (u8)((val >> 32) & 0xff);
	mac_addr[0] = (u8)((val >> 40) & 0xff);

	memcpy(dev->perm_addr, mac_addr, ETH_ALEN);
	memcpy(dev->dev_addr, dev->perm_addr, dev->addr_len);

	/* irq disable */
	for (i = 0; i <= LDN_MAX; i++)
		sxge_ldn_irq_enable(sxgep, i, 0);

	/* LDG init for interrupt */
	sxge_ldg_init(sxgep);

	return err;
}

static void *sxge_pci_alloc_coherent(struct device *dev, size_t size,
	u64 *handle, gfp_t flag)
{
	dma_addr_t	dh;
	void		*ret;

	ret = dma_alloc_coherent(dev, size, &dh, flag);
	if (ret)
		*handle = dh;
	return ret;
}

static void sxge_pci_free_coherent(struct device *dev, size_t size,
	void *cpu_addr, u64 handle)
{
	dma_free_coherent(dev, size, cpu_addr, handle);
}

static u64 sxge_pci_map_page(struct device *dev, struct page *page,
	unsigned long offset, size_t size, enum dma_data_direction direction)
{
	return dma_map_page(dev, page, offset, size, direction);
}

static void sxge_pci_unmap_page(struct device *dev, u64 dma_address,
	size_t size, enum dma_data_direction direction)
{
	dma_unmap_page(dev, dma_address, size, direction);
}

static u64 sxge_pci_map_single(struct device *dev, void *cpu_addr,
	size_t size, enum dma_data_direction direction)
{
	return dma_map_single(dev, cpu_addr, size, direction);
}

static void sxge_pci_unmap_single(struct device *dev, u64 dma_address,
	size_t size, enum dma_data_direction direction)
{
	dma_unmap_single(dev, dma_address, size, direction);
}

static const struct sxge_ops sxge_pci_ops = {
	.alloc_coherent = sxge_pci_alloc_coherent,
	.free_coherent  = sxge_pci_free_coherent,
	.map_page       = sxge_pci_map_page,
	.unmap_page     = sxge_pci_unmap_page,
	.map_single     = sxge_pci_map_single,
	.unmap_single   = sxge_pci_unmap_single,
};

static void __devinit sxge_driver_version(void)
{
	static int sxge_version_printed;

	if (sxge_version_printed++ == 0)
		pr_info("%s", version);
}

static struct net_device * __devinit sxge_alloc_and_init(
	struct device *gen_dev, struct pci_dev *pdev,
	const struct sxge_ops *ops, u8 devfn)
{
	struct net_device *dev;
	struct sxge *sxgep;

	dev = alloc_etherdev_mq(sizeof(struct sxge), 4);
	if (!dev) {
		dev_err(gen_dev, "Etherdev alloc failed, aborting\n");
		return NULL;
	}

	SET_NETDEV_DEV(dev, gen_dev);

	sxgep = netdev_priv(dev);
	sxgep->dev = dev;
	sxgep->pdev = pdev;
	sxgep->device = gen_dev;
	sxgep->ops = ops;

	sxgep->msg_enable = sxge_debug;

	spin_lock_init(&sxgep->lock);
	INIT_WORK(&sxgep->reset_task, sxge_reset_task);

	sxgep->devfn = devfn;

	return dev;
}

static const struct net_device_ops sxge_netdev_ops = {
	.ndo_open		= sxge_open,
	.ndo_stop		= sxge_close,
	.ndo_start_xmit		= sxge_start_xmit,
	.ndo_get_stats		= sxge_get_stats,
	.ndo_set_multicast_list	= sxge_set_rx_mode,
	.ndo_validate_addr	= eth_validate_addr,
	.ndo_set_mac_address	= sxge_set_mac_addr,
	.ndo_do_ioctl		= sxge_ioctl,
	.ndo_tx_timeout		= sxge_tx_timeout,
	.ndo_change_mtu		= sxge_change_mtu,
};

static void __devinit sxge_assign_netdev_ops(struct net_device *dev)
{
	dev->netdev_ops = &sxge_netdev_ops;
	dev->ethtool_ops = &sxge_ethtool_ops;
	dev->watchdog_timeo = SXGE_TX_TIMEOUT;
}

static void __devinit sxge_device_announce(struct sxge *sxgep)
{
	struct net_device	*dev = sxgep->dev;

	pr_info("%s: SXGE Ethernet %pM\n", dev->name, dev->dev_addr);
}

static int __devinit sxge_pci_init_one(struct pci_dev *pdev,
					const struct pci_device_id *ent)
{
	struct net_device	*dev;
	struct sxge		*sxgep;
	int			err, pos;
	u64			dma_mask;
	u16			val16;

	sxge_driver_version();

	err = pci_enable_device(pdev);
	if (err) {
		dev_err(&pdev->dev, "Cannot enable PCI device, aborting\n");
		return err;
	}

	if (!(pci_resource_flags(pdev, 0) & IORESOURCE_MEM) ||
		!(pci_resource_flags(pdev, 2) & IORESOURCE_MEM)) {
			dev_err(&pdev->dev, "Cannot find proper PCI device "
				"base addresses, aborting\n");
			err = -ENODEV;
			goto err_out_disable_pdev;
	}

	err = pci_request_regions(pdev, DRV_MODULE_NAME);
	if (err) {
		dev_err(&pdev->dev, "Cannot obtain PCI resources, aborting\n");
		goto err_out_disable_pdev;
	}

	pos = pci_find_capability(pdev, PCI_CAP_ID_EXP);
	if (pos <= 0) {
		dev_err(&pdev->dev, "Cannot find PCI Express capability, "
			"aborting\n");
		goto err_out_free_res;
	}

	dev = sxge_alloc_and_init(&pdev->dev, pdev,
		&sxge_pci_ops, PCI_FUNC(pdev->devfn));

	if (!dev) {
		err = -ENOMEM;
		goto err_out_free_res;
	}

	sxgep = netdev_priv(dev);

	/* Need to get pci.domain, pci_bus, pci_device? */
	sxgep->dev_busnum = pdev->bus->number;

	pci_read_config_word(pdev, pos + PCI_EXP_DEVCTL, &val16);
	val16 &= ~PCI_EXP_DEVCTL_NOSNOOP_EN;
	val16 |= (PCI_EXP_DEVCTL_CERE |
		PCI_EXP_DEVCTL_NFERE |
		PCI_EXP_DEVCTL_FERE |
		PCI_EXP_DEVCTL_URRE |
		PCI_EXP_DEVCTL_RELAX_EN);
	pci_write_config_word(pdev, pos + PCI_EXP_DEVCTL, val16);

	dma_mask = DMA_BIT_MASK(44);
	err = pci_set_dma_mask(pdev, dma_mask);
	if (!err) {
		dev->features |= NETIF_F_HIGHDMA;
		err = pci_set_consistent_dma_mask(pdev, dma_mask);
		if (err) {
			dev_err(&pdev->dev, "Unable to obtain 44 bit "
				"DMA for consistent allocations, "
				"aborting\n");
			goto err_out_free_dev;
		}
	}

	if (err || dma_mask == DMA_BIT_MASK(32)) {
		err = pci_set_dma_mask(pdev, DMA_BIT_MASK(32));
		if (err) {
			dev_err(&pdev->dev, "No usable DMA configuration, "
				 "aborting\n");
			goto err_out_free_dev;
		}
	}
#if 0
	/*
	 * Network stack pass down the pkts with checksum
	 * If driver enable the HW checksum feature,
	 * the checksum value ends up wrong
	 */
	dev->features |= (NETIF_F_SG | NETIF_F_HW_CSUM);
#endif

	sxgep->regs = pci_ioremap_bar(pdev, 2);
	if (!sxgep->regs) {
		dev_err(&pdev->dev, "Cannot map device registers, "
			"aborting\n");
		err = -ENOMEM;
		goto err_out_free_dev;
	}

	pci_set_master(pdev);
	pci_save_state(pdev);

	/* Assign dev ops */
	dev->irq = pdev->irq;
	sxge_assign_netdev_ops(dev);

	/* LDG INIT for interrupts */
	err = sxge_get_invariants(sxgep);
	if (err) {
		if (err != -ENODEV)
			dev_err(&pdev->dev, "Problem fetching invariants "
				"of chip, aborting\n");
		goto err_out_iounmap;
	}

#ifdef CONFIG_PCI_IOV
	if (pdev->device == 0x207a) {
		struct pci_sriov *iov;
		u16 vfs;

		iov = sxgep->pdev->sriov;
		if (!iov)
			netdev_warn(dev, "iov is NULL, not a SR-IOV device\n");

		if (!sxgep->pdev->is_physfn)
			netdev_warn(dev, "No PF is seen, !dev->is_physfn\n");

		pci_read_config_word(pdev, 0x16c, &vfs);
		err = pci_enable_sriov(pdev, vfs);
		if (err) {
			netdev_warn(dev, "misconfiguration, "
				"pci_enable_sriov failed\n");
		} else {
			sxgep->flags |= SXGE_FLAGS_SRIOV;
		}
	}
#endif

	/* The following will be done in sxge_get_invariants and and sxge_open*/
	/* Init code PFC? */
	/* Not sxge */
	/* TODO: INIT param */
	/* TODO: INIT STATS */
	/* TODO: INIT DMA pages */
	/* TODO: INIT real HW */
	/* TODO: INIT XCVR */

	err = register_netdev(dev);
	if (err) {
		dev_err(&pdev->dev, "Cannot register net device, "
			"aborting\n");
		goto err_out_iounmap;
	}

	pci_set_drvdata(pdev, dev);

	sxge_device_announce(sxgep);

	return 0;

err_out_iounmap:
	if (sxgep->regs) {
		iounmap(sxgep->regs);
		sxgep->regs = NULL;
	}

err_out_free_dev:
	free_netdev(dev);

err_out_free_res:
	pci_release_regions(pdev);

err_out_disable_pdev:
	pci_disable_device(pdev);
	pci_set_drvdata(pdev, NULL);

	return err;
}

static void __devexit sxge_pci_remove_one(struct pci_dev *pdev)
{
	struct net_device *dev = pci_get_drvdata(pdev);

	if (dev) {
		struct sxge *sxgep = netdev_priv(dev);

		sxgep->flags &= ~SXGE_FLAGS_HW_INIT;

		unregister_netdev(dev);

		if (pdev->device == 0x207a) {
			if (sxgep->flags & SXGE_FLAGS_SRIOV) {
#ifdef CONFIG_PCI_IOV
				pci_disable_sriov(pdev);
				sxgep->flags &= ~SXGE_FLAGS_SRIOV;
#endif
			}
		}

		if (sxgep->regs) {
			iounmap(sxgep->regs);
			sxgep->regs = NULL;
		}

		sxge_ldg_free(sxgep);

		free_netdev(dev);
		pci_release_regions(pdev);
		pci_disable_device(pdev);
		pci_set_drvdata(pdev, NULL);
	}
}

static int sxge_suspend(struct pci_dev *pdev, pm_message_t state)
{
	struct net_device	*dev = pci_get_drvdata(pdev);
	struct sxge		*sxgep = netdev_priv(dev);
	unsigned long		flags;

	if (!netif_running(dev))
		return 0;

	flush_work_sync(&sxgep->reset_task);
	sxge_netif_stop(sxgep);

	/* TODO: DISABLE & STOP HW */
	spin_lock_irqsave(&sxgep->lock, flags);
	sxge_enable_interrupts(sxgep, 0);
	spin_unlock_irqrestore(&sxgep->lock, flags);

	netif_device_detach(dev);

	spin_lock_irqsave(&sxgep->lock, flags);
	sxge_stop_hw(sxgep);
	spin_unlock_irqrestore(&sxgep->lock, flags);

	pci_save_state(pdev);

	return 0;
}

static int sxge_resume(struct pci_dev *pdev)
{
	struct net_device	*dev = pci_get_drvdata(pdev);
	struct sxge		*sxgep = netdev_priv(dev);
	unsigned long		flags;
	int			err;

	if (!netif_running(dev))
		return 0;

	pci_restore_state(pdev);

	netif_device_attach(dev);

	spin_lock_irqsave(&sxgep->lock, flags);

	/* TODO: Init & start HW */
	err = sxge_init_hw(sxgep);
	if (!err)
		sxge_netif_start(sxgep);

	spin_unlock_irqrestore(&sxgep->lock, flags);

	return err;
}

static struct pci_driver sxge_pci_driver = {
	.name		= DRV_MODULE_NAME,
	.id_table	= sxge_pci_tbl,
	.probe		= sxge_pci_init_one,
	.remove		= __devexit_p(sxge_pci_remove_one),
	.suspend	= sxge_suspend,
	.resume		= sxge_resume,
};

static int __init sxge_init(void)
{
	int err = 0;

	sxge_debug = netif_msg_init(debug, SXGE_MSG_DEFAULT);

	if (!err)
		err = pci_register_driver(&sxge_pci_driver);

	return err;
}

static void __exit sxge_exit(void)
{
	pci_unregister_driver(&sxge_pci_driver);
}

module_init(sxge_init);
module_exit(sxge_exit);
