// SPDX-License-Identifier: GPL-2.0
/* Marvell CNF10K BPHY RFOE Netdev Driver
 *
 * Copyright (C) 2022 Marvell.
 */

#include "cnf10k_rfoe.h"
#include "cnf10k_bphy_hw.h"
#include "otx2_bphy_debugfs.h"

static const char *cnf10k_rfoe_debugfs_get_formatter(void)
{
	static const char *buffer_format = "ptp-tx-in-progress: %u\n"
					   "queued-ptp-reqs: %u\n"
					   "queue-stopped: %u\n"
					   "state-up: %u\n"
					   "last-tx-jiffies: %lu\n"
					   "last-tx-dropped-jiffies: %lu\n"
					   "last-tx-ptp-jiffies: %lu\n"
					   "last-tx-ptp-dropped-jiffies: %lu\n"
					   "last-rx-jiffies: %lu\n"
					   "last-rx-dropped-jiffies: %lu\n"
					   "last-rx-ptp-jiffies: %lu\n"
					   "last-rx-ptp-dropped-jiffies: %lu\n"
					   "current-jiffies: %lu\n"
					   "other-tx-psm-space: %u\n"
					   "ptp-tx-psm-space: %u\n";

	return buffer_format;
}

static void cnf10k_rfoe_debugfs_reader(char *buffer, size_t count, void *priv)
{
	u16 other_tx_psm_space, ptp_tx_psm_space, queue_id;
	struct cnf10k_rfoe_ndev_priv *netdev;
	struct cnf10k_rfoe_drv_ctx *ctx;
	unsigned int queued_ptp_reqs;
	u8 queue_stopped, state_up;
	u8 ptp_tx_in_progress;
	const char *formatter;
	u64 regval;

	ctx = priv;
	netdev = netdev_priv(ctx->netdev);
	ptp_tx_in_progress = test_bit(PTP_TX_IN_PROGRESS, &netdev->state);
	queued_ptp_reqs = netdev->ptp_skb_list.count;
	queue_stopped = netif_queue_stopped(ctx->netdev);
	state_up = netdev->link_state;
	formatter = cnf10k_rfoe_debugfs_get_formatter();

	/* other tx psm space */
	queue_id = netdev->rfoe_common->tx_oth_job_cfg.psm_queue_id;
	regval = readq(netdev->psm_reg_base + PSM_QUEUE_SPACE(queue_id));
	other_tx_psm_space = regval & 0x7FFF;

	/* ptp tx psm space */
	queue_id = netdev->tx_ptp_job_cfg.psm_queue_id;
	regval = readq(netdev->psm_reg_base + PSM_QUEUE_SPACE(queue_id));
	ptp_tx_psm_space = regval & 0x7FFF;

	snprintf(buffer, count, formatter,
		 ptp_tx_in_progress,
		 queued_ptp_reqs,
		 queue_stopped,
		 state_up,
		 netdev->last_tx_jiffies,
		 netdev->last_tx_dropped_jiffies,
		 netdev->last_tx_ptp_jiffies,
		 netdev->last_tx_ptp_dropped_jiffies,
		 netdev->last_rx_jiffies,
		 netdev->last_rx_dropped_jiffies,
		 netdev->last_rx_ptp_jiffies,
		 netdev->last_rx_ptp_dropped_jiffies,
		 jiffies,
		 other_tx_psm_space,
		 ptp_tx_psm_space);
}

static size_t cnf10k_rfoe_debugfs_get_buffer_size(void)
{
	static size_t buffer_size;

	if (!buffer_size) {
		const char *formatter = cnf10k_rfoe_debugfs_get_formatter();
		u8 max_boolean = 1;
		int max_ptp_req_count = max_ptp_req;
		unsigned long max_jiffies = (unsigned long)-1;
		u16 max_psm_space = (u16)-1;

		buffer_size = snprintf(NULL, 0, formatter,
				       max_boolean,
				       max_ptp_req_count,
				       max_boolean,
				       max_boolean,
				       max_jiffies,
				       max_jiffies,
				       max_jiffies,
				       max_jiffies,
				       max_jiffies,
				       max_jiffies,
				       max_jiffies,
				       max_jiffies,
				       max_jiffies,
				       max_psm_space,
				       max_psm_space);
		++buffer_size;
	}

	return buffer_size;
}

void cnf10k_rfoe_debugfs_create(struct cnf10k_rfoe_drv_ctx *ctx)
{
	size_t buffer_size = cnf10k_rfoe_debugfs_get_buffer_size();

	ctx->debugfs = otx2_bphy_debugfs_add_file(ctx->netdev->name,
						  buffer_size, ctx,
						  cnf10k_rfoe_debugfs_reader);
}

void cnf10k_rfoe_debugfs_remove(struct cnf10k_rfoe_drv_ctx *ctx)
{
	if (ctx->debugfs)
		otx2_bphy_debugfs_remove_file(ctx->debugfs);
}
