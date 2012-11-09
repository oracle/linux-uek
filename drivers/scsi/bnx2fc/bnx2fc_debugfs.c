/* bnx2fc_fcoe.c: Broadcom NetXtreme II Linux FCoE offload driver.
 *
 * This file contains the debugfs code to display debug info
 * Copyright (c) 2008 - 2012 Broadcom Corporation
 *
 * Author: Nithin Nayak Sujir <nsujir@broadcom.com>
 *
 */
#include "bnx2fc.h"

#include <linux/debugfs.h>
#include <linux/seq_file.h>

static struct dentry *bnx2fc_debugfs_root;
static struct dentry *bnx2fc_debugfs_info;


static void bnx2fc_debugfs_add_stats(struct bnx2fc_tgt_dbg_stats *stats,
				     struct bnx2fc_rport *tgt)
{
	stats->num_cmd_timeouts		   += tgt->stats.num_cmd_timeouts;
	stats->num_eh_abort_timeouts       += tgt->stats.num_eh_abort_timeouts;
	stats->num_abts_timeouts	   += tgt->stats.num_abts_timeouts;
	stats->num_explicit_logos	   += tgt->stats.num_explicit_logos;
	stats->num_io_compl_before_abts    +=
					    tgt->stats.num_io_compl_before_abts;
	stats->num_els_abts_timeouts       += tgt->stats.num_els_abts_timeouts;
	stats->num_els_timeouts		   += tgt->stats.num_els_timeouts;
	stats->num_rrq_issued		   += tgt->stats.num_rrq_issued;
	stats->num_cleanup_issued	   += tgt->stats.num_cleanup_issued;
	stats->num_cleanup_compl	   += tgt->stats.num_cleanup_compl;
	stats->num_rec_issued		   += tgt->stats.num_rec_issued;
	stats->num_rec_compl		   += tgt->stats.num_rec_compl;
	stats->num_srr_issued		   += tgt->stats.num_srr_issued;
	stats->num_srr_compl		   += tgt->stats.num_srr_compl;
	stats->num_seq_cleanup_issued      += tgt->stats.num_seq_cleanup_issued;
	stats->num_seq_cleanup_compl       += tgt->stats.num_seq_cleanup_compl;
	stats->num_cmd_lost		   += tgt->stats.num_cmd_lost;
	stats->num_rsp_lost		   += tgt->stats.num_rsp_lost;
	stats->num_data_lost		   += tgt->stats.num_data_lost;
	stats->num_xfer_rdy_lost	   += tgt->stats.num_xfer_rdy_lost;
	stats->num_pending_ios_after_flush +=
					 tgt->stats.num_pending_ios_after_flush;
	stats->num_unsol_requests	   += tgt->stats.num_unsol_requests;
	stats->num_adisc_issued		   += tgt->stats.num_adisc_issued;
}

static void bnx2fc_debugfs_print_stats(struct seq_file *s,
				       struct bnx2fc_tgt_dbg_stats *stats)
{
	seq_printf(s, "\t\t-----[ Timeouts ]-------------------------------\n");
	seq_printf(s, "%50s: %10d\n", "Cmd timeouts",
				      stats->num_cmd_timeouts);
	seq_printf(s, "%50s: %10d\n", "EH Abort Timeouts",
				      stats->num_eh_abort_timeouts);
	seq_printf(s, "%50s: %10d\n", "Abts Timeouts",
				      stats->num_abts_timeouts);
	seq_printf(s, "%50s: %10d\n", "ELS abts timeouts",
				      stats->num_els_abts_timeouts);
	seq_printf(s, "%50s: %10d\n", "ELS timeouts",
				      stats->num_els_timeouts);

	seq_printf(s, "\t\t-----[ Error Handling ]-------------------------\n");
	seq_printf(s, "%50s: %10d\n", "Explicit Logos",
				      stats->num_explicit_logos);
	seq_printf(s, "%50s: %10d\n", "Io completes before abts issue",
				      stats->num_io_compl_before_abts);
	seq_printf(s, "%50s: %10d\n", "RRQ Issued", stats->num_rrq_issued);
	seq_printf(s, "%50s: %10d/%d\n", "Cleanup Issued/Completion",
					 stats->num_cleanup_issued,
					 stats->num_cleanup_compl);
	seq_printf(s, "%50s: %10d/%d\n", "REC Issued/Completion",
					 stats->num_rec_issued,
					 stats->num_rec_compl);
	seq_printf(s, "%50s: %10d/%d\n", "SRR Issued/Completion",
					 stats->num_srr_issued,
					 stats->num_srr_compl);
	seq_printf(s, "%50s: %10d/%d\n", "SEQ Cleanup Issued/Completion",
					 stats->num_seq_cleanup_issued,
					 stats->num_seq_cleanup_compl);

	seq_printf(s, "\t\t-----[ Lost Packets ]---------------------------\n");
	seq_printf(s, "%50s: %10d\n", "CMDs Lost", stats->num_cmd_lost);
	seq_printf(s, "%50s: %10d\n", "RSP Lost", stats->num_rsp_lost);
	seq_printf(s, "%50s: %10d\n", "Data Lost", stats->num_data_lost);
	seq_printf(s, "%50s: %10d\n", "Xfer RDY Lost",
				      stats->num_xfer_rdy_lost);

	seq_printf(s, "\t\t-----[ Misc ]-----------------------------------\n");
	seq_printf(s, "%50s: %10d\n", "num_pending_ios_after_flush",
				      stats->num_pending_ios_after_flush);
	seq_printf(s, "%50s: %10d\n", "num_unsol_requests",
				      stats->num_unsol_requests);
	seq_printf(s, "%50s: %10d\n", "num_adisc_issued",
				      stats->num_adisc_issued);
	seq_printf(s, "\n");
}

/* bnx2fc_debugfs_sync_stat - Adds the stats from the tgt structure to the hba
 * aggregate structure. If the hba does not contain the port from a previous
 * upload, a new structure is created. Called when a tgt is being uploaded.
 *
 * @hba:	The parent hba of tgt
 * @tgt:	The tgt that is being uploaded
 */
void bnx2fc_debugfs_sync_stat(struct bnx2fc_hba *hba, struct bnx2fc_rport *tgt)
{
	struct list_head *list;
	struct bnx2fc_tgt_dbg_stats *stats = NULL;

	spin_lock_bh(&hba->hba_lock);
	list_for_each(list, &hba->bnx2fc_stat_list) {
		struct bnx2fc_tgt_dbg_stats *tmp =
					    (struct bnx2fc_tgt_dbg_stats *)list;

		if (tmp->port_id == tgt->rport->port_id) {
			stats = tmp;
			break;
		}
	}

	if (!stats) {
		stats = kzalloc(sizeof(struct bnx2fc_tgt_dbg_stats),
				    GFP_ATOMIC);
		if (!stats)
			goto unlock;

		stats->port_id = tgt->rport->port_id;
		list_add_tail(&stats->list, &hba->bnx2fc_stat_list);
	}

	bnx2fc_debugfs_add_stats(stats, tgt);

unlock:
	spin_unlock_bh(&hba->hba_lock);
}

static void bnx2fc_debugfs_print_tgt(struct seq_file *s,
				     struct bnx2fc_rport *tgt)
{
	struct bnx2fc_tgt_dbg_stats *dbg = &tgt->stats;
	seq_printf(s, "%50s: %10d\n", "fcoe_conn_id", tgt->fcoe_conn_id);
	seq_printf(s, "%50s: %#10x\n", "sid", tgt->sid);
	seq_printf(s, "%50s: %#10lx\n", "flags", tgt->flags);
	seq_printf(s, "%50s: %10d\n", "free_sqes",
				      atomic_read(&tgt->free_sqes));
	seq_printf(s, "%50s: %10d\n", "num_active_ios",
				      atomic_read(&tgt->num_active_ios));
	seq_printf(s, "%50s: %10d\n", "Flush_in_prog", tgt->flush_in_prog);
	bnx2fc_debugfs_print_stats(s, dbg);
}

static int bnx2fc_debugfs_show(struct seq_file *s, void *unused)
{
	struct list_head *list;
	struct bnx2fc_hba *hba;

	seq_printf(s, "bnx2fc debug info:\n");
	seq_printf(s, "Adapter count:		%d\n", adapter_count);

	mutex_lock(&bnx2fc_dev_lock);

	list_for_each(list, &adapter_list) {
		int i;

		hba = (struct bnx2fc_hba *)list;
		spin_lock_bh(&hba->hba_lock);
		seq_printf(s, "=====[ HBA %s ]=============================\n",
				hba->phys_dev->name);
		seq_printf(s, "\tadapter_state: %lu\n", hba->adapter_state);
		seq_printf(s, "\tflags: 0x%lx\n", hba->flags);
		seq_printf(s, "\twait_for_link_down: %d\n",
				 hba->wait_for_link_down);
		seq_printf(s, "\tNumber of offload sessions: %d\n",
				 hba->num_ofld_sess);
		seq_printf(s, "\tTgt Offload Failed: %d\n",
				 hba->stats.num_tgt_offload_failed);
		seq_printf(s, "\tTgt Enable Failed: %d\n",
				 hba->stats.num_tgt_enable_failed);


		seq_printf(s, "\n");
		for (i = 0; i < BNX2FC_NUM_MAX_SESS; i++) {
			struct bnx2fc_rport *tgt = hba->tgt_ofld_list[i];
			if (tgt) {
				spin_lock_bh(&tgt->tgt_lock);
				seq_printf(s, "\t______[ Tgt %#x ]_____________"
					      "____________________________\n",
					      tgt->rport->port_id);
				bnx2fc_debugfs_print_tgt(s, tgt);
				spin_unlock_bh(&tgt->tgt_lock);
			}
		}

		spin_unlock_bh(&hba->hba_lock);
	}

	/* Print aggregated stats for uploaded tgts */
	seq_printf(s, "\n=====[ Aggregated Stats For Uploaded Targets ]========"
			"==================\n");
	list_for_each(list, &adapter_list) {
		struct list_head *slist;

		hba = (struct bnx2fc_hba *)list;
		spin_lock_bh(&hba->hba_lock);
		seq_printf(s, "HBA %s\n", hba->phys_dev->name);

		seq_printf(s, "\n");

		list_for_each(slist, &hba->bnx2fc_stat_list) {
			struct bnx2fc_tgt_dbg_stats *stats =
					   (struct bnx2fc_tgt_dbg_stats *)slist;
			seq_printf(s, "\t[ Port Id: %#10x ]\n", stats->port_id);
			bnx2fc_debugfs_print_stats(s, stats);
		}

		spin_unlock_bh(&hba->hba_lock);
	}

	mutex_unlock(&bnx2fc_dev_lock);
	return 0;
}

static int bnx2fc_debugfs_open(struct inode *inode, struct file *file)
{
	return single_open(file, bnx2fc_debugfs_show, NULL);
}

static int bnx2fc_debugfs_release(struct inode *inode, struct file *file)
{
	return single_release(inode, file);
}

static ssize_t bnx2fc_debugfs_clear(struct file *fil, const char __user *u,
				    size_t size, loff_t *off)
{
	return size;
}


static const struct file_operations bnx2fc_dbg_ops = {
	.open		= bnx2fc_debugfs_open,
	.read		= seq_read,
	.write		= bnx2fc_debugfs_clear,
	.llseek		= seq_lseek,
	.release	= bnx2fc_debugfs_release,
};

void bnx2fc_debugfs_init(void)
{
	bnx2fc_debugfs_root = debugfs_create_dir(BNX2FC_NAME, NULL);
	if (!bnx2fc_debugfs_root) {
		BNX2FC_MISC_DBG("Unable to create debugfs root directory.\n");
		return;
	}

	bnx2fc_debugfs_info = debugfs_create_file("info", S_IRUSR,
			bnx2fc_debugfs_root, NULL, &bnx2fc_dbg_ops);
	if (!bnx2fc_debugfs_info) {
		BNX2FC_MISC_DBG("Unable to create debugfs info node.\n");
		debugfs_remove(bnx2fc_debugfs_root);
	}
}

void bnx2fc_debugfs_remove(void)
{
	debugfs_remove_recursive(bnx2fc_debugfs_root);
}
