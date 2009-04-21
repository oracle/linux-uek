/*
 * Copyright (c) 2008 Mellanox Technologies Ltd.  All rights reserved.
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
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
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

#include <linux/proc_fs.h>
#include "sdp_socket.h"
#include "sdp.h"

#ifdef CONFIG_PROC_FS

#define PROC_SDP_STATS "sdpstats"

static void *sdp_get_idx(struct seq_file *seq, loff_t pos)
{
	int i = 0;
	struct sdp_sock *ssk;

	if (!list_empty(&sock_list))
		list_for_each_entry(ssk, &sock_list, sock_list) {
			if (i == pos)
				return ssk;
			i++;
		}

	return NULL;
}

static void *sdp_seq_start(struct seq_file *seq, loff_t *pos)
{
	void *start = NULL;
	struct sdp_iter_state* st = seq->private;

	st->num = 0;

	if (!*pos)
		return SEQ_START_TOKEN;

	spin_lock_irq(&sock_list_lock);
	start = sdp_get_idx(seq, *pos - 1);
	if (start)
		sock_hold((struct sock *)start, SOCK_REF_SEQ);
	spin_unlock_irq(&sock_list_lock);

	return start;
}

static void *sdp_seq_next(struct seq_file *seq, void *v, loff_t *pos)
{
	struct sdp_iter_state* st = seq->private;
	void *next = NULL;

	spin_lock_irq(&sock_list_lock);
	if (v == SEQ_START_TOKEN)
		next = sdp_get_idx(seq, 0);
	else
		next = sdp_get_idx(seq, *pos);
	if (next)
		sock_hold((struct sock *)next, SOCK_REF_SEQ);
	spin_unlock_irq(&sock_list_lock);

	*pos += 1;
	st->num++;

	return next;
}

static void sdp_seq_stop(struct seq_file *seq, void *v)
{
}

#define TMPSZ 150

static int sdp_seq_show(struct seq_file *seq, void *v)
{
	struct sdp_iter_state* st;
	struct sock *sk = v;
	char tmpbuf[TMPSZ + 1];
	unsigned int dest;
	unsigned int src;
	int uid;
	unsigned long inode;
	__u16 destp;
	__u16 srcp;
	__u32 rx_queue, tx_queue;

	if (v == SEQ_START_TOKEN) {
		seq_printf(seq, "%-*s\n", TMPSZ - 1,
				"  sl  local_address rem_address        uid inode"
				"   rx_queue tx_queue state");
		goto out;
	}

	st = seq->private;

	dest = inet_sk(sk)->daddr;
	src = inet_sk(sk)->rcv_saddr;
	destp = ntohs(inet_sk(sk)->dport);
	srcp = ntohs(inet_sk(sk)->sport);
	uid = sock_i_uid(sk);
	inode = sock_i_ino(sk);
	rx_queue = sdp_sk(sk)->rcv_nxt - sdp_sk(sk)->copied_seq;
	tx_queue = sdp_sk(sk)->write_seq - sdp_sk(sk)->tx_ring.una_seq;

	sprintf(tmpbuf, "%4d: %08X:%04X %08X:%04X %5d %lu	%08X:%08X %X",
		st->num, src, srcp, dest, destp, uid, inode,
		rx_queue, tx_queue, sk->sk_state);

	seq_printf(seq, "%-*s\n", TMPSZ - 1, tmpbuf);

	sock_put(sk, SOCK_REF_SEQ);
out:
	return 0;
}

static int sdp_seq_open(struct inode *inode, struct file *file)
{
	struct sdp_seq_afinfo *afinfo = PDE(inode)->data;
	struct seq_file *seq;
	struct sdp_iter_state *s;
	int rc;

	if (unlikely(afinfo == NULL))
		return -EINVAL;

	s = kzalloc(sizeof(*s), GFP_KERNEL);
	if (!s)
		return -ENOMEM;
	s->family               = afinfo->family;
	s->seq_ops.start        = sdp_seq_start;
	s->seq_ops.next         = sdp_seq_next;
	s->seq_ops.show         = afinfo->seq_show;
	s->seq_ops.stop         = sdp_seq_stop;

	rc = seq_open(file, &s->seq_ops);
	if (rc)
		goto out_kfree;
	seq          = file->private_data;
	seq->private = s;
out:
	return rc;
out_kfree:
	kfree(s);
	goto out;
}


static struct file_operations sdp_seq_fops;
static struct sdp_seq_afinfo sdp_seq_afinfo = {
	.owner          = THIS_MODULE,
	.name           = "sdp",
	.family         = AF_INET_SDP,
	.seq_show       = sdp_seq_show,
	.seq_fops       = &sdp_seq_fops,
};

#ifdef SDPSTATS_ON
struct sdpstats sdpstats = { { 0 } };

static void sdpstats_seq_hist(struct seq_file *seq, char *str, u32 *h, int n, int is_log)
{
	int i;
	u32 max = 0;

	seq_printf(seq, "%s:\n", str);

	for (i = 0; i < n; i++) {
		if (h[i] > max)
			max = h[i];
	}

	if (max == 0) {
		seq_printf(seq, " - all values are 0\n");
		return;
	}

	for (i = 0; i < n; i++) {
		char s[51];
		int j = 50 * h[i] / max;
		int val = is_log ? (i == n-1 ? 0 : 1<<i) : i;
		memset(s, '*', j);
		s[j] = '\0';

		seq_printf(seq, "%10d | %-50s - %d\n", val, s, h[i]);
	}
}

static int sdpstats_seq_show(struct seq_file *seq, void *v)
{
#define ENUM2STR(e) [e] = #e
	static char *mid2str[] = {
		ENUM2STR(SDP_MID_HELLO),
		ENUM2STR(SDP_MID_HELLO_ACK),
		ENUM2STR(SDP_MID_DISCONN),
		ENUM2STR(SDP_MID_CHRCVBUF),
		ENUM2STR(SDP_MID_CHRCVBUF_ACK),
		ENUM2STR(SDP_MID_DATA),
	};
	int i;

	seq_printf(seq, "SDP statistics:\n");

	sdpstats_seq_hist(seq, "sendmsg_seglen", sdpstats.sendmsg_seglen,
		ARRAY_SIZE(sdpstats.sendmsg_seglen), 1);

	sdpstats_seq_hist(seq, "send_size", sdpstats.send_size,
		ARRAY_SIZE(sdpstats.send_size), 1);

	sdpstats_seq_hist(seq, "credits_before_update", sdpstats.credits_before_update,
		ARRAY_SIZE(sdpstats.credits_before_update), 0);

//	sdpstats_seq_hist(seq, "send_interval", sdpstats.send_interval,
//		ARRAY_SIZE(sdpstats.send_interval));

	seq_printf(seq, "sdp_sendmsg() calls\t\t: %d\n", sdpstats.sendmsg);
	seq_printf(seq, "bcopy segments     \t\t: %d\n", sdpstats.sendmsg_bcopy_segment);
	seq_printf(seq, "bzcopy segments    \t\t: %d\n", sdpstats.sendmsg_bzcopy_segment);
	seq_printf(seq, "post_send_credits  \t\t: %d\n", sdpstats.post_send_credits);
	seq_printf(seq, "memcpy_count       \t\t: %u\n", sdpstats.memcpy_count);

	for (i = 0; i < ARRAY_SIZE(sdpstats.post_send); i++) {
		if (mid2str[i]) {
			seq_printf(seq, "post_send %-20s\t: %d\n",
					mid2str[i], sdpstats.post_send[i]);
		}
	}

	seq_printf(seq, "\n");
	seq_printf(seq, "post_recv         \t\t: %d\n", sdpstats.post_recv);
	seq_printf(seq, "BZCopy poll miss  \t\t: %d\n", sdpstats.bzcopy_poll_miss);
	seq_printf(seq, "send_wait_for_mem \t\t: %d\n", sdpstats.send_wait_for_mem);
	seq_printf(seq, "send_miss_no_credits\t\t: %d\n", sdpstats.send_miss_no_credits);

	seq_printf(seq, "rx_poll_miss      \t\t: %d\n", sdpstats.rx_poll_miss);
	seq_printf(seq, "tx_poll_miss      \t\t: %d\n", sdpstats.tx_poll_miss);

	seq_printf(seq, "CQ stats:\n");
	seq_printf(seq, "- interrupts\t\t: %d\n", sdpstats.int_count);
	return 0;
}

static ssize_t sdpstats_write(struct file *file, const char __user *buf,
			    size_t count, loff_t *offs)
{
	memset(&sdpstats, 0, sizeof(sdpstats));
	printk("Cleared sdp statistics\n");

	return count;
}

static const struct seq_operations sdpstats_seq_ops = {
	.show   = sdpstats_seq_show,
};

static int sdpstats_seq_open(struct inode *inode, struct file *file)
{
	return single_open(file, sdpstats_seq_show, NULL);
}

static struct file_operations sdpstats_fops = {
	.owner		= THIS_MODULE,
	.open		= sdpstats_seq_open,
	.read		= seq_read,
	.write		= sdpstats_write,
	.llseek		= seq_lseek,
	.release	= single_release,
};

#endif

int __init sdp_proc_init(void)
{
	struct proc_dir_entry *p = NULL;
	struct proc_dir_entry *sdpstats = NULL;

	sdp_seq_afinfo.seq_fops->owner         = sdp_seq_afinfo.owner;
	sdp_seq_afinfo.seq_fops->open          = sdp_seq_open;
	sdp_seq_afinfo.seq_fops->read          = seq_read;
	sdp_seq_afinfo.seq_fops->llseek        = seq_lseek;
	sdp_seq_afinfo.seq_fops->release       = seq_release_private;

	p = proc_net_fops_create(sdp_seq_afinfo.name, S_IRUGO,
				 sdp_seq_afinfo.seq_fops);
	if (p)
		p->data = &sdp_seq_afinfo;
	else
		goto no_mem;;

#ifdef SDPSTATS_ON

 	sdpstats = proc_net_fops_create(PROC_SDP_STATS,
			S_IRUGO | S_IWUGO, &sdpstats_fops); 
	if (!sdpstats)
		goto no_mem;;

	return 0;
#endif

no_mem:
	if (sdpstats)
		proc_net_remove(PROC_SDP_STATS);

	if (p)
		proc_net_remove(sdp_seq_afinfo.name);

	return -ENOMEM;
}

void sdp_proc_unregister(void)
{
	proc_net_remove(sdp_seq_afinfo.name);
	memset(sdp_seq_afinfo.seq_fops, 0, sizeof(*sdp_seq_afinfo.seq_fops));

#ifdef SDPSTATS_ON
	proc_net_remove(PROC_SDP_STATS);
#endif
}

#else /* CONFIG_PROC_FS */

int __init sdp_proc_init(void)
{
	return 0;
}

void sdp_proc_unregister(void)
{

}
#endif /* CONFIG_PROC_FS */
