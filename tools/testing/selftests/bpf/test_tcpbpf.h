// SPDX-License-Identifier: GPL-2.0

#ifndef _TEST_TCPBPF_H
#define _TEST_TCPBPF_H

struct tcp_sock {
	__u32	rcv_nxt;
	__u32	snd_nxt;
	__u32	snd_una;
	__u32	window_clamp;
	__u8	ecn_flags;
	__u32	delivered;
	__u32	delivered_ce;
	__u32	snd_cwnd;
	__u32	snd_cwnd_cnt;
	__u32	snd_cwnd_clamp;
	__u32	snd_ssthresh;
	__u8	syn_data:1,	/* SYN includes data */
		syn_fastopen:1,	/* SYN includes Fast Open option */
		syn_fastopen_exp:1,/* SYN includes Fast Open exp. option */
		syn_fastopen_ch:1, /* Active TFO re-enabling probe */
		syn_data_acked:1,/* data in SYN is acked by SYN-ACK */
		save_syn:1,	/* Save headers of SYN packet */
		is_cwnd_limited:1,/* forward progress limited by snd_cwnd? */
		syn_smc:1;	/* SYN includes SMC */
	__u32	max_packets_out;
	__u32	lsndtime;
	__u32	prior_cwnd;
	__u64	tcp_mstamp;	/* most recent packet received/sent */
} __attribute__((preserve_access_index));

struct tcpbpf_globals {
	__u32 event_map;
	__u32 total_retrans;
	__u32 data_segs_in;
	__u32 data_segs_out;
	__u32 bad_cb_test_rv;
	__u32 good_cb_test_rv;
	__u64 bytes_received;
	__u64 bytes_acked;
	__u32 num_listen;
	__u32 num_close_events;
	__u32 tcp_save_syn;
	__u32 tcp_saved_syn;
	__u32 window_clamp_client;
	__u32 window_clamp_server;
};
#endif
