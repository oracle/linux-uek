/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_RSEQ_TYPES_H
#define _LINUX_RSEQ_TYPES_H

#ifdef CONFIG_RSEQ

/**
 * union rseq_slice_state - Status information for rseq time slice extension
 * @state:	Compound to access the overall state
 * @enabled:	Time slice extension is enabled for the task
 * @granted:	Time slice extension was granted to the task
 */
union rseq_slice_state {
	u16			state;
	struct {
		u8		enabled;
		u8		granted;
	};
};

/**
 * struct rseq_slice - Status information for rseq time slice extension
 * @state:	Time slice extension state
 */
struct rseq_slice {
	union rseq_slice_state	state;
};
#endif /* !CONFIG_RSEQ */
#endif
