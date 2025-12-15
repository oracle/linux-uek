/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_RSEQ_ENTRY_H
#define _LINUX_RSEQ_ENTRY_H

#ifdef CONFIG_RSEQ
#include <linux/jump_label.h>

#ifdef CONFIG_RSEQ_SLICE_EXTENSION
DECLARE_STATIC_KEY_TRUE(rseq_slice_extension_key);

static __always_inline bool rseq_slice_extension_enabled(void)
{
	return static_branch_likely(&rseq_slice_extension_key);
}
#else /* CONFIG_RSEQ_SLICE_EXTENSION */
static inline bool rseq_slice_extension_enabled(void) { return false; }
#endif /* !CONFIG_RSEQ_SLICE_EXTENSION */
#endif /* !CONFIG_RSEQ */

#endif /* _LINUX_RSEQ_ENTRY_H */
