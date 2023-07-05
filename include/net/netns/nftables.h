/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _NETNS_NFTABLES_H_
#define _NETNS_NFTABLES_H_

#include <linux/list.h>
#include <linux/uek_kabi.h>

struct netns_nftables {
	UEK_KABI_DEPRECATE(struct list_head, tables)
	UEK_KABI_DEPRECATE(struct list_head, commit_list)
	UEK_KABI_DEPRECATE(struct list_head, module_list)
	UEK_KABI_DEPRECATE(struct mutex, commit_mutex)
	UEK_KABI_DEPRECATE(unsigned int, base_seq)
	u8			gencursor;
	UEK_KABI_DEPRECATE(u8, validate_state)
};

#endif
