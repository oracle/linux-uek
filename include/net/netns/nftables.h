/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _NETNS_NFTABLES_H_
#define _NETNS_NFTABLES_H_

struct netns_nftables {
	u8			gencursor;
	UEK_KABI_EXTEND(unsigned int	base_seq)
};

#endif
