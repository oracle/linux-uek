// SPDX-License-Identifier: GPL-2.0
/* Marvell OcteonTx2 RVU Ethernet driver
 *
 * Copyright (C) 2018 Marvell International Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef OTX2_STRUCT_H
#define OTX2_STRUCT_H

/* NIX WQE/CQE size 128 byte or 512 byte */
enum nix_cqesz_e {
	NIX_XQESZ_W64 = 0x0,
	NIX_XQESZ_W16 = 0x1,
};

/* NIX wqe/cqe types */
enum nix_xqe_type {
	NIX_XQE_TYPE_INVALID   = 0x0,
	NIX_XQE_TYPE_RX        = 0x1,
	NIX_XQE_TYPE_RX_IPSECS = 0x2,
	NIX_XQE_TYPE_RX_IPSECH = 0x3,
	NIX_XQE_TYPE_RX_IPSECD = 0x4,
	NIX_XQE_TYPE_SEND      = 0x8,
};

/* NIX CQE header structure */
struct nix_cqe_hdr_s {
#if defined(__BIG_ENDIAN_BITFIELD)
	u64 cqe_type              : 4;
	u64 node                  : 2;
	u64 reserved_52_57        : 6;
	u64 q                     : 20;
	u64 flow_tag              : 32;
#else
	u64 flow_tag              : 32;
	u64 q                     : 20;
	u64 reserved_52_57        : 6;
	u64 node                  : 2;
	u64 cqe_type              : 4;
#endif
};

#endif /* OTX2_STRUCT_H */
