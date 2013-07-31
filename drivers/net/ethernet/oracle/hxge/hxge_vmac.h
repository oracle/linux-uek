/*****************************************************************************
* DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS HEADER.
*
* Copyright 2009, 2011 Oracle America, Inc. All rights reserved.
*
* This program is free software; you can redistribute it and/or modify it under
* the terms of the GNU General Public License version 2 only, as published by
* the Free Software Foundation.
*
* This program is distributed in the hope that it will be useful, but WITHOUT
* ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
* FOR A PARTICULAR PURPOSE.  See the GNU General Public License version 2 for
* more details (a copy is included in the LICENSE file that accompanied this
* code).
*
* You should have received a copy of the GNU General Public License version 2
* along with this program; If not,
* see http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt
*
* Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 or
* visit www.oracle.com if you need additional information or have any
* questions.
*
******************************************************************************/

#ifndef	_HXGE_HXGE_VMAC_H
#define	_HXGE_HXGE_VMAC_H

#include "hxge_vmac_hw.h"

/* VMAC statistics */

typedef	struct _hxge_vmac_stats {
	/* vmac_tx_stat_t */
	uint64_t	tx_byte_cnt_overflow;
	uint64_t	tx_frame_cnt_overflow;
	uint64_t	frame_tx;

	/* vmac_rx_stat_t */
	uint64_t	bcast_cnt_overflow;
	uint64_t	mcast_cnt_overflow;
	uint64_t	pause_cnt_overflow;
	uint64_t	crc_err_cnt_overflow;
	uint64_t	rx_drop_byte_cnt_overflow;
	uint64_t	rx_drop_frame_cnt_overflow;
	uint64_t	rx_byte_cnt_overflow;
	uint64_t	rx_frame_cnt_overflow;
	uint64_t	frame_rx;

	uint64_t	tx_frame_cnt;		/* vmac_tx_frame_cnt_t */
	uint64_t	tx_byte_cnt;		/* vmac_tx_byte_cnt_t */

	uint64_t	rx_frame_cnt;		/* vmac_rx_frame_cnt_t */
	uint64_t	rx_byte_cnt;		/* vmac_rx_byte_cnt_t */
	uint64_t	rx_drop_frame_cnt;	/* vmac_rx_drop_fr_cnt_t */
	uint64_t	rx_drop_byte_cnt;	/* vmac_rx_drop_byte_cnt_t */
	uint64_t	rx_crc_cnt;		/* vmac_rx_crc_cnt_t */
	uint64_t	rx_pause_cnt;		/* vmac_rx_pause_cnt_t */
	uint64_t	rx_bcast_fr_cnt;	/* vmac_rx_bcast_fr_cnt_t */
	uint64_t	rx_mcast_fr_cnt;	/* vmac_rx_mcast_fr_cnt_t */
} hxge_vmac_stats_t, *p_hxge_vmac_stats_t;


typedef	struct _hxge_vmac {
	boolean_t		is_jumbo;
	boolean_t		promisc;
	boolean_t		loopback;
	uint64_t		tx_config;
	uint64_t		rx_config;
	uint16_t		minframesize;
	uint16_t		maxframesize;
	uint16_t		maxburstsize;
	uint16_t		rx_max_framesize;
//	uint8_t			mac_addr[HXGE_MAX_MAC_ADDRS];
} hxge_vmac_t;


#endif	/* _HXGE_HXGE_VMAC_H */
