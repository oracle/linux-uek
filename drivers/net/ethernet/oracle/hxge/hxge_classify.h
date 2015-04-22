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

#ifndef _HXGE_CLASSIFY_H
#define	_HXGE_CLASSIFY_H

/*
 * The following are the user configurable ether types. Refer to
 * /usr/include/sys/ethernet.h
 *
 * ETHERTYPE_PUP	(0x0200)
 * ETHERTYPE_802_MIN	(0x0600)
 * ETHERTYPE_IP		(0x0800)
 * ETHERTYPE_ARP	(0x0806)
 * ETHERTYPE_REVARP	(0x8035)
 * ETHERTYPE_AT		(0x809b)
 * ETHERTYPE_AARP	(0x80f3)
 * ETHERTYPE_IPV6	(0x86dd)
 * ETHERTYPE_SLOW	(0x8809)
 * ETHERTYPE_PPPOED	(0x8863)
 * ETHERTYPE_PPPOES	(0x8864)
 * ETHERTYPE_MAX	(0xffff)
 */

/*
 * Used for ip class tcam key config
 */
#define	HXGE_CLASS_TCAM_LOOKUP		0x10000
#define	HXGE_CLASS_DISCARD		0x20000
#define	HXGE_CLASS_VALID		0x40000
#define	HXGE_CLASS_ETHER_TYPE_MASK	0x0FFFF

typedef struct _tcam_flow_spec {
	hxge_tcam_entry_t tce;
	uint64_t flags;
	uint64_t user_info;
} tcam_flow_spec_t, *p_tcam_flow_spec_t;

typedef struct {
	uint16_t	ether_type;
	int		count;	/* How many TCAM entries using this class. */
} hxge_class_usage_t;

#define HXGE_PFC_HW_UNINIT	0x0
#define	HXGE_PFC_HW_RESET	0x1
#define	HXGE_PFC_HW_INIT	0x2
#define	HXGE_PFC_SW_INIT	0x4

typedef struct _hxge_classify {
	uint32_t 		tcam_size;
	uint32_t		n_used;
	uint32_t 		state;
	p_hxge_pfc_stats_t	pfc_stats;

	tcam_flow_spec_t	*tcam_entries;
	uint8_t			tcam_location;
	hxge_class_usage_t	class_usage[TCAM_CLASS_MAX];
} hxge_classify_t, *p_hxge_classify_t;

#endif	/* _HXGE_CLASSIFY_H */
