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

#include "hxge.h"

void
hxge_init_stats(struct hxge_adapter *hxgep)
{
	HXGE_DBG(hxgep, "Initializing statistics");
        hxgep->statsp = kzalloc(sizeof(hxge_stats_t), GFP_KERNEL);
}

void
hxge_free_stats(struct hxge_adapter *hxgep)
{
	HXGE_DBG(hxgep, "Free statistics");
	if (hxgep->statsp) 
		kfree(hxgep->statsp);
	hxgep->statsp = NULL;
}


/* Get the Hydra network statistics and package the information in a format
 * that can displayed by the OS network layer */
struct net_device_stats *
hxge_get_stats (struct net_device *netdev)
{
        struct hxge_adapter *hxgep= netdev_priv(netdev);
        struct net_device_stats  *stats = &hxgep->net_stats;
        struct rx_ring_t *rx_ring;
        struct tx_ring_t *tx_ring;
        int i;
	hxge_vmac_stats_t *vmac_stats = &hxgep->statsp->vmac_stats;
	
        spin_lock(&hxgep->stats_lock);

        memset(stats, 0, sizeof(struct net_device_stats));

        for (i = 0, rx_ring=&hxgep->rx_ring[i];
	     rx_ring && i < hxgep->max_rdcs;
	     i++, rx_ring=&hxgep->rx_ring[i]) {
                stats->rx_packets += rx_ring->stats.ipackets;
                stats->rx_bytes   += rx_ring->stats.ibytes;
                stats->rx_errors  += rx_ring->stats.ierrors;

                /* Various reasons for dropped packets */
                stats->rx_dropped += rx_ring->stats.pkt_too_long
			+ rx_ring->stats.no_rbr_avail
			+ rx_ring->stats.rvm_errors
			+ rx_ring->stats.frame_errors
			+ rx_ring->stats.ram_errors 
			+ rx_ring->stats.nomem_drop
			+ vmac_stats->rx_drop_frame_cnt;
			      
                stats->rx_frame_errors += rx_ring->stats.frame_errors;
                stats->rx_crc_errors += rx_ring->stats.crc_errors;
                stats->rx_over_errors += rx_ring->stats.no_rbr_avail;
                stats->rx_length_errors += rx_ring->stats.pkt_too_long;
        }

	/* Account for non-channel-specific RX errors */
	stats->rx_errors += hxgep->statsp->rx_ierrors
		+ hxgep->statsp->peu_errors; /* Count PEU as "RX" for now */

        for (i = 0, tx_ring=&hxgep->tx_ring[i];
	     tx_ring && i < hxgep->max_tdcs;
	     i++, tx_ring=&hxgep->tx_ring[i]) {
		stats->tx_packets += tx_ring->stats.opackets;
		stats->tx_bytes   += tx_ring->stats.obytes;
		stats->tx_errors  += tx_ring->stats.oerrors;
		stats->tx_dropped += tx_ring->stats.hdr_error_cnt
			+ tx_ring->stats.abort_cnt
			+ tx_ring->stats.runt_cnt;
	}

	/* Account for non-channel-specific TX errors */
	stats->tx_errors += hxgep->statsp->tx_oerrors;

        spin_unlock(&hxgep->stats_lock);

        return stats;
}
