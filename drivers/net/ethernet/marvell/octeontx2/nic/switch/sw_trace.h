/* SPDX-License-Identifier: GPL-2.0 */
/* Marvell RVU Admin Function driver
 *
 * Copyright (C) 2025 Marvell.
 *
 */

#undef TRACE_SYSTEM
#define TRACE_SYSTEM rvu

#if !defined(SW_TRACE_H) || defined(TRACE_HEADER_MULTI_READ)
#define SW_TRACE_H

#include <linux/types.h>
#include <linux/tracepoint.h>

#include "mbox.h"

TRACE_EVENT(sw_fl_dump,
	    TP_PROTO(const char *fname, int line, struct fl_tuple *ftuple),
	    TP_ARGS(fname, line, ftuple),
	    TP_STRUCT__entry(__string(f, fname)
			     __field(int, l)
			     __array(u8, smac, ETH_ALEN)
			     __array(u8, dmac, ETH_ALEN)
			     __field(u16, eth_type)
			     __field(u32, sip)
			     __field(u32, dip)
			     __field(u8, ip_proto)
			     __field(u16, sport)
			     __field(u16, dport)
			     __field(u8, uni_di)
			     __field(u16, in_pf)
			     __field(u16, out_pf)

	    ),
	    TP_fast_assign(__assign_str(f, (char *)fname);
			   __entry->l = line;
			   memcpy(__entry->smac, ftuple->smac, ETH_ALEN);
			   memcpy(__entry->dmac, ftuple->dmac, ETH_ALEN);
			   __entry->sip = ftuple->ip4src;
			   __entry->dip = ftuple->ip4dst;
			   __entry->eth_type = ftuple->eth_type;
			   __entry->ip_proto = ftuple->proto;
			   __entry->sport = ftuple->sport;
			   __entry->dport = ftuple->dport;
			   __entry->uni_di = ftuple->uni_di;
			   __entry->in_pf = ftuple->in_pf;
			   __entry->out_pf = ftuple->xmit_pf;
	    ),
	    TP_printk("[%s:%d] %pM %pI4:%u to %pM %pI4:%u eth_type=%#x proto=%u uni=%u in=%#x out=%#x",
		      __get_str(f), __entry->l, __entry->smac, &__entry->sip, __entry->sport,
		      __entry->dmac, &__entry->dip, __entry->dport,
		      ntohs(__entry->eth_type), __entry->ip_proto, __entry->uni_di,
		      __entry->in_pf, __entry->out_pf)
);

TRACE_EVENT(sw_act_dump,
	    TP_PROTO(const char *fname, int line, u32 act),
	    TP_ARGS(fname, line, act),
	    TP_STRUCT__entry(__string(fname, fname)
			     __field(int, line)
			     __field(u32, act)
	    ),

	    TP_fast_assign(__assign_str(fname, fname);
			   __entry->line = line;
			   __entry->act = act;
	    ),

	    TP_printk("[%s:%d] %u",
		       __get_str(fname), __entry->line, __entry->act)
);

#endif

#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH ../../drivers/net/ethernet/marvell/octeontx2/nic/switch/

#undef TRACE_INCLUDE_FILE
#define TRACE_INCLUDE_FILE sw_trace

#include <trace/define_trace.h>
