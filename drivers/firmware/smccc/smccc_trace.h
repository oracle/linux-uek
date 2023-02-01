/* SPDX-License-Identifier: GPL-2.0 */

#undef TRACE_SYSTEM
#define TRACE_SYSTEM smccc

#if !defined(__SMCCC_TRACE_H) || defined(TRACE_HEADER_MULTI_READ)
#define __SMCCC_TRACE_H

#include <linux/types.h>
#include <linux/tracepoint.h>

TRACE_EVENT(arm_smccc_smc_start,
	    TP_PROTO(unsigned long smc_id),
	    TP_ARGS(smc_id),
	    TP_STRUCT__entry(__field(unsigned long, smc_id)),
	    TP_fast_assign(__entry->smc_id = smc_id;),
	    TP_printk("SMC ID: 0x%lx", __entry->smc_id)
);

TRACE_EVENT(arm_smccc_smc_end,
	    TP_PROTO(unsigned long smc_id, u64 elapsed_time),
	    TP_ARGS(smc_id, elapsed_time),
	    TP_STRUCT__entry(__field(unsigned long, smc_id)
			     __field(u64, elapsed_time)
	    ),
	    TP_fast_assign(__entry->smc_id = smc_id;
			   __entry->elapsed_time = elapsed_time;
	    ),
	    TP_printk("SMC ID: 0x%lx time taken to process: %llu ns",
		      __entry->smc_id, __entry->elapsed_time)
);

#endif /* __SMCCC_TRACE_H */

#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH .

#undef TRACE_INCLUDE_FILE
#define TRACE_INCLUDE_FILE smccc_trace

#include <trace/define_trace.h>
