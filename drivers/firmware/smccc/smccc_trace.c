// SPDX-License-Identifier: GPL-2.0

#define CREATE_TRACE_POINTS
#include "smccc_trace.h"

EXPORT_TRACEPOINT_SYMBOL(arm_smccc_smc_start);
EXPORT_TRACEPOINT_SYMBOL(arm_smccc_smc_end);
