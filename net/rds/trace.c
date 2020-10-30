// SPDX-License-Identifier: GPL-2.0-only
/* Trace points for core RDS functions.
 *
 * Author: Alan Maguire <alan.maguire@oracle.com>
 *
 * Copyright (c) 2020, Oracle and/or its affiliates. All rights reserved.
 */

#define CREATE_TRACE_POINTS

#include <linux/in6.h>
#include <linux/rds.h>
#include <linux/cgroup.h>
#include "rds.h"

#include <trace/events/rds.h>

EXPORT_TRACEPOINT_SYMBOL_GPL(rds_state_change);
EXPORT_TRACEPOINT_SYMBOL_GPL(rds_state_change_err);
