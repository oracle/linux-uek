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
EXPORT_TRACEPOINT_SYMBOL_GPL(rds_receive);
EXPORT_TRACEPOINT_SYMBOL_GPL(rds_drop_ingress);
EXPORT_TRACEPOINT_SYMBOL_GPL(rds_drop_egress);
EXPORT_TRACEPOINT_SYMBOL_GPL(rds_ib_add_device);
EXPORT_TRACEPOINT_SYMBOL_GPL(rds_ib_add_device_err);
EXPORT_TRACEPOINT_SYMBOL_GPL(rds_ib_remove_device);
EXPORT_TRACEPOINT_SYMBOL_GPL(rds_ib_remove_device_err);
EXPORT_TRACEPOINT_SYMBOL_GPL(rds_ib_shutdown_device);
EXPORT_TRACEPOINT_SYMBOL_GPL(rds_ib_cm_mismatch);
EXPORT_TRACEPOINT_SYMBOL_GPL(rds_ib_cm_handle_connect);
EXPORT_TRACEPOINT_SYMBOL_GPL(rds_ib_cm_handle_connect_err);
EXPORT_TRACEPOINT_SYMBOL_GPL(rds_ib_cm_initiate_connect);
EXPORT_TRACEPOINT_SYMBOL_GPL(rds_ib_cm_initiate_connect_err);
EXPORT_TRACEPOINT_SYMBOL_GPL(rds_ib_conn_path_connect);
EXPORT_TRACEPOINT_SYMBOL_GPL(rds_ib_conn_path_connect_err);
EXPORT_TRACEPOINT_SYMBOL_GPL(rds_ib_conn_path_shutdown);
EXPORT_TRACEPOINT_SYMBOL_GPL(rds_ib_conn_path_shutdown_err);
EXPORT_TRACEPOINT_SYMBOL_GPL(rds_ib_setup_fastreg);
EXPORT_TRACEPOINT_SYMBOL_GPL(rds_ib_setup_fastreg_err);
EXPORT_TRACEPOINT_SYMBOL_GPL(rds_ib_setup_qp);
EXPORT_TRACEPOINT_SYMBOL_GPL(rds_ib_setup_qp_err);
EXPORT_TRACEPOINT_SYMBOL_GPL(rds_ib_send_cqe_handler);
EXPORT_TRACEPOINT_SYMBOL_GPL(rds_ib_send_cqe_handler_err);
EXPORT_TRACEPOINT_SYMBOL_GPL(rds_ib_reconnect_racing);
EXPORT_TRACEPOINT_SYMBOL_GPL(rds_rdma_cm_event_handler);
EXPORT_TRACEPOINT_SYMBOL_GPL(rds_rdma_cm_event_handler_err);
EXPORT_TRACEPOINT_SYMBOL_GPL(rds_ib_flow_cntrl_add_credits);
EXPORT_TRACEPOINT_SYMBOL_GPL(rds_ib_flow_cntrl_advertise_credits);
EXPORT_TRACEPOINT_SYMBOL_GPL(rds_ib_flow_cntrl_grab_credits);
EXPORT_TRACEPOINT_SYMBOL_GPL(rds_ib_queue_work);
EXPORT_TRACEPOINT_SYMBOL_GPL(rds_ib_queue_worker);
EXPORT_TRACEPOINT_SYMBOL_GPL(rds_ib_queue_cancel_work);
EXPORT_TRACEPOINT_SYMBOL_GPL(rds_ib_queue_flush_work);
EXPORT_TRACEPOINT_SYMBOL_GPL(rds_queue_work);
EXPORT_TRACEPOINT_SYMBOL_GPL(rds_queue_worker);
EXPORT_TRACEPOINT_SYMBOL_GPL(rds_queue_cancel_work);
