/*
 * Copyright (c) 2015, 2016, Oracle and/or its affiliates. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 *
 * Driver for Oracle Scalable Infiniband Fabric (SIF) Host Channel Adapters
 */

#ifndef	_PSIF_HW_PRINT_H
#define	_PSIF_HW_PRINT_H


#include "psif_api.h"

#include "psif_hw_data.h"
#if !defined(XFILE)
#define XFILE FILE
#endif

void write_bits_u8(XFILE *fd, int extent, u8 data);
void write_bits_u16(XFILE *fd, int extent, u16 data);
void write_bits_u32(XFILE *fd, int extent, u32 data);
void write_bits_u64(XFILE *fd, int extent, u64 data);
const char *string_enum_psif_mmu_translation(enum psif_mmu_translation val);
void write_enum_psif_mmu_translation(XFILE *fd,
	enum psif_mmu_translation data);
const char *string_enum_psif_page_size(enum psif_page_size val);
void write_enum_psif_page_size(XFILE *fd,
	enum psif_page_size data);
const char *string_enum_psif_wr_type(enum psif_wr_type val);
void write_enum_psif_wr_type(XFILE *fd,
	enum psif_wr_type data);
const char *string_enum_psif_port(enum psif_port val);
void write_enum_psif_port(XFILE *fd,
	enum psif_port data);
const char *string_enum_psif_use_ah(enum psif_use_ah val);
void write_enum_psif_use_ah(XFILE *fd,
	enum psif_use_ah data);
const char *string_enum_psif_tsu_qos(enum psif_tsu_qos val);
void write_enum_psif_tsu_qos(XFILE *fd,
	enum psif_tsu_qos data);
const char *string_enum_psif_wc_opcode(enum psif_wc_opcode val);
void write_enum_psif_wc_opcode(XFILE *fd,
	enum psif_wc_opcode data);
const char *string_enum_psif_wc_status(enum psif_wc_status val);
void write_enum_psif_wc_status(XFILE *fd,
	enum psif_wc_status data);
const char *string_enum_psif_eps_a_core(enum psif_eps_a_core val);
void write_enum_psif_eps_a_core(XFILE *fd,
	enum psif_eps_a_core data);
const char *string_enum_psif_qp_state(enum psif_qp_state val);
void write_enum_psif_qp_state(XFILE *fd,
	enum psif_qp_state data);
const char *string_enum_psif_cmpl_outstanding_error(enum psif_cmpl_outstanding_error val);
void write_enum_psif_cmpl_outstanding_error(XFILE *fd,
	enum psif_cmpl_outstanding_error data);
const char *string_enum_psif_expected_op(enum psif_expected_op val);
void write_enum_psif_expected_op(XFILE *fd,
	enum psif_expected_op data);
const char *string_enum_psif_migration(enum psif_migration val);
void write_enum_psif_migration(XFILE *fd,
	enum psif_migration data);
const char *string_enum_psif_qp_trans(enum psif_qp_trans val);
void write_enum_psif_qp_trans(XFILE *fd,
	enum psif_qp_trans data);
const char *string_enum_psif_bool(enum psif_bool val);
void write_enum_psif_bool(XFILE *fd,
	enum psif_bool data);
const char *string_enum_psif_eoib_type(enum psif_eoib_type val);
void write_enum_psif_eoib_type(XFILE *fd,
	enum psif_eoib_type data);
const char *string_enum_psif_comm_live(enum psif_comm_live val);
void write_enum_psif_comm_live(XFILE *fd,
	enum psif_comm_live data);
const char *string_enum_psif_path_mtu(enum psif_path_mtu val);
void write_enum_psif_path_mtu(XFILE *fd,
	enum psif_path_mtu data);
const char *string_enum_psif_use_grh(enum psif_use_grh val);
void write_enum_psif_use_grh(XFILE *fd,
	enum psif_use_grh data);
const char *string_enum_psif_loopback(enum psif_loopback val);
void write_enum_psif_loopback(XFILE *fd,
	enum psif_loopback data);
const char *string_enum_psif_qp_command(enum psif_qp_command val);
void write_enum_psif_qp_command(XFILE *fd,
	enum psif_qp_command data);
const char *string_enum_psif_mbox_type(enum psif_mbox_type val);
void write_enum_psif_mbox_type(XFILE *fd,
	enum psif_mbox_type data);
const char *string_enum_psif_dma_vt_key_states(enum psif_dma_vt_key_states val);
void write_enum_psif_dma_vt_key_states(XFILE *fd,
	enum psif_dma_vt_key_states data);
const char *string_enum_psif_event(enum psif_event val);
void write_enum_psif_event(XFILE *fd,
	enum psif_event data);
const char *string_enum_psif_tsu_error_types(enum psif_tsu_error_types val);
void write_enum_psif_tsu_error_types(XFILE *fd,
	enum psif_tsu_error_types data);
const char *string_enum_psif_eps_core_id(enum psif_eps_core_id val);
void write_enum_psif_eps_core_id(XFILE *fd,
	enum psif_eps_core_id data);
const char *string_enum_psif_epsc_log_mode(enum psif_epsc_log_mode val);
void write_enum_psif_epsc_log_mode(XFILE *fd,
	enum psif_epsc_log_mode data);
const char *string_enum_psif_epsc_log_level(enum psif_epsc_log_level val);
void write_enum_psif_epsc_log_level(XFILE *fd,
	enum psif_epsc_log_level data);
const char *string_enum_psif_epsc_degrade_cause(enum psif_epsc_degrade_cause val);
void write_enum_psif_epsc_degrade_cause(XFILE *fd,
	enum psif_epsc_degrade_cause data);
const char *string_enum_psif_epsc_csr_status(enum psif_epsc_csr_status val);
void write_enum_psif_epsc_csr_status(XFILE *fd,
	enum psif_epsc_csr_status data);
const char *string_enum_psif_epsc_csr_opcode(enum psif_epsc_csr_opcode val);
void write_enum_psif_epsc_csr_opcode(XFILE *fd,
	enum psif_epsc_csr_opcode data);
const char *string_enum_psif_epsc_csr_flags(enum psif_epsc_csr_flags val);
void write_enum_psif_epsc_csr_flags(XFILE *fd,
	enum psif_epsc_csr_flags data);
const char *string_enum_psif_vlink_state(enum psif_vlink_state val);
void write_enum_psif_vlink_state(XFILE *fd,
	enum psif_vlink_state data);
const char *string_enum_psif_epsc_csr_modify_device_flags(enum psif_epsc_csr_modify_device_flags val);
void write_enum_psif_epsc_csr_modify_device_flags(XFILE *fd,
	enum psif_epsc_csr_modify_device_flags data);
const char *string_enum_psif_epsc_csr_modify_port_flags(enum psif_epsc_csr_modify_port_flags val);
void write_enum_psif_epsc_csr_modify_port_flags(XFILE *fd,
	enum psif_epsc_csr_modify_port_flags data);
const char *string_enum_psif_epsc_csr_epsa_command(enum psif_epsc_csr_epsa_command val);
void write_enum_psif_epsc_csr_epsa_command(XFILE *fd,
	enum psif_epsc_csr_epsa_command data);
const char *string_enum_psif_epsa_command(enum psif_epsa_command val);
void write_enum_psif_epsa_command(XFILE *fd,
	enum psif_epsa_command data);
const char *string_enum_psif_epsc_query_op(enum psif_epsc_query_op val);
void write_enum_psif_epsc_query_op(XFILE *fd,
	enum psif_epsc_query_op data);
const char *string_enum_psif_epsc_csr_update_opcode(enum psif_epsc_csr_update_opcode val);
void write_enum_psif_epsc_csr_update_opcode(XFILE *fd,
	enum psif_epsc_csr_update_opcode data);
const char *string_enum_psif_epsc_flash_slot(enum psif_epsc_flash_slot val);
void write_enum_psif_epsc_flash_slot(XFILE *fd,
	enum psif_epsc_flash_slot data);
const char *string_enum_psif_epsc_update_set(enum psif_epsc_update_set val);
void write_enum_psif_epsc_update_set(XFILE *fd,
	enum psif_epsc_update_set data);
const char *string_enum_psif_epsc_csr_uf_ctrl_opcode(enum psif_epsc_csr_uf_ctrl_opcode val);
void write_enum_psif_epsc_csr_uf_ctrl_opcode(XFILE *fd,
	enum psif_epsc_csr_uf_ctrl_opcode data);
const char *string_enum_psif_epsc_vimma_ctrl_opcode(enum psif_epsc_vimma_ctrl_opcode val);
void write_enum_psif_epsc_vimma_ctrl_opcode(XFILE *fd,
	enum psif_epsc_vimma_ctrl_opcode data);
const char *string_enum_psif_epsc_vimma_admmode(enum psif_epsc_vimma_admmode val);
void write_enum_psif_epsc_vimma_admmode(XFILE *fd,
	enum psif_epsc_vimma_admmode data);
const char *string_enum_psif_cq_state(enum psif_cq_state val);
void write_enum_psif_cq_state(XFILE *fd,
	enum psif_cq_state data);
const char *string_enum_psif_rss_hash_source(enum psif_rss_hash_source val);
void write_enum_psif_rss_hash_source(XFILE *fd,
	enum psif_rss_hash_source data);

#if !defined(PSIF_EXCLUDE_WRITE_STRUCTS)

void write_struct_psif_mmu_cntx(XFILE *fd,
	int network_order,
	const struct psif_mmu_cntx *data);
void write_struct_psif_vlan_union_struct(XFILE *fd,
	int network_order,
	const struct psif_vlan_union_struct *data);
void write_union_psif_cq_desc_vlan_pri(XFILE *fd,
	int network_order,
	const union psif_cq_desc_vlan_pri *data);
void write_struct_psif_wr_common(XFILE *fd,
	int network_order,
	const struct psif_wr_common *data);
void write_struct_psif_wr_qp(XFILE *fd,
	int network_order,
	const struct psif_wr_qp *data);
void write_struct_psif_wr_local(XFILE *fd,
	int network_order,
	const struct psif_wr_local *data);
void write_struct_psif_wr_addr(XFILE *fd,
	int network_order,
	const struct psif_wr_addr *data);
void write_struct_psif_wr_send_header_ud(XFILE *fd,
	int network_order,
	const struct psif_wr_send_header_ud *data);
void write_struct_psif_wr_send_header_uc_rc_xrc(XFILE *fd,
	int network_order,
	const struct psif_wr_send_header_uc_rc_xrc *data);
void write_union_psif_wr_send_header(XFILE *fd,
	int network_order,
	const union psif_wr_send_header *data);
void write_struct_psif_wr_remote(XFILE *fd,
	int network_order,
	const struct psif_wr_remote *data);
void write_struct_psif_wr_rdma(XFILE *fd,
	int network_order,
	const struct psif_wr_rdma *data);
void write_struct_psif_send_completion_id(XFILE *fd,
	int network_order,
	const struct psif_send_completion_id *data);
void write_struct_psif_event_completion_id(XFILE *fd,
	int network_order,
	const struct psif_event_completion_id *data);
void write_union_psif_completion_wc_id(XFILE *fd,
	int network_order,
	const union psif_completion_wc_id *data);
void write_union_psif_descriptor_union(XFILE *fd,
	int network_order,
	const union psif_descriptor_union *data);
void write_struct_psif_wr_su(XFILE *fd,
	int network_order,
	const struct psif_wr_su *data);
void write_union_psif_wr_details(XFILE *fd,
	int network_order,
	const union psif_wr_details *data);
void write_struct_psif_wr_xrc(XFILE *fd,
	int network_order,
	const struct psif_wr_xrc *data);
void write_struct_psif_wr(XFILE *fd,
	int network_order,
	const struct psif_wr *data);
void write_struct_psif_wr_expand(XFILE *fd,
	int network_order,
	const struct psif_wr *data);
void write_struct_psif_sq_sw(XFILE *fd,
	int network_order,
	const struct psif_sq_sw *data);
void write_struct_psif_next(XFILE *fd,
	int network_order,
	const struct psif_next *data);
void write_struct_psif_sq_hw(XFILE *fd,
	int network_order,
	const struct psif_sq_hw *data);
void write_struct_psif_sq_entry(XFILE *fd,
	int network_order,
	const struct psif_sq_entry *data);
void write_struct_psif_rq_scatter(XFILE *fd,
	int network_order,
	const struct psif_rq_scatter *data);
void write_struct_psif_rq_sw(XFILE *fd,
	int network_order,
	const struct psif_rq_sw *data);
void write_struct_psif_rq_hw(XFILE *fd,
	int network_order,
	const struct psif_rq_hw *data);
void write_struct_psif_rq_entry(XFILE *fd,
	int network_order,
	const struct psif_rq_entry *data);
void write_struct_psif_qp_core(XFILE *fd,
	int network_order,
	const struct psif_qp_core *data);
void write_struct_psif_qp_path(XFILE *fd,
	int network_order,
	const struct psif_qp_path *data);
void write_struct_psif_query_qp(XFILE *fd,
	int network_order,
	const struct psif_query_qp *data);
void write_struct_psif_qp(XFILE *fd,
	int network_order,
	const struct psif_qp *data);
void write_struct_psif_modify_qp(XFILE *fd,
	int network_order,
	const struct psif_modify_qp *data);
void write_struct_psif_key(XFILE *fd,
	int network_order,
	const struct psif_key *data);
void write_struct_psif_eq_entry(XFILE *fd,
	int network_order,
	const struct psif_eq_entry *data);
void write_struct_psif_epsc_csr_opaque(XFILE *fd,
	int network_order,
	const struct psif_epsc_csr_opaque *data);
void write_struct_psif_epsc_csr_single(XFILE *fd,
	int network_order,
	const struct psif_epsc_csr_single *data);
void write_struct_psif_epsc_csr_base_addr(XFILE *fd,
	int network_order,
	const struct psif_epsc_csr_base_addr *data);
void write_struct_psif_csr_modify_qp_ctrl(XFILE *fd,
	int network_order,
	const struct psif_csr_modify_qp_ctrl *data);
void write_struct_psif_epsc_csr_modify_qp(XFILE *fd,
	int network_order,
	const struct psif_epsc_csr_modify_qp *data);
void write_struct_psif_epsc_csr_query_qp(XFILE *fd,
	int network_order,
	const struct psif_epsc_csr_query_qp *data);
void write_struct_psif_csr_own_lid_base(XFILE *fd,
	int network_order,
	const struct psif_csr_own_lid_base *data);
void write_struct_psif_csr_snd_lid(XFILE *fd,
	int network_order,
	const struct psif_csr_snd_lid *data);
void write_struct_psif_csr_rcv_lid(XFILE *fd,
	int network_order,
	const struct psif_csr_rcv_lid *data);
void write_struct_psif_epsc_csr_set_lid(XFILE *fd,
	int network_order,
	const struct psif_epsc_csr_set_lid *data);
void write_struct_psif_epsc_csr_set_gid(XFILE *fd,
	int network_order,
	const struct psif_epsc_csr_set_gid *data);
void write_struct_psif_epsc_csr_set_eoib_mac(XFILE *fd,
	int network_order,
	const struct psif_epsc_csr_set_eoib_mac *data);
void write_struct_psif_epsc_csr_vlink_state(XFILE *fd,
	int network_order,
	const struct psif_epsc_csr_vlink_state *data);
void write_struct_psif_epsc_csr_query_hw(XFILE *fd,
	int network_order,
	const struct psif_epsc_csr_query_hw *data);
void write_struct_psif_epsc_csr_query_table(XFILE *fd,
	int network_order,
	const struct psif_epsc_csr_query_table *data);
void write_struct_psif_epsc_csr_mc(XFILE *fd,
	int network_order,
	const struct psif_epsc_csr_mc *data);
void write_struct_psif_epsc_csr_event(XFILE *fd,
	int network_order,
	const struct psif_epsc_csr_event *data);
void write_struct_psif_epsc_csr_modify_device(XFILE *fd,
	int network_order,
	const struct psif_epsc_csr_modify_device *data);
void write_struct_psif_epsc_csr_modify_port(XFILE *fd,
	int network_order,
	const struct psif_epsc_csr_modify_port *data);
void write_struct_psif_epsc_csr_test_host_wrd(XFILE *fd,
	int network_order,
	const struct psif_epsc_csr_test_host_wrd *data);
void write_struct_psif_epsc_csr_flash_access(XFILE *fd,
	int network_order,
	const struct psif_epsc_csr_flash_access *data);
void write_struct_psif_epsc_csr_trace_acquire(XFILE *fd,
	int network_order,
	const struct psif_epsc_csr_trace_acquire *data);
void write_struct_psif_epsc_csr_fw_version(XFILE *fd,
	int network_order,
	const struct psif_epsc_csr_fw_version *data);
void write_struct_psif_epsc_csr_log_ctrl(XFILE *fd,
	int network_order,
	const struct psif_epsc_csr_log_ctrl *data);
void write_struct_psif_epsc_csr_epsa_cntrl(XFILE *fd,
	int network_order,
	const struct psif_epsc_csr_epsa_cntrl *data);
void write_struct_psif_epsc_csr_epsa_cmd(XFILE *fd,
	int network_order,
	const struct psif_epsc_csr_epsa_cmd *data);
void write_struct_psif_epsc_csr_cli_access(XFILE *fd,
	int network_order,
	const struct psif_epsc_csr_cli_access *data);
void write_struct_psif_epsc_csr_mad_process(XFILE *fd,
	int network_order,
	const struct psif_epsc_csr_mad_process *data);
void write_struct_psif_epsc_csr_mad_send_wr(XFILE *fd,
	int network_order,
	const struct psif_epsc_csr_mad_send_wr *data);
void write_struct_psif_epsc_query_req(XFILE *fd,
	int network_order,
	const struct psif_epsc_query_req *data);
void write_struct_psif_epsc_csr_query(XFILE *fd,
	int network_order,
	const struct psif_epsc_csr_query *data);
void write_struct_psif_epsc_csr_set(XFILE *fd,
	int network_order,
	const struct psif_epsc_csr_set *data);
void write_struct_psif_epsc_csr_interrupt_common(XFILE *fd,
	int network_order,
	const struct psif_epsc_csr_interrupt_common *data);
void write_struct_psif_interrupt_attributes(XFILE *fd,
	int network_order,
	const struct psif_interrupt_attributes *data);
void write_struct_psif_epsc_csr_interrupt_channel(XFILE *fd,
	int network_order,
	const struct psif_epsc_csr_interrupt_channel *data);
void write_union_psif_epsc_update_set_or_offset(XFILE *fd,
	int network_order,
	const union psif_epsc_update_set_or_offset *data);
void write_struct_psif_epsc_csr_update(XFILE *fd,
	int network_order,
	const struct psif_epsc_csr_update *data);
void write_struct_psif_epsc_csr_uf_ctrl(XFILE *fd,
	int network_order,
	const struct psif_epsc_csr_uf_ctrl *data);
void write_struct_psif_csr_mmu_flush_caches(XFILE *fd,
	int network_order,
	const struct psif_csr_mmu_flush_caches *data);
void write_struct_psif_epsc_flush_caches(XFILE *fd,
	int network_order,
	const struct psif_epsc_flush_caches *data);
void write_struct_psif_epsc_csr_pma_counters(XFILE *fd,
	int network_order,
	const struct psif_epsc_csr_pma_counters *data);
void write_struct_psif_epsc_vimma_dereg(XFILE *fd,
	int network_order,
	const struct psif_epsc_vimma_dereg *data);
void write_struct_psif_epsc_vimma_vfp_reg(XFILE *fd,
	int network_order,
	const struct psif_epsc_vimma_vfp_reg *data);
void write_struct_psif_epsc_vimma_set_admmode(XFILE *fd,
	int network_order,
	const struct psif_epsc_vimma_set_admmode *data);
void write_struct_psif_epsc_vimma_reg_info(XFILE *fd,
	int network_order,
	const struct psif_epsc_vimma_reg_info *data);
void write_union_psif_epsc_vimma_ctrl_cmd(XFILE *fd,
	int network_order,
	const union psif_epsc_vimma_ctrl_cmd *data);
void write_struct_psif_epsc_csr_vimma_ctrl(XFILE *fd,
	int network_order,
	const struct psif_epsc_csr_vimma_ctrl *data);
void write_struct_psif_epsc_csr_ber_data(XFILE *fd,
	int network_order,
	const struct psif_epsc_csr_ber_data *data);
void write_struct_psif_epsc_csr_diag_counters(XFILE *fd,
	int network_order,
	const struct psif_epsc_csr_diag_counters *data);
void write_union_psif_epsc_csr_details(XFILE *fd,
	int network_order,
	const union psif_epsc_csr_details *data);
void write_struct_psif_epsc_csr_req(XFILE *fd,
	int network_order,
	const struct psif_epsc_csr_req *data);
void write_struct_psif_epsc_csr_req_expand(XFILE *fd,
	int network_order,
	const struct psif_epsc_csr_req *data);
void write_struct_psif_cq_sw(XFILE *fd,
	int network_order,
	const struct psif_cq_sw *data);
void write_struct_psif_cq_hw(XFILE *fd,
	int network_order,
	const struct psif_cq_hw *data);
void write_union_psif_seq_num_immdt(XFILE *fd,
	int network_order,
	const union psif_seq_num_immdt *data);
void write_struct_psif_offload_info(XFILE *fd,
	int network_order,
	const struct psif_offload_info *data);
void write_union_psif_offload_wc_id(XFILE *fd,
	int network_order,
	const union psif_offload_wc_id *data);
void write_struct_psif_cq_entry(XFILE *fd,
	int network_order,
	const struct psif_cq_entry *data);
void write_struct_psif_ah(XFILE *fd,
	int network_order,
	const struct psif_ah *data);

#endif /* !defined(PSIF_EXCLUDE_WRITE_STRUCTS) */



#endif	/* _PSIF_HW_PRINT_H */
