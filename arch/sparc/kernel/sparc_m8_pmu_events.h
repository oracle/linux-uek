#ifndef __SPARC_M8_PMU_EVENTS_H
#define __SPARC_M8_PMU_EVENTS_H

/* Note: The event configurations come from the
 *       'SPARC M8 Supplement to the Oracle SPARC Architecture 2017'
 *       spec, and are of the form:
 *       ((((sl << 8) | mask) << 16) | m8_pic_mask)
 *       Where m8_pic_mask is an encoding of the performance counters
 *       that the perf event can be counted on.
 */
SPARC_M8_EVENT_ATTR(Thread_Fetch_stall_RESET, 0x1010030);
SPARC_M8_EVENT_ATTR(Thread_Fetch_stall_Cache_miss_and_MB_full, 0x1020030);
SPARC_M8_EVENT_ATTR(Thread_Fetch_stall_Cache_miss_and_MB_available, 0x1040030);
SPARC_M8_EVENT_ATTR(Thread_Fetch_stall_Cache_miss, 0x1060030);
SPARC_M8_EVENT_ATTR(Thread_Fetch_stall_ITLB_miss, 0x1080030);
SPARC_M8_EVENT_ATTR(Thread_Fetch_stall_SEL_buffers_full, 0x1100030);
SPARC_M8_EVENT_ATTR(No_fetch_due_to_other_thread_fetching, 0x1200030);
SPARC_M8_EVENT_ATTR(Thread_No_Fetch, 0x1400030);
SPARC_M8_EVENT_ATTR(No_Fetch, 0x1800030);
SPARC_M8_EVENT_ATTR(Cycles_of_one_instruction_fetched, 0x20100c0);
SPARC_M8_EVENT_ATTR(Cycles_of_two_instructions_fetched, 0x20200c0);
SPARC_M8_EVENT_ATTR(Cycles_of_three_instructions_fetched, 0x20400c0);
SPARC_M8_EVENT_ATTR(Cycles_of_four_instructions_fetched, 0x20800c0);
SPARC_M8_EVENT_ATTR(Cycles_of_five_instructions_fetched, 0x21000c0);
SPARC_M8_EVENT_ATTR(Cycles_of_six_instructions_fetched, 0x22000c0);
SPARC_M8_EVENT_ATTR(Cycles_of_seven_instructions_fetched, 0x23000c0);
SPARC_M8_EVENT_ATTR(Cycles_of_eight_instructions_fetched, 0x2800c0);
SPARC_M8_EVENT_ATTR(Cycles_in_which_instructions_fetched, 0x2ff00c0);
SPARC_M8_EVENT_ATTR(Misaligned_fetch, 0x3010030);
SPARC_M8_EVENT_ATTR(Delay_slot_or_single_instruction_fetch, 0x3020030);
SPARC_M8_EVENT_ATTR(Predicted_taken_branch, 0x3040030);
SPARC_M8_EVENT_ATTR(Cycles_with_suboptimal_fetches, 0x3070030);
SPARC_M8_EVENT_ATTR(conditional_branch_table0, 0x40100c0);
SPARC_M8_EVENT_ATTR(conditional_branch_table1, 0x40200c0);
SPARC_M8_EVENT_ATTR(conditional_branch_table2, 0x40400c0);
SPARC_M8_EVENT_ATTR(conditional_branch_table3, 0x40800c0);
SPARC_M8_EVENT_ATTR(conditional_branch_bimodal_table, 0x41000c0);
SPARC_M8_EVENT_ATTR(conditional_branch, 0x41f00c0);
SPARC_M8_EVENT_ATTR(conditional_branch_table0_mispredict, 0x42100c0);
SPARC_M8_EVENT_ATTR(conditional_branch_table1_mispredict, 0x42200c0);
SPARC_M8_EVENT_ATTR(conditional_branch_table2_mispredict, 0x42400c0);
SPARC_M8_EVENT_ATTR(conditional_branch_table3_mispredict, 0x42800c0);
SPARC_M8_EVENT_ATTR(conditional_branch_bimodal_table_mispredict, 0x43000c0);
SPARC_M8_EVENT_ATTR(conditional_branch_mispredict, 0x43f00c0);
SPARC_M8_EVENT_ATTR(conditional_branch_bank_collision, 0x44000c0);
SPARC_M8_EVENT_ATTR(Icache_miss_and_L2I_cache_hit, 0x50100f0);
SPARC_M8_EVENT_ATTR(Icache_miss_and_local_L3_cache_hit, 0x50200f0);
SPARC_M8_EVENT_ATTR(Placeholder, 0x50400f0);
SPARC_M8_EVENT_ATTR(Icache_miss_and_neighbor_L3_hit, 0x50800f0);
SPARC_M8_EVENT_ATTR(Icache_miss_and_remote_L3_cache_hit, 0x51000f0);
SPARC_M8_EVENT_ATTR(Icache_miss_and_local_memory_hit, 0x52000f0);
SPARC_M8_EVENT_ATTR(Icache_miss_and_remote_memory_hit, 0x54000f0);
SPARC_M8_EVENT_ATTR(Icache_miss, 0x57f00f0);
SPARC_M8_EVENT_ATTR(Icache_miss_and_L2I_cache_hit_precise, 0x60100f0);
SPARC_M8_EVENT_ATTR(Icache_miss_and_L3_hit_precise, 0x60200f0);
SPARC_M8_EVENT_ATTR(Icache_miss_and_mem_or_remote_hit_precise, 0x60400f0);
SPARC_M8_EVENT_ATTR(Instruction_cache_microtag_miss_ptag_hit_precise, 0x60800f0);
SPARC_M8_EVENT_ATTR(Instruction_cache_microtag_hit_ptag_hit_way_mismatch_precise, 0x61000f0);
SPARC_M8_EVENT_ATTR(micro_tag_error_precise, 0x61800f0);
SPARC_M8_EVENT_ATTR(ITLB_Miss_precise, 0x62000f0);
SPARC_M8_EVENT_ATTR(ITLB_fill_for_8KB_page, 0x70100f0);
SPARC_M8_EVENT_ATTR(ITLB_fill_for_64KB_page, 0x70200f0);
SPARC_M8_EVENT_ATTR(ITLB_fill_for_4MB_page, 0x70400f0);
SPARC_M8_EVENT_ATTR(ITLB_fill_for_256MB_page, 0x70800f0);
SPARC_M8_EVENT_ATTR(ITLB_fill_for_16GB_page, 0x71000f0);
SPARC_M8_EVENT_ATTR(ITLB_fill_for_1TB_page, 0x72000f0);
SPARC_M8_EVENT_ATTR(ITLB_fill_trap1, 0x74000f0);
SPARC_M8_EVENT_ATTR(ITLB_fill_trap2, 0x78000f0);
SPARC_M8_EVENT_ATTR(ITLB_fill_trap, 0x7c000f0);
SPARC_M8_EVENT_ATTR(All_ITLB_fills, 0x77f00f0);
SPARC_M8_EVENT_ATTR(Instruction_cache_microtag_miss_ptag_miss, 0x80100f0);
SPARC_M8_EVENT_ATTR(Instruction_cache_microtag_miss_ptag_hit, 0x80200f0);
SPARC_M8_EVENT_ATTR(Instruction_cache_microtag_hit_ptag_miss, 0x80400f0);
SPARC_M8_EVENT_ATTR(physical_tag_miss, 0x80500f0);
SPARC_M8_EVENT_ATTR(Instruction_cache_microtag_hit_ptag_hit_way_mismatch, 0x80800f0);
SPARC_M8_EVENT_ATTR(Instruction_cache_misses_with_microtag_and_ptag_mismatches, 0x80f00f0);
SPARC_M8_EVENT_ATTR(BTC_direction_miss, 0x81000f0);
SPARC_M8_EVENT_ATTR(BTC_target_miss, 0x82000f0);
SPARC_M8_EVENT_ATTR(BTC_miss, 0x83000f0);
SPARC_M8_EVENT_ATTR(SEL_Buffer_Full_Flush, 0x84000f0);
SPARC_M8_EVENT_ATTR(IFU_Flush, 0x87f00f0);
SPARC_M8_EVENT_ATTR(No_instructions_at_Select, 0x90100c0);
SPARC_M8_EVENT_ATTR(Select_mispredict_wait_cycles, 0x90200c0);
SPARC_M8_EVENT_ATTR(Postsync_at_Select, 0x90400c0);
SPARC_M8_EVENT_ATTR(Presync_at_Select, 0x90800c0);
SPARC_M8_EVENT_ATTR(Thread_Hog_stall_at_Select, 0x91000c0);
SPARC_M8_EVENT_ATTR(Tag_stall_at_Select, 0x92000c0);
SPARC_M8_EVENT_ATTR(Other_strand_selected, 0x94000c0);
SPARC_M8_EVENT_ATTR(Select_wait_cycles, 0x97f00c0);
SPARC_M8_EVENT_ATTR(MLA_FGU_crypto_ONU_arithmetic_instructions, 0xd0100f0);
SPARC_M8_EVENT_ATTR(MLA_Load_instructions, 0xd0200f0);
SPARC_M8_EVENT_ATTR(MLA_Store_instructions, 0xd0400f0);
SPARC_M8_EVENT_ATTR(MLA_Block_Load_and_Stores, 0xd0800f0);
SPARC_M8_EVENT_ATTR(MLA_SPR_ring_ops, 0xd1000f0);
SPARC_M8_EVENT_ATTR(MLA_atomics, 0xd2000f0);
SPARC_M8_EVENT_ATTR(MLA_Software_Prefetch, 0xd4000f0);
SPARC_M8_EVENT_ATTR(MLA_Other_instructions, 0xd8000f0);
SPARC_M8_EVENT_ATTR(Instructions_in_MLA_mode, 0xdff00f0);
SPARC_M8_EVENT_ATTR(FGU_crypto_ONU_arithmetic_instructions, 0xe0100f0);
SPARC_M8_EVENT_ATTR(Load_instructions, 0xe0200f0);
SPARC_M8_EVENT_ATTR(Store_instructions, 0xe0400f0);
SPARC_M8_EVENT_ATTR(Block_load_and_Stores, 0xe0800f0);
SPARC_M8_EVENT_ATTR(SPR_ring_ops, 0xe1000f0);
SPARC_M8_EVENT_ATTR(atomics, 0xe2000f0);
SPARC_M8_EVENT_ATTR(Software_prefetch, 0xe4000f0);
SPARC_M8_EVENT_ATTR(Other_instructions, 0xe8000f0);
SPARC_M8_EVENT_ATTR(Instructions, 0xeff00f0);
SPARC_M8_EVENT_ATTR(Software_count_instructions_flavor_0, 0xf0100f0);
SPARC_M8_EVENT_ATTR(Software_count_instructions_flavor_1, 0xf0200f0);
SPARC_M8_EVENT_ATTR(Software_count_instructions_flavor_2, 0xf0400f0);
SPARC_M8_EVENT_ATTR(Software_count_instructions_flavor_3, 0xf0800f0);
SPARC_M8_EVENT_ATTR(Near_Relative_Branches, 0xf1000f0);
SPARC_M8_EVENT_ATTR(Far_Call, 0xf2000f0);
SPARC_M8_EVENT_ATTR(Far_Branch, 0xf4000f0);
SPARC_M8_EVENT_ATTR(RETURN, 0xf8000f0);
SPARC_M8_EVENT_ATTR(Branches, 0xff000f0);
SPARC_M8_EVENT_ATTR(Taken_branches, 0x100000f0);
SPARC_M8_EVENT_ATTR(EXU_PQ_tag_wait_cycles, 0x110100f0);
SPARC_M8_EVENT_ATTR(LSU_PQ_tag_wait_cycles, 0x110200f0);
SPARC_M8_EVENT_ATTR(Crypto_Diag_wait_cycles, 0x110400f0);
SPARC_M8_EVENT_ATTR(ROB_tag_wait_cycles, 0x110800f0);
SPARC_M8_EVENT_ATTR(WRF_tag_wait_cycles, 0x111000f0);
SPARC_M8_EVENT_ATTR(LB_tag_wait_cycles, 0x112000f0);
SPARC_M8_EVENT_ATTR(SB_tag_wait_cycles, 0x114000f0);
SPARC_M8_EVENT_ATTR(Branch_Data_Array_PC_full_cycles, 0x120100c0);
SPARC_M8_EVENT_ATTR(Branch_Target_Array_full_cycles, 0x120200c0);
SPARC_M8_EVENT_ATTR(IFU_misc_stalls, 0x120400c0);
SPARC_M8_EVENT_ATTR(IFU_stall, 0x120700c0);
SPARC_M8_EVENT_ATTR(MMU_TTE_buffer_full_cycles, 0x120800c0);
SPARC_M8_EVENT_ATTR(MMU_PRQ_pool_full, 0x121000c0);
SPARC_M8_EVENT_ATTR(ITLB_hardware_tablewalk_references_which_hit_L2I, 0x130100f0);
SPARC_M8_EVENT_ATTR(ITLB_hardware_tablewalk_references_which_hit_local_L3, 0x130200f0);
SPARC_M8_EVENT_ATTR(ITLB_hardware_tablewalk_references_which_miss_local_L3, 0x130400f0);
SPARC_M8_EVENT_ATTR(ITLB_hardware_tablewalk_references, 0x130700f0);
SPARC_M8_EVENT_ATTR(DTLB_hardware_tablewalk_references_which_hit_L2I, 0x130800f0);
SPARC_M8_EVENT_ATTR(DTLB_hardware_tablewalk_references_which_hit_local_L3, 0x131000f0);
SPARC_M8_EVENT_ATTR(DTLB_hardware_tablewalk_references_which_miss_local_L3, 0x132000f0);
SPARC_M8_EVENT_ATTR(DTLB_hardware_tablewalk_references, 0x133800f0);
SPARC_M8_EVENT_ATTR(ITLB_and_DTLB_hardware_tablewalk_references, 0x133f00f0);
SPARC_M8_EVENT_ATTR(Instruction_prefetches_dropped_by_L2I, 0x140100f0);
SPARC_M8_EVENT_ATTR(Instruction_prefetches_hit_L2I, 0x140200f0);
SPARC_M8_EVENT_ATTR(Instruction_prefetches_dropped_by_L3, 0x140400f0);
SPARC_M8_EVENT_ATTR(Instruction_prefetches_hit_local_L3, 0x140800f0);
SPARC_M8_EVENT_ATTR(Instruction_prefetches_hit_neighbour_L3, 0x141000f0);
SPARC_M8_EVENT_ATTR(Instruction_prefetches_hit_remote_L3, 0x142000f0);
SPARC_M8_EVENT_ATTR(Instruction_prefetch_local_memory_hit, 0x144000f0);
SPARC_M8_EVENT_ATTR(Instruction_prefetch_remote_memory_hit, 0x148000f0);
SPARC_M8_EVENT_ATTR(Total_number_of_instruction_prefetches, 0x14ff00f0);
SPARC_M8_EVENT_ATTR(L2I_request_blocked, 0x15010030);
SPARC_M8_EVENT_ATTR(L2I_Thread_Hog_Stall, 0x15020030);
SPARC_M8_EVENT_ATTR(L2I_MB_full, 0x15040030);
SPARC_M8_EVENT_ATTR(L2I_Snoop, 15080030);
SPARC_M8_EVENT_ATTR(L2I_No_Request_credit, 0x15100030);
SPARC_M8_EVENT_ATTR(L2I_No_Response_credit, 0x15200030);
SPARC_M8_EVENT_ATTR(Flush_due_to_thread_hog, 0x160100f0);
SPARC_M8_EVENT_ATTR(Flush_on_branch_mispredict, 0x160200f0);
SPARC_M8_EVENT_ATTR(Flush_on_architectural_exception, 0x160400f0);
SPARC_M8_EVENT_ATTR(Flush_on_evil_twin, 0x160800f0);
SPARC_M8_EVENT_ATTR(Flush_and_refetch_NPC, 0x161000f0);
SPARC_M8_EVENT_ATTR(Flush_and_refetch_PC, 0x162000f0);
SPARC_M8_EVENT_ATTR(Flush_on_Misaligned_For_Mitigation, 0x164000f0);
SPARC_M8_EVENT_ATTR(Flush_for_other_reason, 0x168000f0);
SPARC_M8_EVENT_ATTR(All_pipeline_flushes, 0x16ff00f0);
SPARC_M8_EVENT_ATTR(flush_on_spill_n_normal, 0x170100f0);
SPARC_M8_EVENT_ATTR(flush_on_spill_n_other, 0x170200f0);
SPARC_M8_EVENT_ATTR(flush_on_fill_n_normal, 0x170400f0);
SPARC_M8_EVENT_ATTR(flush_on_fill_n_other, 0x170800f0);
SPARC_M8_EVENT_ATTR(All_pipeline_flushes_due_to_spill_fill_exceptions, 0x170f00f0);
SPARC_M8_EVENT_ATTR(Flush_on_lost_load, 0x171000f0);
SPARC_M8_EVENT_ATTR(Branch_direction_mispredicts, 0x210100f0);
SPARC_M8_EVENT_ATTR(Lower_Branch_target_mispredict_due_to_far_table, 0x210200f0);
SPARC_M8_EVENT_ATTR(Upper_Branch_target_mispredict_due_to_far_table, 0x210400f0);
SPARC_M8_EVENT_ATTR(Branch_target_mispredict_due_to_far_table, 0x210600f0);
SPARC_M8_EVENT_ATTR(Lower_Branch_target_mispredict_due_to_indirect_table, 0x210800f0);
SPARC_M8_EVENT_ATTR(Upper_Branch_target_mispredict_due_to_indirect_table, 0x211000f0);
SPARC_M8_EVENT_ATTR(Branch_target_mispredict_due_to_indirect_table, 0x211800f0);
SPARC_M8_EVENT_ATTR(Branch_target_mispredict_due_to_return_stack, 0x212000f0);
SPARC_M8_EVENT_ATTR(Branch_target_mispredict, 0x213e00f0);
SPARC_M8_EVENT_ATTR(Branch_mispredict, 0x213f00f0);
SPARC_M8_EVENT_ATTR(DTLB_miss_sync, 0x22010030);
SPARC_M8_EVENT_ATTR(Dcache_miss_sync, 0x22020030);
SPARC_M8_EVENT_ATTR(RAW_prediction_sync, 0x22040030);
SPARC_M8_EVENT_ATTR(Twin_Load_sync, 0x22080030);
SPARC_M8_EVENT_ATTR(ATMLD_helper_sync_for_CASA_SWAP_LDSTUB, 0x22100030);
SPARC_M8_EVENT_ATTR(All_LSU_syncs, 0x221f0030);
SPARC_M8_EVENT_ATTR(LSU_store_queue_tag_wait_cycles, 0x230100c0);
SPARC_M8_EVENT_ATTR(LSU_store_queue_tag_wait_cycles_all, 0x230200c0);
SPARC_M8_EVENT_ATTR(L2D_no_request_credit, 0x230400c0);
SPARC_M8_EVENT_ATTR(L2D_no_response_credit, 0x230800c0);
SPARC_M8_EVENT_ATTR(SQRSQ_MQID, 0x24010030);
SPARC_M8_EVENT_ATTR(SQRSQ_IDX, 0x24020030);
SPARC_M8_EVENT_ATTR(SQRSQ_IDXWAY, 0x24040030);
SPARC_M8_EVENT_ATTR(SQRSQ_Setrr_TSO, 0x24080030);
SPARC_M8_EVENT_ATTR(SQRSQ_MQ_pool_full, 0x24100030);
SPARC_M8_EVENT_ATTR(Store_Miss_Prefetch, 0x2420030);
SPARC_M8_EVENT_ATTR(Store_Oldest_Miss, 0x24400030);
SPARC_M8_EVENT_ATTR(SQRSQ_L2DFP_empty, 0x24800030);
SPARC_M8_EVENT_ATTR(Store_Hazard, 0x24ff0030);
SPARC_M8_EVENT_ATTR(LD_WUQ_MQID, 0x250100c0);
SPARC_M8_EVENT_ATTR(LD_WUQ_MQ_Pool_or_OMO, 0x250200c0);
SPARC_M8_EVENT_ATTR(SB_Praw_WUQ, 0x250400c0);
SPARC_M8_EVENT_ATTR(SQ_Praw_WUQ, 0x250800c0);
SPARC_M8_EVENT_ATTR(LD_WUQ_BPQ_or_OMO, 0x251000c0);
SPARC_M8_EVENT_ATTR(LD_ST_WUQ_PRQ_or_OMO, 0x252000c0);
SPARC_M8_EVENT_ATTR(LD_ST_WUQ_DTLBFP_or_OMO, 0x253000c0);
SPARC_M8_EVENT_ATTR(LD_WUQ_LRB_Pool_or_OMO, 0x254000c0);
SPARC_M8_EVENT_ATTR(LD_WUQ_LRB_OMO_only, 0x255000c0);
SPARC_M8_EVENT_ATTR(LD_WUQ_LRB_pool_or_ORC, 0x256000c0);
SPARC_M8_EVENT_ATTR(LD_WUQ_RAW, 0x257000c0);
SPARC_M8_EVENT_ATTR(LD_WUQ_IDX, 0x258000c0);
SPARC_M8_EVENT_ATTR(LD_WUQ_IDXWAY, 0x259000c0);
SPARC_M8_EVENT_ATTR(LD_WUQ_L2DFPempty, 0x25a000c0);
SPARC_M8_EVENT_ATTR(LD_L2D_WUQ_OMO_only, 0x25b000c0);
SPARC_M8_EVENT_ATTR(LD_WUQ_MQ_pool_or_ORC, 0x25c000c0);
SPARC_M8_EVENT_ATTR(LD_WUQ_MQ_ORC_only, 0x25d000c0);
SPARC_M8_EVENT_ATTR(LD_WUQ_direct_wakeup, 0x25e000c0);
SPARC_M8_EVENT_ATTR(LD_ST_WUQ_MMU_OMO, 0x25f000c0);
SPARC_M8_EVENT_ATTR(WUQ_All, 0x25ff00c0);
SPARC_M8_EVENT_ATTR(RAW_prediction, 0x26010030);
SPARC_M8_EVENT_ATTR(False_RAW_prediction, 0x26020030);
SPARC_M8_EVENT_ATTR(DTAG_multiple_way_hit, 0x26040030);
SPARC_M8_EVENT_ATTR(PATAG_miss, 0x26080030);
SPARC_M8_EVENT_ATTR(Attribute_Mismatch, 0x26100030);
SPARC_M8_EVENT_ATTR(Dcache_Flash_Invalidate, 0x261c0030);
SPARC_M8_EVENT_ATTR(L1_data_cache_secondary_miss_and_L2D_cache_hit, 0x270100f0);
SPARC_M8_EVENT_ATTR(L1_data_cache_miss_and_L2D_cache_hit, 0x270200f0);
SPARC_M8_EVENT_ATTR(L1_data_cache_miss_and_local_L3_cache_hit, 0x270400f0);
SPARC_M8_EVENT_ATTR(L1_data_cache_miss_and_c2c_L2D, 0x270800f0);
SPARC_M8_EVENT_ATTR(L1_data_cache_miss_and_neighbor_L3_hit, 0x271000f0);
SPARC_M8_EVENT_ATTR(L1_data_cache_miss_and_remote_L3_cache_hit, 0x272000f0);
SPARC_M8_EVENT_ATTR(L1_data_cache_miss_and_local_memory_hit, 0x274000f0);
SPARC_M8_EVENT_ATTR(L1_data_cache_miss_and_remote_memory_hit, 0x278000f0);
SPARC_M8_EVENT_ATTR(Dcache_miss, 0x27ff00f0);
SPARC_M8_EVENT_ATTR(L1_data_cache_secondary_miss_and_L2D_cache_hit_precise, 0x280100f0);
SPARC_M8_EVENT_ATTR(L1_data_cache_miss_and_L2D_cache_hit_precise, 0x280200f0);
SPARC_M8_EVENT_ATTR(L1_data_cache_miss_and_local_L3_cache_hit_precise, 0x280400f0);
SPARC_M8_EVENT_ATTR(L1_data_cache_miss_and_c2c_L2D_precise, 0x280800f0);
SPARC_M8_EVENT_ATTR(L1_data_cache_miss_and_neighbor_L3_hit_precise, 0x281000f0);
SPARC_M8_EVENT_ATTR(L1_data_cache_miss_and_remote_L3_cache_hit_precise, 0x282000f0);
SPARC_M8_EVENT_ATTR(L1_data_cache_miss_and_local_memory_hit_precise, 0x284000f0);
SPARC_M8_EVENT_ATTR(L1_data_cache_miss_and_remote_memory_hit_precise, 0x288000f0);
SPARC_M8_EVENT_ATTR(Dcache_miss_precise, 0x28ff00f0);
SPARC_M8_EVENT_ATTR(Store_L1D_secondary_miss_non_mla, 0x29010030);
SPARC_M8_EVENT_ATTR(Store_L2D_hit_non_mla, 0x29020030);
SPARC_M8_EVENT_ATTR(Store_local_L3_hit_non_mla, 0x29040030);
SPARC_M8_EVENT_ATTR(Store_neighbor_L2_non_mla, 0x29080030);
SPARC_M8_EVENT_ATTR(Store_neighbor_L3_hit_non_mla, 0x29100030);
SPARC_M8_EVENT_ATTR(Store_remote_L3_hit_non_mla, 0x29200030);
SPARC_M8_EVENT_ATTR(Store_local_memory_non_mla, 0x29400030);
SPARC_M8_EVENT_ATTR(Store_remote_memory_non_mla, 0x29800030);
SPARC_M8_EVENT_ATTR(Stores_non_mla, 0x29ff0030);
SPARC_M8_EVENT_ATTR(Store_L1D_secondary_miss_mla, 0x290100c0);
SPARC_M8_EVENT_ATTR(Store_L2D_hit_mla, 0x290200c0);
SPARC_M8_EVENT_ATTR(Store_local_L3_hit_mla, 0x290400c0);
SPARC_M8_EVENT_ATTR(Store_neighbor_L2_mla, 0x290800c0);
SPARC_M8_EVENT_ATTR(Store_neighbor_L3_hit_mla, 0x291000c0);
SPARC_M8_EVENT_ATTR(Store_remote_L3_hit_mla, 0x292000c0);
SPARC_M8_EVENT_ATTR(Store_local_memory_mla, 0x294000c0);
SPARC_M8_EVENT_ATTR(Store_remote_memory_mla, 0x298000c0);
SPARC_M8_EVENT_ATTR(Stores_mla, 0x29ff00c0);
SPARC_M8_EVENT_ATTR(Store_prefetch_local_L3_hit_non_mla, 0x2a0400c0);
SPARC_M8_EVENT_ATTR(Store_prefetch_neighbor_L2_non_mla, 0x2a0800c0);
SPARC_M8_EVENT_ATTR(Store_prefetch_neighbor_L3_hit_non_mla, 0x2a1000c0);
SPARC_M8_EVENT_ATTR(Store_prefetch_remote_L3_hit_non_mla, 0x2a2000c0);
SPARC_M8_EVENT_ATTR(Store_prefetch_local_memory_non_mla, 0x2a4000c0);
SPARC_M8_EVENT_ATTR(Store_prefetch_remote_memory_non_mla, 0x2a8000c0);
SPARC_M8_EVENT_ATTR(Store_prefetch_non_mla, 0x2aff00c0);
SPARC_M8_EVENT_ATTR(Store_prefetch_local_L3_hit_mla, 0x2a040030);
SPARC_M8_EVENT_ATTR(Store_prefetch_neighbor_L2_mla, 0x2a080030);
SPARC_M8_EVENT_ATTR(Store_prefetch_neighbor_L3_hit_mla, 0x2a100030);
SPARC_M8_EVENT_ATTR(Store_prefetch_remote_L3_hit_mla, 0x2a200030);
SPARC_M8_EVENT_ATTR(Store_prefetch_local_memory_mla, 0x2a400030);
SPARC_M8_EVENT_ATTR(Store_prefetch_remote_memory_mla, 0x2a800030);
SPARC_M8_EVENT_ATTR(Store_prefetch_mla, 0x2aff0030);
SPARC_M8_EVENT_ATTR(L1D_hit_sw, 0x2b0100f0);
SPARC_M8_EVENT_ATTR(L1_secondary_miss_sw, 0x2b0200f0);
SPARC_M8_EVENT_ATTR(L2D_hit_sw, 0x2b0400f0);
SPARC_M8_EVENT_ATTR(L2D_drop_sw, 0x2b0800f0);
SPARC_M8_EVENT_ATTR(L3_hit_sw, 0x2b1000f0);
SPARC_M8_EVENT_ATTR(L3_drop_sw, 0x2b2000f0);
SPARC_M8_EVENT_ATTR(Hit_in_remote_node_sw, 0x2b4000f0);
SPARC_M8_EVENT_ATTR(Hit_in_memory_sw, 0x2b8000f0);
SPARC_M8_EVENT_ATTR(Total_Software_Data_Prefetches_sw, 0x2bff00f0);
SPARC_M8_EVENT_ATTR(L1D_secondary_miss, 0x2c0200f0);
SPARC_M8_EVENT_ATTR(L2D_hit, 0x2c0400f0);
SPARC_M8_EVENT_ATTR(L2D_drop, 0x2c0800f0);
SPARC_M8_EVENT_ATTR(L3_hit, 0x2c1000f0);
SPARC_M8_EVENT_ATTR(L3_drop, 0x2c2000f0);
SPARC_M8_EVENT_ATTR(Hit_in_remote_node, 0x2c4000f0);
SPARC_M8_EVENT_ATTR(Hit_in_memory, 0x2c8000f0);
SPARC_M8_EVENT_ATTR(Total_Hardware_Data_Prefetches, 0x2cff00f0);
SPARC_M8_EVENT_ATTR(Full_RAW_hit_in_store_buffer, 0x2d0100f0);
SPARC_M8_EVENT_ATTR(Partial_RAW_hit_in_store_buffer, 0x2d0200f0);
SPARC_M8_EVENT_ATTR(RAW_hit_in_store_buffer, 0x2d0300f0);
SPARC_M8_EVENT_ATTR(Full_RAW_hit_in_store_queue, 0x2d0400f0);
SPARC_M8_EVENT_ATTR(Partial_RAW_hit_in_store_queue, 0x2d0800f0);
SPARC_M8_EVENT_ATTR(Full_or_partial_RAW_hit_in_store_queue, 0x2d0c00f0);
SPARC_M8_EVENT_ATTR(RAWs, 0x2d0f00f0);
SPARC_M8_EVENT_ATTR(Data_cache_eviction_invalidations, 0x2e010030);
SPARC_M8_EVENT_ATTR(Data_cache_snoop_invalidations, 0x2e020030);
SPARC_M8_EVENT_ATTR(Data_cache_invalidations, 0x2e030030);
SPARC_M8_EVENT_ATTR(Cycles_non_MLA, 0x2f0100f0);
SPARC_M8_EVENT_ATTR(Cycles_MLA, 0x2f0200f0);
SPARC_M8_EVENT_ATTR(Cycles, 0x2f0300f0);
SPARC_M8_EVENT_ATTR(Exit_MLA_LSU_fill, 0x32010030);
SPARC_M8_EVENT_ATTR(Exit_MLA_counter, 0x32020030);
SPARC_M8_EVENT_ATTR(Exit_MLA_presync, 0x32040030);
SPARC_M8_EVENT_ATTR(Exit_MLA_precommit, 0x32080030);
SPARC_M8_EVENT_ATTR(Exit_MLA_exception, 0x32100030);
SPARC_M8_EVENT_ATTR(Exit_MLA_Comit_exception, 0x32200030);
SPARC_M8_EVENT_ATTR(Exit_disrupting_flush, 0x32400030);
SPARC_M8_EVENT_ATTR(Exit_MLA, 0x327f0030);
SPARC_M8_EVENT_ATTR(L1_data_cache_secondary_miss_and_L2D_cache_hit_mla, 0x330100f0);
SPARC_M8_EVENT_ATTR(L1_data_cache_miss_and_L2D_cache_hit_mla, 0x330200f0);
SPARC_M8_EVENT_ATTR(L1_data_cache_miss_and_local_L3_cache_hit_mla, 0x330400f0);
SPARC_M8_EVENT_ATTR(L1_data_cache_miss_and_c2c_L2D_mla, 0x330800f0);
SPARC_M8_EVENT_ATTR(L1_data_cache_miss_and_neighbor_L3_hit_mla, 0x331000f0);
SPARC_M8_EVENT_ATTR(L1_data_cache_miss_and_remote_L3_cache_hit_mla, 0x332000f0);
SPARC_M8_EVENT_ATTR(L1_data_cache_miss_and_local_memory_hit_mla, 0x334000f0);
SPARC_M8_EVENT_ATTR(L1_data_cache_miss_and_remote_memory_hit_mla, 0x338000f0);
SPARC_M8_EVENT_ATTR(Dcache_miss_mla, 0x33ff00f0);
SPARC_M8_EVENT_ATTR(L2D_pipeline_stall_on_load, 0x34010030);
SPARC_M8_EVENT_ATTR(L2D_pipeline_stall_on_store, 0x34020030);
SPARC_M8_EVENT_ATTR(L2D_pipeline_stalls, 0x34030030);
SPARC_M8_EVENT_ATTR(Clean_L2D_evictions, 0x350100c0);
SPARC_M8_EVENT_ATTR(Dirty_L2D_evictions, 0x350200c0);
SPARC_M8_EVENT_ATTR(L2D_evictions, 0x350300c0);
SPARC_M8_EVENT_ATTR(Load_Version_Read, 0x360100c0);
SPARC_M8_EVENT_ATTR(Load_Version_Check, 0x360200c0);
SPARC_M8_EVENT_ATTR(Store_Version_Update, 0x360400c0);
SPARC_M8_EVENT_ATTR(Store_Version_Check, 0x360800c0);
SPARC_M8_EVENT_ATTR(All_Versioned_instructions, 0x360f00c0);
SPARC_M8_EVENT_ATTR(DTLB_fill_for_8KB_page, 0x370100f0);
SPARC_M8_EVENT_ATTR(DTLB_fill_for_64KB_page, 0x370200f0);
SPARC_M8_EVENT_ATTR(DTLB_fill_for_4MB_page, 0x370400f0);
SPARC_M8_EVENT_ATTR(DTLB_fill_for_256MB_page, 0x370800f0);
SPARC_M8_EVENT_ATTR(DTLB_fill_for_16GB_page, 0x371000f0);
SPARC_M8_EVENT_ATTR(DTLB_fill_for_1TB_page, 0x372000f0);
SPARC_M8_EVENT_ATTR(DTLB_fill_trap1, 0x374000f0);
SPARC_M8_EVENT_ATTR(DTLB_fill_trap2, 0x378000f0);
SPARC_M8_EVENT_ATTR(DTLB_fills_or_fill_traps, 0x37ff00f0);
SPARC_M8_EVENT_ATTR(DC_fill_with_no_DTLB_TTE, 0x38010030);
SPARC_M8_EVENT_ATTR(DC_fill_with_replaced_DTLB_TTE, 0x30020030);
SPARC_M8_EVENT_ATTR(DC_fill_no_hit, 0x38030030);
SPARC_M8_EVENT_ATTR(Pick_slot_0, 0x390100c0);
SPARC_M8_EVENT_ATTR(Pick_slot_1, 0x390200c0);
SPARC_M8_EVENT_ATTR(Pick_slot_2, 0x390400c0);
SPARC_M8_EVENT_ATTR(Pick_slot_3, 0x390800c0);
SPARC_M8_EVENT_ATTR(All_microops_picked, 0x390f00c0);
SPARC_M8_EVENT_ATTR(RNG_req, 0x3a0100c0);
SPARC_M8_EVENT_ATTR(RNG_req_half_full, 0x3a0200c0);
SPARC_M8_EVENT_ATTR(RNG_response_dedicated_pool_success, 0x3a0400c0);
SPARC_M8_EVENT_ATTR(RNG_response_shared_pool_success, 0x3a0800c0);
SPARC_M8_EVENT_ATTR(RNG_response_success, 0x3a0c00c0);
SPARC_M8_EVENT_ATTR(RNG_response_fail_ORC, 0x3a1000c0);
SPARC_M8_EVENT_ATTR(RNG_response_fail_OMO_only, 0x3a2000c0);
SPARC_M8_EVENT_ATTR(RNG_fail, 0x3a3000c0);
SPARC_M8_EVENT_ATTR(L1D_hit_sw_mla, 0x3b0100f0);
SPARC_M8_EVENT_ATTR(L1_secondary_miss_sw_mla, 0x3b0200f0);
SPARC_M8_EVENT_ATTR(L2D_hit_sw_mla, 0x3b0400f0);
SPARC_M8_EVENT_ATTR(L2D_drop_sw_mla, 0x3b0800f0);
SPARC_M8_EVENT_ATTR(L3_hit_sw_mla, 0x3b1000f0);
SPARC_M8_EVENT_ATTR(L3_drop_sw_mla, 0x3b2000f0);
SPARC_M8_EVENT_ATTR(Hit_in_remote_node_sw_mla, 0x3b4000f0);
SPARC_M8_EVENT_ATTR(Hit_in_memory_sw_mla, 0x3b8000f0);
SPARC_M8_EVENT_ATTR(Total_Software_Data_Prefetches_sw_mla, 0x3bff00f0);
SPARC_M8_EVENT_ATTR(Instructions_Fetched, 0x3c010010);
SPARC_M8_EVENT_ATTR(Instructions_Fetched_all, 0x3c020010);
SPARC_M8_EVENT_ATTR(Instructions_Decoded, 0x3d010020);
SPARC_M8_EVENT_ATTR(Instructions_Decoded_all, 0x3d020020);
SPARC_M8_EVENT_ATTR(micro_ops_picked, 0x3e010040);
SPARC_M8_EVENT_ATTR(micro_ops_picked_all, 0x3e020040);
SPARC_M8_EVENT_ATTR(micro_ops_committed, 0x3f010080);
SPARC_M8_EVENT_ATTR(Commit_0, 0x3f020080);
SPARC_M8_EVENT_ATTR(Commit_0_all, 0x3f040080);

static struct attribute *sparc_m8_pmu_event_attrs[] = {
	SPARC_M8_EVENT_PTR(Thread_Fetch_stall_RESET),
	SPARC_M8_EVENT_PTR(Thread_Fetch_stall_Cache_miss_and_MB_full),
	SPARC_M8_EVENT_PTR(Thread_Fetch_stall_Cache_miss_and_MB_available),
	SPARC_M8_EVENT_PTR(Thread_Fetch_stall_Cache_miss),
	SPARC_M8_EVENT_PTR(Thread_Fetch_stall_ITLB_miss),
	SPARC_M8_EVENT_PTR(Thread_Fetch_stall_SEL_buffers_full),
	SPARC_M8_EVENT_PTR(No_fetch_due_to_other_thread_fetching),
	SPARC_M8_EVENT_PTR(Thread_No_Fetch),
	SPARC_M8_EVENT_PTR(No_Fetch),
	SPARC_M8_EVENT_PTR(Cycles_of_one_instruction_fetched),
	SPARC_M8_EVENT_PTR(Cycles_of_two_instructions_fetched),
	SPARC_M8_EVENT_PTR(Cycles_of_three_instructions_fetched),
	SPARC_M8_EVENT_PTR(Cycles_of_four_instructions_fetched),
	SPARC_M8_EVENT_PTR(Cycles_of_five_instructions_fetched),
	SPARC_M8_EVENT_PTR(Cycles_of_six_instructions_fetched),
	SPARC_M8_EVENT_PTR(Cycles_of_seven_instructions_fetched),
	SPARC_M8_EVENT_PTR(Cycles_of_eight_instructions_fetched),
	SPARC_M8_EVENT_PTR(Cycles_in_which_instructions_fetched),
	SPARC_M8_EVENT_PTR(Misaligned_fetch),
	SPARC_M8_EVENT_PTR(Delay_slot_or_single_instruction_fetch),
	SPARC_M8_EVENT_PTR(Predicted_taken_branch),
	SPARC_M8_EVENT_PTR(Cycles_with_suboptimal_fetches),
	SPARC_M8_EVENT_PTR(conditional_branch_table0),
	SPARC_M8_EVENT_PTR(conditional_branch_table1),
	SPARC_M8_EVENT_PTR(conditional_branch_table2),
	SPARC_M8_EVENT_PTR(conditional_branch_table3),
	SPARC_M8_EVENT_PTR(conditional_branch_bimodal_table),
	SPARC_M8_EVENT_PTR(conditional_branch),
	SPARC_M8_EVENT_PTR(conditional_branch_table0_mispredict),
	SPARC_M8_EVENT_PTR(conditional_branch_table1_mispredict),
	SPARC_M8_EVENT_PTR(conditional_branch_table2_mispredict),
	SPARC_M8_EVENT_PTR(conditional_branch_table3_mispredict),
	SPARC_M8_EVENT_PTR(conditional_branch_bimodal_table_mispredict),
	SPARC_M8_EVENT_PTR(conditional_branch_mispredict),
	SPARC_M8_EVENT_PTR(conditional_branch_bank_collision),
	SPARC_M8_EVENT_PTR(Icache_miss_and_L2I_cache_hit),
	SPARC_M8_EVENT_PTR(Icache_miss_and_local_L3_cache_hit),
	SPARC_M8_EVENT_PTR(Placeholder),
	SPARC_M8_EVENT_PTR(Icache_miss_and_neighbor_L3_hit),
	SPARC_M8_EVENT_PTR(Icache_miss_and_remote_L3_cache_hit),
	SPARC_M8_EVENT_PTR(Icache_miss_and_local_memory_hit),
	SPARC_M8_EVENT_PTR(Icache_miss_and_remote_memory_hit),
	SPARC_M8_EVENT_PTR(Icache_miss),
	SPARC_M8_EVENT_PTR(Icache_miss_and_L2I_cache_hit_precise),
	SPARC_M8_EVENT_PTR(Icache_miss_and_L3_hit_precise),
	SPARC_M8_EVENT_PTR(Icache_miss_and_mem_or_remote_hit_precise),
	SPARC_M8_EVENT_PTR(Instruction_cache_microtag_miss_ptag_hit_precise),
	SPARC_M8_EVENT_PTR(Instruction_cache_microtag_hit_ptag_hit_way_mismatch_precise),
	SPARC_M8_EVENT_PTR(micro_tag_error_precise),
	SPARC_M8_EVENT_PTR(ITLB_Miss_precise),
	SPARC_M8_EVENT_PTR(ITLB_fill_for_8KB_page),
	SPARC_M8_EVENT_PTR(ITLB_fill_for_64KB_page),
	SPARC_M8_EVENT_PTR(ITLB_fill_for_4MB_page),
	SPARC_M8_EVENT_PTR(ITLB_fill_for_256MB_page),
	SPARC_M8_EVENT_PTR(ITLB_fill_for_16GB_page),
	SPARC_M8_EVENT_PTR(ITLB_fill_for_1TB_page),
	SPARC_M8_EVENT_PTR(ITLB_fill_trap1),
	SPARC_M8_EVENT_PTR(ITLB_fill_trap2),
	SPARC_M8_EVENT_PTR(ITLB_fill_trap),
	SPARC_M8_EVENT_PTR(All_ITLB_fills),
	SPARC_M8_EVENT_PTR(Instruction_cache_microtag_miss_ptag_miss),
	SPARC_M8_EVENT_PTR(Instruction_cache_microtag_miss_ptag_hit),
	SPARC_M8_EVENT_PTR(Instruction_cache_microtag_hit_ptag_miss),
	SPARC_M8_EVENT_PTR(physical_tag_miss),
	SPARC_M8_EVENT_PTR(Instruction_cache_microtag_hit_ptag_hit_way_mismatch),
	SPARC_M8_EVENT_PTR(Instruction_cache_misses_with_microtag_and_ptag_mismatches),
	SPARC_M8_EVENT_PTR(BTC_direction_miss),
	SPARC_M8_EVENT_PTR(BTC_target_miss),
	SPARC_M8_EVENT_PTR(BTC_miss),
	SPARC_M8_EVENT_PTR(SEL_Buffer_Full_Flush),
	SPARC_M8_EVENT_PTR(IFU_Flush),
	SPARC_M8_EVENT_PTR(No_instructions_at_Select),
	SPARC_M8_EVENT_PTR(Select_mispredict_wait_cycles),
	SPARC_M8_EVENT_PTR(Postsync_at_Select),
	SPARC_M8_EVENT_PTR(Presync_at_Select),
	SPARC_M8_EVENT_PTR(Thread_Hog_stall_at_Select),
	SPARC_M8_EVENT_PTR(Tag_stall_at_Select),
	SPARC_M8_EVENT_PTR(Other_strand_selected),
	SPARC_M8_EVENT_PTR(Select_wait_cycles),
	SPARC_M8_EVENT_PTR(MLA_FGU_crypto_ONU_arithmetic_instructions),
	SPARC_M8_EVENT_PTR(MLA_Load_instructions),
	SPARC_M8_EVENT_PTR(MLA_Store_instructions),
	SPARC_M8_EVENT_PTR(MLA_Block_Load_and_Stores),
	SPARC_M8_EVENT_PTR(MLA_SPR_ring_ops),
	SPARC_M8_EVENT_PTR(MLA_atomics),
	SPARC_M8_EVENT_PTR(MLA_Software_Prefetch),
	SPARC_M8_EVENT_PTR(MLA_Other_instructions),
	SPARC_M8_EVENT_PTR(Instructions_in_MLA_mode),
	SPARC_M8_EVENT_PTR(FGU_crypto_ONU_arithmetic_instructions),
	SPARC_M8_EVENT_PTR(Load_instructions),
	SPARC_M8_EVENT_PTR(Store_instructions),
	SPARC_M8_EVENT_PTR(Block_load_and_Stores),
	SPARC_M8_EVENT_PTR(SPR_ring_ops),
	SPARC_M8_EVENT_PTR(atomics),
	SPARC_M8_EVENT_PTR(Software_prefetch),
	SPARC_M8_EVENT_PTR(Other_instructions),
	SPARC_M8_EVENT_PTR(Instructions),
	SPARC_M8_EVENT_PTR(Software_count_instructions_flavor_0),
	SPARC_M8_EVENT_PTR(Software_count_instructions_flavor_1),
	SPARC_M8_EVENT_PTR(Software_count_instructions_flavor_2),
	SPARC_M8_EVENT_PTR(Software_count_instructions_flavor_3),
	SPARC_M8_EVENT_PTR(Near_Relative_Branches),
	SPARC_M8_EVENT_PTR(Far_Call),
	SPARC_M8_EVENT_PTR(Far_Branch),
	SPARC_M8_EVENT_PTR(RETURN),
	SPARC_M8_EVENT_PTR(Branches),
	SPARC_M8_EVENT_PTR(Taken_branches),
	SPARC_M8_EVENT_PTR(EXU_PQ_tag_wait_cycles),
	SPARC_M8_EVENT_PTR(LSU_PQ_tag_wait_cycles),
	SPARC_M8_EVENT_PTR(Crypto_Diag_wait_cycles),
	SPARC_M8_EVENT_PTR(ROB_tag_wait_cycles),
	SPARC_M8_EVENT_PTR(WRF_tag_wait_cycles),
	SPARC_M8_EVENT_PTR(LB_tag_wait_cycles),
	SPARC_M8_EVENT_PTR(SB_tag_wait_cycles),
	SPARC_M8_EVENT_PTR(Branch_Data_Array_PC_full_cycles),
	SPARC_M8_EVENT_PTR(Branch_Target_Array_full_cycles),
	SPARC_M8_EVENT_PTR(IFU_misc_stalls),
	SPARC_M8_EVENT_PTR(IFU_stall),
	SPARC_M8_EVENT_PTR(MMU_TTE_buffer_full_cycles),
	SPARC_M8_EVENT_PTR(MMU_PRQ_pool_full),
	SPARC_M8_EVENT_PTR(ITLB_hardware_tablewalk_references_which_hit_L2I),
	SPARC_M8_EVENT_PTR(ITLB_hardware_tablewalk_references_which_hit_local_L3),
	SPARC_M8_EVENT_PTR(ITLB_hardware_tablewalk_references_which_miss_local_L3),
	SPARC_M8_EVENT_PTR(ITLB_hardware_tablewalk_references),
	SPARC_M8_EVENT_PTR(DTLB_hardware_tablewalk_references_which_hit_L2I),
	SPARC_M8_EVENT_PTR(DTLB_hardware_tablewalk_references_which_hit_local_L3),
	SPARC_M8_EVENT_PTR(DTLB_hardware_tablewalk_references_which_miss_local_L3),
	SPARC_M8_EVENT_PTR(DTLB_hardware_tablewalk_references),
	SPARC_M8_EVENT_PTR(ITLB_and_DTLB_hardware_tablewalk_references),
	SPARC_M8_EVENT_PTR(Instruction_prefetches_dropped_by_L2I),
	SPARC_M8_EVENT_PTR(Instruction_prefetches_hit_L2I),
	SPARC_M8_EVENT_PTR(Instruction_prefetches_dropped_by_L3),
	SPARC_M8_EVENT_PTR(Instruction_prefetches_hit_local_L3),
	SPARC_M8_EVENT_PTR(Instruction_prefetches_hit_neighbour_L3),
	SPARC_M8_EVENT_PTR(Instruction_prefetches_hit_remote_L3),
	SPARC_M8_EVENT_PTR(Instruction_prefetch_local_memory_hit),
	SPARC_M8_EVENT_PTR(Instruction_prefetch_remote_memory_hit),
	SPARC_M8_EVENT_PTR(Total_number_of_instruction_prefetches),
	SPARC_M8_EVENT_PTR(L2I_request_blocked),
	SPARC_M8_EVENT_PTR(L2I_Thread_Hog_Stall),
	SPARC_M8_EVENT_PTR(L2I_MB_full),
	SPARC_M8_EVENT_PTR(L2I_Snoop),
	SPARC_M8_EVENT_PTR(L2I_No_Request_credit),
	SPARC_M8_EVENT_PTR(L2I_No_Response_credit),
	SPARC_M8_EVENT_PTR(Flush_due_to_thread_hog),
	SPARC_M8_EVENT_PTR(Flush_on_branch_mispredict),
	SPARC_M8_EVENT_PTR(Flush_on_architectural_exception),
	SPARC_M8_EVENT_PTR(Flush_on_evil_twin),
	SPARC_M8_EVENT_PTR(Flush_and_refetch_NPC),
	SPARC_M8_EVENT_PTR(Flush_and_refetch_PC),
	SPARC_M8_EVENT_PTR(Flush_on_Misaligned_For_Mitigation),
	SPARC_M8_EVENT_PTR(Flush_for_other_reason),
	SPARC_M8_EVENT_PTR(All_pipeline_flushes),
	SPARC_M8_EVENT_PTR(flush_on_spill_n_normal),
	SPARC_M8_EVENT_PTR(flush_on_spill_n_other),
	SPARC_M8_EVENT_PTR(flush_on_fill_n_normal),
	SPARC_M8_EVENT_PTR(flush_on_fill_n_other),
	SPARC_M8_EVENT_PTR(All_pipeline_flushes_due_to_spill_fill_exceptions),
	SPARC_M8_EVENT_PTR(Flush_on_lost_load),
	SPARC_M8_EVENT_PTR(Branch_direction_mispredicts),
	SPARC_M8_EVENT_PTR(Lower_Branch_target_mispredict_due_to_far_table),
	SPARC_M8_EVENT_PTR(Upper_Branch_target_mispredict_due_to_far_table),
	SPARC_M8_EVENT_PTR(Branch_target_mispredict_due_to_far_table),
	SPARC_M8_EVENT_PTR(Lower_Branch_target_mispredict_due_to_indirect_table),
	SPARC_M8_EVENT_PTR(Upper_Branch_target_mispredict_due_to_indirect_table),
	SPARC_M8_EVENT_PTR(Branch_target_mispredict_due_to_indirect_table),
	SPARC_M8_EVENT_PTR(Branch_target_mispredict_due_to_return_stack),
	SPARC_M8_EVENT_PTR(Branch_target_mispredict),
	SPARC_M8_EVENT_PTR(Branch_mispredict),
	SPARC_M8_EVENT_PTR(DTLB_miss_sync),
	SPARC_M8_EVENT_PTR(Dcache_miss_sync),
	SPARC_M8_EVENT_PTR(RAW_prediction_sync),
	SPARC_M8_EVENT_PTR(Twin_Load_sync),
	SPARC_M8_EVENT_PTR(ATMLD_helper_sync_for_CASA_SWAP_LDSTUB),
	SPARC_M8_EVENT_PTR(All_LSU_syncs),
	SPARC_M8_EVENT_PTR(LSU_store_queue_tag_wait_cycles),
	SPARC_M8_EVENT_PTR(LSU_store_queue_tag_wait_cycles_all),
	SPARC_M8_EVENT_PTR(L2D_no_request_credit),
	SPARC_M8_EVENT_PTR(L2D_no_response_credit),
	SPARC_M8_EVENT_PTR(SQRSQ_MQID),
	SPARC_M8_EVENT_PTR(SQRSQ_IDX),
	SPARC_M8_EVENT_PTR(SQRSQ_IDXWAY),
	SPARC_M8_EVENT_PTR(SQRSQ_Setrr_TSO),
	SPARC_M8_EVENT_PTR(SQRSQ_MQ_pool_full),
	SPARC_M8_EVENT_PTR(Store_Miss_Prefetch),
	SPARC_M8_EVENT_PTR(Store_Oldest_Miss),
	SPARC_M8_EVENT_PTR(SQRSQ_L2DFP_empty),
	SPARC_M8_EVENT_PTR(Store_Hazard),
	SPARC_M8_EVENT_PTR(LD_WUQ_MQID),
	SPARC_M8_EVENT_PTR(LD_WUQ_MQ_Pool_or_OMO),
	SPARC_M8_EVENT_PTR(SB_Praw_WUQ),
	SPARC_M8_EVENT_PTR(SQ_Praw_WUQ),
	SPARC_M8_EVENT_PTR(LD_WUQ_BPQ_or_OMO),
	SPARC_M8_EVENT_PTR(LD_ST_WUQ_PRQ_or_OMO),
	SPARC_M8_EVENT_PTR(LD_ST_WUQ_DTLBFP_or_OMO),
	SPARC_M8_EVENT_PTR(LD_WUQ_LRB_Pool_or_OMO),
	SPARC_M8_EVENT_PTR(LD_WUQ_LRB_OMO_only),
	SPARC_M8_EVENT_PTR(LD_WUQ_LRB_pool_or_ORC),
	SPARC_M8_EVENT_PTR(LD_WUQ_RAW),
	SPARC_M8_EVENT_PTR(LD_WUQ_IDX),
	SPARC_M8_EVENT_PTR(LD_WUQ_IDXWAY),
	SPARC_M8_EVENT_PTR(LD_WUQ_L2DFPempty),
	SPARC_M8_EVENT_PTR(LD_L2D_WUQ_OMO_only),
	SPARC_M8_EVENT_PTR(LD_WUQ_MQ_pool_or_ORC),
	SPARC_M8_EVENT_PTR(LD_WUQ_MQ_ORC_only),
	SPARC_M8_EVENT_PTR(LD_WUQ_direct_wakeup),
	SPARC_M8_EVENT_PTR(LD_ST_WUQ_MMU_OMO),
	SPARC_M8_EVENT_PTR(WUQ_All),
	SPARC_M8_EVENT_PTR(RAW_prediction),
	SPARC_M8_EVENT_PTR(False_RAW_prediction),
	SPARC_M8_EVENT_PTR(DTAG_multiple_way_hit),
	SPARC_M8_EVENT_PTR(PATAG_miss),
	SPARC_M8_EVENT_PTR(Attribute_Mismatch),
	SPARC_M8_EVENT_PTR(Dcache_Flash_Invalidate),
	SPARC_M8_EVENT_PTR(L1_data_cache_secondary_miss_and_L2D_cache_hit),
	SPARC_M8_EVENT_PTR(L1_data_cache_miss_and_L2D_cache_hit),
	SPARC_M8_EVENT_PTR(L1_data_cache_miss_and_local_L3_cache_hit),
	SPARC_M8_EVENT_PTR(L1_data_cache_miss_and_c2c_L2D),
	SPARC_M8_EVENT_PTR(L1_data_cache_miss_and_neighbor_L3_hit),
	SPARC_M8_EVENT_PTR(L1_data_cache_miss_and_remote_L3_cache_hit),
	SPARC_M8_EVENT_PTR(L1_data_cache_miss_and_local_memory_hit),
	SPARC_M8_EVENT_PTR(L1_data_cache_miss_and_remote_memory_hit),
	SPARC_M8_EVENT_PTR(Dcache_miss),
	SPARC_M8_EVENT_PTR(L1_data_cache_secondary_miss_and_L2D_cache_hit_precise),
	SPARC_M8_EVENT_PTR(L1_data_cache_miss_and_L2D_cache_hit_precise),
	SPARC_M8_EVENT_PTR(L1_data_cache_miss_and_local_L3_cache_hit_precise),
	SPARC_M8_EVENT_PTR(L1_data_cache_miss_and_c2c_L2D_precise),
	SPARC_M8_EVENT_PTR(L1_data_cache_miss_and_neighbor_L3_hit_precise),
	SPARC_M8_EVENT_PTR(L1_data_cache_miss_and_remote_L3_cache_hit_precise),
	SPARC_M8_EVENT_PTR(L1_data_cache_miss_and_local_memory_hit_precise),
	SPARC_M8_EVENT_PTR(L1_data_cache_miss_and_remote_memory_hit_precise),
	SPARC_M8_EVENT_PTR(Dcache_miss_precise),
	SPARC_M8_EVENT_PTR(Store_L1D_secondary_miss_non_mla),
	SPARC_M8_EVENT_PTR(Store_L2D_hit_non_mla),
	SPARC_M8_EVENT_PTR(Store_local_L3_hit_non_mla),
	SPARC_M8_EVENT_PTR(Store_neighbor_L2_non_mla),
	SPARC_M8_EVENT_PTR(Store_neighbor_L3_hit_non_mla),
	SPARC_M8_EVENT_PTR(Store_remote_L3_hit_non_mla),
	SPARC_M8_EVENT_PTR(Store_local_memory_non_mla),
	SPARC_M8_EVENT_PTR(Store_remote_memory_non_mla),
	SPARC_M8_EVENT_PTR(Stores_non_mla),
	SPARC_M8_EVENT_PTR(Store_L1D_secondary_miss_mla),
	SPARC_M8_EVENT_PTR(Store_L2D_hit_mla),
	SPARC_M8_EVENT_PTR(Store_local_L3_hit_mla),
	SPARC_M8_EVENT_PTR(Store_neighbor_L2_mla),
	SPARC_M8_EVENT_PTR(Store_neighbor_L3_hit_mla),
	SPARC_M8_EVENT_PTR(Store_remote_L3_hit_mla),
	SPARC_M8_EVENT_PTR(Store_local_memory_mla),
	SPARC_M8_EVENT_PTR(Store_remote_memory_mla),
	SPARC_M8_EVENT_PTR(Stores_mla),
	SPARC_M8_EVENT_PTR(Store_prefetch_local_L3_hit_non_mla),
	SPARC_M8_EVENT_PTR(Store_prefetch_neighbor_L2_non_mla),
	SPARC_M8_EVENT_PTR(Store_prefetch_neighbor_L3_hit_non_mla),
	SPARC_M8_EVENT_PTR(Store_prefetch_remote_L3_hit_non_mla),
	SPARC_M8_EVENT_PTR(Store_prefetch_local_memory_non_mla),
	SPARC_M8_EVENT_PTR(Store_prefetch_remote_memory_non_mla),
	SPARC_M8_EVENT_PTR(Store_prefetch_non_mla),
	SPARC_M8_EVENT_PTR(Store_prefetch_local_L3_hit_mla),
	SPARC_M8_EVENT_PTR(Store_prefetch_neighbor_L2_mla),
	SPARC_M8_EVENT_PTR(Store_prefetch_neighbor_L3_hit_mla),
	SPARC_M8_EVENT_PTR(Store_prefetch_remote_L3_hit_mla),
	SPARC_M8_EVENT_PTR(Store_prefetch_local_memory_mla),
	SPARC_M8_EVENT_PTR(Store_prefetch_remote_memory_mla),
	SPARC_M8_EVENT_PTR(Store_prefetch_mla),
	SPARC_M8_EVENT_PTR(L1D_hit_sw),
	SPARC_M8_EVENT_PTR(L1_secondary_miss_sw),
	SPARC_M8_EVENT_PTR(L2D_hit_sw),
	SPARC_M8_EVENT_PTR(L2D_drop_sw),
	SPARC_M8_EVENT_PTR(L3_hit_sw),
	SPARC_M8_EVENT_PTR(L3_drop_sw),
	SPARC_M8_EVENT_PTR(Hit_in_remote_node_sw),
	SPARC_M8_EVENT_PTR(Hit_in_memory_sw),
	SPARC_M8_EVENT_PTR(Total_Software_Data_Prefetches_sw),
	SPARC_M8_EVENT_PTR(L1D_secondary_miss),
	SPARC_M8_EVENT_PTR(L2D_hit),
	SPARC_M8_EVENT_PTR(L2D_drop),
	SPARC_M8_EVENT_PTR(L3_hit),
	SPARC_M8_EVENT_PTR(L3_drop),
	SPARC_M8_EVENT_PTR(Hit_in_remote_node),
	SPARC_M8_EVENT_PTR(Hit_in_memory),
	SPARC_M8_EVENT_PTR(Total_Hardware_Data_Prefetches),
	SPARC_M8_EVENT_PTR(Full_RAW_hit_in_store_buffer),
	SPARC_M8_EVENT_PTR(Partial_RAW_hit_in_store_buffer),
	SPARC_M8_EVENT_PTR(RAW_hit_in_store_buffer),
	SPARC_M8_EVENT_PTR(Full_RAW_hit_in_store_queue),
	SPARC_M8_EVENT_PTR(Partial_RAW_hit_in_store_queue),
	SPARC_M8_EVENT_PTR(Full_or_partial_RAW_hit_in_store_queue),
	SPARC_M8_EVENT_PTR(RAWs),
	SPARC_M8_EVENT_PTR(Data_cache_eviction_invalidations),
	SPARC_M8_EVENT_PTR(Data_cache_snoop_invalidations),
	SPARC_M8_EVENT_PTR(Data_cache_invalidations),
	SPARC_M8_EVENT_PTR(Cycles_non_MLA),
	SPARC_M8_EVENT_PTR(Cycles_MLA),
	SPARC_M8_EVENT_PTR(Cycles),
	SPARC_M8_EVENT_PTR(Exit_MLA_LSU_fill),
	SPARC_M8_EVENT_PTR(Exit_MLA_counter),
	SPARC_M8_EVENT_PTR(Exit_MLA_presync),
	SPARC_M8_EVENT_PTR(Exit_MLA_precommit),
	SPARC_M8_EVENT_PTR(Exit_MLA_exception),
	SPARC_M8_EVENT_PTR(Exit_MLA_Comit_exception),
	SPARC_M8_EVENT_PTR(Exit_disrupting_flush),
	SPARC_M8_EVENT_PTR(Exit_MLA),
	SPARC_M8_EVENT_PTR(L1_data_cache_secondary_miss_and_L2D_cache_hit_mla),
	SPARC_M8_EVENT_PTR(L1_data_cache_miss_and_L2D_cache_hit_mla),
	SPARC_M8_EVENT_PTR(L1_data_cache_miss_and_local_L3_cache_hit_mla),
	SPARC_M8_EVENT_PTR(L1_data_cache_miss_and_c2c_L2D_mla),
	SPARC_M8_EVENT_PTR(L1_data_cache_miss_and_neighbor_L3_hit_mla),
	SPARC_M8_EVENT_PTR(L1_data_cache_miss_and_remote_L3_cache_hit_mla),
	SPARC_M8_EVENT_PTR(L1_data_cache_miss_and_local_memory_hit_mla),
	SPARC_M8_EVENT_PTR(L1_data_cache_miss_and_remote_memory_hit_mla),
	SPARC_M8_EVENT_PTR(Dcache_miss_mla),
	SPARC_M8_EVENT_PTR(L2D_pipeline_stall_on_load),
	SPARC_M8_EVENT_PTR(L2D_pipeline_stall_on_store),
	SPARC_M8_EVENT_PTR(L2D_pipeline_stalls),
	SPARC_M8_EVENT_PTR(Clean_L2D_evictions),
	SPARC_M8_EVENT_PTR(Dirty_L2D_evictions),
	SPARC_M8_EVENT_PTR(L2D_evictions),
	SPARC_M8_EVENT_PTR(Load_Version_Read),
	SPARC_M8_EVENT_PTR(Load_Version_Check),
	SPARC_M8_EVENT_PTR(Store_Version_Update),
	SPARC_M8_EVENT_PTR(Store_Version_Check),
	SPARC_M8_EVENT_PTR(All_Versioned_instructions),
	SPARC_M8_EVENT_PTR(DTLB_fill_for_8KB_page),
	SPARC_M8_EVENT_PTR(DTLB_fill_for_64KB_page),
	SPARC_M8_EVENT_PTR(DTLB_fill_for_4MB_page),
	SPARC_M8_EVENT_PTR(DTLB_fill_for_256MB_page),
	SPARC_M8_EVENT_PTR(DTLB_fill_for_16GB_page),
	SPARC_M8_EVENT_PTR(DTLB_fill_for_1TB_page),
	SPARC_M8_EVENT_PTR(DTLB_fill_trap1),
	SPARC_M8_EVENT_PTR(DTLB_fill_trap2),
	SPARC_M8_EVENT_PTR(DTLB_fills_or_fill_traps),
	SPARC_M8_EVENT_PTR(DC_fill_with_no_DTLB_TTE),
	SPARC_M8_EVENT_PTR(DC_fill_with_replaced_DTLB_TTE),
	SPARC_M8_EVENT_PTR(DC_fill_no_hit),
	SPARC_M8_EVENT_PTR(Pick_slot_0),
	SPARC_M8_EVENT_PTR(Pick_slot_1),
	SPARC_M8_EVENT_PTR(Pick_slot_2),
	SPARC_M8_EVENT_PTR(Pick_slot_3),
	SPARC_M8_EVENT_PTR(All_microops_picked),
	SPARC_M8_EVENT_PTR(RNG_req),
	SPARC_M8_EVENT_PTR(RNG_req_half_full),
	SPARC_M8_EVENT_PTR(RNG_response_dedicated_pool_success),
	SPARC_M8_EVENT_PTR(RNG_response_shared_pool_success),
	SPARC_M8_EVENT_PTR(RNG_response_success),
	SPARC_M8_EVENT_PTR(RNG_response_fail_ORC),
	SPARC_M8_EVENT_PTR(RNG_response_fail_OMO_only),
	SPARC_M8_EVENT_PTR(RNG_fail),
	SPARC_M8_EVENT_PTR(L1D_hit_sw_mla),
	SPARC_M8_EVENT_PTR(L1_secondary_miss_sw_mla),
	SPARC_M8_EVENT_PTR(L2D_hit_sw_mla),
	SPARC_M8_EVENT_PTR(L2D_drop_sw_mla),
	SPARC_M8_EVENT_PTR(L3_hit_sw_mla),
	SPARC_M8_EVENT_PTR(L3_drop_sw_mla),
	SPARC_M8_EVENT_PTR(Hit_in_remote_node_sw_mla),
	SPARC_M8_EVENT_PTR(Hit_in_memory_sw_mla),
	SPARC_M8_EVENT_PTR(Total_Software_Data_Prefetches_sw_mla),
	SPARC_M8_EVENT_PTR(Instructions_Fetched),
	SPARC_M8_EVENT_PTR(Instructions_Fetched_all),
	SPARC_M8_EVENT_PTR(Instructions_Decoded),
	SPARC_M8_EVENT_PTR(Instructions_Decoded_all),
	SPARC_M8_EVENT_PTR(micro_ops_picked),
	SPARC_M8_EVENT_PTR(micro_ops_picked_all),
	SPARC_M8_EVENT_PTR(micro_ops_committed),
	SPARC_M8_EVENT_PTR(Commit_0),
	SPARC_M8_EVENT_PTR(Commit_0_all),
	NULL,
};

#endif /* __SPARC_M8_PMU_EVENTS_H */

