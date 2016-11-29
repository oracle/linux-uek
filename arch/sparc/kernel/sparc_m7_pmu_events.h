#ifndef __SPARC_M7_PMU_EVENTS_H
#define __SPARC_M7_PMU_EVENTS_H

/* Note: The event configurations come from the
 *       'SPARC M7 Supplement to the Oracle SPARC Architecture 2015'
 *       spec, and are of the form (((sl << 6) | mask) << 16)
 */
SPARC_M7_EVENT_ATTR(Sel_pipe_drain_cyc, 0x41);
SPARC_M7_EVENT_ATTR(Sel_0_wait_cyc, 0x42);
SPARC_M7_EVENT_ATTR(Sel_0_ready_cyc, 0x44);
SPARC_M7_EVENT_ATTR(Sel_1_cyc, 0x45);
SPARC_M7_EVENT_ATTR(Sel_2_cyc, 0x50);
SPARC_M7_EVENT_ATTR(Pick_0_cyc, 0x81);
SPARC_M7_EVENT_ATTR(Pick_1_cyc, 0x82);
SPARC_M7_EVENT_ATTR(Pick_2_cyc, 0x84);
SPARC_M7_EVENT_ATTR(Pick_3_cyc, 0x88);
SPARC_M7_EVENT_ATTR(Pick_any_cyc, 0x8e);
SPARC_M7_EVENT_ATTR(Branches, 0xc1);
SPARC_M7_EVENT_ATTR(Instr_FGU_crypto, 0xc2);
SPARC_M7_EVENT_ATTR(Instr_ld, 0xc4);
SPARC_M7_EVENT_ATTR(Instr_st, 0xc8);
SPARC_M7_EVENT_ATTR(Instr_SPR_ring_ops, 0xd0);
SPARC_M7_EVENT_ATTR(Instr_other, 0xe0);
SPARC_M7_EVENT_ATTR(Instr_all, 0xff);
SPARC_M7_EVENT_ATTR(Br_taken, 0x102);
SPARC_M7_EVENT_ATTR(Instr_SW_count, 0x104);
SPARC_M7_EVENT_ATTR(Instr_atomic, 0x108);
SPARC_M7_EVENT_ATTR(Instr_SW_prefetch, 0x110);
SPARC_M7_EVENT_ATTR(Instr_block_ld_st, 0x120);
SPARC_M7_EVENT_ATTR(IC_miss_L2_L3_hit_commit, 0x141);
SPARC_M7_EVENT_ATTR(IC_miss_nbr_scc_hit_commit, 0x142);
SPARC_M7_EVENT_ATTR(IC_miss_nbr_scc_miss_commit, 0x144);
SPARC_M7_EVENT_ATTR(IC_miss_commit, 0x147);
SPARC_M7_EVENT_ATTR(Br_BTC_miss, 0x148);
SPARC_M7_EVENT_ATTR(ITLB_miss, 0x150);
SPARC_M7_EVENT_ATTR(ITLB_HWTW_hit_8K, 0x181);
SPARC_M7_EVENT_ATTR(ITLB_HWTW_hit_64K, 0x182);
SPARC_M7_EVENT_ATTR(ITLB_HWTW_hit_4M, 0x184);
SPARC_M7_EVENT_ATTR(ITLB_HWTW_hit_256M, 0x188);
SPARC_M7_EVENT_ATTR(ITLB_HWTW_hit_2G_16G, 0x190);
SPARC_M7_EVENT_ATTR(ITLB_HWTW_miss_trap, 0x1a0);
SPARC_M7_EVENT_ATTR(ITLB_HWTW_search, 0x1bf);
SPARC_M7_EVENT_ATTR(IC_mtag_miss, 0x1c1);
SPARC_M7_EVENT_ATTR(IC_mtag_miss_ptag_hit, 0x1c2);
SPARC_M7_EVENT_ATTR(IC_mtag_hit_ptag_miss, 0x1c4);
SPARC_M7_EVENT_ATTR(IC_mtag_ptag_hit_way_mismatch, 0x1c8);
SPARC_M7_EVENT_ATTR(Fetch_0_cyc, 0x201);
SPARC_M7_EVENT_ATTR(Fetch_0_all_cyc, 0x202);
SPARC_M7_EVENT_ATTR(Instr_buffer_full_cyc, 0x204);
SPARC_M7_EVENT_ATTR(Br_BTC_target_incorrect, 0x208);
SPARC_M7_EVENT_ATTR(PQ_tag_wait_cyc, 0x241);
SPARC_M7_EVENT_ATTR(ROB_tag_wait_cyc, 0x242);
SPARC_M7_EVENT_ATTR(LB_tag_wait_cyc, 0x244);
SPARC_M7_EVENT_ATTR(SB_tag_wait_cyc, 0x248);
SPARC_M7_EVENT_ATTR(ROB_LB_tag_wait_cyc, 0x246);
SPARC_M7_EVENT_ATTR(ROB_SB_tag_wait_cyc, 0x24a);
SPARC_M7_EVENT_ATTR(LB_SB_tag_wait_cyc, 0x24c);
SPARC_M7_EVENT_ATTR(ROB_LB_SB_tag_wait_cyc, 0x24e);
SPARC_M7_EVENT_ATTR(DTLB_miss_tag_wait_cyc, 0x250);
SPARC_M7_EVENT_ATTR(ITLB_HWTW_L2_hit, 0x281);
SPARC_M7_EVENT_ATTR(ITLB_HWTW_L3_hit, 0x282);
SPARC_M7_EVENT_ATTR(ITLB_HWTW_L3_miss, 0x284);
SPARC_M7_EVENT_ATTR(ITLB_HWTW_ref, 0x287);
SPARC_M7_EVENT_ATTR(DTLB_HWTW_L2_hit, 0x288);
SPARC_M7_EVENT_ATTR(DTLB_HWTW_L3_hit, 0x290);
SPARC_M7_EVENT_ATTR(DTLB_HWTW_L3_miss, 0x2a0);
SPARC_M7_EVENT_ATTR(DTLB_HWTW_ref, 0x2b8);
SPARC_M7_EVENT_ATTR(IC_hit, 0x2c1);
SPARC_M7_EVENT_ATTR(IC_miss_L2_hit, 0x2c2);
SPARC_M7_EVENT_ATTR(IC_miss_L3_hit, 0x2c4);
SPARC_M7_EVENT_ATTR(IC_miss_nbr_L2_hit, 0x2c8);
SPARC_M7_EVENT_ATTR(IC_miss_nbr_scc_hit, 0x2d0);
SPARC_M7_EVENT_ATTR(IC_miss_nbr_scc_miss, 0x2e0);
SPARC_M7_EVENT_ATTR(IC_miss, 0x2fe);
SPARC_M7_EVENT_ATTR(IC_miss_L2_miss, 0x2fc);
SPARC_M7_EVENT_ATTR(IC_miss_L3_miss, 0x2f0);
SPARC_M7_EVENT_ATTR(IC_miss_remote_scc_hit, 0x301);
SPARC_M7_EVENT_ATTR(IC_miss_local_mem_hit, 0x302);
SPARC_M7_EVENT_ATTR(IC_miss_remote_mem_hit, 0x304);
SPARC_M7_EVENT_ATTR(L1I_pf_total, 0x341);
SPARC_M7_EVENT_ATTR(L1I_pf_L2_L3_drop, 0x342);
SPARC_M7_EVENT_ATTR(L1I_pf_L2_L3_hit, 0x344);
SPARC_M7_EVENT_ATTR(L1I_pf_nbr_scc_hit, 0x348);
SPARC_M7_EVENT_ATTR(L1I_pf_remote_scc_hit, 0x350);
SPARC_M7_EVENT_ATTR(L1I_pf_mem_hit, 0x360);
SPARC_M7_EVENT_ATTR(L2I_mistype_access, 0x381);
SPARC_M7_EVENT_ATTR(L2I_input_block_other, 0x382);
SPARC_M7_EVENT_ATTR(L2I_input_block_MB_thread_hog, 0x384);
SPARC_M7_EVENT_ATTR(L2I_MB_full, 0x388);
SPARC_M7_EVENT_ATTR(L2I_eviction, 0x390);
SPARC_M7_EVENT_ATTR(L3_stall_insuff_credit, 0x3a0);
SPARC_M7_EVENT_ATTR(DC_miss_L2_L3_hit_commit, 0x401);
SPARC_M7_EVENT_ATTR(DC_miss_nbr_scc_hit_commit, 0x402);
SPARC_M7_EVENT_ATTR(DC_miss_nbr_scc_miss_commit, 0x404);
SPARC_M7_EVENT_ATTR(DC_miss_commit, 0x407);
SPARC_M7_EVENT_ATTR(DTLB_HWTW_hit_8K, 0x441);
SPARC_M7_EVENT_ATTR(DTLB_HWTW_hit_64K, 0x442);
SPARC_M7_EVENT_ATTR(DTLB_HWTW_hit_4M, 0x444);
SPARC_M7_EVENT_ATTR(DTLB_HWTW_hit_256M, 0x448);
SPARC_M7_EVENT_ATTR(DTLB_HWTW_hit_2G_16G, 0x450);
SPARC_M7_EVENT_ATTR(DTLB_HWTW_miss_trap, 0x460);
SPARC_M7_EVENT_ATTR(DTLB_HWTW_search, 0x47f);
SPARC_M7_EVENT_ATTR(L1D_HW_pf_total, 0x4bc);
SPARC_M7_EVENT_ATTR(L1D_HW_pf_L1D_hit, 0x489);
SPARC_M7_EVENT_ATTR(L1D_HW_pf_L2D_hit, 0x491);
SPARC_M7_EVENT_ATTR(L1D_HW_pf_L2D_drop, 0x4a1);
SPARC_M7_EVENT_ATTR(L1D_SW_pf_total, 0x482);
SPARC_M7_EVENT_ATTR(L1D_SW_pf_L1D_drop, 0x484);
SPARC_M7_EVENT_ATTR(L1D_SW_pf_L1D_hit, 0x488);
SPARC_M7_EVENT_ATTR(L1D_SW_pf_L2D_hit, 0x490);
SPARC_M7_EVENT_ATTR(L1D_SW_pf_L2D_drop, 0x4a0);
SPARC_M7_EVENT_ATTR(RAW_hit_st_buf_full, 0x4c1);
SPARC_M7_EVENT_ATTR(RAW_hit_st_buf_partial, 0x4c2);
SPARC_M7_EVENT_ATTR(RAW_hit_st_buf, 0x4fc);
SPARC_M7_EVENT_ATTR(RAW_hit_st_q_full, 0x4c4);
SPARC_M7_EVENT_ATTR(RAW_hit_st_q_partial, 0x4c8);
SPARC_M7_EVENT_ATTR(RAW_hit_st_q, 0x4cc);
SPARC_M7_EVENT_ATTR(IC_invalidation_evict, 0x501);
SPARC_M7_EVENT_ATTR(IC_invalidation_snoop, 0x502);
SPARC_M7_EVENT_ATTR(IC_invalidation, 0x53c);
SPARC_M7_EVENT_ATTR(DC_invalidation_evict, 0x504);
SPARC_M7_EVENT_ATTR(DC_invalidation_snoop, 0x508);
SPARC_M7_EVENT_ATTR(DC_invalidation, 0x50c);
SPARC_M7_EVENT_ATTR(L1_invalidation_snoop, 0x50a);
SPARC_M7_EVENT_ATTR(L1_invalidation, 0x50f);
SPARC_M7_EVENT_ATTR(St_q_tag_wait_cyc, 0x510);
SPARC_M7_EVENT_ATTR(L1D_HW_pf_L3_hit, 0x57c);
SPARC_M7_EVENT_ATTR(L1D_HW_pf_L3_drop, 0x545);
SPARC_M7_EVENT_ATTR(L1D_HW_pf_nbr_hit, 0x549);
SPARC_M7_EVENT_ATTR(L1D_HW_pf_local_mem_hit, 0x551);
SPARC_M7_EVENT_ATTR(L1D_HW_pf_remote_hit, 0x561);
SPARC_M7_EVENT_ATTR(L1D_SW_pf_L3_hit, 0x542);
SPARC_M7_EVENT_ATTR(L1D_SW_pf_L3_drop, 0x544);
SPARC_M7_EVENT_ATTR(L1D_SW_pf_nbr_hit, 0x548);
SPARC_M7_EVENT_ATTR(L1D_SW_pf_local_mem_hit, 0x550);
SPARC_M7_EVENT_ATTR(L1D_SW_pf_remote_hit, 0x560);
SPARC_M7_EVENT_ATTR(St_L2_hit, 0x581);
SPARC_M7_EVENT_ATTR(St_L3_hit, 0x582);
SPARC_M7_EVENT_ATTR(St_nbr_scc_hit, 0x584);
SPARC_M7_EVENT_ATTR(St_remote_scc_hit, 0x588);
SPARC_M7_EVENT_ATTR(St_local_mem_hit, 0x590);
SPARC_M7_EVENT_ATTR(St_remote_mem_hit, 0x5a0);
SPARC_M7_EVENT_ATTR(DC_hit, 0x5c1);
SPARC_M7_EVENT_ATTR(DC_miss_L2_hit, 0x5c2);
SPARC_M7_EVENT_ATTR(DC_miss_L3_hit, 0x5c4);
SPARC_M7_EVENT_ATTR(DC_miss_nbr_L2_hit, 0x5c8);
SPARC_M7_EVENT_ATTR(DC_miss_nbr_scc_hit, 0x5d0);
SPARC_M7_EVENT_ATTR(DC_miss_nbr_scc_miss, 0x5e0);
SPARC_M7_EVENT_ATTR(DC_miss, 0x5fe);
SPARC_M7_EVENT_ATTR(DC_miss_L2_miss, 0x5fc);
SPARC_M7_EVENT_ATTR(DC_miss_L3_miss, 0x5f0);
SPARC_M7_EVENT_ATTR(DC_miss_remote_scc_hit, 0x601);
SPARC_M7_EVENT_ATTR(DC_miss_local_mem_hit, 0x602);
SPARC_M7_EVENT_ATTR(DC_miss_remote_mem_hit, 0x604);
SPARC_M7_EVENT_ATTR(Br_dir_mispred, 0x641);
SPARC_M7_EVENT_ATTR(Br_tgt_mispred_far_tbl, 0x642);
SPARC_M7_EVENT_ATTR(Br_tgt_mispred_indir_tbl, 0x644);
SPARC_M7_EVENT_ATTR(Br_tgt_mispred_ret_stk, 0x648);
SPARC_M7_EVENT_ATTR(Br_tgt_mispred, 0x64e);
SPARC_M7_EVENT_ATTR(Br_mispred, 0x64f);
SPARC_M7_EVENT_ATTR(Cycles_user, 0x680);
SPARC_M7_EVENT_ATTR(Flush_L3_miss, 0x6c1);
SPARC_M7_EVENT_ATTR(Flush_br_mispred, 0x6c2);
SPARC_M7_EVENT_ATTR(Flush_arch_exception, 0x6c4);
SPARC_M7_EVENT_ATTR(Flush_evil_twin, 0x6c8);
SPARC_M7_EVENT_ATTR(Flush_LSU_trap, 0x6d0);
SPARC_M7_EVENT_ATTR(Flush_other, 0x6e0);
SPARC_M7_EVENT_ATTR(Commit_0_cyc, 0x701);
SPARC_M7_EVENT_ATTR(Commit_0_all_cyc, 0x702);
SPARC_M7_EVENT_ATTR(Commit_1_cyc, 0x704);
SPARC_M7_EVENT_ATTR(Commit_2_cyc, 0x708);
SPARC_M7_EVENT_ATTR(Commit_1_or_2_cyc, 0x70c);
SPARC_M7_EVENT_ATTR(L2D_SW_pf_total, 0x742);
SPARC_M7_EVENT_ATTR(L2D_SW_pf_L1_drop_MB_full, 0x744);
SPARC_M7_EVENT_ATTR(L2D_SW_pf_L1_hit, 0x748);
SPARC_M7_EVENT_ATTR(L2D_SW_pf_L2_hit, 0x750);
SPARC_M7_EVENT_ATTR(L2D_SW_pf_L2_drop, 0x760);
SPARC_M7_EVENT_ATTR(L2D_clean_eviction, 0x781);
SPARC_M7_EVENT_ATTR(L2D_dirty_eviction, 0x782);
SPARC_M7_EVENT_ATTR(L2D_RQB_full, 0x784);
SPARC_M7_EVENT_ATTR(L2D_MB_fail_replay, 0x788);
SPARC_M7_EVENT_ATTR(L2D_MB_full, 0x790);
SPARC_M7_EVENT_ATTR(L2D_pipeline_stall, 0x7a0);
SPARC_M7_EVENT_ATTR(L2D_SW_pf_L3_hit, 0x7c2);
SPARC_M7_EVENT_ATTR(L2D_SW_pf_L3_drop, 0x7c4);
SPARC_M7_EVENT_ATTR(L2D_SW_pf_nbr_hit, 0x7c8);
SPARC_M7_EVENT_ATTR(L2D_SW_pf_local_mem_hit, 0x7d0);
SPARC_M7_EVENT_ATTR(L2D_SW_pf_remote_hit, 0x7e0);

static struct attribute *sparc_m7_pmu_event_attrs[] = {
	SPARC_M7_EVENT_PTR(Sel_pipe_drain_cyc),
	SPARC_M7_EVENT_PTR(Sel_0_wait_cyc),
	SPARC_M7_EVENT_PTR(Sel_0_ready_cyc),
	SPARC_M7_EVENT_PTR(Sel_1_cyc),
	SPARC_M7_EVENT_PTR(Sel_2_cyc),
	SPARC_M7_EVENT_PTR(Pick_0_cyc),
	SPARC_M7_EVENT_PTR(Pick_1_cyc),
	SPARC_M7_EVENT_PTR(Pick_2_cyc),
	SPARC_M7_EVENT_PTR(Pick_3_cyc),
	SPARC_M7_EVENT_PTR(Pick_any_cyc),
	SPARC_M7_EVENT_PTR(Branches),
	SPARC_M7_EVENT_PTR(Instr_FGU_crypto),
	SPARC_M7_EVENT_PTR(Instr_ld),
	SPARC_M7_EVENT_PTR(Instr_st),
	SPARC_M7_EVENT_PTR(Instr_SPR_ring_ops),
	SPARC_M7_EVENT_PTR(Instr_other),
	SPARC_M7_EVENT_PTR(Instr_all),
	SPARC_M7_EVENT_PTR(Br_taken),
	SPARC_M7_EVENT_PTR(Instr_SW_count),
	SPARC_M7_EVENT_PTR(Instr_atomic),
	SPARC_M7_EVENT_PTR(Instr_SW_prefetch),
	SPARC_M7_EVENT_PTR(Instr_block_ld_st),
	SPARC_M7_EVENT_PTR(IC_miss_L2_L3_hit_commit),
	SPARC_M7_EVENT_PTR(IC_miss_nbr_scc_hit_commit),
	SPARC_M7_EVENT_PTR(IC_miss_nbr_scc_miss_commit),
	SPARC_M7_EVENT_PTR(IC_miss_commit),
	SPARC_M7_EVENT_PTR(Br_BTC_miss),
	SPARC_M7_EVENT_PTR(ITLB_miss),
	SPARC_M7_EVENT_PTR(ITLB_HWTW_hit_8K),
	SPARC_M7_EVENT_PTR(ITLB_HWTW_hit_64K),
	SPARC_M7_EVENT_PTR(ITLB_HWTW_hit_4M),
	SPARC_M7_EVENT_PTR(ITLB_HWTW_hit_256M),
	SPARC_M7_EVENT_PTR(ITLB_HWTW_hit_2G_16G),
	SPARC_M7_EVENT_PTR(ITLB_HWTW_miss_trap),
	SPARC_M7_EVENT_PTR(ITLB_HWTW_search),
	SPARC_M7_EVENT_PTR(IC_mtag_miss),
	SPARC_M7_EVENT_PTR(IC_mtag_miss_ptag_hit),
	SPARC_M7_EVENT_PTR(IC_mtag_hit_ptag_miss),
	SPARC_M7_EVENT_PTR(IC_mtag_ptag_hit_way_mismatch),
	SPARC_M7_EVENT_PTR(Fetch_0_cyc),
	SPARC_M7_EVENT_PTR(Fetch_0_all_cyc),
	SPARC_M7_EVENT_PTR(Instr_buffer_full_cyc),
	SPARC_M7_EVENT_PTR(Br_BTC_target_incorrect),
	SPARC_M7_EVENT_PTR(PQ_tag_wait_cyc),
	SPARC_M7_EVENT_PTR(ROB_tag_wait_cyc),
	SPARC_M7_EVENT_PTR(LB_tag_wait_cyc),
	SPARC_M7_EVENT_PTR(SB_tag_wait_cyc),
	SPARC_M7_EVENT_PTR(ROB_LB_tag_wait_cyc),
	SPARC_M7_EVENT_PTR(ROB_SB_tag_wait_cyc),
	SPARC_M7_EVENT_PTR(LB_SB_tag_wait_cyc),
	SPARC_M7_EVENT_PTR(ROB_LB_SB_tag_wait_cyc),
	SPARC_M7_EVENT_PTR(DTLB_miss_tag_wait_cyc),
	SPARC_M7_EVENT_PTR(ITLB_HWTW_L2_hit),
	SPARC_M7_EVENT_PTR(ITLB_HWTW_L3_hit),
	SPARC_M7_EVENT_PTR(ITLB_HWTW_L3_miss),
	SPARC_M7_EVENT_PTR(ITLB_HWTW_ref),
	SPARC_M7_EVENT_PTR(DTLB_HWTW_L2_hit),
	SPARC_M7_EVENT_PTR(DTLB_HWTW_L3_hit),
	SPARC_M7_EVENT_PTR(DTLB_HWTW_L3_miss),
	SPARC_M7_EVENT_PTR(DTLB_HWTW_ref),
	SPARC_M7_EVENT_PTR(IC_hit),
	SPARC_M7_EVENT_PTR(IC_miss_L2_hit),
	SPARC_M7_EVENT_PTR(IC_miss_L3_hit),
	SPARC_M7_EVENT_PTR(IC_miss_nbr_L2_hit),
	SPARC_M7_EVENT_PTR(IC_miss_nbr_scc_hit),
	SPARC_M7_EVENT_PTR(IC_miss_nbr_scc_miss),
	SPARC_M7_EVENT_PTR(IC_miss),
	SPARC_M7_EVENT_PTR(IC_miss_L2_miss),
	SPARC_M7_EVENT_PTR(IC_miss_L3_miss),
	SPARC_M7_EVENT_PTR(IC_miss_remote_scc_hit),
	SPARC_M7_EVENT_PTR(IC_miss_local_mem_hit),
	SPARC_M7_EVENT_PTR(IC_miss_remote_mem_hit),
	SPARC_M7_EVENT_PTR(L1I_pf_total),
	SPARC_M7_EVENT_PTR(L1I_pf_L2_L3_drop),
	SPARC_M7_EVENT_PTR(L1I_pf_L2_L3_hit),
	SPARC_M7_EVENT_PTR(L1I_pf_nbr_scc_hit),
	SPARC_M7_EVENT_PTR(L1I_pf_remote_scc_hit),
	SPARC_M7_EVENT_PTR(L1I_pf_mem_hit),
	SPARC_M7_EVENT_PTR(L2I_mistype_access),
	SPARC_M7_EVENT_PTR(L2I_input_block_other),
	SPARC_M7_EVENT_PTR(L2I_input_block_MB_thread_hog),
	SPARC_M7_EVENT_PTR(L2I_MB_full),
	SPARC_M7_EVENT_PTR(L2I_eviction),
	SPARC_M7_EVENT_PTR(L3_stall_insuff_credit),
	SPARC_M7_EVENT_PTR(DC_miss_L2_L3_hit_commit),
	SPARC_M7_EVENT_PTR(DC_miss_nbr_scc_hit_commit),
	SPARC_M7_EVENT_PTR(DC_miss_nbr_scc_miss_commit),
	SPARC_M7_EVENT_PTR(DC_miss_commit),
	SPARC_M7_EVENT_PTR(DTLB_HWTW_hit_8K),
	SPARC_M7_EVENT_PTR(DTLB_HWTW_hit_64K),
	SPARC_M7_EVENT_PTR(DTLB_HWTW_hit_4M),
	SPARC_M7_EVENT_PTR(DTLB_HWTW_hit_256M),
	SPARC_M7_EVENT_PTR(DTLB_HWTW_hit_2G_16G),
	SPARC_M7_EVENT_PTR(DTLB_HWTW_miss_trap),
	SPARC_M7_EVENT_PTR(DTLB_HWTW_search),
	SPARC_M7_EVENT_PTR(L1D_HW_pf_total),
	SPARC_M7_EVENT_PTR(L1D_HW_pf_L1D_hit),
	SPARC_M7_EVENT_PTR(L1D_HW_pf_L2D_hit),
	SPARC_M7_EVENT_PTR(L1D_HW_pf_L2D_drop),
	SPARC_M7_EVENT_PTR(L1D_SW_pf_total),
	SPARC_M7_EVENT_PTR(L1D_SW_pf_L1D_drop),
	SPARC_M7_EVENT_PTR(L1D_SW_pf_L1D_hit),
	SPARC_M7_EVENT_PTR(L1D_SW_pf_L2D_hit),
	SPARC_M7_EVENT_PTR(L1D_SW_pf_L2D_drop),
	SPARC_M7_EVENT_PTR(RAW_hit_st_buf_full),
	SPARC_M7_EVENT_PTR(RAW_hit_st_buf_partial),
	SPARC_M7_EVENT_PTR(RAW_hit_st_buf),
	SPARC_M7_EVENT_PTR(RAW_hit_st_q_full),
	SPARC_M7_EVENT_PTR(RAW_hit_st_q_partial),
	SPARC_M7_EVENT_PTR(RAW_hit_st_q),
	SPARC_M7_EVENT_PTR(IC_invalidation_evict),
	SPARC_M7_EVENT_PTR(IC_invalidation_snoop),
	SPARC_M7_EVENT_PTR(IC_invalidation),
	SPARC_M7_EVENT_PTR(DC_invalidation_evict),
	SPARC_M7_EVENT_PTR(DC_invalidation_snoop),
	SPARC_M7_EVENT_PTR(DC_invalidation),
	SPARC_M7_EVENT_PTR(L1_invalidation_snoop),
	SPARC_M7_EVENT_PTR(L1_invalidation),
	SPARC_M7_EVENT_PTR(St_q_tag_wait_cyc),
	SPARC_M7_EVENT_PTR(L1D_HW_pf_L3_hit),
	SPARC_M7_EVENT_PTR(L1D_HW_pf_L3_drop),
	SPARC_M7_EVENT_PTR(L1D_HW_pf_nbr_hit),
	SPARC_M7_EVENT_PTR(L1D_HW_pf_local_mem_hit),
	SPARC_M7_EVENT_PTR(L1D_HW_pf_remote_hit),
	SPARC_M7_EVENT_PTR(L1D_SW_pf_L3_hit),
	SPARC_M7_EVENT_PTR(L1D_SW_pf_L3_drop),
	SPARC_M7_EVENT_PTR(L1D_SW_pf_nbr_hit),
	SPARC_M7_EVENT_PTR(L1D_SW_pf_local_mem_hit),
	SPARC_M7_EVENT_PTR(L1D_SW_pf_remote_hit),
	SPARC_M7_EVENT_PTR(St_L2_hit),
	SPARC_M7_EVENT_PTR(St_L3_hit),
	SPARC_M7_EVENT_PTR(St_nbr_scc_hit),
	SPARC_M7_EVENT_PTR(St_remote_scc_hit),
	SPARC_M7_EVENT_PTR(St_local_mem_hit),
	SPARC_M7_EVENT_PTR(St_remote_mem_hit),
	SPARC_M7_EVENT_PTR(DC_hit),
	SPARC_M7_EVENT_PTR(DC_miss_L2_hit),
	SPARC_M7_EVENT_PTR(DC_miss_L3_hit),
	SPARC_M7_EVENT_PTR(DC_miss_nbr_L2_hit),
	SPARC_M7_EVENT_PTR(DC_miss_nbr_scc_hit),
	SPARC_M7_EVENT_PTR(DC_miss_nbr_scc_miss),
	SPARC_M7_EVENT_PTR(DC_miss),
	SPARC_M7_EVENT_PTR(DC_miss_L2_miss),
	SPARC_M7_EVENT_PTR(DC_miss_L3_miss),
	SPARC_M7_EVENT_PTR(DC_miss_remote_scc_hit),
	SPARC_M7_EVENT_PTR(DC_miss_local_mem_hit),
	SPARC_M7_EVENT_PTR(DC_miss_remote_mem_hit),
	SPARC_M7_EVENT_PTR(Br_dir_mispred),
	SPARC_M7_EVENT_PTR(Br_tgt_mispred_far_tbl),
	SPARC_M7_EVENT_PTR(Br_tgt_mispred_indir_tbl),
	SPARC_M7_EVENT_PTR(Br_tgt_mispred_ret_stk),
	SPARC_M7_EVENT_PTR(Br_tgt_mispred),
	SPARC_M7_EVENT_PTR(Br_mispred),
	SPARC_M7_EVENT_PTR(Cycles_user),
	SPARC_M7_EVENT_PTR(Flush_L3_miss),
	SPARC_M7_EVENT_PTR(Flush_br_mispred),
	SPARC_M7_EVENT_PTR(Flush_arch_exception),
	SPARC_M7_EVENT_PTR(Flush_evil_twin),
	SPARC_M7_EVENT_PTR(Flush_LSU_trap),
	SPARC_M7_EVENT_PTR(Flush_other),
	SPARC_M7_EVENT_PTR(Commit_0_cyc),
	SPARC_M7_EVENT_PTR(Commit_0_all_cyc),
	SPARC_M7_EVENT_PTR(Commit_1_cyc),
	SPARC_M7_EVENT_PTR(Commit_2_cyc),
	SPARC_M7_EVENT_PTR(Commit_1_or_2_cyc),
	SPARC_M7_EVENT_PTR(L2D_SW_pf_total),
	SPARC_M7_EVENT_PTR(L2D_SW_pf_L1_drop_MB_full),
	SPARC_M7_EVENT_PTR(L2D_SW_pf_L1_hit),
	SPARC_M7_EVENT_PTR(L2D_SW_pf_L2_hit),
	SPARC_M7_EVENT_PTR(L2D_SW_pf_L2_drop),
	SPARC_M7_EVENT_PTR(L2D_clean_eviction),
	SPARC_M7_EVENT_PTR(L2D_dirty_eviction),
	SPARC_M7_EVENT_PTR(L2D_RQB_full),
	SPARC_M7_EVENT_PTR(L2D_MB_fail_replay),
	SPARC_M7_EVENT_PTR(L2D_MB_full),
	SPARC_M7_EVENT_PTR(L2D_pipeline_stall),
	SPARC_M7_EVENT_PTR(L2D_SW_pf_L3_hit),
	SPARC_M7_EVENT_PTR(L2D_SW_pf_L3_drop),
	SPARC_M7_EVENT_PTR(L2D_SW_pf_nbr_hit),
	SPARC_M7_EVENT_PTR(L2D_SW_pf_local_mem_hit),
	SPARC_M7_EVENT_PTR(L2D_SW_pf_remote_hit),
	NULL,
};

#endif /* __SPARC_M7_PMU_EVENTS_H */
