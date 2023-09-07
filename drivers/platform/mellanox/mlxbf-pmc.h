// SPDX-License-Identifier: GPL-2.0 or BSD-3-Clause

#ifndef __MLXBF_PMC_H__
#define __MLXBF_PMC_H__

#define MLNX_WRITE_REG_32		(0x82000009)
#define MLNX_READ_REG_32		(0x8200000A)
#define MLNX_WRITE_REG_64		(0x8200000B)
#define MLNX_READ_REG_64		(0x8200000C)
#define MLNX_SIP_SVC_UID		(0x8200ff01)
#define MLNX_SIP_SVC_VERSION		(0x8200ff03)

#define SMCCC_INVALID_PARAMETERS	(-2)
#define SMCCC_OUT_OF_RANGE		(-3)
#define SMCCC_ACCESS_VIOLATION		(-4)

#define MLNX_EVENT_SET_BF1	0
#define MLNX_EVENT_SET_BF2	1

#define MLNX_PMC_SVC_REQ_MAJOR 0
#define MLNX_PMC_SVC_MIN_MINOR 3

#define MLXBF_PMC_MAX_BLOCKS		30

/**
 * Structure to hold info for each HW block
 *
 * @mmio_base: The VA at which the PMC block is mapped
 * @blk_size: Size of each mapped region
 * @counters: Number of counters in the block
 * @type: Type of counters in the block
 * @block_dir: Kobjects to create sub-directories
 * @attr_counter: Attributes for "counter" sysfs files
 * @attr_event: Attributes for "event" sysfs files
 * @attr_event_list: Attributes for "event_list" sysfs files
 * @attr_enable: Attributes for "enable" sysfs files
 * @sysfs_event_cnt: Number of sysfs event files in the block
 */
struct mlxbf_pmc_block_info {
	void *mmio_base;
	size_t blk_size;
	size_t counters;
	int type;
	struct kobject *block_dir;
	struct kobj_attribute *attr_counter;
	struct kobj_attribute *attr_event;
	struct kobj_attribute attr_event_list;
	struct kobj_attribute attr_enable;
	int sysfs_event_cnt;
};

/**
 * Structure to hold PMC context info
 *
 * @pdev: The kernel structure representing the device
 * @total_blocks: Total number of blocks
 * @tile_count: Number of tiles in the system
 * @hwmon_dev: Hwmon device for bfperf
 * @ko: Kobject for bfperf
 * @block_name: Block name
 * @block_name:  Block info
 * @sv_sreg_support: Whether SMCs are used to access performance registers
 * @sreg_tbl_perf: Secure register access table number
 * @event_set: Event set to use
 */
struct mlxbf_pmc_context {
	struct platform_device *pdev;
	uint32_t total_blocks;
	uint32_t tile_count;
	struct device *hwmon_dev;
	struct kobject *ko;
	const char *block_name[MLXBF_PMC_MAX_BLOCKS];
	struct mlxbf_pmc_block_info block[MLXBF_PMC_MAX_BLOCKS];
	bool svc_sreg_support;
	uint32_t sreg_tbl_perf;
	unsigned int event_set;
};

#define MLXBF_PERFTYPE_COUNTER	1
#define MLXBF_PERFTYPE_REGISTER	0

#define MLXBF_PERFCTL 0
#define MLXBF_PERFEVT 1
#define MLXBF_PERFVALEXT 2
#define MLXBF_PERFACC0 4
#define MLXBF_PERFACC1 5
#define MLXBF_PERFMVAL0 6
#define MLXBF_PERFMVAL1 7

#define MLXBF_GEN_PERFMON_CONFIG__WR_R_B	BIT(0)
#define MLXBF_GEN_PERFMON_CONFIG__STROBE	BIT(1)
#define MLXBF_GEN_PERFMON_CONFIG__ADDR		GENMASK_ULL(4, 2)
#define MLXBF_GEN_PERFMON_CONFIG__WDATA		GENMASK_ULL(60, 5)

#define MLXBF_GEN_PERFCTL__FM1			GENMASK_ULL(2, 0)
#define MLXBF_GEN_PERFCTL__MS1			GENMASK_ULL(5, 4)
#define MLXBF_GEN_PERFCTL__ACCM1		GENMASK_ULL(10, 8)
#define MLXBF_GEN_PERFCTL__AD1			BIT(11)
#define MLXBF_GEN_PERFCTL__ETRIG1		GENMASK_ULL(13, 12)
#define MLXBF_GEN_PERFCTL__EB1			BIT(14)
#define MLXBF_GEN_PERFCTL__EN1			BIT(15)
#define MLXBF_GEN_PERFCTL__FM0			GENMASK_ULL(18, 16)
#define MLXBF_GEN_PERFCTL__MS0			GENMASK_ULL(21, 20)
#define MLXBF_GEN_PERFCTL__ACCM0		GENMASK_ULL(26, 24)
#define MLXBF_GEN_PERFCTL__AD0			BIT(27)
#define MLXBF_GEN_PERFCTL__ETRIG0		GENMASK_ULL(29, 28)
#define MLXBF_GEN_PERFCTL__EB0			BIT(30)
#define MLXBF_GEN_PERFCTL__EN0			BIT(31)

#define MLXBF_GEN_PERFEVT__PVALSEL		GENMASK_ULL(19, 16)
#define MLXBF_GEN_PERFEVT__MODSEL		GENMASK_ULL(23, 20)
#define MLXBF_GEN_PERFEVT__EVTSEL		GENMASK_ULL(31, 24)

#define MLXBF_L3C_PERF_CNT_CFG			0x0
#define MLXBF_L3C_PERF_CNT_CFG_1		0x4
#define MLXBF_L3C_PERF_CNT_CFG_2		0x8
#define MLXBF_L3C_PERF_CNT_SEL			0x10
#define MLXBF_L3C_PERF_CNT_SEL_1		0x14
#define MLXBF_L3C_PERF_CNT_LOW			0x40
#define MLXBF_L3C_PERF_CNT_HIGH			0x60

#define MLXBF_L3C_PERF_CNT_CFG__EN		BIT(0)
#define MLXBF_L3C_PERF_CNT_CFG__RST		BIT(1)
#define MLXBF_L3C_PERF_CNT_CFG__SRCID_SEL	GENMASK(14, 8)
#define MLXBF_L3C_PERF_CNT_CFG__SRCID_MASK	GENMASK(22, 16)
#define MLXBF_L3C_PERF_CNT_CFG__PRF_SEL		GENMASK(27, 24)
#define MLXBF_L3C_PERF_CNT_CFG__PRF_MASK	GENMASK(31, 28)

#define MLXBF_L3C_PERF_CNT_CFG_1__SET_SEL	GENMASK(10,0)
#define MLXBF_L3C_PERF_CNT_CFG_1__SET_MASK	GENMASK(22,12)
#define MLXBF_L3C_PERF_CNT_CFG_1__EMEM_USAGE_TH	GENMASK(30, 24)

#define MLXBF_L3C_PERF_CNT_CFG_2__STRM_SEL	GENMASK(7, 0)
#define MLXBF_L3C_PERF_CNT_CFG_2__STRM_MASK	GENMASK(15, 8)

#define MLXBF_L3C_PERF_CNT_SEL__CNT_0		GENMASK(5, 0)
#define MLXBF_L3C_PERF_CNT_SEL__CNT_1		GENMASK(13, 8)
#define MLXBF_L3C_PERF_CNT_SEL__CNT_2		GENMASK(21, 16)
#define MLXBF_L3C_PERF_CNT_SEL__CNT_3		GENMASK(29, 24)

#define MLXBF_L3C_PERF_CNT_SEL_1__CNT_4		GENMASK(5, 0)

#define MLXBF_L3C_PERF_CNT_LOW__VAL		GENMASK(31, 0)
#define MLXBF_L3C_PERF_CNT_HIGH__VAL		GENMASK(24, 0)

struct mlxbf_pmc_events {
	uint32_t evt_num;
	char *evt_name;
};

struct mlxbf_pmc_events mlxbf_pcie_events[] = {
{0x0,  "IN_P_PKT_CNT"},
{0x10, "IN_NP_PKT_CNT"},
{0x18, "IN_C_PKT_CNT"},
{0x20, "OUT_P_PKT_CNT"},
{0x28, "OUT_NP_PKT_CNT"},
{0x30, "OUT_C_PKT_CNT"},
{0x38, "IN_P_BYTE_CNT"},
{0x40, "IN_NP_BYTE_CNT"},
{0x48, "IN_C_BYTE_CNT"},
{0x50, "OUT_P_BYTE_CNT"},
{0x58, "OUT_NP_BYTE_CNT"},
{0x60, "OUT_C_BYTE_CNT"},
{-1, NULL}
};

struct mlxbf_pmc_events mlxbf_smgen_events[] = {
{0x0,  "AW_REQ"},
{0x1,  "AW_BEATS"},
{0x2,  "AW_TRANS"},
{0x3,  "AW_RESP"},
{0x4,  "AW_STL"},
{0x5,  "AW_LAT"},
{0x6,  "AW_REQ_TBU"},
{0x8,  "AR_REQ"},
{0x9,  "AR_BEATS"},
{0xa,  "AR_TRANS"},
{0xb,  "AR_STL"},
{0xc,  "AR_LAT"},
{0xd,  "AR_REQ_TBU"},
{0xe,  "TBU_MISS"},
{0xf,  "TX_DAT_AF"},
{0x10, "RX_DAT_AF"},
{0x11, "RETRYQ_CRED"},
{-1, NULL}
};

struct mlxbf_pmc_events mlxbf1_trio_events[] = {
{0x00, "DISABLE"},
{0xa0, "TPIO_DATA_BEAT"},
{0xa1, "TDMA_DATA_BEAT"},
{0xa2, "MAP_DATA_BEAT"},
{0xa3, "TXMSG_DATA_BEAT"},
{0xa4, "TPIO_DATA_PACKET"},
{0xa5, "TDMA_DATA_PACKET"},
{0xa6, "MAP_DATA_PACKET"},
{0xa7, "TXMSG_DATA_PACKET"},
{0xa8, "TDMA_RT_AF"},
{0xa9, "TDMA_PBUF_MAC_AF"},
{0xaa, "TRIO_MAP_WRQ_BUF_EMPTY"},
{0xab, "TRIO_MAP_CPL_BUF_EMPTY"},
{0xac, "TRIO_MAP_RDQ0_BUF_EMPTY"},
{0xad, "TRIO_MAP_RDQ1_BUF_EMPTY"},
{0xae, "TRIO_MAP_RDQ2_BUF_EMPTY"},
{0xaf, "TRIO_MAP_RDQ3_BUF_EMPTY"},
{0xb0, "TRIO_MAP_RDQ4_BUF_EMPTY"},
{0xb1, "TRIO_MAP_RDQ5_BUF_EMPTY"},
{0xb2, "TRIO_MAP_RDQ6_BUF_EMPTY"},
{0xb3, "TRIO_MAP_RDQ7_BUF_EMPTY"},
{-1, NULL}
};

struct mlxbf_pmc_events mlxbf2_trio_events[] = {
{0x00, "DISABLE"},
{0xa0, "TPIO_DATA_BEAT"},
{0xa1, "TDMA_DATA_BEAT"},
{0xa2, "MAP_DATA_BEAT"},
{0xa3, "TXMSG_DATA_BEAT"},
{0xa4, "TPIO_DATA_PACKET"},
{0xa5, "TDMA_DATA_PACKET"},
{0xa6, "MAP_DATA_PACKET"},
{0xa7, "TXMSG_DATA_PACKET"},
{0xa8, "TDMA_RT_AF"},
{0xa9, "TDMA_PBUF_MAC_AF"},
{0xaa, "TRIO_MAP_WRQ_BUF_EMPTY"},
{0xab, "TRIO_MAP_CPL_BUF_EMPTY"},
{0xac, "TRIO_MAP_RDQ0_BUF_EMPTY"},
{0xad, "TRIO_MAP_RDQ1_BUF_EMPTY"},
{0xae, "TRIO_MAP_RDQ2_BUF_EMPTY"},
{0xaf, "TRIO_MAP_RDQ3_BUF_EMPTY"},
{0xb0, "TRIO_MAP_RDQ4_BUF_EMPTY"},
{0xb1, "TRIO_MAP_RDQ5_BUF_EMPTY"},
{0xb2, "TRIO_MAP_RDQ6_BUF_EMPTY"},
{0xb3, "TRIO_MAP_RDQ7_BUF_EMPTY"},
{0xb4, "TRIO_RING_TX_FLIT_CH0"},
{0xb5, "TRIO_RING_TX_FLIT_CH1"},
{0xb6, "TRIO_RING_TX_FLIT_CH2"},
{0xb7, "TRIO_RING_TX_FLIT_CH3"},
{0xb8, "TRIO_RING_TX_FLIT_CH4"},
{0xb9, "TRIO_RING_RX_FLIT_CH0"},
{0xba, "TRIO_RING_RX_FLIT_CH1"},
{0xbb, "TRIO_RING_RX_FLIT_CH2"},
{0xbc, "TRIO_RING_RX_FLIT_CH3"},
{-1, NULL}
};

struct mlxbf_pmc_events mlxbf_ecc_events[] = {
{0x00, "DISABLE"},
{0x100, "ECC_SINGLE_ERROR_CNT"},
{0x104, "ECC_DOUBLE_ERROR_CNT"},
{0x114, "SERR_INJ"},
{0x118, "DERR_INJ"},
{0x124, "ECC_SINGLE_ERROR_0"},
{0x164, "ECC_DOUBLE_ERROR_0"},
{0x340, "DRAM_ECC_COUNT"},
{0x344, "DRAM_ECC_INJECT"},
{0x348, "DRAM_ECC_ERROR",},
{-1, NULL}
};

struct mlxbf_pmc_events mlxbf_mss_events[] = {
{0x00, "DISABLE"},
{0xc0, "RXREQ_MSS"},
{0xc1, "RXDAT_MSS"},
{0xc2, "TXRSP_MSS"},
{0xc3, "TXDAT_MSS"},
{-1, NULL}
};

struct mlxbf_pmc_events mlxbf_hnf_events[] = {
{0x00, "DISABLE"},
{0x45, "HNF_REQUESTS"},
{0x46, "HNF_REJECTS"},
{0x47, "ALL_BUSY"},
{0x48, "MAF_BUSY"},
{0x49, "MAF_REQUESTS"},
{0x4a, "RNF_REQUESTS"},
{0x4b, "REQUEST_TYPE"},
{0x4c, "MEMORY_READS"},
{0x4d, "MEMORY_WRITES"},
{0x4e, "VICTIM_WRITE"},
{0x4f, "POC_FULL"},
{0x50, "POC_FAIL"},
{0x51, "POC_SUCCESS"},
{0x52, "POC_WRITES"},
{0x53, "POC_READS"},
{0x54, "FORWARD"},
{0x55, "RXREQ_HNF"},
{0x56, "RXRSP_HNF"},
{0x57, "RXDAT_HNF"},
{0x58, "TXREQ_HNF"},
{0x59, "TXRSP_HNF"},
{0x5a, "TXDAT_HNF"},
{0x5b, "TXSNP_HNF"},
{0x5c, "INDEX_MATCH"},
{0x5d, "A72_ACCESS"},
{0x5e, "IO_ACCESS"},
{0x5f, "TSO_WRITE"},
{0x60, "TSO_CONFLICT"},
{0x61, "DIR_HIT"},
{0x62, "HNF_ACCEPTS"},
{0x63, "REQ_BUF_EMPTY"},
{0x64, "REQ_BUF_IDLE_MAF"},
{0x65, "TSO_NOARB"},
{0x66, "TSO_NOARB_CYCLES"},
{0x67, "MSS_NO_CREDIT"},
{0x68, "TXDAT_NO_LCRD"},
{0x69, "TXSNP_NO_LCRD"},
{0x6a, "TXRSP_NO_LCRD"},
{0x6b, "TXREQ_NO_LCRD"},
{0x6c, "TSO_CL_MATCH"},
{0x6d, "MEMORY_READS_BYPASS"},
{0x6e, "TSO_NOARB_TIMEOUT"},
{0x6f, "ALLOCATE"},
{0x70, "VICTIM"},
{0x71, "A72_WRITE"},
{0x72, "A72_Read"},
{0x73, "IO_WRITE"},
{0x74, "IO_READ"},
{0x75, "TSO_REJECT"},
{0x80, "TXREQ_RN"},
{0x81, "TXRSP_RN"},
{0x82, "TXDAT_RN"},
{0x83, "RXSNP_RN"},
{0x84, "RXRSP_RN"},
{0x85, "RXDAT_RN"},
{-1, NULL}
};

struct mlxbf_pmc_events mlxbf2_hnfnet_events[] = {
{0x00, "DISABLE"},
{0x12, "CDN_REQ"},
{0x13, "DDN_REQ"},
{0x14, "NDN_REQ"},
{0x15, "CDN_DIAG_N_OUT_OF_CRED"},
{0x16, "CDN_DIAG_S_OUT_OF_CRED"},
{0x17, "CDN_DIAG_E_OUT_OF_CRED"},
{0x18, "CDN_DIAG_W_OUT_OF_CRED"},
{0x19, "CDN_DIAG_C_OUT_OF_CRED"},
{0x1a, "CDN_DIAG_N_EGRESS"},
{0x1b, "CDN_DIAG_S_EGRESS"},
{0x1c, "CDN_DIAG_E_EGRESS"},
{0x1d, "CDN_DIAG_W_EGRESS"},
{0x1e, "CDN_DIAG_C_EGRESS"},
{0x1f, "CDN_DIAG_N_INGRESS"},
{0x20, "CDN_DIAG_S_INGRESS"},
{0x21, "CDN_DIAG_E_INGRESS"},
{0x22, "CDN_DIAG_W_INGRESS"},
{0x23, "CDN_DIAG_C_INGRESS"},
{0x24, "CDN_DIAG_CORE_SENT"},
{0x25, "DDN_DIAG_N_OUT_OF_CRED"},
{0x26, "DDN_DIAG_S_OUT_OF_CRED"},
{0x27, "DDN_DIAG_E_OUT_OF_CRED"},
{0x28, "DDN_DIAG_W_OUT_OF_CRED"},
{0x29, "DDN_DIAG_C_OUT_OF_CRED"},
{0x2a, "DDN_DIAG_N_EGRESS"},
{0x2b, "DDN_DIAG_S_EGRESS"},
{0x2c, "DDN_DIAG_E_EGRESS"},
{0x2d, "DDN_DIAG_W_EGRESS"},
{0x2e, "DDN_DIAG_C_EGRESS"},
{0x2f, "DDN_DIAG_N_INGRESS"},
{0x30, "DDN_DIAG_S_INGRESS"},
{0x31, "DDN_DIAG_E_INGRESS"},
{0x32, "DDN_DIAG_W_INGRESS"},
{0x33, "DDN_DIAG_C_INGRESS"},
{0x34, "DDN_DIAG_CORE_SENT"},
{0x35, "NDN_DIAG_N_OUT_OF_CRED"},
{0x36, "NDN_DIAG_S_OUT_OF_CRED"},
{0x37, "NDN_DIAG_E_OUT_OF_CRED"},
{0x38, "NDN_DIAG_W_OUT_OF_CRED"},
{0x39, "NDN_DIAG_C_OUT_OF_CRED"},
{0x3a, "NDN_DIAG_N_EGRESS"},
{0x3b, "NDN_DIAG_S_EGRESS"},
{0x3c, "NDN_DIAG_E_EGRESS"},
{0x3d, "NDN_DIAG_W_EGRESS"},
{0x3e, "NDN_DIAG_C_EGRESS"},
{0x3f, "NDN_DIAG_N_INGRESS"},
{0x40, "NDN_DIAG_S_INGRESS"},
{0x41, "NDN_DIAG_E_INGRESS"},
{0x42, "NDN_DIAG_W_INGRESS"},
{0x43, "NDN_DIAG_C_INGRESS"},
{0x44, "NDN_DIAG_CORE_SENT"},
{-1, NULL}
};

struct mlxbf_pmc_events mlxbf_l3cache_events[] = {
{0x00, "DISABLE"},
{0x01, "CYCLES"},
{0x02, "TOTAL_RD_REQ_IN"},
{0x03, "TOTAL_WR_REQ_IN"},
{0x04, "TOTAL_WR_DBID_ACK"},
{0x05, "TOTAL_WR_DATA_IN"},
{0x06, "TOTAL_WR_COMP"},
{0x07, "TOTAL_RD_DATA_OUT"},
{0x08, "TOTAL_CDN_REQ_IN_BANK0"},
{0x09, "TOTAL_CDN_REQ_IN_BANK1"},
{0x0a, "TOTAL_DDN_REQ_IN_BANK0"},
{0x0b, "TOTAL_DDN_REQ_IN_BANK1"},
{0x0c, "TOTAL_EMEM_RD_RES_IN_BANK0"},
{0x0d, "TOTAL_EMEM_RD_RES_IN_BANK1"},
{0x0e, "TOTAL_CACHE_RD_RES_IN_BANK0"},
{0x0f, "TOTAL_CACHE_RD_RES_IN_BANK1"},
{0x10, "TOTAL_EMEM_RD_REQ_BANK0"},
{0x11, "TOTAL_EMEM_RD_REQ_BANK1"},
{0x12, "TOTAL_EMEM_WR_REQ_BANK0"},
{0x13, "TOTAL_EMEM_WR_REQ_BANK1"},
{0x14, "TOTAL_RD_REQ_OUT"},
{0x15, "TOTAL_WR_REQ_OUT"},
{0x16, "TOTAL_RD_RES_IN"},
{0x17, "HITS_BANK0"},
{0x18, "HITS_BANK1"},
{0x19, "MISSES_BANK0"},
{0x1a, "MISSES_BANK1"},
{0x1b, "ALLOCATIONS_BANK0"},
{0x1c, "ALLOCATIONS_BANK1"},
{0x1d, "EVICTIONS_BANK0"},
{0x1e, "EVICTIONS_BANK1"},
{0x1f, "DBID_REJECT"},
{0x20, "WRDB_REJECT_BANK0"},
{0x21, "WRDB_REJECT_BANK1"},
{0x22, "CMDQ_REJECT_BANK0"},
{0x23, "CMDQ_REJECT_BANK1"},
{0x24, "COB_REJECT_BANK0"},
{0x25, "COB_REJECT_BANK1"},
{0x26, "TRB_REJECT_BANK0"},
{0x27, "TRB_REJECT_BANK1"},
{0x28, "TAG_REJECT_BANK0"},
{0x29, "TAG_REJECT_BANK1"},
{0x2a, "ANY_REJECT_BANK0"},
{0x2b, "ANY_REJECT_BANK1"},
{-1, NULL}
};

#endif				/* __MLXBF_PMC_H__ */
