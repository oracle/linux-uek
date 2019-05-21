#ifndef IB_VERBS_EXP_H
#define IB_VERBS_EXP_H

#include <rdma/ib_verbs.h>

struct ib_exp_umr_caps {
	u32                max_reg_descriptors;
	u32                max_send_wqe_inline_klms;
	u32                max_umr_recursion_depth;
	u32                max_umr_stride_dimenson;
};

struct ib_exp_odp_caps {
	uint64_t	general_odp_caps;
	uint64_t	max_size;
	struct {
		uint32_t	rc_odp_caps;
		uint32_t	uc_odp_caps;
		uint32_t	ud_odp_caps;
		uint32_t	dc_odp_caps;
		uint32_t	xrc_odp_caps;
		uint32_t	raw_eth_odp_caps;
	} per_transport_caps;
};

enum ib_cq_cap_flags {
	IB_CQ_IGNORE_OVERRUN           = (1 << 0)
};

struct ib_cq_attr {
	struct {
		u16     cq_count;
		u16     cq_period;
	} moderation;
	u32     cq_cap_flags;
};

struct ib_qpg_init_attrib {
	u32 tss_child_count;
	u32 rss_child_count;
};

enum ib_wq_vlan_offloads {
	IB_WQ_CVLAN_STRIPPING	= (1 << 0),
	IB_WQ_CVLAN_INSERTION	= (1 << 1),
};

enum ib_mp_rq_shifts {
	IB_MP_RQ_NO_SHIFT	= 0,
	IB_MP_RQ_2BYTES_SHIFT	= 1 << 0
};

/*
 * RX Hash Function flags.
*/
enum ib_rx_hash_function_flags {
	IB_EXP_RX_HASH_FUNC_TOEPLITZ	= 1 << 0,
	IB_EXP_RX_HASH_FUNC_XOR		= 1 << 1
};

/*
 * RX Hash flags, these flags allows to set which incoming packet field should
 * participates in RX Hash. Each flag represent certain packet's field,
 * when the flag is set the field that is represented by the flag will
 * participate in RX Hash calculation.
 * Notice: *IPV4 and *IPV6 flags can't be enabled together on the same QP
 * and *TCP and *UDP flags can't be enabled together on the same QP.
*/
enum ib_rx_hash_fields {
	IB_RX_HASH_SRC_IPV4		= 1 << 0,
	IB_RX_HASH_DST_IPV4		= 1 << 1,
	IB_RX_HASH_SRC_IPV6		= 1 << 2,
	IB_RX_HASH_DST_IPV6		= 1 << 3,
	IB_RX_HASH_SRC_PORT_TCP	= 1 << 4,
	IB_RX_HASH_DST_PORT_TCP	= 1 << 5,
	IB_RX_HASH_SRC_PORT_UDP	= 1 << 6,
	IB_RX_HASH_DST_PORT_UDP	= 1 << 7,
	IB_RX_HASH_INNER	= (1ULL << 31),
};

struct ib_rx_hash_conf {
	enum ib_rx_hash_function_flags rx_hash_function;
	u8 rx_key_len; /* valid only for Toeplitz */
	u8 *rx_hash_key;
	uint64_t rx_hash_fields_mask; /* enum ib_rx_hash_fields */
	struct ib_rwq_ind_table *rwq_ind_tbl;
};

enum ib_exp_mp_rq_sup_types {
	IB_EXP_MP_RQ_SUP_TYPE_SRQ_TM	= 1 << 0,
	/*
	 * For backport compatibility we use IB_EXP_QPT_RAW_PACKET value for the
	 * IB_EXP_MP_SUP_TYPE_WQ_RQ.
	 */
	IB_EXP_MP_RQ_SUP_TYPE_WQ_RQ	= 1 << 5,
};

struct ib_exp_mp_rq_caps {
	uint32_t supported_qps; /* use ib_exp_mp_rq_sup_types */
	uint32_t allowed_shifts; /* use ib_mp_rq_shifts */
	uint8_t min_single_wqe_log_num_of_strides;
	uint8_t max_single_wqe_log_num_of_strides;
	uint8_t min_single_stride_log_num_of_bytes;
	uint8_t max_single_stride_log_num_of_bytes;
};

struct ib_exp_masked_atomic_caps {
	u32 max_fa_bit_boudary;
	u32 log_max_atomic_inline_arg;
	u64 masked_log_atomic_arg_sizes;
	u64 masked_log_atomic_arg_sizes_network_endianness;
};

enum ib_exp_device_attr_comp_mask {
	IB_EXP_DEVICE_ATTR_WITH_TIMESTAMP_MASK = 1ULL << 1,
	IB_EXP_DEVICE_ATTR_WITH_HCA_CORE_CLOCK = 1ULL << 2,
	IB_EXP_DEVICE_ATTR_CAP_FLAGS2		= 1ULL << 3,
	IB_EXP_DEVICE_ATTR_DC_REQ_RD		= 1ULL << 4,
	IB_EXP_DEVICE_ATTR_DC_RES_RD		= 1ULL << 5,
	IB_EXP_DEVICE_ATTR_INLINE_RECV_SZ	= 1ULL << 6,
	IB_EXP_DEVICE_ATTR_RSS_TBL_SZ		= 1ULL << 7,
	IB_EXP_DEVICE_ATTR_EXT_ATOMIC_ARGS	= 1ULL << 8,
	IB_EXP_DEVICE_ATTR_UMR                  = 1ULL << 9,
	IB_EXP_DEVICE_ATTR_ODP			= 1ULL << 10,
	IB_EXP_DEVICE_ATTR_MAX_DCT		= 1ULL << 11,
	IB_EXP_DEVICE_ATTR_MAX_CTX_RES_DOMAIN	= 1ULL << 12,
	IB_EXP_DEVICE_ATTR_RX_HASH		= 1ULL << 13,
	IB_EXP_DEVICE_ATTR_MAX_WQ_TYPE_RQ	= 1ULL << 14,
	IB_EXP_DEVICE_ATTR_MAX_DEVICE_CTX	= 1ULL << 15,
	IB_EXP_DEVICE_ATTR_MP_RQ		= 1ULL << 16,
	IB_EXP_DEVICE_ATTR_EC_CAPS		= 1ULL << 18,
	IB_EXP_DEVICE_ATTR_VLAN_OFFLOADS	= 1ULL << 17,
	IB_EXP_DEVICE_ATTR_EXT_MASKED_ATOMICS	= 1ULL << 19,
	IB_EXP_DEVICE_ATTR_RX_PAD_END_ALIGN	= 1ULL << 20,
	IB_EXP_DEVICE_ATTR_TSO_CAPS		= 1ULL << 21,
	IB_EXP_DEVICE_ATTR_PACKET_PACING_CAPS	= 1ULL << 22,
	IB_EXP_DEVICE_ATTR_OOO_CAPS		= 1ULL << 24,
	IB_EXP_DEVICE_ATTR_SW_PARSING_CAPS	= 1ULL << 25,
	IB_EXP_DEVICE_ATTR_ODP_MAX_SIZE		= 1ULL << 26,
	IB_EXP_DEVICE_ATTR_TM_CAPS		= 1ULL << 27,
	IB_EXP_DEVICE_ATTR_TUNNEL_OFFLOADS_CAPS	= 1ULL << 28,
	IB_EXP_DEVICE_ATTR_MAX_DM_SIZE		= 1ULL << 29,
	IB_EXP_DEVICE_ATTR_TUNNELED_ATOMIC	= 1ULL << 30,
	IB_EXP_DEVICE_ATTR_COMP_MASK_2		= 1ULL << 31,
};

enum ib_exp_device_attr_comp_mask_2 {
	IB_EXP_DEVICE_ATTR_UMR_FIXED_SIZE_CAPS  = 1ULL << 0,
	IB_EXP_DEVICE_ATTR_PCI_ATOMIC_CAPS	= 1ULL << 1,
};

enum ib_exp_device_cap_flags2 {
	IB_EXP_DEVICE_DC_TRANSPORT	= 1 << 0,
	IB_EXP_DEVICE_QPG		= 1 << 1,
	IB_EXP_DEVICE_UD_RSS		= 1 << 2,
	IB_EXP_DEVICE_UD_TSS		= 1 << 3,
	IB_EXP_DEVICE_EXT_ATOMICS	= 1 << 4,
	IB_EXP_DEVICE_NOP		= 1 << 5,
	IB_EXP_DEVICE_UMR		= 1 << 6,
	IB_EXP_DEVICE_ODP               = 1 << 7,
	IB_EXP_DEVICE_VXLAN_SUPPORT		= 1 << 10,
	IB_EXP_DEVICE_RX_CSUM_TCP_UDP_PKT	= 1 << 11,
	IB_EXP_DEVICE_RX_CSUM_IP_PKT		= 1 << 12,
	IB_EXP_DEVICE_EC_OFFLOAD		= 1 << 13,
	IB_EXP_DEVICE_EXT_MASKED_ATOMICS	= 1 << 14,
	IB_EXP_DEVICE_RX_TCP_UDP_PKT_TYPE       = 1 << 15,
	IB_EXP_DEVICE_SCATTER_FCS               = 1 << 16,
	IB_EXP_DEVICE_DELAY_DROP                = 1 << 18,
	IB_EXP_DEVICE_PHYSICAL_RANGE_MR		= 1 << 19,
	IB_EXP_DEVICE_CAPI			= 1 << 20,
	IB_EXP_DEVICE_UMR_FIXED_SIZE		= 1 << 25,
	IB_EXP_DEVICE_PACKET_BASED_CREDIT_MODE	= 1 << 26,
	IB_EXP_DEVICE_CROSS_CHANNEL	= 1 << 28, /* Comapt with user exp area */
	IB_EXP_DEVICE_MASK =	IB_DEVICE_CROSS_CHANNEL |
				IB_EXP_DEVICE_EC_OFFLOAD,
};

enum ib_exp_supported_qp_types {
	IB_EXP_QPT_RAW_PACKET	= 1ULL << 5,
};

struct ib_exp_rx_hash_caps {
	uint32_t max_rwq_indirection_tables;
	uint32_t max_rwq_indirection_table_size;
	uint8_t  supported_hash_functions; /* from ib_rx_hash_function_flags */
	uint64_t supported_packet_fields;	/* from ib_rx_hash_fields */
	uint32_t supported_qps;  /* from ib_exp_supported_qp_types */
};

struct ib_exp_tso_caps {
	__u32 max_tso; /* Maximum tso payload size in bytes */

	/* Corresponding bit will be set if qp type from
	 * 'enum ib_qp_type' is supported, e.g.
	 * supported_qpts |= 1 << IB_QPT_RAW_PACKET
	 */
	__u32 supported_qpts;
};

enum ib_exp_packet_pacing_cap_flags {
	IB_EXP_QP_SUPPORT_BURST               = 1 << 0,
};

struct ib_exp_packet_pacing_caps {
	__u32 qp_rate_limit_min;
	__u32 qp_rate_limit_max; /* In kpbs */

	/* Corresponding bit will be set if qp type from
	 * 'enum ib_qp_type' is supported, e.g.
	 * supported_qpts |= 1 << IB_QPT_RAW_PACKET
	 */
	__u32 supported_qpts;
	__u8  cap_flags; /* ib_exp_packet_pacing_cap_flags */
	__u8  reserved[3];
};

struct ib_exp_ec_caps {
	uint32_t	max_ec_data_vector_count;
	uint32_t	max_ec_calc_inflight_calcs;
};

enum ib_exp_ooo_flags {
	/*
	 * Device should set IB_EXP_DEVICE_OOO_RW_DATA_PLACEMENT
	 * capability, when it supports handling RDMA reads and writes
	 * received out of order.
	 */
	IB_EXP_DEVICE_OOO_RW_DATA_PLACEMENT	= (1 << 0),
};

struct ib_exp_ooo_caps {
	u32 rc_caps;
	u32 xrc_caps;
	u32 dc_caps;
	u32 ud_caps;
};

enum ib_exp_tunnel_offloads_caps {
	IBV_EXP_RAW_PACKET_CAP_TUNNELED_OFFLOAD_VXLAN  = 1 << 0,
	IBV_EXP_RAW_PACKET_CAP_TUNNELED_OFFLOAD_GRE    = 1 << 1,
	IBV_EXP_RAW_PACKET_CAP_TUNNELED_OFFLOAD_GENEVE = 1 << 2
};

enum ib_exp_tunneled_atomic_caps {
	IB_EXP_TUNNELED_ATOMIC_SUPPORTED	= 1 << 0,
};

enum ib_exp_sw_parsing_offloads {
	IB_RAW_PACKET_QP_SW_PARSING	 = (1 << 0),
	IB_RAW_PACKET_QP_SW_PARSING_CSUM = (1 << 1),
	IB_RAW_PACKET_QP_SW_PARSING_LSO	 = (1 << 2),
};

struct ib_exp_sw_parsing_caps {
	u32 sw_parsing_offloads;
	u32 supported_qpts;
};

struct ib_exp_context_attr {
	u64	peer_id;
	u8     *peer_name;
	u32	comp_mask;
};

struct ib_exp_tm_caps {
	/* Max size of RNDV header */
	u32 max_rndv_hdr_size;
	/* Max number of entries in a tag matching list */
	u32 max_num_tags;
	/* TM capabilities mask - from enum ib_exp_tm_cap_flags */
	u32 capability_flags;
	/* Max number of outstanding list operations */
	u32 max_ops;
	/* Max number of SGQ in a tag matching entry */
	u32 max_sge;
};

struct ib_exp_umr_fixed_size_caps {
	u64 max_entity_size;
};

struct ib_exp_pci_atomic_caps {
	u16 fetch_add;
	u16 swap;
	u16 compare_swap;
};

struct ib_exp_device_attr {
	struct ib_device_attr	base;
	/* Use IB_EXP_DEVICE_ATTR_... for exp_comp_mask */
	uint32_t		exp_comp_mask;
	uint64_t		device_cap_flags2;
	u32			dc_rd_req;
	u32			dc_rd_res;
	uint32_t		inline_recv_sz;
	u32			max_dct;
	uint32_t		max_rss_tbl_sz;
	/*
	  * This field is a bit mask for the supported atomic argument sizes.
	  * A bit set signifies an argument of size of 2 ^ bit_nubmer bytes is
	  * supported.
	  */
	u64                     atomic_arg_sizes;
	u32                     max_fa_bit_boudary;
	u32                     log_max_atomic_inline_arg;
	struct ib_exp_umr_caps  umr_caps;
	struct ib_exp_odp_caps	odp_caps;
	uint32_t		max_ctx_res_domain;
	struct ib_exp_masked_atomic_caps masked_atomic_caps;
	uint32_t		max_device_ctx;
	struct ib_exp_rx_hash_caps	rx_hash_caps;
	uint32_t			max_wq_type_rq;
	struct ib_exp_mp_rq_caps	mp_rq_caps;
	u16				vlan_offloads;
	/*
	 * This field is a bit mask for the supported Galois field
	 * bits GF(2^w) for Erasure coding. E.g. if ec_w_mask = 0x8B
	 * then w=1, w=2, w=4 and w=8 are supported.
	 */
	u32				ec_w_mask;
	struct ib_exp_ec_caps		ec_caps;
	/*
	 * The alignment of the padding end address.
	 * Which means that when RX end of packet padding is enabled the device
	 * will padd the end of RX packet up until the next address which is
	 * aligned to the rx_pad_end_addr_align size.
	 */
	u16				rx_pad_end_addr_align;
	struct ib_exp_tso_caps		tso_caps;
	struct ib_exp_packet_pacing_caps packet_pacing_caps;
	struct ib_exp_ooo_caps		ooo_caps;
	struct ib_exp_sw_parsing_caps	sw_parsing_caps;
	struct ib_exp_tm_caps		tm_caps;
	u32				tunnel_offloads_caps; /* ib_exp_tunnel_offloads_caps */
	u64			max_dm_size;
	u32				tunneled_atomic_caps; /* ib_exp_tunneled_atomic_caps */
	u64				exp_comp_mask_2;         /* ib_exp_device_attr_comp_mask_2 */
	struct ib_exp_umr_fixed_size_caps umr_fixed_size_caps;
	struct ib_exp_pci_atomic_caps pci_atomic_caps;
};

enum ib_dct_create_flags {
	IB_EXP_DCT_OOO_RW_DATA_PLACEMENT	= 1 << 0,
	IB_DCT_CREATE_FLAGS_MASK		=
				IB_EXP_DCT_OOO_RW_DATA_PLACEMENT,
};

struct ib_dct_init_attr {
	struct ib_pd	       *pd;
	struct ib_cq	       *cq;
	struct ib_srq	       *srq;
	u64			dc_key;
	u8			port;
	u32			access_flags;
	u8			min_rnr_timer;
	u8			tclass;
	u32			flow_label;
	enum ib_mtu		mtu;
	u8			pkey_index;
	u8			gid_index;
	u8			hop_limit;
	u32			create_flags;
	u32			inline_size;
	void		      (*event_handler)(struct ib_event *, void *);
	void		       *dct_context;
};

struct ib_dct_attr {
	u64			dc_key;
	u8			port;
	u32			access_flags;
	u8			min_rnr_timer;
	u8			tclass;
	u32			flow_label;
	enum ib_mtu		mtu;
	u8			pkey_index;
	u8			gid_index;
	u8			hop_limit;
	u32			key_violations;
	u8			state;
};

struct ib_dct {
	struct ib_device       *device;
	struct ib_uobject      *uobject;
	struct ib_pd	       *pd;
	struct ib_cq	       *cq;
	struct ib_srq	       *srq;
	void		      (*event_handler)(struct ib_event *, void *);
	void		       *dct_context;
	u32			dct_num;
};

/**
 * struct ib_mkey_attr - Memory key attributes
 *
 * @max_reg_descriptors: how many mrs we can we register with this mkey
 */
struct ib_mkey_attr {
	u32 max_reg_descriptors;
};

/**
 * ib_exp_modify_cq - Modifies the attributes for the specified CQ and then
 *   transitions the CQ to the given state.
 * @cq: The CQ to modify.
 * @cq_attr: specifies the CQ attributes to modify.
 * @cq_attr_mask: A bit-mask used to specify which attributes of the CQ
 *   are being modified.
 */
int ib_exp_modify_cq(struct ib_cq *cq,
		     struct ib_cq_attr *cq_attr,
		     int cq_attr_mask);
int ib_exp_query_device(struct ib_device *device,
			struct ib_exp_device_attr *device_attr,
			struct ib_udata *uhw);

struct ib_dct *ib_exp_create_dct(struct ib_pd *pd,
				 struct ib_dct_init_attr *attr,
				 struct ib_udata *udata);
int ib_exp_destroy_dct(struct ib_dct *dct);
int ib_exp_query_dct(struct ib_dct *dct, struct ib_dct_attr *attr);

int ib_exp_query_mkey(struct ib_mr *mr, u64 mkey_attr_mask,
		  struct ib_mkey_attr *mkey_attr);
/* NVMEoF target offload EXP API */
struct ib_nvmf_ctrl {
	struct ib_srq	*srq;
	u32		id;
	atomic_t	usecnt; /* count all attached namespaces */
	void		(*event_handler)(struct ib_event *, void *);
	void		*be_context;
};

struct ib_nvmf_backend_ctrl_init_attr {
	void		(*event_handler)(struct ib_event *, void *);
	void		*be_context;
	u32		cq_page_offset;
	u32		sq_page_offset;
	u8		cq_log_page_size;
	u8		sq_log_page_size;
	u16		initial_cqh_db_value;
	u16		initial_sqt_db_value;
	u32		cmd_timeout_us;
	u64		cqh_dbr_addr;
	u64		sqt_dbr_addr;
	u64		cq_pas;
	u64		sq_pas;
};

struct ib_nvmf_ns {
	struct ib_nvmf_ctrl	*ctrl;
	u32			nsid;
};

struct ib_nvmf_ns_init_attr {
	u32		frontend_namespace;
	u32		backend_namespace;
	u16		lba_data_size;
	u16		backend_ctrl_id;
};

struct ib_nvmf_ns_attr {
	u64	num_read_cmd;
	u64	num_read_blocks;
	u64	num_write_cmd;
	u64	num_write_blocks;
	u64	num_write_inline_cmd;
	u64	num_flush_cmd;
	u64	num_error_cmd;
	u64	num_backend_error_cmd;
};

int ib_query_nvmf_ns(struct ib_nvmf_ns *ns, struct ib_nvmf_ns_attr *ns_attr);
struct ib_nvmf_ctrl *ib_create_nvmf_backend_ctrl(struct ib_srq *srq,
		struct ib_nvmf_backend_ctrl_init_attr *init_attr);
int ib_destroy_nvmf_backend_ctrl(struct ib_nvmf_ctrl *ctrl);
struct ib_nvmf_ns *ib_attach_nvmf_ns(struct ib_nvmf_ctrl *ctrl,
			struct ib_nvmf_ns_init_attr *init_attr);
int ib_detach_nvmf_ns(struct ib_nvmf_ns *ns);
struct ib_dm *ib_exp_alloc_dm(struct ib_device *device, u64 length);
int ib_exp_free_dm(struct ib_dm *dm);
//int ib_exp_memcpy_dm(struct ib_dm *dm, struct ib_exp_memcpy_dm_attr *attr);
struct ib_mr *ib_exp_alloc_mr(struct ib_pd *pd, struct ib_mr_init_attr *attr);
int ib_exp_invalidate_range(struct ib_device  *device, struct ib_mr *ibmr,
			    u64 start, u64 length, u32 flags);
#endif
