/*
 * QLogic Fibre Channel HBA Driver
 * Copyright (c)  2003-2012 QLogic Corporation
 *
 * See LICENSE.qla2xxx for copyright and licensing details.
 */
#ifndef __QLA_MR_H
#define __QLA_MR_H

/*
 * The PCI VendorID and DeviceID for our board.
 */
#define PCI_DEVICE_ID_QLOGIC_ISPF001		0xF001

/* FX00 specific definitions */

#define FX00_COMMAND_TYPE_7	0x07	/* Command Type 7 entry for 7XXX */
typedef struct cmd_type_7_fx00 {
	uint8_t entry_type;		/* Entry type. */
	uint8_t entry_count;		/* Entry count. */
	uint8_t sys_define;		/* System defined. */
	uint8_t entry_status;		/* Entry Status. */

	uint32_t handle;		/* System handle. */
	uint8_t reserved_0;
	uint8_t port_path_ctrl;
	uint16_t reserved_1;

	__le16 tgt_idx;		/* Target Idx. */
	__le16 timeout;		/* Command timeout. */
#define FW_MAX_TIMEOUT		0x1999

	__le16 dseg_count;		/* Data segment count. */
	uint8_t scsi_rsp_dsd_len;
	uint8_t reserved_2;

	struct scsi_lun lun;		/* LUN (LE). */

	uint8_t cntrl_flags;
#define TMF_NOT_MSG_ENABLE_FX00		BIT_3
#define TMF_DSD_LIST_ENABLE_FX00	BIT_2
#define TMF_READ_DATA_FX00		BIT_1
#define TMF_WRITE_DATA_FX00		BIT_0

	uint8_t task_mgmt_flags;	/* Task management flags. */
#define TMF_CLEAR_ACA_FX00		BIT_6
#define TMF_TARGET_RESET_FX00		BIT_5
#define TMF_LUN_RESET_FX00		BIT_4
#define TMF_CLEAR_TASK_SET_FX00		BIT_2
#define TMF_ABORT_TASK_SET_FX00		BIT_1

	uint8_t task;
#define TSK_SIMPLE		0
#define TSK_HEAD_OF_QUEUE	1
#define TSK_ORDERED		2
#define TSK_ACA			4
#define TSK_UNTAGGED		5

	uint8_t crn;

	uint8_t fcp_cdb[MAX_CMDSZ];	/* SCSI command words. */
	__le32 byte_count;		/* Total byte count. */

	__le32 dseg_0_address[2];	/* Data segment 0 address. */
	__le32 dseg_0_len;		/* Data segment 0 length. */
} cmd_type_7_fx00_t;

#define	STATUS_TYPE_FX00	0x01		/* Status entry. */
struct sts_entry_fx00 {
	uint8_t entry_type;		/* Entry type. */
	uint8_t entry_count;		/* Entry count. */
	uint8_t sys_define;		/* System defined. */
	uint8_t entry_status;		/* Entry Status. */

	uint32_t handle;		/* System handle. */
	uint32_t reserved_3;		/* System handle. */

	__le16 comp_status;		/* Completion status. */
	uint16_t reserved_0;			/* OX_ID used by the firmware. */

	__le32 residual_len;		/* FW calc residual transfer length. */

	uint16_t reserved_1;
	__le16 state_flags;		/* State flags. */

#define SF_TRANSFERRED_DATA	BIT_11
#define SF_FCP_RSP_DMA		BIT_0

	uint16_t reserved_2;
	__le16 scsi_status;		/* SCSI status. */
#define SS_CONFIRMATION_REQ		BIT_12

	__le32 sense_len;		/* FCP SENSE length. */
	uint8_t data[32];		/* FCP response/sense information. */
};


#define MAX_HANDLE_COUNT	15
#define MULTI_STATUS_TYPE_FX00	0x0D

struct multi_sts_entry_fx00 {
	uint8_t entry_type;		/* Entry type. */
	uint8_t entry_count;		/* Entry count. */
	uint8_t handle_count;
	uint8_t entry_status;

	uint32_t handles[MAX_HANDLE_COUNT];
};

#define TSK_MGMT_IOCB_TYPE_FX00		0x05
struct tsk_mgmt_entry_fx00 {
	uint8_t entry_type;		/* Entry type. */
	uint8_t entry_count;		/* Entry count. */
	uint8_t sys_define;
	uint8_t entry_status;		/* Entry Status. */

	uint32_t handle;		/* System handle. */

	uint32_t reserved_0;		/* System handle. */

	__le16 tgt_id;		/* Target Idx. */

	uint16_t reserved_1;
	uint16_t reserved_3;
	uint16_t reserved_4;

	struct scsi_lun lun;		/* LUN (LE). */

	__le32 control_flags;		/* Control Flags. */
#define TCF_NOTMCMD_TO_TARGET	BIT_31
#define TCF_LUN_RESET		BIT_4
#define TCF_ABORT_TASK_SET	BIT_3
#define TCF_CLEAR_TASK_SET	BIT_2
#define TCF_TARGET_RESET	BIT_1
#define TCF_CLEAR_ACA		BIT_0

	uint8_t reserved_2[32];
};


#define	ABORT_IOCB_TYPE_FX00	0x08		/* Abort IOCB status. */
typedef struct abort_iocb_entry_fx00 {
	uint8_t entry_type;		/* Entry type. */
	uint8_t entry_count;		/* Entry count. */
	uint8_t sys_define;		/* System defined. */
	uint8_t entry_status;		/* Entry Status. */

	uint32_t handle;		/* System handle. */
	uint32_t reserved_0;

	__le16 tgt_id_sts;		/* Completion status. */
	__le16 options;

	uint32_t abort_handle;		/* System handle. */
	uint32_t reserved_2;

	__le16 req_que_no;
	uint8_t reserved_1[38];
} abort_iocb_entry_fx00_t;

#define IOCTL_IOSB_TYPE_FX00	0x0C
typedef struct ioctl_iocb_entry_fx00 {
	uint8_t entry_type;		/* Entry type. */
	uint8_t entry_count;		/* Entry count. */
	uint8_t sys_define;		/* System defined. */
	uint8_t entry_status;		/* Entry Status. */

	uint32_t handle;		/* System handle. */
	uint32_t reserved_0;		/* System handle. */

	__le16 comp_func_num;
	__le16 fw_iotcl_flags;

	__le32 dataword_r;		/* Data word returned */
	__le64 adapid;		/* Adapter ID */
	__le32 dataword_r_extra;

	__le32 seq_no;
	uint8_t reserved_2[20];
	__le32 residuallen;
	__le32 status;
} __packed ioctl_iocb_entry_fx00_t;

#define STATUS_CONT_TYPE_FX00 0x04

#define FX00_IOCB_TYPE		0x0B
typedef struct fxdisc_entry_fx00 {
	uint8_t entry_type;		/* Entry type. */
	uint8_t entry_count;		/* Entry count. */
	uint8_t sys_define;		/* System Defined. */
	uint8_t entry_status;		/* Entry Status. */

	uint32_t handle;		/* System handle. */
	uint32_t reserved_0;		/* System handle. */

	__le16 func_num;
	__le16 req_xfrcnt;
	__le16 req_dsdcnt;
	__le16 rsp_xfrcnt;
	__le16 rsp_dsdcnt;
	uint8_t flags;
	uint8_t reserved_1;

	__le32 dseg_rq_address[2];	/* Data segment 0 address. */
	__le32 dseg_rq_len;		/* Data segment 0 length. */
	__le32 dseg_rsp_address[2];	/* Data segment 1 address. */
	__le32 dseg_rsp_len;		/* Data segment 1 length. */

	__le32 dataword;
	__le64 adapid;
	__le32 dataword_extra;
} __packed fxdisc_entry_fx00_t;

struct qlafx00_tgt_node_info {
	uint8_t tgt_node_wwpn[WWN_SIZE];
	uint8_t tgt_node_wwnn[WWN_SIZE];
	__le32 tgt_node_state;
	uint8_t reserved[128];
	uint32_t reserved_1[8];
	uint64_t reserved_2[4];
} __packed;
typedef struct qlafx00_tgt_node_info qlafx00_tgt_node_info_t;

#define QLAFX00_TGT_NODE_INFO sizeof(struct qlafx00_tgt_node_info)

#define QLAFX00_LINK_STATUS_DOWN	0x10
#define QLAFX00_LINK_STATUS_UP		0x11

#define QLAFX00_PORT_SPEED_2G	0x2
#define QLAFX00_PORT_SPEED_4G	0x4
#define QLAFX00_PORT_SPEED_8G	0x8
#define QLAFX00_PORT_SPEED_10G	0xa
struct port_info_data {
	uint8_t         port_state;
	uint8_t         port_type;
	__le16          port_identifier;
	__le32          up_port_state;
	uint8_t         fw_ver_num[32];
	uint8_t         portal_attrib;
	__le16          host_option;
	uint8_t         reset_delay;
	uint8_t         pdwn_retry_cnt;
	__le16          max_luns2tgt;
	uint8_t         risc_ver;
	uint8_t         pconn_option;
	__le16          risc_option;
	__le16          max_frame_len;
	__le16          max_iocb_alloc;
	__le16          exec_throttle;
	uint8_t         retry_cnt;
	uint8_t         retry_delay;
	uint8_t         port_name[8];
	uint8_t         port_id[3];
	uint8_t         link_status;
	uint8_t         plink_rate;
	__le32          link_config;
	__le16          adap_haddr;
	uint8_t         tgt_disc;
	uint8_t         log_tout;
	uint8_t         node_name[8];
	__le16          erisc_opt1;
	uint8_t         resp_acc_tmr;
	uint8_t         intr_del_tmr;
	uint8_t         erisc_opt2;
	uint8_t         alt_port_name[8];
	uint8_t         alt_node_name[8];
	uint8_t         link_down_tout;
	uint8_t         conn_type;
	uint8_t         fc_fw_mode;
	uint32_t        uiReserved[48];
} __packed;
typedef struct port_info_data port_info_data_t;

/* OS Type Designations */
#define OS_TYPE_UNKNOWN             0
#define OS_TYPE_LINUX               2

/* Linux Info */
#define SYSNAME_LENGTH              128
#define NODENAME_LENGTH             64
#define RELEASE_LENGTH              64
#define VERSION_LENGTH              64
#define MACHINE_LENGTH              64
#define DOMNAME_LENGTH              64
#define SYSINFO_LENGTH              128
#define HOSTNAME_LENGTH             64

struct host_system_info {
	__le32  os_type;
	char    sysname[SYSNAME_LENGTH];
	char    nodename[NODENAME_LENGTH];
	char    release[RELEASE_LENGTH];
	char    version[VERSION_LENGTH];
	char    machine[MACHINE_LENGTH];
	char    domainname[DOMNAME_LENGTH];
	char    hostdriver[VERSION_LENGTH];
	uint32_t reserved[64];
} __packed;
typedef struct host_system_info host_system_info_t;

struct register_host_info {
	struct host_system_info     hsi;	/* host system info */
	__le64          utc;			/* UTC (system time) */
	uint32_t        reserved[64];		/* future additions */
} __packed;


#define QLAFX00_PORT_DATA_INFO (sizeof(port_info_data_t))
#define QLAFX00_TGT_NODE_LIST_SIZE (sizeof(uint32_t) * 32)

struct config_info_data {
	uint8_t		model_num[16];
	uint8_t		model_desciption[80];
	uint8_t		reserved0[160];
	uint8_t		symbolic_name[64];
	uint8_t		serial_num[32];
	uint8_t		hw_version[16];
	uint8_t		fw_version[16];
	uint8_t		uboot_version[16];
	uint8_t		fru_serial_num[32];

	uint8_t		fc_port_count;
	uint8_t		iscsi_port_count;
	uint8_t		reserved1[2];

	uint8_t		mode;
	uint8_t		log_level;
	uint8_t		reserved2[2];

	__le32		log_size;

	uint8_t		tgt_pres_mode;
	uint8_t		iqn_flags;
	uint8_t		lun_mapping;

	__le64		adapter_id;

	__le32		cluster_key_len;
	uint8_t		cluster_key[16];

	__le64		cluster_master_id;
	__le64		cluster_slave_id;
	uint8_t		cluster_flags;
	__le32		enabled_capabilities;
	__le32		nominal_temp_value;
} __packed;
typedef struct config_info_data config_info_data_t;

#define QLAFX00_MAX_ADAPTERS		10
#define FXDISC_GET_CONFIG_INFO		0x01
#define FXDISC_GET_PORT_INFO		0x02
#define FXDISC_GET_TGT_NODE_INFO	0x80
#define FXDISC_GET_TGT_NODE_LIST	0x81
#define FXDISC_REG_HOST_INFO		0x99
#define FXDISC_ABORT_IOCTL		0xff

#define QLAFX00_HBA_ICNTRL_REG		0x20B08
#define QLAFX00_ICR_ENB_MASK            0x80000000
#define QLAFX00_ICR_DIS_MASK            0x7fffffff
#define QLAFX00_HST_RST_REG		0x18264
#define QLAFX00_SOC_TEMP_REG		0x184C4
#define QLAFX00_HST_TO_HBA_REG		0x20A04
#define QLAFX00_HBA_TO_HOST_REG		0x21B70
#define QLAFX00_FUNC_TYPE_FC		0x0
#define QLAFX00_HST_INT_STS_BITS	0x7
#define QLAFX00_BAR1_BASE_ADDR_REG	0x40018
#define QLAFX00_PEX0_WIN0_BASE_ADDR_REG	0x41824

/* BIT0 - MB completion
 * BIT1 - Response Q completion
 * BIT2 - Async
 */
#define QLAFX00_INTR_MB_CMPLT		0x1
#define QLAFX00_INTR_RSP_CMPLT		0x2
#define QLAFX00_INTR_ASYNC_CMPLT	0x4

#define QLAFX00_MBA_SYSTEM_ERR		0x8002
#define QLAFX00_MBA_TEMP_OVER		0x8005
#define QLAFX00_MBA_TEMP_NORM		0x8006
#define QLAFX00_MBA_TEMP_CRIT		0x8007
#define QLAFX00_MBA_LINK_UP		0x8011
#define QLAFX00_MBA_LINK_DOWN		0x8012
#define QLAFX00_MBA_PORT_UPDATE		0x8014
#define QLAFX00_MBA_FW_NOT_STARTED	0x8050
#define QLAFX00_MBA_FW_STARTING		0x8051
#define QLAFX00_MBA_FW_RESTART_COMPL	0x8060
#define QLAFX00_MBA_INIT_RQRD		0x8061
#define QLAFX00_MBA_SHUTDOWN_RQSTD	0x8062
#define QLAFX00_MBA_FW_INIT_FAILURE	0x8401
#define QLAFX00_MBA_MIR_LUN_SCN_NOTIF	0x8402

#define SOC_SW_RST_CONTROL_REG_CORE0     0x0020800
#define SOC_FABRIC_RST_CONTROL_REG       0x0020840
#define SOC_FABRIC_CONTROL_REG           0x0020200
#define SOC_FABRIC_CONFIG_REG            0x0020204
#define SOC_CLOCK_GATING_CONTROL         0x0018220
#define SOC_PWR_MANAGEMENT_PWR_DOWN_REG  0x001820C

#define SOC_INTERRUPT_SOURCE_I_CONTROL_REG     0x0020B00
#define SOC_CORE_TIMER_REG                     0x0021850
#define SOC_IRQ_ACK_REG                        0x00218b4

/* No target Id. */
#define RMP_INVALID_TGT_ID		0xffff

#define CONTINUE_A64_TYPE_FX00	0x03	/* Continuation entry. */

#define QLAFX00_SET_HST_INTR(ha, value) \
	WRT_REG_DWORD((ha)->cregbase + QLAFX00_HST_TO_HBA_REG, \
	value)

#define QLAFX00_CLR_HST_INTR(ha, value) \
	WRT_REG_DWORD((ha)->cregbase + QLAFX00_HBA_TO_HOST_REG, \
	~value)

#define QLAFX00_RD_INTR_REG(ha) \
	RD_REG_DWORD((ha)->cregbase + QLAFX00_HBA_TO_HOST_REG)

#define QLAFX00_CLR_INTR_REG(ha, value) \
	WRT_REG_DWORD((ha)->cregbase + QLAFX00_HBA_TO_HOST_REG, \
	~value)

#define QLAFX00_SET_HBA_SOC_REG(ha, off, val)\
	WRT_REG_DWORD((ha)->cregbase + off, val)

#define QLAFX00_GET_HBA_SOC_REG(ha, off)\
	RD_REG_DWORD((ha)->cregbase + off)

#define QLAFX00_HBA_RST_REG(ha, val)\
	WRT_REG_DWORD((ha)->cregbase + QLAFX00_HST_RST_REG, val)

#define QLAFX00_RD_ICNTRL_REG(ha) \
	RD_REG_DWORD((ha)->cregbase + QLAFX00_HBA_ICNTRL_REG)

#define QLAFX00_ENABLE_ICNTRL_REG(ha) \
	WRT_REG_DWORD((ha)->cregbase + QLAFX00_HBA_ICNTRL_REG, \
	(QLAFX00_GET_HBA_SOC_REG(ha, QLAFX00_HBA_ICNTRL_REG) | \
	 QLAFX00_ICR_ENB_MASK))

#define QLAFX00_DISABLE_ICNTRL_REG(ha) \
	WRT_REG_DWORD((ha)->cregbase + QLAFX00_HBA_ICNTRL_REG, \
	(QLAFX00_GET_HBA_SOC_REG(ha, QLAFX00_HBA_ICNTRL_REG) & \
	 QLAFX00_ICR_DIS_MASK))

#define QLAFX00_RD_REG(ha, off) \
	RD_REG_DWORD((ha)->cregbase + off)

#define QLAFX00_WR_REG(ha, off, val) \
	WRT_REG_DWORD((ha)->cregbase + off, val)

typedef struct qla_mt_iocb_rqst_fx00 {
	uint32_t reserved_0;

	uint16_t func_type;
	uint8_t flags;
	uint8_t reserved_1;

	uint32_t dataword;

	uint64_t adapid;

	uint32_t dataword_extra;

	uint16_t req_len;
	uint16_t reserved_2;

	uint16_t rsp_len;
	uint16_t reserved_3;
} __packed qla_mt_iocb_rqst_fx00_t;

typedef struct qla_mt_iocb_rsp_fx00 {
	uint32_t reserved_1;

	uint16_t func_type;
	uint16_t ioctl_flags;

	uint32_t ioctl_data;

	uint64_t adapid;

	uint32_t reserved_2;
	uint32_t seq_number;

	uint8_t reserved_3[20];

	int32_t res_count;

	uint32_t status;
} __packed qla_mt_iocb_rsp_fx00_t;


#define MAILBOX_REGISTER_COUNT_FX00	16
#define AEN_MAILBOX_REGISTER_COUNT_FX00	8
#define MAX_FIBRE_DEVICES_FX00	512
#define	MAX_DEVICES_FX00	512
#define MAX_LUNS_FX00		0x1024 /** @todo - seems incorrect, check */
#define MAX_TARGETS_FX00	MAX_ISA_DEVICES
#define REQUEST_ENTRY_CNT_FX00		512	/* Number of request entries. */
#define RESPONSE_ENTRY_CNT_FX00		256	/* Number of response entries.*/

/*
 * Firmware state codes for QLAFX00 adapters
 */
#define FSTATE_FX00_CONFIG_WAIT     0x0000	/* Waiting for driver to issue
						 * Initialize FW Mbox cmd
						 */
#define FSTATE_FX00_PCIE_WAIT       0x0007	/* PCIe EndPoint driver is waiting
						 * for BridgeApp IO_READY
						 */
#define FSTATE_FX00_INITIALIZED     0x1000	/* FW has been initialized by the
						 * driver
						 */

#define FX00_DEF_RATOV	10

#define FX00_BSG_DMA_POOL_SIZE (32 * 1024)

struct mr_data_fx00 {
	uint8_t	symbolic_name[64];
	uint8_t	serial_num[32];
	uint8_t	hw_version[16];
	uint8_t	fw_version[16];
	uint8_t	uboot_version[16];
	uint8_t	fru_serial_num[32];
	fc_port_t       fcport;		/* fcport used for Mt. Rainier
					 * request that are not linked
					 * to a particular target
					 */
	uint8_t fw_hbt_en;
	uint8_t fw_hbt_cnt;
	uint8_t fw_hbt_miss_cnt;
	uint32_t old_fw_hbt_cnt;
	uint16_t fw_reset_timer_tick;
	uint8_t fw_reset_timer_exp;
	uint16_t fw_critemp_timer_tick;
	uint32_t old_aenmbx0_state;
	uint32_t critical_temperature;
	bool extended_io_enabled;
	bool host_info_resend;
	uint8_t hinfo_resend_timer_tick;
};

#define QLAFX00_EXTENDED_IO_EN_MASK    0x20

/*
 * SoC Junction Temperature is stored in
 * bits 9:1 of SoC Junction Temperature Register
 * in a firmware specific format format.
 * To get the temperature in Celsius degrees
 * the value from this bitfiled should be converted
 * using this formula:
 * Temperature (degrees C) = ((3,153,000 - (10,000 * X)) / 13,825)
 * where X is the bit field value
 * this macro reads the register, extracts the bitfield value,
 * performs the calcualtions and returns temperature in Celsius
 */
#define QLAFX00_GET_TEMPERATURE(ha) ((3153000 - (10000 * \
        ((QLAFX00_RD_REG(ha, QLAFX00_SOC_TEMP_REG) & 0x3FE) >> 1))) / 13825)

#define QLAFX00_LOOP_DOWN_TIME		615     /* 600 */
#define QLAFX00_HEARTBEAT_INTERVAL	6	/* number of seconds */
#define QLAFX00_HEARTBEAT_MISS_CNT	3	/* number of miss */
#define QLAFX00_RESET_INTERVAL		120	/* number of seconds */
#define QLAFX00_MAX_RESET_INTERVAL	600	/* number of seconds */
#define QLAFX00_CRITEMP_INTERVAL	60      /* number of seconds */
#define QLAFX00_HINFO_RESEND_INTERVAL	60	/* number of seconds */

#define QLAFX00_CRITEMP_THRSHLD		80	/* Celsius degress */

#define qla_for_each_bit(bit, addr, size) \
	for ((bit) = find_first_bit((addr), (size)); \
	    (bit) < (size); \
		(bit) = find_next_bit((addr), (size), (bit) + 1))

/* Max conncurrent IOs that can be queued*/
#define QLAFX00_MAX_CANQUEUE		1024

/* IOCTL IOCB abort success */
#define QLAFX00_IOCTL_ICOB_ABORT_SUCCESS	0x68

#endif
