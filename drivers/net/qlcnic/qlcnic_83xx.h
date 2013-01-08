#ifndef __QLCNIC_83XX_H
#define __QLCNIC_83XX_H

#include <linux/types.h>
#include <linux/etherdevice.h>
#include "qlcnic_hw.h"

/* Directly mapped registers */
#define QLC_83XX_CRB_WIN_BASE		0x3800
#define QLC_83XX_CRB_WIN_FUNC(f)	(QLC_83XX_CRB_WIN_BASE+((f)*4))
#define QLC_83XX_SEM_LOCK_BASE		0x3840
#define QLC_83XX_SEM_UNLOCK_BASE	0x3844
#define QLC_83XX_SEM_LOCK_FUNC(f)	(QLC_83XX_SEM_LOCK_BASE+((f)*8))
#define QLC_83XX_SEM_UNLOCK_FUNC(f)	(QLC_83XX_SEM_UNLOCK_BASE+((f)*8))
#define QLC_83XX_LINK_STATE(f)		(0x3698+((f) > 7 ? 4:0))
#define QLC_83XX_LINK_SPEED(f)		(0x36E0+(((f) >> 2) * 4))
#define QLC_83XX_LINK_SPEED_FACTOR	10
#define QLC_83xx_FUNC_VAL(v, f)	((v) & (1 << (f * 4)))
#define QLCNIC_83XX_INTX_PTR		0x38C0
#define QLCNIC_83XX_INTX_TRGR		0x38C4
#define QLCNIC_83XX_INTX_MASK		0x38C8

/* Indirectly mapped registers */
#define QLC_83XX_FLASH_SPI_STATUS	0x2808E010
#define QLC_83XX_FLASH_SPI_CONTROL	0x2808E014
#define QLC_83XX_FLASH_STATUS		0x42100004
#define QLC_83XX_FLASH_CONTROL		0x42110004
#define QLC_83XX_FLASH_ADDR		0x42110008
#define QLC_83XX_FLASH_WRDATA		0x4211000C
#define QLC_83XX_FLASH_RDDATA		0x42110018
#define QLC_83XX_FLASH_DIRECT_WINDOW		0x42110030
#define QLC_83XX_FLASH_DIRECT_DATA(DATA)	(0x42150000 | (0x0000FFFF&DATA))

#define QLC_83XX_FLASH_SECTOR_ERASE_CMD		0xdeadbeef
#define QLC_83XX_FLASH_WRITE_CMD		0xdacdacda
#define QLC_83XX_FLASH_BULK_WRITE_CMD		0xcadcadca
#define QLC_83XX_FLASH_READ_RETRY_COUNT		5000
#define QLC_83XX_FLASH_STATUS_READY		0x6
#define	QLC_83XX_FLASH_BULK_WRITE_MIN		2
#define	QLC_83XX_FLASH_BULK_WRITE_MAX		64
#define QLC_83XX_FLASH_STATUS_REG_POLL_DELAY	1
#define QLC_83XX_ERASE_MODE			1
#define QLC_83XX_WRITE_MODE			2
#define QLC_83XX_BULK_WRITE_MODE		3

/* Peg PC status registers */
#define QLC_83XX_CRB_PEG_NET_0		0x3400003c
#define QLC_83XX_CRB_PEG_NET_1		0x3410003c
#define QLC_83XX_CRB_PEG_NET_2		0x3420003c
#define QLC_83XX_CRB_PEG_NET_3		0x3430003c
#define QLC_83XX_CRB_PEG_NET_4		0x34b0003c

/* QLCNIC_CMD_CONFIG_MAC_VLAN [0x45] error codes */
#define QLCNIC_NO_CARD_RESOURCE		0x5
#define QLCNIC_MAC_ALREADY_EXISTS	0xC
#define QLCNIC_MAC_DOES_NOT_EXIST	0xD

/* Pause control registers */
#define QLC_83XX_SRE_SHIM_REG		0x0D200284
#define QLC_83XX_PORT0_THRESHOLD	0x0B2003A4
#define QLC_83XX_PORT1_THRESHOLD	0x0B2013A4
#define QLC_83XX_PORT0_TC_MC_REG	0x0B200388
#define QLC_83XX_PORT1_TC_MC_REG	0x0B201388
#define QLC_83XX_PORT0_TC_STATS		0x0B20039C
#define QLC_83XX_PORT1_TC_STATS		0x0B20139C
#define QLC_83XX_PORT2_IFB_THRESHOLD	0x0B200704
#define QLC_83XX_PORT3_IFB_THRESHOLD	0x0B201704

/* Flash Operations Misc Signatures*/
#define QLC_83XX_FLASH_FDT_WRITE_DEF_SIG	0xFD0100
#define QLC_83XX_FLASH_FDT_ERASE_DEF_SIG	0xFD0300
#define QLC_83XX_FLASH_FDT_READ_MFG_ID_VAL	0xFD009F

#define QLC_83XX_FLASH_OEM_ERASE_SIG		0xFD03D8
#define QLC_83XX_FLASH_OEM_WRITE_SIG		0xFD0101
#define QLC_83XX_FLASH_OEM_READ_SIG		0xFD0005

#define QLC_83XX_FLASH_ADDR_TEMP_VAL		0x00800000
#define QLC_83XX_FLASH_ADDR_SECOND_TEMP_VAL	0x00800001

#define QLC_83XX_FLASH_WRDATA_DEF_VAL		0x0
#define QLC_83XX_FLASH_READ_CONTROL_VAL		0x3F
#define QLC_83XX_FLASH_SPI_CONTROL_VAL		0x4

#define QLC_83XX_FLASH_FIRST_ERASE_MS_VAL	0x2
#define QLC_83XX_FLASH_SECOND_ERASE_MS_VAL	0x5
#define QLC_83XX_FLASH_LAST_ERASE_MS_VAL	0x3D

#define QLC_83XX_FLASH_FIRST_WRITE_MS_PATTERN	0x43
#define QLC_83XX_FLASH_SECOND_WRITE_MS_PATTERN	0x7F
#define QLC_83XX_FLASH_LAST_WRITE_MS_PATTERN	0x7D

/* FLASH API defines */
#define QLC_83xx_FLASH_MAX_WAIT_USEC	100
#define QLC_83XX_FLASH_LOCK_TIMEOUT	10000
#define QLC_83XX_DRV_LOCK_WAIT_COUNTER	100
#define QLC_83XX_DRV_LOCK_WAIT_DELAY	20
#define QLC_83XX_NEED_DRV_LOCK_RECOVERY	1
#define QLC_83XX_DRV_LOCK_RECOVERY_IN_PROGRESS	2
#define QLC_83XX_MAX_DRV_LOCK_RECOVERY_ATTEMPT	3
#define QLC_83XX_DRV_LOCK_RECOVERY_DELAY	200
#define QLC_83XX_DRV_LOCK_RECOVERY_STATUS_MASK	0x3

#define QLC_83XX_FLASH_SECTOR_SIZE	(64 * 1024)


/* PEG status definitions */
#define QLC_83xx_CMDPEG_COMPLETE        0xff01

/* Firmware image definitions */
#define QLC_83XX_BOOTLOADER_FLASH_ADDR 0x10000
#define QLC_83XX_FW_FILE_NAME		"83xx_fw.bin"

#define QLC_83XX_BOOT_FROM_FLASH	0
#define QLC_83XX_BOOT_FROM_FILE		0x12345678

/* Reset template definitions */
#define QLC_83XX_MAX_RESET_SEQ_ENTRIES	16
#define QLC_83XX_RESTART_TEMPLATE_SIZE	0x2000
#define QLC_83XX_RESET_TEMPLATE_ADDR	0x4F0000
#define QLC_83XX_RESET_SEQ_VERSION	0x0101

#define OPCODE_NOP			0x0000
#define OPCODE_WRITE_LIST		0x0001
#define OPCODE_READ_WRITE_LIST		0x0002
#define OPCODE_POLL_LIST		0x0004
#define OPCODE_POLL_WRITE_LIST		0x0008
#define OPCODE_READ_MODIFY_WRITE	0x0010
#define OPCODE_SEQ_PAUSE		0x0020
#define OPCODE_SEQ_END			0x0040
#define OPCODE_TMPL_END		0x0080
#define OPCODE_POLL_READ_LIST		0x0100

#define qlcnic_83xx_pktln(sts)	\
	((sts >> 32) & 0x3FFF)
#define qlcnic_83xx_hndl(sts)  \
	((sts >> 48) & 0x7FFF)
#define qlcnic_83xx_csum_status(sts)	\
	((sts >> 39) & 7)
#define qlcnic_83xx_opcode(sts)	\
	((sts >> 42) & 0xF)
#define qlcnic_83xx_vlan_tag(sts)	\
	(((sts) >> 48) & 0xFFFF)
#define qlcnic_83xx_lro_pktln(sts)	\
	(((sts) >> 32) & 0xFFFF)
#define qlcnic_83xx_l2_hdr_off(sts)	\
	(((sts) >> 16) & 0xFF)
#define qlcnic_83xx_l4_hdr_off(sts)	\
	(((sts) >> 24) & 0xFF)
#define qlcnic_83xx_pkt_cnt(sts)	\
	(((sts) >> 16) & 0x7)
#define qlcnic_83xx_get_lro_sts_mss(sts) \
	((sts) & 0xFFFFFFFF)

#define qlcnic_83xx_is_tstamp(sts)	\
	(((sts) >> 40) & 1)
#define qlcnic_83xx_is_psh_bit(sts)	\
	(((sts) >> 41) & 1)
#define qlcnic_83xx_is_ip_align(sts)	\
	(((sts) >> 46) & 1)
#define qlcnic_83xx_has_vlan_tag(sts)	\
	(((sts) >> 47) & 1)

#define QLCNIC_83XX_VALID_INTX_BIT30(val)\
	((val) & BIT_30)
#define QLCNIC_83XX_VALID_INTX_BIT31(val)\
	((val) & BIT_31)
#define QLCNIC_83XX_INTX_FUNC(val)	\
	((val) & 0xFF)

#define QLC_83XX_LEGACY_INTX_DELAY	4

#define QLCNIC_83XX_REG_DESC	1
#define QLCNIC_83XX_LRO_DESC	2
#define QLCNIC_83XX_CTRL_DESC	3

#define QLCNIC_FW_83XX_CAPABILITY_TSO	BIT_6
#define QLCNIC_FW_83XX_CAP_LRO_MSS	BIT_17

#define QLCNIC_HOST_83XX_RDS_MODE_UNIQUE 0
#define QLCNIC_HOST_SDS_MBX_IDX	8
/* status descriptor mailbox data
 * @phy_addr: physical address of buffer
 * @sds_ring_size: buffer size
 * @intrpt_id: interrupt id
 * @intrpt_val: source of interrupt
 */
struct qlcnic_sds_mbx {
	__le64	phy_addr;
	u8	rsvd1[16];
	__le16	sds_ring_size;
	__le16	rsvd2[3];
	__le16	intrpt_id;
	u8	intrpt_val;
	u8	rsvd3[5];
} __packed;

#define QLCNIC_HOST_RDS_MBX_IDX	88
/* receive descriptor buffer data
 * phy_addr_reg: physical address of regular buffer
 * phy_addr_jmb: physical address of jumbo buffer
 * reg_ring_sz: size of regular buffer
 * reg_ring_len: no. of entries in regular buffer
 * jmb_ring_len: no. of entries in jumbo buffer
 * jmb_ring_sz: size of jumbo buffer
 */
struct qlcnic_rds_mbx {
	__le64	phy_addr_reg;
	__le64	phy_addr_jmb;
	__le16	reg_ring_sz;
	__le16	reg_ring_len;
	__le16	jmb_ring_sz;
	__le16	jmb_ring_len;
} __packed;

/* host producers for regular and jumbo rings */
struct __host_producer_mbx {
	__le32	reg_buf;
	__le32	jmb_buf;
} __packed;

#define QLCNIC_MAX_RING_SETS	8
/* Receive context mailbox data outbox registers
 * @state: state of the context
 * @vport_id: virtual port id
 * @context_id: receive context id
 * @num_pci_func: number of pci functions of the port
 * @phy_port: physical port id
 */
struct qlcnic_rcv_mbx_out {
	u8	rcv_num;
	u8	sts_num;
	__le16	ctx_id;
	u8	state;
	u8	num_pci_func;
	u8	phy_port;
	u8	vport_id;
	__le32	host_csmr[QLCNIC_MAX_RING_SETS];
	struct __host_producer_mbx host_prod[QLCNIC_MAX_RING_SETS];
} __packed;

struct qlcnic_add_rings_mbx_out {
	u8      rcv_num;
	u8      sts_num;
	__le16  ctx_id;
	__le32  host_csmr[QLCNIC_MAX_RING_SETS];
	struct __host_producer_mbx host_prod[QLCNIC_MAX_RING_SETS];
} __packed;

/* Transmit context mailbox inbox registers
 * @phys_addr: DMA address of the transmit buffer
 * @cnsmr_index: host consumer index
 * @size: legth of transmit buffer ring
 * @intr_id: interrput id
 * @src: src of interrupt
 */
struct qlcnic_tx_mbx {
	__le64	phys_addr;
	__le64	cnsmr_index;
	__le16	size;
	__le16	intr_id;
	u8	src;
	u8	rsvd[3];
} __packed;

/* Transmit context mailbox outbox registers
 * @host_prod: host producer index
 * @ctx_id: transmit context id
 * @state: state of the transmit context
 */
struct qlcnic_tx_mbx_out {
	__le32	host_prod;
	__le16	ctx_id;
	u8	state;
	u8	rsvd;
} __packed;

struct qlcnic_intrpt_config {
	u8	type;
	u8	enabled;
	u16	id;
	u32	src;
};

struct qlcnic_macvlan_mbx {
	u8	mac[ETH_ALEN];
	__le16	vlan;
};

/* Template Header */
struct qlcnic_83xx_reset_template_hdr {
	__le16	version;
	__le16	signature;
	__le16	size;
	__le16	entries;
	__le16	hdr_size;
	__le16	checksum;
	__le16	init_seq_offset;
	__le16	start_seq_offset;
} __packed;

/* Common Entry Header. */
struct qlcnic_83xx_reset_entry_hdr {
	__le16 cmd;
	__le16 size;
	__le16 count;
	__le16 delay;
} __packed;

/* Generic poll entry type. */
struct qlcnic_83xx_poll {
	__le32	test_mask;
	__le32	test_value;
} __packed;

/* Read modify write entry type. */
struct qlcnic_83xx_rmw {
	__le32	test_mask;
	__le32	xor_value;
	__le32	or_value;
	u8	shl;
	u8	shr;
	u8	index_a;
	u8	rsvd;
} __packed;

/* Generic Entry Item with 2 DWords. */
struct qlcnic_83xx_entry {
	__le32 arg1;
	__le32 arg2;
} __packed;

/* Generic Entry Item with 4 DWords.*/
struct qlcnic_83xx_quad_entry {
	__le32 dr_addr;
	__le32 dr_value;
	__le32 ar_addr;
	__le32 ar_value;
} __packed;

struct qlcnic_83xx_reset {
	int seq_index;
	int seq_error ;
	int array_index;
	u32 array[QLC_83XX_MAX_RESET_SEQ_ENTRIES];
	u8 *buff;
	u8 *stop_offset;
	u8 *start_offset;
	u8 *init_offset;
	struct qlcnic_83xx_reset_template_hdr *hdr;
	u8 seq_end;
	u8 template_end;
};

struct qlcnic_83xx_fw_info {
	u16 major_fw_version;
	u8  minor_fw_version;
	u8  sub_fw_version;
	u8  fw_build_num;
	const struct firmware *fw;
};

/* IDC Device States */
enum qlc_83xx_states {
	QLC_83XX_IDC_DEV_UNKNOWN,
	QLC_83XX_IDC_DEV_COLD,
	QLC_83XX_IDC_DEV_INIT,
	QLC_83XX_IDC_DEV_READY,
	QLC_83XX_IDC_DEV_NEED_RESET,
	QLC_83XX_IDC_DEV_NEED_QUISCENT,
	QLC_83XX_IDC_DEV_FAILED,
	QLC_83XX_IDC_DEV_QUISCENT
};

#define QLC_83XX_IDC_DISABLE_FW_RESET_RECOVERY	0x1
#define QLC_83XX_IDC_GRACEFULL_RESET    0x2


#define QLC_83XX_IDC_TIMESTAMP                 0
#define QLC_83XX_IDC_DURATION                  1

#define QLC_83XX_IDC_INIT_TIMEOUT_SECS         30
#define QLC_83XX_IDC_RESET_ACK_TIMEOUT_SECS    10
#define QLC_83XX_IDC_RESET_TIMEOUT_SECS		10
#define QLC_83XX_IDC_QUIESCE_ACK_TIMEOUT_SECS  20
#define QLC_83XX_IDC_FW_POLL_DELAY             (1 * HZ)
#define QLC_83XX_IDC_FW_FAIL_THRESH            2

#define QLC_83XX_IDC_MAX_FUNC_PER_PARTITION_INFO 8
#define QLC_83XX_IDC_MAX_CNA_FUNCTIONS 16

#define QLC_83XX_IDC_MAJOR_VERSION 1
#define QLC_83XX_IDC_MINOR_VERSION 0

#define QLC_83XX_IDC_FLASH_PARAM_ADDR 0x3e8020
#define QLC_83XX_MBX_AEN_CNT 5 		/* Mailbox process AEN count */

struct qlcnic_adapter;
struct qlcnic_83xx_idc {
	u64 sec_counter;
	u64 delay;
	unsigned long status;
	int err_code;
	int collect_dump;
	u8 curr_state;
	u8 prev_state;
	u8 vnic_state;
	u8 vnic_wait_limit;
	u8 quiesce_req;
	int (*ready_state_entry_action) (struct qlcnic_adapter *);
	char **name;
#define QLC_83XX_MODULE_LOADED	1
#define QLC_83XX_MBX_READY	2
#define QLC_83XX_IDC_COMP_AEN 	3
};

#define IS_QLCNIC_83XX_USED(a, b, c)	\
	(((1 << a->portnum) & b) || ((c >> 6) & 0x1))

#define QLC_83XX_SFP_PRESENT(data) ((data) & 3)
#define QLC_83XX_SFP_ERR(data) (((data) >> 2) & 3)
#define QLC_83XX_SFP_MODULE_TYPE(data) (((data) >> 4) & 0x1F)
#define QLC_83XX_SFP_CU_LENGTH(data) (LSB((data) >> 16))
#define QLC_83XX_SFP_TX_FAULT(data) ((data) & BIT_10)
#define QLC_83XX_SFP_10G_CAPABLE(data) ((data) & BIT_11)
#define QLC_83XX_LINK_STATS(data) ((data) & BIT_0)
#define QLC_83XX_CURRENT_LINK_SPEED(data) (((data) >> 3) & 7)
#define QLC_83XX_LINK_PAUSE(data) (((data) >> 6) & 3)
#define QLC_83XX_LINK_LB(data) (((data) >> 8) & 7)
#define QLC_83XX_LINK_FEC(data) ((data) & BIT_12)
#define QLC_83XX_LINK_EEE(data) ((data) & BIT_13)
#define QLC_83XX_DCBX(data) (((data) >> 28) & 7)
#define QLC_83XX_AUTONEG(data) ((data) & BIT_15)
#define QLC_83XX_CFG_STD_PAUSE (1 << 5)		/* Standard Pause config */
#define QLC_83XX_CFG_STD_TX_PAUSE (1 << 20) 	/* Transmit Pause enabled */
#define QLC_83XX_CFG_STD_RX_PAUSE (2 << 20) 	/* Receive Pause enabled */
#define QLC_83XX_CFG_STD_TX_RX_PAUSE (3 << 20) 	/* Tx and Rx Pause enabled */
#define QLC_83XX_ENABLE_AUTONEG (1 << 15) 	/* Auto-negotiation enabled */
#define QLC_83XX_CFG_LOOPBACK_HSS (2 << 1)	/* HSS Internal Loopback Mode */
#define QLC_83XX_CFG_LOOPBACK_PHY (3 << 1)	/* PHY Internal Loopback Mode */
#define QLC_83XX_CFG_LOOPBACK_EXT (4 << 1)	/* External Loopback Mode */

/* LED configuration settings */
#define QLCNIC_83XX_ENABLE_BEACON 0xe
#define QLCNIC_83XX_LED_RATE 0xff
#define QLCNIC_83XX_LED_ACT (1 << 10)
#define QLCNIC_83XX_LED_MOD (0 << 13)
#define QLCNIC_83XX_LED_CONFIG (QLCNIC_83XX_LED_RATE | QLCNIC_83XX_LED_ACT |\
				QLCNIC_83XX_LED_MOD)

#define QLC_83XX_10M_LINK	1
#define QLC_83XX_100M_LINK	2
#define QLC_83XX_1G_LINK	3
#define QLC_83XX_10G_LINK	4

#define QLCNIC_83XX_STAT_TX	3
#define QLCNIC_83XX_STAT_RX	2

#define QLCNIC_83XX_STAT_MAC	1

#define QLCNIC_83XX_TX_STAT_REGS	14
#define QLCNIC_83XX_RX_STAT_REGS	40
#define QLCNIC_83XX_MAC_STAT_REGS	80

#define QLCNIC_GET_VPORT_INFO	1

#define QLC_83XX_GET_FUNC_PRIVILEGE_LEVEL(VAL, FN) (0x3 & ((VAL) >> (FN * 2)))
#define QLC_83XX_SET_FUNC_OPMODE(VAL, FN)   ((VAL) << (FN * 2))
#define QLC_83XX_DEFAULT_OPMODE 0x55555555
#define QLC_83XX_PRIVLEGED_FUNC 0x1
#define QLC_83XX_VIRTUAL_FUNC 0x2

#define QLC_83XX_GET_FUNC_MODE_FROM_NPAR_INFO(val) (val & 0x80000000)
#define QLC_83XX_GET_LRO_CAPABILITY(val) (val & 0x20)
#define QLC_83XX_GET_LSO_CAPABILITY(val) (val & 0x40)
#define QLC_83XX_GET_LSO_CAPABILITY(val) (val & 0x40)
#define QLC_83XX_GET_HW_LRO_CAPABILITY(val) (val & 0x400)
#define QLC_83XX_GET_VLAN_ALIGN_CAPABILITY(val) (val & 0x4000)
#define QLC_83XX_GET_FW_LRO_MSS_CAPABILITY(val) (val & 0x20000)

#define QLC_83XX_VIRTUAL_NIC_MODE 0xFF
#define QLC_83XX_DEFAULT_MODE 0x0
#define QLC_83XX_MINIMUM_VECTOR 3

#define QLC_83XX_LB_MAX_FILTERS 2048
#define QLC_83XX_LB_BUCKET_SIZE 256

#endif
