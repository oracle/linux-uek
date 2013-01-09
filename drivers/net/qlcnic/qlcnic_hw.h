#ifndef __QLCNIC_HW_H
#define __QLCNIC_HW_H

#define MASK(n) ((1ULL<<(n))-1)
#define OCM_WIN_P3P(addr) (addr & 0xffc0000)
#define OCM_WIN_83XX(addr)	(addr & 0xFFE0000)

#define GET_MEM_OFFS_2M(addr) (addr & MASK(18))
#define GET_83XX_OCM_OFFSET(addr)	(addr & MASK(17))

#define CRB_BLK(off)	((off >> 20) & 0x3f)
#define CRB_SUBBLK(off)	((off >> 16) & 0xf)
#define CRB_WINDOW_2M	(0x130060)
#define CRB_HI(off)	((crb_hub_agt[CRB_BLK(off)] << 20) | ((off) & 0xf0000))
#define CRB_INDIRECT_2M	(0x1e0000UL)



/* List of PCI device IDs */
#define PCI_DEVICE_ID_QLOGIC_QLE824X	0x8020
#define PCI_DEVICE_ID_QLOGIC_QLE834X	0x8030
#define QLCNIC_82XX_BAR0_LENGTH	0x00200000UL
#define QLCNIC_83XX_BAR0_LENGTH	0x4000

#define QLCNIC_IS_83XX(adapter)	\
	(((adapter)->pdev->device == PCI_DEVICE_ID_QLOGIC_QLE834X) ? 1 : 0)

#define QLCNIC_IS_82XX(adapter)	\
	(((adapter)->pdev->device == PCI_DEVICE_ID_QLOGIC_QLE824X) ? 1 : 0)

/* Existing registers in Hilda and P3P */
enum qlcnic_regs {
	QLCNIC_PEG_HALT_STATUS1 = 0,
	QLCNIC_PEG_HALT_STATUS2,
	QLCNIC_PEG_ALIVE_COUNTER,
	QLCNIC_FLASH_LOCK_OWNER,
	QLCNIC_FW_CAPABILITIES,
	QLCNIC_CRB_DRV_ACTIVE,
	QLCNIC_CRB_DEV_STATE,
	QLCNIC_CRB_DRV_STATE,
	QLCNIC_CRB_DRV_SCRATCH,
	QLCNIC_CRB_DEV_PARTITION_INFO,
	QLCNIC_CRB_DRV_IDC_VER,
	QLCNIC_FW_VERSION_MAJOR,
	QLCNIC_FW_VERSION_MINOR,
	QLCNIC_FW_VERSION_SUB,
	QLCNIC_CRB_DEV_NPAR_STATE,
	QLCNIC_FW_IMG_VALID,
	QLCNIC_CMDPEG_STATE,
	QLCNIC_RCVPEG_STATE,
	QLCNIC_ASIC_TEMP,
	QLCNIC_FW_API,
	QLCNIC_DRV_OP_MODE,
	QLCNIC_FLASH_LOCK,
	QLCNIC_FLASH_UNLOCK,
	QLCNIC_FW_CAPABILITIES_2,
};

/* Additional registers in Hilda */
enum qlcnic_ext_regs {
	QLCNIC_GLOBAL_RESET = 0,
	QLCNIC_WILDCARD,
	QLCNIC_INFORMANT,
	QLCNIC_HOST_MBX_CTRL,
	QLCNIC_FW_MBX_CTRL,
	QLCNIC_BOOTLOADER_ADDR,
	QLCNIC_BOOTLOADER_SIZE,
	QLCNIC_FW_IMAGE_ADDR,
	QLCNIC_MBX_INTR_ENBL,
	QLCNIC_DEF_INT_MASK,
	QLCNIC_DEF_INT_ID,
	QLC_83XX_IDC_MAJ_VERSION,
	QLC_83XX_IDC_DEV_STATE,
	QLC_83XX_IDC_DRV_PRESENCE,
	QLC_83XX_IDC_DRV_ACK,
	QLC_83XX_IDC_CTRL,
	QLC_83XX_IDC_DRV_AUDIT,
	QLC_83XX_IDC_MIN_VERSION,
	QLC_83XX_RECOVER_DRV_LOCK,
	QLC_83XX_IDC_PF_0,
	QLC_83XX_IDC_PF_1,
	QLC_83XX_IDC_PF_2,
	QLC_83XX_IDC_PF_3,
	QLC_83XX_IDC_PF_4,
	QLC_83XX_IDC_PF_5,
	QLC_83XX_IDC_PF_6,
	QLC_83XX_IDC_PF_7,
	QLC_83XX_IDC_PF_8,
	QLC_83XX_IDC_PF_9,
	QLC_83XX_IDC_PF_10,
	QLC_83XX_IDC_PF_11,
	QLC_83XX_IDC_PF_12,
	QLC_83XX_IDC_PF_13,
	QLC_83XX_IDC_PF_14,
	QLC_83XX_IDC_PF_15,
	QLC_83XX_IDC_DEV_PARTITION_INFO_1,
	QLC_83XX_IDC_DEV_PARTITION_INFO_2,
	QLC_83XX_DRV_OP_MODE,
	QLC_83XX_VNIC_STATE,
	QLC_83XX_DRV_LOCK,
	QLC_83XX_DRV_UNLOCK,
	QLC_83XX_DRV_LOCK_ID,
	QLC_83XX_ASIC_TEMP,
};

struct qlcnic_ms_reg_ctrl {
	u32 ocm_window;
	u32 control;
	u32 hi;
	u32 low;
	u32 rd[4];
	u32 wd[4];
	u64 off;
};

/* Read from an address offset from BAR0, existing registers */
#define QLCRD(a, addr)			\
	readl(((a)->ahw->pci_base0) + ((a)->ahw->reg_tbl[addr]))
/* Write to an address offset from BAR0, existing registers */
#define QLCWR(a, addr, value)		\
	writel(value, ((a)->ahw->pci_base0) + ((a)->ahw->reg_tbl[addr]))

/* Read from a direct address offset from BAR0, additional registers */
#define QLCRDX(ahw, addr)			\
	readl(((ahw)->pci_base0) + ((ahw)->ext_reg_tbl[addr]))
/* Write to a direct address offset from BAR0, additional registers */
#define QLCWRX(ahw, addr, value)		\
	writel(value, (((ahw)->pci_base0) + ((ahw)->ext_reg_tbl[addr])))

#define QLCNIC_READ_LINK_SPEED(adapter, pcifn, err)\
	(QLCNIC_IS_83XX(adapter) ?\
	(((readl(adapter->ahw->pci_base0 + QLC_83XX_LINK_SPEED(pcifn)) >> \
	((pcifn % 4) << 4)) & 0xFFFF) * QLC_83XX_LINK_SPEED_FACTOR) :\
	(P3P_LINK_SPEED_MHZ * P3P_LINK_SPEED_VAL(pcifn, \
	QLCRD32(adapter, P3P_LINK_SPEED_REG(pcifn), err))))

/* Mailbox ownership */
#define QLCNIC_GET_OWNER(val)	\
	((val) & (BIT_0 | BIT_1))
#define QLCNIC_SET_OWNER	1
#define QLCNIC_CLR_OWNER	0
#define QLCNIC_MBX_TIMEOUT	5
#define QLCNIC_MBX_POLL_CNT	5000
#define QLCNIC_MBX_POLL_DELAY_MSEC 1

#define QLCNIC_CMD_CONFIGURE_IP_ADDR		0x1
#define QLCNIC_CMD_CONFIG_INTRPT		0x2
#define QLCNIC_CMD_CREATE_RX_CTX		0x7
#define QLCNIC_CMD_DESTROY_RX_CTX		0x8
#define QLCNIC_CMD_CREATE_TX_CTX		0x9
#define QLCNIC_CMD_DESTROY_TX_CTX		0xa
#define QLCNIC_CMD_CONFIGURE_LRO		0xC
#define QLCNIC_CMD_CONFIGURE_MAC_LEARNING	0xD
#define QLCNIC_CMD_GET_STATISTICS		0xF
#define QLCNIC_CMD_INTRPT_TEST			0x11
#define QLCNIC_CMD_SET_MTU			0x12
#define QLCNIC_CMD_READ_PHY			0x13
#define QLCNIC_CMD_WRITE_PHY			0x14
#define QLCNIC_CMD_READ_HW_REG			0x15
#define QLCNIC_CMD_GET_FLOW_CTL			0x16
#define QLCNIC_CMD_SET_FLOW_CTL			0x17
#define QLCNIC_CMD_READ_MAX_MTU			0x18
#define QLCNIC_CMD_READ_MAX_LRO			0x19
#define QLCNIC_CMD_MAC_ADDRESS			0x1f
#define QLCNIC_CMD_GET_PCI_INFO			0x20
#define QLCNIC_CMD_GET_NIC_INFO			0x21
#define QLCNIC_CMD_SET_NIC_INFO			0x22
#define QLCNIC_CMD_GET_ESWITCH_CAPABILITY	0x24
#define QLCNIC_CMD_TOGGLE_ESWITCH		0x25
#define QLCNIC_CMD_GET_ESWITCH_STATUS		0x26
#define QLCNIC_CMD_SET_PORTMIRRORING		0x27
#define QLCNIC_CMD_CONFIGURE_ESWITCH		0x28
#define QLCNIC_CMD_GET_ESWITCH_PORT_CONFIG	0x29
#define QLCNIC_CMD_GET_ESWITCH_STATS		0x2a
#define QLCNIC_CMD_CONFIG_PORT			0x2e
#define QLCNIC_CMD_TEMP_SIZE			0x2f
#define QLCNIC_CMD_GET_TEMP_HDR			0x30
#define QLCNIC_CMD_GET_MAC_STATS		0x37
#define QLCNIC_CMD_SET_DRV_VER			0x38
#define QLCNIC_CMD_CONFIGURE_RSS		0x41
#define QLCNIC_CMD_CONFIG_INTR_COAL		0x43
#define QLCNIC_CMD_CONFIGURE_LED		0x44
#define QLCNIC_CMD_CONFIG_MAC_VLAN		0x45
#define QLCNIC_CMD_GET_LINK_EVENT		0x48
#define QLCNIC_CMD_CONFIGURE_MAC_RX_MODE	0x49
#define QLCNIC_CMD_CONFIGURE_HW_LRO		0x4A
#define QLCNIC_CMD_INIT_NIC_FUNC		0x60
#define QLCNIC_CMD_STOP_NIC_FUNC		0x61
#define QLCNIC_CMD_IDC_ACK			0x63
#define QLCNIC_CMD_SET_PORT_CONFIG		0x66
#define QLCNIC_CMD_GET_PORT_CONFIG		0x67
#define QLCNIC_CMD_GET_LINK_STATUS		0x68
#define QLCNIC_CMD_SET_LED_CONFIG		0x69
#define QLCNIC_CMD_GET_LED_CONFIG		0x6A
#define QLCNIC_CMD_ADD_RCV_RINGS		0x0B

#define QLC_TCP_HDR_SIZE            20
#define QLC_TCP_TS_OPTION_SIZE      12
#define QLC_TCP_TS_HDR_SIZE         (QLC_TCP_HDR_SIZE + QLC_TCP_TS_OPTION_SIZE)

#define QLCNIC_INTRPT_INTX	1
#define QLCNIC_INTRPT_MSIX	3
#define QLCNIC_INTRPT_ADD	1
#define QLCNIC_INTRPT_DEL	2

#define QLCNIC_GET_CURRENT_MAC	1
#define QLCNIC_SET_STATION_MAC	2
#define QLCNIC_GET_DEFAULT_MAC	3
#define QLCNIC_GET_FAC_DEF_MAC	4
#define QLCNIC_SET_FAC_DEF_MAC	5

#define QLCNIC_MBX_LINK_EVENT		0x8001
#define QLCNIC_MBX_COMP_EVENT		0x8100
#define QLCNIC_MBX_REQUEST_EVENT	0x8101
#define QLCNIC_MBX_TIME_EXTEND_EVENT	0x8102
#define QLCNIC_MBX_SFP_INSERT_EVENT	0x8130
#define QLCNIC_MBX_SFP_REMOVE_EVENT	0x8131

struct qlcnic_mailbox_metadata {
	u32 cmd;
	u32 in_args;
	u32 out_args;
};

#define QLCNIC_BAR_LENGTH(dev_id, bar)			\
do {							\
	switch (dev_id) {				\
	case PCI_DEVICE_ID_QLOGIC_QLE824X:		\
		*bar = QLCNIC_82XX_BAR0_LENGTH;		\
		break;					\
	case PCI_DEVICE_ID_QLOGIC_QLE834X:		\
		*bar = QLCNIC_83XX_BAR0_LENGTH;	\
		break;					\
	default:					\
		*bar = 0;				\
	}						\
} while (0)

/* Make a handle with reference handle (0:14) and RDS ring
 * number (15).
 */
#define QLCNIC_MAKE_REF_HANDLE(adapter, handle, ring_id)		\
	((adapter->pdev->device == PCI_DEVICE_ID_QLOGIC_QLE834X) ?	\
	((handle) | ((ring_id) << 15)) : handle)

#define QLCNIC_FETCH_RING_ID(handle)			\
	((handle) >> 63)

#define QLCNIC_ENABLE_INTR(adapter, crb) {		\
	writel(1, crb);					\
	if (!QLCNIC_IS_MSI_FAMILY(adapter))		\
		writel(0xfbff, adapter->tgt_mask_reg);	\
}

#define QLCNIC_DISABLE_INTR(crb) {			\
	writel(0, crb);					\
}

#define QLCNIC_MBX_RSP_OK	1
#define QLCNIC_MBX_PORT_RSP_OK	0x1a
#define QLCNIC_MBX_ASYNC_EVENT	BIT_15

#define QLCNIC_MBX_RSP(reg)\
	LSW(reg)
#define QLCNIC_MBX_NUM_REGS(reg)\
	(MSW(reg) & 0x1FF)
#define QLCNIC_MBX_STATUS(reg)	\
	(((reg) >> 25) & 0x7F)

/* Mailbox registers*/
#define QLCNIC_MBX_HOST(ahw, i)	\
	((ahw)->pci_base0 + ((i) * 4))
#define QLCNIC_MBX_FW(ahw, i)	\
	((ahw)->pci_base0 + 0x800 + ((i) * 4))

#define QLCNIC_IS_TSO_CAPABLE(adapter)\
	((QLCNIC_IS_82XX(adapter)) ?\
	((adapter)->ahw->capabilities & QLCNIC_FW_CAPABILITY_TSO) :\
	((adapter)->ahw->capabilities & QLCNIC_FW_83XX_CAPABILITY_TSO))

#define QLCNIC_IS_VLAN_TX_CAPABLE(adapter) \
	((QLCNIC_IS_82XX(adapter)) ?\
	((adapter)->ahw->capabilities & QLCNIC_FW_CAPABILITY_FVLANTX) :\
	1)

#endif				/* __QLCNIC_HDR_H_ */
