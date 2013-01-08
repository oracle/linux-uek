#include "qlcnic.h"
#include <linux/if_vlan.h>
#include <linux/ipv6.h>

/* Array of FW control command structs with command type and required
 * number of input and output arguments respectively.
*/
static const struct qlcnic_mailbox_metadata qlcnic_83xx_mbx_tbl[] = {
	{ QLCNIC_CMD_CONFIGURE_IP_ADDR, 6, 1 },
	{ QLCNIC_CMD_CONFIG_INTRPT, 18, 34 },
	{ QLCNIC_CMD_CREATE_RX_CTX, 136, 27 },
	{ QLCNIC_CMD_DESTROY_RX_CTX, 2, 1 },
	{ QLCNIC_CMD_CREATE_TX_CTX, 54, 18 },
	{ QLCNIC_CMD_DESTROY_TX_CTX, 2, 1 },
	{ QLCNIC_CMD_CONFIGURE_MAC_LEARNING, 2, 1 },
	{ QLCNIC_CMD_INTRPT_TEST, 22, 12 },
	{ QLCNIC_CMD_SET_MTU, 3, 1 },
	{ QLCNIC_CMD_READ_PHY, 4, 2 },
	{ QLCNIC_CMD_WRITE_PHY, 5, 1 },
	{ QLCNIC_CMD_READ_HW_REG, 4, 1 },
	{ QLCNIC_CMD_GET_FLOW_CTL, 4, 2 },
	{ QLCNIC_CMD_SET_FLOW_CTL, 4, 1 },
	{ QLCNIC_CMD_READ_MAX_MTU, 4, 2 },
	{ QLCNIC_CMD_READ_MAX_LRO, 4, 2 },
	{ QLCNIC_CMD_MAC_ADDRESS, 4, 3 },
	{ QLCNIC_CMD_GET_PCI_INFO, 1, 66 },
	{ QLCNIC_CMD_GET_NIC_INFO, 2, 19 },
	{ QLCNIC_CMD_SET_NIC_INFO, 32, 1 },
	{ QLCNIC_CMD_GET_ESWITCH_CAPABILITY, 4, 3 },
	{ QLCNIC_CMD_TOGGLE_ESWITCH, 4, 1 },
	{ QLCNIC_CMD_GET_ESWITCH_STATUS, 4, 3 },
	{ QLCNIC_CMD_SET_PORTMIRRORING, 4, 1 },
	{ QLCNIC_CMD_CONFIGURE_ESWITCH, 4, 1 },
	{ QLCNIC_CMD_GET_ESWITCH_PORT_CONFIG, 4, 3 },
	{ QLCNIC_CMD_GET_ESWITCH_STATS, 5, 1 },
	{ QLCNIC_CMD_CONFIG_PORT, 4, 1 },
	{ QLCNIC_CMD_TEMP_SIZE, 1, 4 },
	{ QLCNIC_CMD_GET_TEMP_HDR, 5, 5 },
	{ QLCNIC_CMD_GET_LINK_EVENT, 2, 1 },
	{ QLCNIC_CMD_CONFIG_MAC_VLAN, 4, 3 },
	{ QLCNIC_CMD_CONFIG_INTR_COAL, 6, 1 },
	{ QLCNIC_CMD_CONFIGURE_RSS, 14, 1 },
	{ QLCNIC_CMD_CONFIGURE_LED, 2, 1 },
	{ QLCNIC_CMD_CONFIGURE_MAC_RX_MODE, 2, 1 },
	{ QLCNIC_CMD_CONFIGURE_HW_LRO, 2, 1 },
	{ QLCNIC_CMD_GET_STATISTICS, 2,	80 },
	{ QLCNIC_CMD_SET_PORT_CONFIG, 2, 1 },
	{ QLCNIC_CMD_GET_PORT_CONFIG, 2, 2 },
	{ QLCNIC_CMD_GET_LINK_STATUS, 2, 4},
	{ QLCNIC_CMD_IDC_ACK, 5, 1},
	{ QLCNIC_CMD_INIT_NIC_FUNC, 2, 1},
	{ QLCNIC_CMD_STOP_NIC_FUNC, 2, 1},
	{ QLCNIC_CMD_SET_LED_CONFIG, 5, 1},
	{ QLCNIC_CMD_GET_LED_CONFIG, 1, 5},
	{ QLCNIC_CMD_ADD_RCV_RINGS, 130, 26},
};

const u32 qlcnic_83xx_ext_reg_tbl[] = {
	0x38CC, /* Global Reset */
	0x38F0, /* Wildcard */
	0x38FC, /* Informant */
	0x3038, /* Host MBX ctrl */
	0x303C, /* FW MBX ctrl */
	0x355C, /* BOOT LOADER ADDRESS REG */
	0x3560, /* BOOT LOADER SIZE REG */
	0x3564, /* FW IMAGE ADDR REG */
	0x1000, /* MBX intr enable */
	0x1200, /* Default Intr mask */
	0x1204, /* Default Interrupt ID */
	0x3780, /* QLC_83XX_IDC_MAJ_VERSION */
	0x3784, /* QLC_83XX_IDC_DEV_STATE */
	0x3788, /* QLC_83XX_IDC_DRV_PRESENCE */
	0x378C, /* QLC_83XX_IDC_DRV_ACK */
	0x3790, /* QLC_83XX_IDC_CTRL */
	0x3794, /* QLC_83XX_IDC_DRV_AUDIT */
	0x3798, /* QLC_83XX_IDC_MIN_VERSION */
	0x379C, /* QLC_83XX_RECOVER_DRV_LOCK */
	0x37A0, /* QLC_83XX_IDC_PF_0 */
	0x37A4, /* QLC_83XX_IDC_PF_1 */
	0x37A8, /* QLC_83XX_IDC_PF_2 */
	0x37AC, /* QLC_83XX_IDC_PF_3 */
	0x37B0, /* QLC_83XX_IDC_PF_4 */
	0x37B4, /* QLC_83XX_IDC_PF_5 */
	0x37B8, /* QLC_83XX_IDC_PF_6 */
	0x37BC, /* QLC_83XX_IDC_PF_7 */
	0x37C0, /* QLC_83XX_IDC_PF_8 */
	0x37C4, /* QLC_83XX_IDC_PF_9 */
	0x37C8, /* QLC_83XX_IDC_PF_10 */
	0x37CC, /* QLC_83XX_IDC_PF_11 */
	0x37D0, /* QLC_83XX_IDC_PF_12 */
	0x37D4, /* QLC_83XX_IDC_PF_13 */
	0x37D8, /* QLC_83XX_IDC_PF_14 */
	0x37DC, /* QLC_83XX_IDC_PF_15 */
	0x37E0, /* QLC_83XX_IDC_DEV_PARTITION_INFO_1 */
	0x37E4, /* QLC_83XX_IDC_DEV_PARTITION_INFO_2 */
	0x37F0, /* QLC_83XX_DRV_OP_MODE */
	0x37F4, /* QLC_83XX_VNIC_STATE */
	0x3868, /* QLC_83XX_DRV_LOCK */
	0x386C, /* QLC_83XX_DRV_UNLOCK */
	0x3504, /* QLC_83XX_DRV_LOCK_ID */
	0x34A4, /* QLC_83XX_ASIC_TEMP */
};

const u32 qlcnic_83xx_reg_tbl[] = {
	0x34A8, /* PEG_HALT_STAT1 */
	0x34AC, /* PEG_HALT_STAT2 */
	0x34B0, /* FW_HEARTBEAT */
	0x3500, /* FLASH LOCK_ID */
	0x3528, /* FW_CAPABILITIES */
	0x3538, /* drv active, DRV_REG0 */
	0x3540, /* dev state, DRV_REG1 */
	0x3544, /* drv state, DRV_REG2 */
	0x3548, /* drv scratch, DRV_REG3 */
	0x354C, /* dev part info, DRV_REG4 */
	0x3524, /* drv IDC ver, DRV_REG5 */
	0x3550, /* FW_VER_MAJOR */
	0x3554, /* FW_VER_MINOR */
	0x3558, /* FW_VER_SUB */
	0x359C,	/* NPAR STATE */
	0x35FC, /* FW_IMG_VALID */
	0x3650, /* CMD_PEG_STATE */
	0x373C, /* RCV_PEG_STATE */
	0x37B4, /* ASIC TEMP */
	0x356C,	/* FW API */
	0x3570,	/* DRV OP MODE */
	0x3850, /* FLASH LOCK */
	0x3854, /* FLASH UNLOCK */
};

static struct qlcnic_hardware_ops qlcnic_83xx_hw_ops = {
	.read_crb = qlcnic_83xx_read_crb,
	.write_crb = qlcnic_83xx_write_crb,
	.rdreg = qlcnic_83xx_rd_reg_indirect,
	.wrtreg = qlcnic_83xx_wrt_reg_indirect,
	.get_mac_address = qlcnic_83xx_get_mac_address,
	.setup_intr = qlcnic_83xx_setup_intr,
	.alloc_mbx_args = qlcnic_83xx_alloc_mbx_args,
	.mbx_cmd = qlcnic_83xx_mbx_op,
	.get_func_no = qlcnic_83xx_get_func_no,
	.api_lock = qlcnic_83xx_cam_lock,
	.api_unlock = qlcnic_83xx_cam_unlock,
	.add_sysfs = qlcnic_83xx_add_sysfs,
	.remove_sysfs = qlcnic_83xx_remove_sysfs,
	.process_lb_rcv_ring_diag = qlcnic_83xx_process_rcv_ring_diag,
	.create_rx_ctx = qlcnic_83xx_create_rx_ctx,
	.create_tx_ctx = qlcnic_83xx_create_tx_ctx,
	.setup_link_event = qlcnic_83xx_setup_link_event,
	.get_nic_info = qlcnic_83xx_get_nic_info,
	.get_pci_info = qlcnic_83xx_get_pci_info,
	.set_nic_info = qlcnic_83xx_set_nic_info,
	.change_macvlan = qlcnic_83xx_sre_macaddr_change,
	.napi_enable = qlcnic_83xx_napi_enable,
	.napi_disable = qlcnic_83xx_napi_disable,
	.config_intr_coal = qlcnic_83xx_config_intr_coal,
	.config_rss = qlcnic_83xx_config_rss,
	.config_hw_lro = qlcnic_83xx_config_hw_lro,
	.config_promisc_mode = qlcnic_83xx_nic_set_promisc,
	.change_l2_filter = qlcnic_83xx_change_l2_filter,
	.get_board_info = qlcnic_83xx_get_port_info,
};

static void
qlcnic_83xx_handle_link_aen(struct qlcnic_adapter *adapter, u32 data[]);
static void
qlcnic_83xx_handle_idc_comp_aen(struct qlcnic_adapter *adapter, u32 data[]);

void
qlcnic_83xx_register_map(struct qlcnic_hardware_context *ahw)
{
	ahw->hw_ops = &qlcnic_83xx_hw_ops;
	ahw->reg_tbl = (u32 *) qlcnic_83xx_reg_tbl;
	ahw->ext_reg_tbl = (u32 *) qlcnic_83xx_ext_reg_tbl;
}

int
qlcnic_83xx_get_fw_version(struct qlcnic_adapter *adapter)
{
	u32 fw_major, fw_minor, fw_build;
	struct pci_dev *pdev = adapter->pdev;

	fw_major = QLCRD(adapter, QLCNIC_FW_VERSION_MAJOR);
	fw_minor = QLCRD(adapter, QLCNIC_FW_VERSION_MINOR);
	fw_build = QLCRD(adapter, QLCNIC_FW_VERSION_SUB);
	adapter->fw_version = QLCNIC_VERSION_CODE(fw_major, fw_minor, fw_build);

	dev_info(&pdev->dev, "Driver v%s, firmware version %d.%d.%d\n",
		QLCNIC_LINUX_VERSIONID, fw_major, fw_minor, fw_build);

	return adapter->fw_version;
}

void
qlcnic_83xx_get_minidump_template(struct qlcnic_adapter *adapter)
{
	u32 prev_version, current_version;
	struct qlcnic_hardware_context *ahw = adapter->ahw;
	struct qlcnic_fw_dump *fw_dump = &ahw->fw_dump;
	struct pci_dev *pdev = adapter->pdev;

	prev_version = adapter->fw_version;
	current_version = qlcnic_83xx_get_fw_version(adapter);

	if (fw_dump->tmpl_hdr == NULL || current_version > prev_version) {
		if (fw_dump->tmpl_hdr)
			vfree(fw_dump->tmpl_hdr);
		if (!qlcnic_fw_cmd_get_minidump_temp(adapter))
			dev_info(&pdev->dev,
				"Supports FW dump capability\n");
	}
}

/* Caller needs to use locking before accessing this function */
static int
__qlcnic_set_win_base(struct qlcnic_adapter *adapter, u32 addr)
{
	void __iomem *base;
	u32 val;

	base = adapter->ahw->pci_base0 +
		QLC_83XX_CRB_WIN_FUNC(adapter->ahw->pci_func);
	writel(addr, base);
	val = readl(base);
	if (val != addr)
		return -EIO;

	return 0;
}

u32
qlcnic_83xx_rd_reg_indirect(struct qlcnic_adapter *adapter,
						ulong addr, int *err)
{
	int ret;
	struct qlcnic_hardware_context *ahw = adapter->ahw;

	ret = __qlcnic_set_win_base(adapter, (u32) addr);
	if (!ret) {
		*err = 0;
		return QLCRDX(ahw, QLCNIC_WILDCARD);
	} else {
		dev_err(&adapter->pdev->dev,
			"%s failed, addr = 0x%x\n", __func__, (int)addr);
		if (err)
			*err = -EIO;

		return -1;
	}
}

/* Caller needs to use locking before accessing this function */
int
qlcnic_83xx_wrt_reg_indirect(struct qlcnic_adapter *adapter, ulong addr,
		u32 data)
{
	int err;
	struct qlcnic_hardware_context *ahw = adapter->ahw;

	err = __qlcnic_set_win_base(adapter, (u32) addr);
	if (!err) {
		QLCWRX(ahw, QLCNIC_WILDCARD, data);
		return 0;
	} else {
		dev_err(&adapter->pdev->dev,
			"%s failed, addr = 0x%x data = 0x%x\n",
						__func__, (int)addr, data);
		return err;
	}
}

int
qlcnic_83xx_setup_intr(struct qlcnic_adapter *adapter, u8 num_intr)
{
	int err, i, num_msix;
	struct qlcnic_hardware_context *ahw = adapter->ahw;

	if (!num_intr)
		num_intr = QLCNIC_DEF_NUM_STS_DESC_RINGS;
	num_msix = rounddown_pow_of_two(min_t(int, num_online_cpus(),
				num_intr));

	/* account for AEN interrupt MSI-X based interrupts */
	num_msix += 1;
	num_msix += adapter->max_drv_tx_rings;
	err = qlcnic_enable_msix(adapter, num_msix);
	if (err == -ENOMEM)
		return err;
	if (adapter->flags & QLCNIC_MSIX_ENABLED)
		num_msix = adapter->ahw->num_msix;
	else
		num_msix = 1;
	/* setup interrupt mapping table for fw */
	ahw->intr_tbl = (struct qlcnic_intrpt_config *) vmalloc(num_msix *
		sizeof(struct qlcnic_intrpt_config));
	if (!ahw->intr_tbl)
		return -ENOMEM;
	if (!(adapter->flags & QLCNIC_MSIX_ENABLED)) {
		/* MSI-X enablement failed, use legacy interrupt */
		adapter->tgt_status_reg = ahw->pci_base0 + QLCNIC_83XX_INTX_PTR;
		adapter->tgt_mask_reg = ahw->pci_base0 + QLCNIC_83XX_INTX_MASK;
		adapter->isr_int_vec = ahw->pci_base0 + QLCNIC_83XX_INTX_TRGR;
		adapter->msix_entries[0].vector = adapter->pdev->irq;
		dev_info(&adapter->pdev->dev, "using legacy interrupt\n");
	}
	memset(ahw->intr_tbl, 0, sizeof(struct qlcnic_intrpt_config));
	for (i = 0; i < num_msix; i++) {
		if (adapter->flags & QLCNIC_MSIX_ENABLED)
			ahw->intr_tbl[i].type = QLCNIC_INTRPT_MSIX;
		else
			ahw->intr_tbl[i].type = QLCNIC_INTRPT_INTX;
		ahw->intr_tbl[i].id = i;
		ahw->intr_tbl[i].src = 0;
	}
	return 0;
}

inline void
qlcnic_83xx_enable_intr(struct qlcnic_adapter *adapter,
	struct qlcnic_host_sds_ring *sds_ring)
{
	writel(0, sds_ring->crb_intr_mask);
	if (!QLCNIC_IS_MSI_FAMILY(adapter))
		writel(0, adapter->tgt_mask_reg);
}

inline void
qlcnic_83xx_enable_tx_intr(struct qlcnic_adapter *adapter,
	struct qlcnic_host_tx_ring *tx_ring)
{
	writel(0, tx_ring->crb_intr_mask);
}

inline void
qlcnic_83xx_get_mbx_data(struct qlcnic_adapter *adapter,
			struct qlcnic_cmd_args *cmd)
{
	int i;
	for (i = 0; i < cmd->rsp.num; i++)
		cmd->rsp.arg[i] = readl(QLCNIC_MBX_FW(adapter->ahw, i));
}

inline void
qlcnic_83xx_disable_tx_intr(struct qlcnic_adapter *adapter,
	struct qlcnic_host_tx_ring *tx_ring)
{
	writel(1, tx_ring->crb_intr_mask);
}

irqreturn_t qlcnic_83xx_clear_legacy_intr(struct qlcnic_adapter *adapter)
{
	u32 intr_val;
	struct qlcnic_hardware_context *ahw = adapter->ahw;

	intr_val = readl(adapter->tgt_status_reg);

	if (!QLCNIC_83XX_VALID_INTX_BIT31(intr_val))
		return IRQ_NONE;

	if (QLCNIC_83XX_INTX_FUNC(intr_val) != adapter->ahw->pci_func) {
		adapter->stats.spurious_intr++;
		return IRQ_NONE;
	}
	/* The barrier is required to ensure writes to the registers */
	wmb();

	/* clear the interrupt trigger control register */
	writel(0, adapter->isr_int_vec);
	intr_val = readl(adapter->isr_int_vec);

	/* Legacy Workaround for A0 & B0 */
	do {
		intr_val = readl(adapter->tgt_status_reg);
		if (QLCNIC_83XX_INTX_FUNC(intr_val) != ahw->pci_func)
			break;
	} while (QLCNIC_83XX_VALID_INTX_BIT30(intr_val));

	return IRQ_HANDLED;
}

irqreturn_t qlcnic_83xx_tmp_intr(int irq, void *data)
{
	struct qlcnic_host_sds_ring *sds_ring = data;
	struct qlcnic_adapter *adapter = sds_ring->adapter;

	if (adapter->flags & QLCNIC_MSIX_ENABLED)
		goto done;

	if (qlcnic_83xx_clear_legacy_intr(adapter) == IRQ_NONE)
		return IRQ_NONE;

done:
	adapter->ahw->diag_cnt++;
	qlcnic_83xx_enable_intr(adapter, sds_ring);

	return IRQ_HANDLED;
}

void qlcnic_83xx_free_mbx_intr(struct qlcnic_adapter *adapter)
{
	u32 val = 0;
	u32 num_msix = adapter->ahw->num_msix - 1;

	val = (num_msix << 8);

	QLCWRX(adapter->ahw, QLCNIC_MBX_INTR_ENBL, val);
	if (adapter->flags & QLCNIC_MSIX_ENABLED)
		free_irq(adapter->msix_entries[num_msix].vector, adapter);
}

int
qlcnic_83xx_setup_mbx_intr(struct qlcnic_adapter *adapter)
{
	irq_handler_t handler;
	u32 val;
	char name[32];
	int err = 0;
	unsigned long flags = 0;

	if (!(adapter->flags & QLCNIC_MSI_ENABLED) &&
		!(adapter->flags & QLCNIC_MSIX_ENABLED)) {
		flags |= IRQF_SHARED;
	}

	if (adapter->flags & QLCNIC_MSIX_ENABLED) {
		handler = qlcnic_83xx_handle_aen;
		val = adapter->msix_entries[adapter->ahw->num_msix - 1].vector;
		snprintf(name, (IFNAMSIZ+4),
			"%s[%s]", adapter->netdev->name, "aen");
		err = request_irq(val, handler, flags, name, adapter);
		if (err) {
			dev_err(&adapter->pdev->dev,
				"failed to register MBX interrupt\n");
			return err;
		}
	}

	/* Enable mailbox interrupt */
	qlcnic_83xx_enable_mbx_intrpt(adapter);
	if (adapter->flags & QLCNIC_MSIX_ENABLED)
		err = qlcnic_83xx_config_intrpt(adapter, 1);

	return err;
}

void qlcnic_83xx_get_func_no(struct qlcnic_adapter *adapter)
{
	u32 val = QLCRDX(adapter->ahw, QLCNIC_INFORMANT);
	adapter->ahw->pci_func = val & 0xf;
}

int qlcnic_83xx_cam_lock(struct qlcnic_adapter *adapter)
{
	void __iomem *addr;
	u32 val;
	u32 timeo = 0;

	struct qlcnic_hardware_context *ahw = adapter->ahw;

	addr = ahw->pci_base0 + QLC_83XX_SEM_LOCK_FUNC(ahw->pci_func);
	do {
		val = readl(addr);
		if (val) {
			/* write the function number to register */
			QLCWR(adapter, QLCNIC_FLASH_LOCK_OWNER, ahw->pci_func);
			return 0;
		}
		msleep(1);
	} while (++timeo <= QLCNIC_PCIE_SEM_TIMEOUT);

	return -EIO;
}

void qlcnic_83xx_cam_unlock(struct qlcnic_adapter *adapter)
{
	void __iomem *addr;
	u32 val;
	struct qlcnic_hardware_context *ahw = adapter->ahw;

	addr = ahw->pci_base0 + QLC_83XX_SEM_UNLOCK_FUNC(ahw->pci_func);
	val = readl(addr);
}

static void
qlcnic_dump_mbx(struct qlcnic_adapter *adapter,
	struct qlcnic_cmd_args *cmd)
{
	int i;

	dev_info(&adapter->pdev->dev,
		"Host MBX regs(%d)\n", cmd->req.num);
	for (i = 0; i < cmd->req.num; i++) {
		if (i && !(i % 8))
			printk(KERN_INFO "\n");
		printk(KERN_INFO "%08x ", le32_to_cpu(cmd->req.arg[i]));
	}
	printk(KERN_INFO "\n");
	dev_info(&adapter->pdev->dev,
		"FW MBX regs(%d)\n", cmd->rsp.num);
	for (i = 0; i < cmd->rsp.num; i++) {
		if (i && !(i % 8))
			printk(KERN_INFO "\n");
		printk(KERN_INFO "%08x ", le32_to_cpu(cmd->rsp.arg[i]));
	}
	printk(KERN_INFO "\n");
}

static u32 qlcnic_83xx_mac_rcode(struct qlcnic_adapter *adapter)
{
	u32 fw_data;
	u8 mac_cmd_rcode;

	fw_data = readl(QLCNIC_MBX_FW(adapter->ahw, 2));
	mac_cmd_rcode = (u8)le32_to_cpu(fw_data);
	if (mac_cmd_rcode == QLCNIC_NO_CARD_RESOURCE ||
		mac_cmd_rcode == QLCNIC_MAC_ALREADY_EXISTS ||
		mac_cmd_rcode == QLCNIC_MAC_DOES_NOT_EXIST)
		return QLCNIC_RCODE_SUCCESS;
	return 1;
}

/* Wait for a single mailbox command to complete */
static u32 qlcnic_83xx_wait_mbx_cmd_cmplt(struct qlcnic_adapter *adapter)
{
	struct qlcnic_hardware_context *ahw = adapter->ahw;
	u32 data;
	int count = QLCNIC_MBX_POLL_CNT;

	/* wait for mailbox completion */
	do {
		data = QLCRDX(ahw, QLCNIC_FW_MBX_CTRL);
		if (data)
			return data;
		mdelay(QLCNIC_MBX_POLL_DELAY_MSEC);
	} while (--count);
	return QLCNIC_RCODE_TIMEOUT;
}

int
qlcnic_83xx_mbx_op(struct qlcnic_adapter *adapter, struct qlcnic_cmd_args *cmd)
{
	struct qlcnic_hardware_context *ahw = adapter->ahw;
	unsigned long flags, count;
	u32 rsp, mbx_val, fw_data, rsp_num, mbx_cmd;
	u16 opcode;
	u8 mbx_err_code;
	int i;

	opcode = LSW(le32_to_cpu(cmd->req.arg[0]));
	if (!test_bit(QLC_83XX_MBX_READY, &adapter->ahw->idc.status)) {
		QLCDB(adapter, DRV,
		      "Mailbox cmd attempted, 0x%x\n", opcode);
		QLCDB(adapter, DRV, "Mailbox detached\n");
		return 0;
	}

	spin_lock_irqsave(&ahw->mbx_lock, flags);

	mbx_val = QLCRDX(ahw, QLCNIC_HOST_MBX_CTRL);
	if (mbx_val) {
		QLCDB(adapter, DRV,
		      "Mailbox cmd attempted, 0x%x\n", opcode);
		QLCDB(adapter, DRV,
		      "Mailbox not available, 0x%x, collect FW dump\n",
		      mbx_val);
		/* Take FW dump */
		qlcnic_83xx_dev_request_reset(adapter,
			QLCNIC_FORCE_FW_DUMP_KEY);
		cmd->rsp.arg[0] = QLCNIC_RCODE_TIMEOUT;
		spin_unlock_irqrestore(&ahw->mbx_lock, flags);

		return cmd->rsp.arg[0];
	}

	/* Fill in mailbox registers */
	mbx_cmd = cpu_to_le32(cmd->req.arg[0]);
	writel(mbx_cmd, QLCNIC_MBX_HOST(ahw, 0));
	for (i = 1; i < cmd->req.num; i++)
		writel(cmd->req.arg[i], QLCNIC_MBX_HOST(ahw, i));

	/* Signal FW about the impending command */
	QLCWRX(ahw, QLCNIC_HOST_MBX_CTRL, QLCNIC_SET_OWNER);

	/* Waiting for the mailbox cmd to complete and while waiting here
	 * some AEN might arrive. If more than 5 seconds expire we can
	 * assume something is wrong.
	 */
	count = jiffies + HZ * QLCNIC_MBX_TIMEOUT;
	do {
		rsp = qlcnic_83xx_wait_mbx_cmd_cmplt(adapter);
		/* Get the FW response data */
		fw_data = le32_to_cpu(readl(QLCNIC_MBX_FW(ahw, 0)));
		mbx_err_code = QLCNIC_MBX_STATUS(fw_data);
		rsp_num = QLCNIC_MBX_NUM_REGS(fw_data);
		opcode = QLCNIC_MBX_RSP(fw_data);
		qlcnic_83xx_get_mbx_data(adapter, cmd);

		if (rsp != QLCNIC_RCODE_TIMEOUT) {
			if (fw_data &  QLCNIC_MBX_ASYNC_EVENT) {
				qlcnic_83xx_process_aen(adapter);
				continue;
			}
			switch (mbx_err_code) {
			case QLCNIC_MBX_RSP_OK:
			case QLCNIC_MBX_PORT_RSP_OK:
				rsp = QLCNIC_RCODE_SUCCESS;
				break;
			default:
				if (opcode == QLCNIC_CMD_CONFIG_MAC_VLAN) {
					rsp = qlcnic_83xx_mac_rcode(adapter);
					if (!rsp)
						goto out;
				}
				netdev_err(adapter->netdev,
					   "MBX command 0x%x failed with err:0x%x\n",
					   opcode, mbx_err_code);
				rsp = mbx_err_code;
				qlcnic_dump_mbx(adapter, cmd);
				break;
			}
			goto out;
		}
	} while (time_before(jiffies, count));

	netdev_err(adapter->netdev, "MBX command 0x%x timed out\n", opcode);
	rsp = QLCNIC_RCODE_TIMEOUT;
	qlcnic_dump_mbx(adapter, cmd);
	/* Take FW dump */
	qlcnic_83xx_dev_request_reset(adapter, QLCNIC_FORCE_FW_DUMP_KEY);
out:
	/* clear fw mbx control register */
	QLCWRX(ahw, QLCNIC_FW_MBX_CTRL, QLCNIC_CLR_OWNER);
	spin_unlock_irqrestore(&ahw->mbx_lock, flags);
	return rsp;
}

/* Allocate mailbox incoming and outgoing registers. It should be used with a
 * follow up call to qlcnic_free_mbx_args
 */
int qlcnic_83xx_alloc_mbx_args(struct qlcnic_cmd_args *mbx,
		struct qlcnic_adapter *adapter, u32 type)
{
	int i, size;
	const struct qlcnic_mailbox_metadata *mbx_tbl;

	mbx_tbl = qlcnic_83xx_mbx_tbl;
	size = ARRAY_SIZE(qlcnic_83xx_mbx_tbl);
	for (i = 0; i < size; i++) {
		if (type == mbx_tbl[i].cmd) {
			mbx->req.num = mbx_tbl[i].in_args;
			mbx->rsp.num = mbx_tbl[i].out_args;
			mbx->req.arg = (u32 *) kcalloc(mbx->req.num,
				sizeof(u32), GFP_ATOMIC);
			if (!mbx->req.arg)
				return -ENOMEM;
			mbx->rsp.arg = (u32 *) kcalloc(mbx->rsp.num,
				sizeof(u32), GFP_ATOMIC);
			if (!mbx->rsp.arg) {
				kfree(mbx->req.arg);
				mbx->req.arg = NULL;
				return -ENOMEM;
			}
			memset(mbx->req.arg, 0, sizeof(u32) * mbx->req.num);
			memset(mbx->rsp.arg, 0, sizeof(u32) * mbx->rsp.num);
			mbx->req.arg[0] = (type | (mbx->req.num << 16) |
			(adapter->ahw->fw_hal_version << 29));
			break;
		}
	}
	return 0;
}

/* Free up mailbox registers
 */
void qlcnic_free_mbx_args(struct qlcnic_cmd_args *cmd)
{
	kfree(cmd->req.arg);
	cmd->req.arg = NULL;
	kfree(cmd->rsp.arg);
	cmd->rsp.arg = NULL;
}

void qlcnic_83xx_read_crb(struct qlcnic_adapter *adapter, char *buf,
	loff_t offset, size_t size)
{
	u32 data;
	int err;

	if (adapter->ahw->hw_ops->api_lock(adapter)) {
		netdev_err(adapter->netdev,
			"%s: failed to acquire lock. addr offset 0x%x\n",
			__func__, (u32)offset);
		return;
	}

	data = qlcnic_83xx_rd_reg_indirect(adapter, (u32) offset, &err);
	adapter->ahw->hw_ops->api_unlock(adapter);

	if (err == -EIO) {
		netdev_err(adapter->netdev,
			"%s: failed. addr offset 0x%x\n",
					__func__, (u32)offset);
		return;
	}
	memcpy(buf, &data, size);
}

void qlcnic_83xx_write_crb(struct qlcnic_adapter *adapter, char *buf,
	loff_t offset, size_t size)
{
	u32 data;

	memcpy(&data, buf, size);
	qlcnic_83xx_wrt_reg_indirect(adapter, (u32) offset, data);
}

static void
qlcnic_83xx_recover_driver_lock(struct qlcnic_adapter *adapter)
{
	u32 val;
	u32 id;

	val = QLCRDX(adapter->ahw, QLC_83XX_RECOVER_DRV_LOCK);

	/* Check if recovery need to be performed by the calling function */
	if ((val & QLC_83XX_DRV_LOCK_RECOVERY_STATUS_MASK) == 0) {
		val = val & ~0x3F;
		val = val | ((adapter->portnum << 2) |
				QLC_83XX_NEED_DRV_LOCK_RECOVERY);
		QLCWRX(adapter->ahw, QLC_83XX_RECOVER_DRV_LOCK, val);
		netdev_info(adapter->netdev,
			"%s: lock recovery initiated\n", __func__);
		msleep(QLC_83XX_DRV_LOCK_RECOVERY_DELAY);
		val = QLCRDX(adapter->ahw, QLC_83XX_RECOVER_DRV_LOCK);
		id = ((val >> 2) & 0xF);
		if (id == adapter->portnum) {
			val = val & ~QLC_83XX_DRV_LOCK_RECOVERY_STATUS_MASK;
			val = val | QLC_83XX_DRV_LOCK_RECOVERY_IN_PROGRESS;
			QLCWRX(adapter->ahw, QLC_83XX_RECOVER_DRV_LOCK, val);
			/* Force release the lock */
			QLCRDX(adapter->ahw, QLC_83XX_DRV_UNLOCK);
			/* Clear recovery bits */
			val = val & ~0x3F;
			QLCWRX(adapter->ahw, QLC_83XX_RECOVER_DRV_LOCK, val);
			netdev_info(adapter->netdev,
				"%s: lock recovery completed\n", __func__);
		} else {
			netdev_info(adapter->netdev,
				"%s: func %d to resume lock recovery process\n",
					 __func__, id);
		}
	} else {
		netdev_info(adapter->netdev,
			"%s: lock recovery initiated by other functions\n",
					 __func__);
	}
}

int
qlcnic_83xx_lock_driver(struct qlcnic_adapter *adapter)
{
	u32 lock_alive_counter, val, id, i = 0, status = 0, temp = 0;
	int max_attempt = 0;

	while (status == 0) {
		status = QLCRDX(adapter->ahw, QLC_83XX_DRV_LOCK);
		if (status)
			break;

		msleep(QLC_83XX_DRV_LOCK_WAIT_DELAY);
		i++;

		if (i == 1)
			temp = QLCRDX(adapter->ahw, QLC_83XX_DRV_LOCK_ID);

		if (i == QLC_83XX_DRV_LOCK_WAIT_COUNTER) {
			val = QLCRDX(adapter->ahw, QLC_83XX_DRV_LOCK_ID);
			if (val == temp) {
				id = val & 0xFF;
				netdev_info(adapter->netdev,
					"%s: lock to be recovered from %d\n",
								 __func__, id);
				qlcnic_83xx_recover_driver_lock(adapter);
				i = 0;
				max_attempt++;
			} else {
				netdev_info(adapter->netdev,
				"%s: failed to acquire lock\n", __func__);
				return -EIO;
			}
		}

		/* Force exit from while loop after few attempts */
		if (max_attempt == QLC_83XX_MAX_DRV_LOCK_RECOVERY_ATTEMPT) {
			netdev_info(adapter->netdev,
				"%s: failed to acquire lock\n", __func__);
			return -EIO;
		}
	}

	val = QLCRDX(adapter->ahw, QLC_83XX_DRV_LOCK_ID);
	lock_alive_counter = val >> 8;
	lock_alive_counter++;
	val = lock_alive_counter << 8 | adapter->portnum;
	QLCWRX(adapter->ahw, QLC_83XX_DRV_LOCK_ID, val);

	return 0;
}

void
qlcnic_83xx_unlock_driver(struct qlcnic_adapter *adapter)
{
	u32 val, lock_alive_counter, id;

	val = QLCRDX(adapter->ahw, QLC_83XX_DRV_LOCK_ID);
	id = val & 0xFF;
	lock_alive_counter = val >> 8;

	if (id != adapter->portnum)
		netdev_err(adapter->netdev,
			"%s: Warning! func %d is unlocking lock owned by %d\n",
					__func__, adapter->portnum, id);

	val = (lock_alive_counter << 8) | 0xFF;
	QLCWRX(adapter->ahw, QLC_83XX_DRV_LOCK_ID, val);
	QLCRDX(adapter->ahw, QLC_83XX_DRV_UNLOCK);
}

int
qlcnic_83xx_lock_flash(struct qlcnic_adapter *adapter)
{
	int id, timeout = 0;
	u32 status = 0;

	while (status == 0) {
		status = QLCRD(adapter, QLCNIC_FLASH_LOCK);
		if (status)
			break;

		if (++timeout >= QLC_83XX_FLASH_LOCK_TIMEOUT) {
			id = QLCRD(adapter, QLCNIC_FLASH_LOCK_OWNER);
			netdev_err(adapter->netdev,
				"%s: failed: lock held by %d\n", __func__, id);
			return -EIO;
		}
		msleep(1);
	}

	QLCWR(adapter, QLCNIC_FLASH_LOCK_OWNER, adapter->portnum);
	return 0;
}

void
qlcnic_83xx_unlock_flash(struct qlcnic_adapter *adapter)
{
	QLCRD(adapter, QLCNIC_FLASH_UNLOCK);
	QLCWR(adapter, QLCNIC_FLASH_LOCK_OWNER, 0xFF);
}

static int
qlcnic_83xx_poll_flash_status_reg(struct qlcnic_adapter *adapter)
{
	u32 status;
	int err, retries = QLC_83XX_FLASH_READ_RETRY_COUNT;

	do {
		status = qlcnic_83xx_rd_reg_indirect(adapter,
						QLC_83XX_FLASH_STATUS, &err);
		if (err == -EIO)
			return -EIO;

		if ((status & QLC_83XX_FLASH_STATUS_READY) ==
						QLC_83XX_FLASH_STATUS_READY)
			break;

		msleep(QLC_83XX_FLASH_STATUS_REG_POLL_DELAY);
	} while (--retries);

	if (!retries)
		return -EIO;

	return 0;
}

static int
qlcnic_83xx_enable_flash_write_op(struct qlcnic_adapter *adapter)
{
	int ret;

	qlcnic_83xx_wrt_reg_indirect(adapter, QLC_83XX_FLASH_ADDR,
			(QLC_83XX_FLASH_FDT_WRITE_DEF_SIG |
			adapter->ahw->flash_fdt.write_statusreg_cmd));
	qlcnic_83xx_wrt_reg_indirect(adapter, QLC_83XX_FLASH_WRDATA,
			adapter->ahw->flash_fdt.write_enable_bits);
	qlcnic_83xx_wrt_reg_indirect(adapter, QLC_83XX_FLASH_CONTROL,
			QLC_83XX_FLASH_SECOND_ERASE_MS_VAL);

	ret = qlcnic_83xx_poll_flash_status_reg(adapter);
	if (ret)
		return -EIO;

	return 0;
}

static int
qlcnic_83xx_disable_flash_write_op(struct qlcnic_adapter *adapter)
{
	int ret;

	qlcnic_83xx_wrt_reg_indirect(adapter, QLC_83XX_FLASH_ADDR,
			(QLC_83XX_FLASH_FDT_WRITE_DEF_SIG |
			adapter->ahw->flash_fdt.write_statusreg_cmd));
	qlcnic_83xx_wrt_reg_indirect(adapter, QLC_83XX_FLASH_WRDATA,
			adapter->ahw->flash_fdt.write_enable_bits);
	qlcnic_83xx_wrt_reg_indirect(adapter, QLC_83XX_FLASH_CONTROL,
			QLC_83XX_FLASH_SECOND_ERASE_MS_VAL);

	ret = qlcnic_83xx_poll_flash_status_reg(adapter);
	if (ret)
		return -EIO;

	return 0;
}

int
qlcnic_83xx_flash_read_u32(struct qlcnic_adapter *adapter, u32 flash_addr,
						u8 *p_data, int u32_word_count)
{
	int i, err;
	u32 u32_word;
	u32 addr = flash_addr;

	if (qlcnic_83xx_lock_flash(adapter) != 0)
		return -EIO;

	if (addr & 0x3) {
		dev_err(&adapter->pdev->dev, "Illegal addr = 0x%x\n", addr);
		qlcnic_83xx_unlock_flash(adapter);
		return -EIO;
	}

	for (i = 0; i < u32_word_count; i++) {
		if (qlcnic_83xx_wrt_reg_indirect(adapter,
					QLC_83XX_FLASH_DIRECT_WINDOW, (addr))) {
			qlcnic_83xx_unlock_flash(adapter);
			return -EIO;
		}

		u32_word = qlcnic_83xx_rd_reg_indirect(adapter,
					QLC_83XX_FLASH_DIRECT_DATA(addr), &err);
		if (err == -EIO) {
			qlcnic_83xx_unlock_flash(adapter);
			return -EIO;
		}

		*(__le32 *)p_data  = le32_to_cpu(u32_word);
		p_data = p_data + 4;
		addr = addr + 4;
	}

	qlcnic_83xx_unlock_flash(adapter);

	return 0;
}

int
qlcnic_83xx_lockless_flash_read_u32(struct qlcnic_adapter *adapter,
			 u32 flash_addr, u8 *p_data, int u32_word_count)
{
	int err;
	u32 i, u32_word, flash_offset;
	u32 addr = flash_addr;

	flash_offset = addr & (QLCNIC_FLASH_SECTOR_SIZE - 1);

	if (addr & 0x3) {
		dev_err(&adapter->pdev->dev, "Illegal addr = 0x%x\n", addr);
		return -EIO;
	}

	qlcnic_83xx_wrt_reg_indirect(adapter,
			QLC_83XX_FLASH_DIRECT_WINDOW, (addr));

	/* Check if data is spread across multiple sectors  */
	if ((flash_offset + (u32_word_count * sizeof(u32))) >
				(QLCNIC_FLASH_SECTOR_SIZE - 1)) {

		/* Multi sector read */
		for (i = 0; i < u32_word_count; i++) {
			u32_word = qlcnic_83xx_rd_reg_indirect(adapter,
					QLC_83XX_FLASH_DIRECT_DATA(addr), &err);
			if (err == -EIO)
				return -EIO;

			*(__le32 *)p_data  = le32_to_cpu(u32_word);
			p_data = p_data + 4;
			addr = addr + 4;
			flash_offset = flash_offset + 4;

			if (flash_offset > (QLCNIC_FLASH_SECTOR_SIZE - 1)) {
				/* This write is needed once for each sector */
				qlcnic_83xx_wrt_reg_indirect(adapter,
					QLC_83XX_FLASH_DIRECT_WINDOW, (addr));
				flash_offset = 0;
			}
		}
	} else {
		/* Single sector read */
		for (i = 0; i < u32_word_count; i++) {
			u32_word = qlcnic_83xx_rd_reg_indirect(adapter,
					QLC_83XX_FLASH_DIRECT_DATA(addr), &err);
			if (err == -EIO)
				return -EIO;

			*(__le32 *)p_data  = cpu_to_le32(u32_word);
			p_data = p_data + 4;
			addr = addr + 4;
		}
	}

	return 0;
}

static int
qlcnic_83xx_read_flash_status_reg(struct qlcnic_adapter *adapter)
{
	int ret, err;

	qlcnic_83xx_wrt_reg_indirect(adapter, QLC_83XX_FLASH_ADDR,
				QLC_83XX_FLASH_OEM_READ_SIG);
	qlcnic_83xx_wrt_reg_indirect(adapter, QLC_83XX_FLASH_CONTROL,
				QLC_83XX_FLASH_READ_CONTROL_VAL);
	ret = qlcnic_83xx_poll_flash_status_reg(adapter);
	if (ret)
		return -EIO;

	ret = qlcnic_83xx_rd_reg_indirect(adapter, QLC_83XX_FLASH_RDDATA, &err);
	return ret&0xFF;
}

int
qlcnic_83xx_read_flash_mfg_id(struct qlcnic_adapter *adapter)
{
	int ret, err, mfg_id;

	if (qlcnic_83xx_lock_flash(adapter))
		return -EIO;

	qlcnic_83xx_wrt_reg_indirect(adapter, QLC_83XX_FLASH_ADDR,
			QLC_83XX_FLASH_FDT_READ_MFG_ID_VAL);
	qlcnic_83xx_wrt_reg_indirect(adapter, QLC_83XX_FLASH_CONTROL,
			QLC_83XX_FLASH_READ_CONTROL_VAL);

	ret = qlcnic_83xx_poll_flash_status_reg(adapter);
	if (ret) {
		qlcnic_83xx_unlock_flash(adapter);
		return -EIO;
	}

	mfg_id = qlcnic_83xx_rd_reg_indirect(adapter,
				QLC_83XX_FLASH_RDDATA, &err);
	qlcnic_83xx_unlock_flash(adapter);

	if (err == -EIO)
		return -EIO;

	adapter->flash_mfg_id = (mfg_id & 0xFF);

	return 0;
}

int
qlcnic_83xx_read_flash_descriptor_table(struct qlcnic_adapter *adapter)
{
	int count, fdt_size, ret = 0;

	fdt_size = sizeof(struct qlcnic_flash_desc_table);
	count = fdt_size/sizeof(u32);

	if (qlcnic_83xx_lock_flash(adapter))
		return -EIO;

	memset(&adapter->ahw->flash_fdt, 0, fdt_size);
	ret = qlcnic_83xx_lockless_flash_read_u32(adapter,
				QLCNIC_FDT_LOCATION,
				(u8 *)&adapter->ahw->flash_fdt,
				count);

	qlcnic_83xx_unlock_flash(adapter);
	return ret;
}

int
qlcnic_83xx_erase_flash_sector(struct qlcnic_adapter *adapter,
					u32 sector_start_addr)
{
	u32 reversed_addr;
	int ret = -EIO;

	if (qlcnic_83xx_lock_flash(adapter) != 0)
		return -EIO;

	if (adapter->ahw->flash_fdt.flash_manuf == adapter->flash_mfg_id) {
		ret = qlcnic_83xx_enable_flash_write_op(adapter);
		if (ret) {
			qlcnic_83xx_unlock_flash(adapter);
			netdev_err(adapter->netdev,
				"%s failed at %d\n",
				__func__, __LINE__);
			return ret;
		}
	}

	ret = qlcnic_83xx_poll_flash_status_reg(adapter);
	if (ret) {
		qlcnic_83xx_unlock_flash(adapter);
		dev_err(&adapter->pdev->dev,
			 " %s: failed at %d\n", __func__, __LINE__);
		return -EIO;
	}

	reversed_addr = (((sector_start_addr & 0xFF) << 16) |
			((sector_start_addr & 0xFF0000) >> 16));

	qlcnic_83xx_wrt_reg_indirect(adapter,
				QLC_83XX_FLASH_WRDATA, reversed_addr);

	if (adapter->ahw->flash_fdt.flash_manuf == adapter->flash_mfg_id)
		qlcnic_83xx_wrt_reg_indirect(adapter, QLC_83XX_FLASH_ADDR,
			(QLC_83XX_FLASH_FDT_ERASE_DEF_SIG |
			adapter->ahw->flash_fdt.erase_cmd));
	else
		qlcnic_83xx_wrt_reg_indirect(adapter, QLC_83XX_FLASH_ADDR,
				QLC_83XX_FLASH_OEM_ERASE_SIG);
	qlcnic_83xx_wrt_reg_indirect(adapter, QLC_83XX_FLASH_CONTROL,
				QLC_83XX_FLASH_LAST_ERASE_MS_VAL);

	ret = qlcnic_83xx_poll_flash_status_reg(adapter);
	if (ret) {
		qlcnic_83xx_unlock_flash(adapter);
		dev_err(&adapter->pdev->dev,
			 " %s: failed at %d\n", __func__, __LINE__);
		return -EIO;
	}

	if (adapter->ahw->flash_fdt.flash_manuf == adapter->flash_mfg_id) {
		ret = qlcnic_83xx_disable_flash_write_op(adapter);
		if (ret) {
			qlcnic_83xx_unlock_flash(adapter);
			netdev_err(adapter->netdev,
				 " %s: failed at %d\n", __func__, __LINE__);
			return ret;
		}
	}

	qlcnic_83xx_unlock_flash(adapter);

	return 0;
}

/* Note: User should take appropriate locks */
int
qlcnic_83xx_flash_write_u32(struct qlcnic_adapter *adapter, u32 addr,
					u32 *p_data)
{
	int ret = -EIO;

	qlcnic_83xx_wrt_reg_indirect(adapter, QLC_83XX_FLASH_ADDR,
						0x00800000 | (addr >> 2));
	qlcnic_83xx_wrt_reg_indirect(adapter, QLC_83XX_FLASH_WRDATA, *p_data);
	qlcnic_83xx_wrt_reg_indirect(adapter, QLC_83XX_FLASH_CONTROL,
				QLC_83XX_FLASH_LAST_ERASE_MS_VAL);
	ret = qlcnic_83xx_poll_flash_status_reg(adapter);
	if (ret) {
		dev_err(&adapter->pdev->dev,
			 " %s: failed at %d\n", __func__, __LINE__);
		return -EIO;
	}

	return 0;
}

/* Use this API to write data in bulk mode. */
/* Note: User should take appropriate locks */
/* min size = 2 4 byte words, max size = 64 4 byte words */

int
qlcnic_83xx_flash_bulk_write(struct qlcnic_adapter *adapter, u32 addr,
					u32 *p_data, int u32_word_count)
{
	u32 temp;
	int ret = -EIO, err;

	if ((u32_word_count <  QLC_83XX_FLASH_BULK_WRITE_MIN) ||
	(u32_word_count >  QLC_83XX_FLASH_BULK_WRITE_MAX)) {
		dev_err(&adapter->pdev->dev,
			 " %s: Invalid word count\n", __func__);
		return -EIO;
	}

	temp = qlcnic_83xx_rd_reg_indirect(adapter,
				QLC_83XX_FLASH_SPI_CONTROL, &err);
	if (err == -EIO)
		return -EIO;

	qlcnic_83xx_wrt_reg_indirect(adapter,
				QLC_83XX_FLASH_SPI_CONTROL,
				(temp | QLC_83XX_FLASH_SPI_CONTROL_VAL));
	qlcnic_83xx_wrt_reg_indirect(adapter, QLC_83XX_FLASH_ADDR,
				QLC_83XX_FLASH_ADDR_TEMP_VAL);

	/* First DWORD write */
	qlcnic_83xx_wrt_reg_indirect(adapter, QLC_83XX_FLASH_WRDATA, *p_data++);
	qlcnic_83xx_wrt_reg_indirect(adapter, QLC_83XX_FLASH_CONTROL,
				QLC_83XX_FLASH_FIRST_WRITE_MS_PATTERN);
	ret = qlcnic_83xx_poll_flash_status_reg(adapter);
	if (ret) {
		netdev_err(adapter->netdev,
			 " %s: failed at %d\n", __func__, __LINE__);
		return -EIO;
	}

	u32_word_count--;

	qlcnic_83xx_wrt_reg_indirect(adapter, QLC_83XX_FLASH_ADDR,
			QLC_83XX_FLASH_ADDR_SECOND_TEMP_VAL);

	/* Second to N-1 DWORD writes */
	while (u32_word_count != 1) {
		qlcnic_83xx_wrt_reg_indirect(adapter,
					QLC_83XX_FLASH_WRDATA, *p_data++);
		qlcnic_83xx_wrt_reg_indirect(adapter,
					QLC_83XX_FLASH_CONTROL,
					QLC_83XX_FLASH_SECOND_WRITE_MS_PATTERN);
		ret = qlcnic_83xx_poll_flash_status_reg(adapter);
		if (ret) {
			dev_err(&adapter->pdev->dev,
				 " %s: failed at %d\n", __func__, __LINE__);
			return -EIO;
		}
		u32_word_count--;
	}

	qlcnic_83xx_wrt_reg_indirect(adapter, QLC_83XX_FLASH_ADDR,
				QLC_83XX_FLASH_ADDR_TEMP_VAL | (addr >> 2));
	/* Last DWORD write */
	qlcnic_83xx_wrt_reg_indirect(adapter, QLC_83XX_FLASH_WRDATA, *p_data++);
	qlcnic_83xx_wrt_reg_indirect(adapter, QLC_83XX_FLASH_CONTROL,
				QLC_83XX_FLASH_LAST_WRITE_MS_PATTERN);
	ret = qlcnic_83xx_poll_flash_status_reg(adapter);
	if (ret) {
		dev_err(&adapter->pdev->dev,
			 " %s: failed at %d\n", __func__, __LINE__);
		return -EIO;
	}

	ret = qlcnic_83xx_rd_reg_indirect(adapter,
				QLC_83XX_FLASH_SPI_STATUS, &err);
	if (err == -EIO)
		return -EIO;

	if ((ret & QLC_83XX_FLASH_SPI_CONTROL_VAL) ==
	QLC_83XX_FLASH_SPI_CONTROL_VAL) {
		dev_err(&adapter->pdev->dev,
			 " %s: failed at %d\n", __func__, __LINE__);
		/* Operation failed, clear error bit */
		temp = qlcnic_83xx_rd_reg_indirect(adapter,
					QLC_83XX_FLASH_SPI_CONTROL, &err);
		if (err == -EIO)
			return -EIO;

		qlcnic_83xx_wrt_reg_indirect(adapter,
				QLC_83XX_FLASH_SPI_CONTROL,
				(temp | QLC_83XX_FLASH_SPI_CONTROL_VAL));
	}

	return 0;
}

static struct qlcnic_rx_buffer *
qlcnic_83xx_process_rcv(struct qlcnic_adapter *adapter,
		struct qlcnic_host_sds_ring *sds_ring,
		u8 ring, u64 sts_data[])
{
	struct net_device *netdev = adapter->netdev;
	struct qlcnic_recv_context *recv_ctx = adapter->recv_ctx;
	struct qlcnic_rx_buffer *buffer;
	struct sk_buff *skb;
	struct qlcnic_host_rds_ring *rds_ring;
	int index, length, cksum;
	u16 vid = 0xffff;

	if (unlikely(ring >= adapter->max_rds_rings))
		return NULL;

	rds_ring = &recv_ctx->rds_rings[ring];

	index = qlcnic_83xx_hndl(sts_data[0]);
	if (unlikely(index >= rds_ring->num_desc))
		return NULL;

	buffer = &rds_ring->rx_buf_arr[index];

	length = qlcnic_83xx_pktln(sts_data[0]);
	cksum  = qlcnic_83xx_csum_status(sts_data[1]);
	skb = qlcnic_process_rxbuf(adapter, rds_ring, index, cksum);
	if (!skb)
		return buffer;

	if (length > rds_ring->skb_size)
		skb_put(skb, rds_ring->skb_size);
	else
		skb_put(skb, length);

	if (unlikely(qlcnic_check_rx_tagging(adapter, skb, &vid))) {
		adapter->stats.rxdropped++;
		dev_kfree_skb(skb);
		return buffer;
	}

	skb->protocol = eth_type_trans(skb, netdev);

	if ((vid != 0xffff) && netdev->vlgrp)
		vlan_gro_receive(&sds_ring->napi, netdev->vlgrp, vid, skb);
	else
		napi_gro_receive(&sds_ring->napi, skb);

	adapter->stats.rx_pkts++;
	adapter->stats.rxbytes += length;

	return buffer;
}

static struct qlcnic_rx_buffer *
qlcnic_83xx_process_lro(struct qlcnic_adapter *adapter,
		struct qlcnic_host_sds_ring *sds_ring,
		u8 ring, u64 sts_data[])
{
	struct net_device *netdev = adapter->netdev;
	struct qlcnic_recv_context *recv_ctx = adapter->recv_ctx;
	struct qlcnic_rx_buffer *buffer;
	struct sk_buff *skb;
	struct qlcnic_host_rds_ring *rds_ring;
	struct iphdr *iph;
	struct ipv6hdr *ipv6h;
	struct tcphdr *th;
	bool push;
	int l2_hdr_offset, l4_hdr_offset;
	int index;
	u16 lro_length, length, data_offset;
	u16 vid = 0xffff;

	if (unlikely(ring > adapter->max_rds_rings))
		return NULL;

	rds_ring = &recv_ctx->rds_rings[ring];

	index = qlcnic_83xx_hndl(sts_data[0]);
	if (unlikely(index > rds_ring->num_desc))
		return NULL;

	buffer = &rds_ring->rx_buf_arr[index];

	lro_length = qlcnic_83xx_lro_pktln(sts_data[0]);
	l2_hdr_offset = qlcnic_83xx_l2_hdr_off(sts_data[1]);
	l4_hdr_offset = qlcnic_83xx_l4_hdr_off(sts_data[1]);
	push = qlcnic_83xx_is_psh_bit(sts_data[1]);

	skb = qlcnic_process_rxbuf(adapter, rds_ring, index, STATUS_CKSUM_OK);
	if (!skb)
		return buffer;
	if (qlcnic_83xx_is_tstamp(sts_data[1]))
		data_offset = l4_hdr_offset + QLC_TCP_TS_HDR_SIZE;
	else
		data_offset = l4_hdr_offset + QLC_TCP_HDR_SIZE;

	skb_put(skb, lro_length + data_offset);

	skb_pull(skb, l2_hdr_offset);

	if (unlikely(qlcnic_check_rx_tagging(adapter, skb, &vid))) {
		adapter->stats.rxdropped++;
		dev_kfree_skb(skb);
		return buffer;
	}

	skb->protocol = eth_type_trans(skb, netdev);

	if (htons(skb->protocol) == ETH_P_IPV6) {
		ipv6h = (struct ipv6hdr *)skb->data;
		th = (struct tcphdr *)(skb->data + sizeof(struct ipv6hdr));

		length = (th->doff << 2) + lro_length;
		ipv6h->payload_len = htons(length);
	} else {
		iph = (struct iphdr *)skb->data;
		th = (struct tcphdr *)(skb->data + (iph->ihl << 2));

		length = (iph->ihl << 2) + (th->doff << 2) + lro_length;
		iph->tot_len = htons(length);
		iph->check = 0;
		iph->check = ip_fast_csum((unsigned char *)iph, iph->ihl);
	}


	th->psh = push;

	length = skb->len;

	if (adapter->flags & QLCNIC_FW_LRO_MSS_CAP)
		skb_shinfo(skb)->gso_size =
			qlcnic_83xx_get_lro_sts_mss(sts_data[0]);

	if ((vid != 0xffff) && netdev->vlgrp)
		vlan_hwaccel_receive_skb(skb, netdev->vlgrp, vid);
	else
		netif_receive_skb(skb);

	adapter->stats.lro_pkts++;
	adapter->stats.lrobytes += length;
	return buffer;
}

static int
qlcnic_83xx_process_rcv_ring(struct qlcnic_host_sds_ring *sds_ring, int max)
{
	struct qlcnic_adapter *adapter = sds_ring->adapter;
	struct list_head *cur;
	struct status_desc *desc;
	struct qlcnic_rx_buffer *rxbuf = NULL;
	u64 sts_data[2];

	int count = 0, opcode;
	u8 ring;
	u32 consumer = sds_ring->consumer;

	while (count < max) {
		desc = &sds_ring->desc_head[consumer];
		sts_data[1] = le64_to_cpu(desc->status_desc_data[1]);
		opcode = qlcnic_83xx_opcode(sts_data[1]);
		if (!opcode)
			break;
		sts_data[0] = le64_to_cpu(desc->status_desc_data[0]);
		ring = QLCNIC_FETCH_RING_ID(sts_data[0]);

		switch (opcode) {
		case QLCNIC_83XX_REG_DESC:
			rxbuf = qlcnic_83xx_process_rcv(adapter, sds_ring,
					ring, sts_data);
			break;
		case QLCNIC_83XX_LRO_DESC:
			rxbuf = qlcnic_83xx_process_lro(adapter, sds_ring,
					ring, sts_data);
			break;
		default:
			dev_info(&adapter->pdev->dev,
				"Unkonwn opcode: 0x%x\n", opcode);
			goto skip;
		}

		if (likely(rxbuf))
			list_add_tail(&rxbuf->list, &sds_ring->free_list[ring]);
		else
			adapter->stats.null_rxbuf++;

skip:
		desc = &sds_ring->desc_head[consumer];
		/* Reset the descriptor */
		desc->status_desc_data[1] = 0;
		consumer = get_next_index(consumer, sds_ring->num_desc);
		count++;
	}
	for (ring = 0; ring < adapter->max_rds_rings; ring++) {
		struct qlcnic_host_rds_ring *rds_ring =
			&adapter->recv_ctx->rds_rings[ring];

		if (!list_empty(&sds_ring->free_list[ring])) {
			list_for_each(cur, &sds_ring->free_list[ring]) {
				rxbuf = list_entry(cur,
						struct qlcnic_rx_buffer, list);
				qlcnic_alloc_rx_skb(adapter, rds_ring, rxbuf);
			}
			spin_lock(&rds_ring->lock);
			list_splice_tail_init(&sds_ring->free_list[ring],
						&rds_ring->free_list);
			spin_unlock(&rds_ring->lock);
		}

		qlcnic_post_rx_buffers_nodb(adapter, rds_ring, ring);
	}

	if (count) {
		sds_ring->consumer = consumer;
		writel(consumer, sds_ring->crb_sts_consumer);
	}
	return count;
}

void qlcnic_83xx_idc_aen_work(struct work_struct *work)
{
	struct qlcnic_adapter *adapter;
	struct qlcnic_cmd_args cmd;
	int i, err = 0;

	adapter = container_of(work, struct qlcnic_adapter, idc_aen_work.work);

	adapter->ahw->hw_ops->alloc_mbx_args(&cmd, adapter, QLCNIC_CMD_IDC_ACK);
	for (i = 1; i < QLC_83XX_MBX_AEN_CNT; i++)
		cmd.req.arg[i] = adapter->ahw->mbox_aen[i];
	err = adapter->ahw->hw_ops->mbx_cmd(adapter, &cmd);
	if (err)
		netdev_info(adapter->netdev,
			    "%s: Mailbox IDC ACK failed.\n", __func__);
	qlcnic_free_mbx_args(&cmd);
}

static void
qlcnic_83xx_handle_idc_comp_aen(struct qlcnic_adapter *adapter, u32 data[])
{
	dev_dbg(&adapter->pdev->dev, "Completion AEN:0x%x.\n",
			QLCNIC_MBX_RSP(data[0]));
	clear_bit(QLC_83XX_IDC_COMP_AEN, &adapter->ahw->idc.status);
	return;
}

void qlcnic_83xx_process_aen(struct qlcnic_adapter *adapter)
{
	struct qlcnic_hardware_context *ahw = adapter->ahw;
	u32 event[QLC_83XX_MBX_AEN_CNT];
	int i;

	for (i = 0; i < QLC_83XX_MBX_AEN_CNT; i++)
		event[i] = le32_to_cpu(readl(QLCNIC_MBX_FW(ahw, i)));
	switch (QLCNIC_MBX_RSP(event[0])) {

	/* This case is only active when we arrive here
	 * as a result of issuing a mailbox command to
	 * the firmware.
	 */
	case QLCNIC_MBX_LINK_EVENT:
		/* Link Event */
		qlcnic_83xx_handle_link_aen(adapter, event);
		break;
	case QLCNIC_MBX_COMP_EVENT:
		/* IDC Completion Notification */
		qlcnic_83xx_handle_idc_comp_aen(adapter, event);
		break;
	case QLCNIC_MBX_REQUEST_EVENT:
		/* IDC Request Notification */
		for (i = 0; i < QLC_83XX_MBX_AEN_CNT; i++)
			adapter->ahw->mbox_aen[i] = QLCNIC_MBX_RSP(event[i]);
		queue_delayed_work(adapter->qlcnic_wq,
						&adapter->idc_aen_work, 0);
		break;
	case QLCNIC_MBX_TIME_EXTEND_EVENT:
		/* IDC Time Extend Notification */
		break;
	case QLCNIC_MBX_SFP_INSERT_EVENT:
		/* IDC SFP+ Transceiver Insertion Notification */
		dev_info(&adapter->pdev->dev, "SFP+ Insert AEN:0x%x.\n",
				QLCNIC_MBX_RSP(event[0]));
		break;
	case QLCNIC_MBX_SFP_REMOVE_EVENT:
		/* IDC SFP+ Transceiver Removal Notification */
		dev_info(&adapter->pdev->dev, "SFP Removed AEN:0x%x.\n",
				QLCNIC_MBX_RSP(event[0]));
		break;
	default:
		dev_dbg(&adapter->pdev->dev, "Unsupported AEN:0x%x.\n",
				QLCNIC_MBX_RSP(event[0]));
		break;
	}
	QLCWRX(ahw, QLCNIC_FW_MBX_CTRL, QLCNIC_CLR_OWNER);
}

static void qlcnic_83xx_poll_process_aen(struct qlcnic_adapter *adapter)
{
	unsigned long flags;
	u32 mask, resp, event;

	spin_lock_irqsave(&adapter->ahw->mbx_lock, flags);
	resp = QLCRDX(adapter->ahw, QLCNIC_FW_MBX_CTRL);
	if (!(resp & QLCNIC_SET_OWNER))
		goto out;
	event = le32_to_cpu(readl(QLCNIC_MBX_FW(adapter->ahw, 0)));
	if (event &  QLCNIC_MBX_ASYNC_EVENT)
		qlcnic_83xx_process_aen(adapter);
out:
	mask = QLCRDX(adapter->ahw, QLCNIC_DEF_INT_MASK);
	writel(0, adapter->ahw->pci_base0 + mask);
	spin_unlock_irqrestore(&adapter->ahw->mbx_lock, flags);
}

static int qlcnic_83xx_poll(struct napi_struct *napi, int budget)
{
	struct qlcnic_host_sds_ring *sds_ring =
		container_of(napi, struct qlcnic_host_sds_ring, napi);

	struct qlcnic_adapter *adapter = sds_ring->adapter;

	/* there is only 1 tx ring in this path */
	struct qlcnic_host_tx_ring *tx_ring = adapter->tx_ring;

	int tx_complete, work_done;

	if (!(adapter->flags & QLCNIC_MSIX_ENABLED))
		qlcnic_83xx_poll_process_aen(adapter);

	tx_complete = qlcnic_process_cmd_ring(adapter, tx_ring, budget);

	work_done = qlcnic_83xx_process_rcv_ring(sds_ring, budget);

	if ((work_done < budget) && tx_complete) {
		napi_complete(&sds_ring->napi);
		if (test_bit(__QLCNIC_DEV_UP, &adapter->state))
			qlcnic_83xx_enable_intr(adapter, sds_ring);
	}

	return work_done;
}

static int qlcnic_83xx_msix_tx_poll(struct napi_struct *napi, int budget)
{
	struct qlcnic_host_tx_ring *tx_ring =
		container_of(napi, struct qlcnic_host_tx_ring, napi);

	struct qlcnic_adapter *adapter = tx_ring->adapter;
	int work_done;

	work_done = qlcnic_process_cmd_ring(adapter, tx_ring,
				 QLCNIC_TX_POLL_BUDGET);

	if (work_done) {
		napi_complete(&tx_ring->napi);
		if (test_bit(__QLCNIC_DEV_UP , &adapter->state))
			qlcnic_83xx_enable_tx_intr(adapter, tx_ring);
	}

	return work_done;
}

static int qlcnic_83xx_rx_poll(struct napi_struct *napi, int budget)
{
	struct qlcnic_host_sds_ring *sds_ring =
		container_of(napi, struct qlcnic_host_sds_ring, napi);

	struct qlcnic_adapter *adapter = sds_ring->adapter;
	int work_done;

	work_done = qlcnic_83xx_process_rcv_ring(sds_ring, budget);

	if (work_done < budget) {
		napi_complete(&sds_ring->napi);
		if (test_bit(__QLCNIC_DEV_UP, &adapter->state))
			qlcnic_83xx_enable_intr(adapter, sds_ring);
	}

	return work_done;
}

void
qlcnic_83xx_napi_enable(struct qlcnic_adapter *adapter)
{
	int ring;
	struct qlcnic_host_sds_ring *sds_ring;
	struct qlcnic_host_tx_ring *tx_ring;
	struct qlcnic_recv_context *recv_ctx = adapter->recv_ctx;

	if (adapter->is_up != QLCNIC_ADAPTER_UP_MAGIC)
		return;

	for (ring = 0; ring < adapter->max_sds_rings; ring++) {
		sds_ring = &recv_ctx->sds_rings[ring];
		napi_enable(&sds_ring->napi);
		qlcnic_83xx_enable_intr(adapter, sds_ring);
	}

	if (adapter->flags & QLCNIC_MSIX_ENABLED) {
		for (ring = 0; ring < adapter->max_drv_tx_rings; ring++) {
			tx_ring = &adapter->tx_ring[ring];
			napi_enable(&tx_ring->napi);
			qlcnic_83xx_enable_tx_intr(adapter, tx_ring);
		}
	}
}

void
qlcnic_83xx_napi_disable(struct qlcnic_adapter *adapter)
{
	int ring;
	struct qlcnic_host_sds_ring *sds_ring;
	struct qlcnic_recv_context *recv_ctx = adapter->recv_ctx;
	struct qlcnic_host_tx_ring *tx_ring;

	if (adapter->is_up != QLCNIC_ADAPTER_UP_MAGIC)
		return;

	for (ring = 0; ring < adapter->max_sds_rings; ring++) {
		sds_ring = &recv_ctx->sds_rings[ring];
		writel(1, sds_ring->crb_intr_mask);
		napi_synchronize(&sds_ring->napi);
		napi_disable(&sds_ring->napi);
	}

	if (adapter->flags & QLCNIC_MSIX_ENABLED) {
		for (ring = 0; ring < adapter->max_drv_tx_rings; ring++) {
			tx_ring = &adapter->tx_ring[ring];
			qlcnic_83xx_disable_tx_intr(adapter, tx_ring);
			napi_synchronize(&tx_ring->napi);
			napi_disable(&tx_ring->napi);
		}
	}
}

int
qlcnic_83xx_napi_add(struct qlcnic_adapter *adapter, struct net_device *netdev)
{
	int ring;
	struct qlcnic_host_sds_ring *sds_ring;
	struct qlcnic_host_tx_ring *tx_ring;
	struct qlcnic_recv_context *recv_ctx = adapter->recv_ctx;

	if (qlcnic_alloc_sds_rings(recv_ctx, adapter->max_sds_rings))
		return -ENOMEM;

	for (ring = 0; ring < adapter->max_sds_rings; ring++) {
		sds_ring = &recv_ctx->sds_rings[ring];
		if (adapter->flags & QLCNIC_MSIX_ENABLED)
			netif_napi_add(netdev, &sds_ring->napi,
			    qlcnic_83xx_rx_poll, QLCNIC_NETDEV_WEIGHT * 2);
		else
			netif_napi_add(netdev, &sds_ring->napi,
			    qlcnic_83xx_poll,
				QLCNIC_NETDEV_WEIGHT/adapter->max_sds_rings);
	}

	if (qlcnic_alloc_tx_rings(adapter, netdev)) {
		qlcnic_free_sds_rings(recv_ctx);
		return -ENOMEM;
	}

	if (adapter->flags & QLCNIC_MSIX_ENABLED) {
		for (ring = 0; ring < adapter->max_drv_tx_rings; ring++) {
			tx_ring = &adapter->tx_ring[ring];
			netif_napi_add(netdev, &tx_ring->napi,
				qlcnic_83xx_msix_tx_poll,
				QLCNIC_NETDEV_WEIGHT);
		}
	}

	return 0;
}

void
qlcnic_83xx_napi_del(struct qlcnic_adapter *adapter)
{
	int ring;
	struct qlcnic_host_sds_ring *sds_ring;
	struct qlcnic_recv_context *recv_ctx = adapter->recv_ctx;
	struct qlcnic_host_tx_ring *tx_ring;

	for (ring = 0; ring < adapter->max_sds_rings; ring++) {
		sds_ring = &recv_ctx->sds_rings[ring];
		netif_napi_del(&sds_ring->napi);
	}

	qlcnic_free_sds_rings(adapter->recv_ctx);

	if ((adapter->flags & QLCNIC_MSIX_ENABLED)) {
		for (ring = 0; ring < adapter->max_drv_tx_rings; ring++) {
			tx_ring = &adapter->tx_ring[ring];
			netif_napi_del(&tx_ring->napi);
		}
	}

	qlcnic_free_tx_rings(adapter);
}

void qlcnic_83xx_process_rcv_diag(struct qlcnic_adapter *adapter,
		struct qlcnic_host_sds_ring *sds_ring,
		int ring, u64 sts_data[])
{
	struct qlcnic_recv_context *recv_ctx = adapter->recv_ctx;
	struct sk_buff *skb;
	struct qlcnic_host_rds_ring *rds_ring;
	int index, length, cksum;

	if (unlikely(ring >= adapter->max_rds_rings))
		return;

	rds_ring = &recv_ctx->rds_rings[ring];
	index = qlcnic_83xx_hndl(sts_data[0]);
	if (unlikely(index >= rds_ring->num_desc))
		return;

	length = qlcnic_83xx_pktln(sts_data[0]);
	cksum  = qlcnic_83xx_csum_status(sts_data[0]);
	skb = qlcnic_process_rxbuf(adapter, rds_ring, index, STATUS_CKSUM_OK);
	if (!skb)
		return;

	if (length > rds_ring->skb_size)
		skb_put(skb, rds_ring->skb_size);
	else
		skb_put(skb, length);

	if (!qlcnic_check_loopback_buff(skb->data, adapter->mac_addr))
		adapter->ahw->diag_cnt++;
	else
		dump_skb(skb, adapter);

	dev_kfree_skb_any(skb);
	return;
}

void qlcnic_83xx_process_rcv_ring_diag(struct qlcnic_host_sds_ring *sds_ring)
{
	struct qlcnic_adapter *adapter = sds_ring->adapter;
	struct status_desc *desc;
	u64 sts_data[2];
	int ring, opcode;

	u32 consumer = sds_ring->consumer;

	desc = &sds_ring->desc_head[consumer];
	sts_data[0] = le64_to_cpu(desc->status_desc_data[0]);
	sts_data[1] = le64_to_cpu(desc->status_desc_data[1]);
	opcode = qlcnic_83xx_opcode(sts_data[1]);
	if (!opcode)
		return;

	ring = QLCNIC_FETCH_RING_ID(qlcnic_83xx_hndl(sts_data[0]));
	qlcnic_83xx_process_rcv_diag(adapter, sds_ring, ring, sts_data);

	desc = &sds_ring->desc_head[consumer];
	desc->status_desc_data[0] = cpu_to_le64(STATUS_OWNER_PHANTOM);
	consumer = get_next_index(consumer, sds_ring->num_desc);

	sds_ring->consumer = consumer;
	writel(consumer, sds_ring->crb_sts_consumer);
}

/* Configure interrupts command registers interrupt vectors with the FW
 * @op_type: 1 for creation and 0 for deletion
 * @type: Interrupt type, INTx or MSI-X
 * */
int qlcnic_83xx_config_intrpt(struct qlcnic_adapter *adapter, bool op_type)

{
	int i, index, err;
	u8 max_ints;
	u32 val;
	struct qlcnic_cmd_args cmd;

	max_ints = adapter->ahw->num_msix;
	adapter->ahw->hw_ops->alloc_mbx_args(&cmd, adapter,
					QLCNIC_CMD_CONFIG_INTRPT);
	cmd.req.arg[1] = cpu_to_le32(max_ints);
	for(i = 0, index = 2; i < max_ints; i++) {
		val = (op_type ? QLCNIC_INTRPT_ADD : QLCNIC_INTRPT_DEL) |
			(adapter->ahw->intr_tbl[i].type << 4);
		if (adapter->ahw->intr_tbl[i].type == QLCNIC_INTRPT_MSIX)
			val |= (adapter->ahw->intr_tbl[i].id << 16);
		cmd.req.arg[index++] = cpu_to_le32(val);
	}
	err = adapter->ahw->hw_ops->mbx_cmd(adapter, &cmd);
	if (err) {
		dev_err(&adapter->pdev->dev,
			"Failed to configure interrupts 0x%x\n", err);
		goto out;
	}

	max_ints = le32_to_cpu(cmd.rsp.arg[1]);
	for (i = 0, index = 2; i < max_ints; i++, index += 2) {

		val = le32_to_cpu(cmd.rsp.arg[index]);
		if (LSB(val)) {
			dev_info(&adapter->pdev->dev,
				"Can't configure interrupt %d\n",
				adapter->ahw->intr_tbl[i].id);
			continue;
		}
		if (op_type) {
			adapter->ahw->intr_tbl[i].id = MSW(val);
			adapter->ahw->intr_tbl[i].enabled = 1;
			adapter->ahw->intr_tbl[i].src =
				le32_to_cpu(cmd.rsp.arg[index + 1]);
		} else {
			adapter->ahw->intr_tbl[i].id = i;
			adapter->ahw->intr_tbl[i].enabled = 0;
			adapter->ahw->intr_tbl[i].src = 0;
		}
	}
out:
	qlcnic_free_mbx_args(&cmd);
	return err;
}

int qlcnic_83xx_add_rings(struct qlcnic_adapter *adapter)
{
	int index, i, err, sds_mbx_size;
	u32 *buf, intrpt_id, intr_mask;
	u16 context_id;
	u8 num_sds;
	struct qlcnic_cmd_args cmd;
	struct qlcnic_host_sds_ring *sds;
	struct qlcnic_sds_mbx sds_mbx;
	struct qlcnic_add_rings_mbx_out *mbx_out;
	struct qlcnic_recv_context *recv_ctx = adapter->recv_ctx;
	struct qlcnic_hardware_context *ahw = adapter->ahw;
	sds_mbx_size = sizeof(struct qlcnic_sds_mbx);
	context_id = recv_ctx->context_id;

	num_sds = (adapter->max_sds_rings - QLCNIC_MAX_RING_SETS);

	ahw->hw_ops->alloc_mbx_args(&cmd, adapter,
				    QLCNIC_CMD_ADD_RCV_RINGS);

	cmd.req.arg[1] = cpu_to_le32(0 | (num_sds << 8) | (context_id << 16));

	/* set up status rings, mbx 2-81 */
	index = 2;

	for (i = 8; i < adapter->max_sds_rings; i++) {
		memset(&sds_mbx, 0, sds_mbx_size);
		sds = &recv_ctx->sds_rings[i];
		sds->consumer = 0;
		memset(sds->desc_head, 0, STATUS_DESC_RINGSIZE(sds));
		sds_mbx.phy_addr = cpu_to_le64(sds->phys_addr);
		sds_mbx.sds_ring_size = cpu_to_le16(sds->num_desc);

		if (adapter->flags & QLCNIC_MSIX_ENABLED)
			intrpt_id = ahw->intr_tbl[i].id;
		else
			intrpt_id = QLCRDX(ahw, QLCNIC_DEF_INT_ID);

		if (adapter->ahw->diag_test != QLCNIC_LOOPBACK_TEST)
			sds_mbx.intrpt_id = cpu_to_le32(intrpt_id);
		else
			sds_mbx.intrpt_id = 0xffff;
		sds_mbx.intrpt_val = 0;
		buf = &cmd.req.arg[index];
		memcpy(buf, &sds_mbx, sds_mbx_size);
		index += sds_mbx_size/sizeof(u32);
	}

	/* send the mailbox command */
	err = ahw->hw_ops->mbx_cmd(adapter, &cmd);
	if (err) {
		dev_err(&adapter->pdev->dev,
			"Failed to add rings %d\n", err);
		goto out;
	}
	mbx_out = (struct qlcnic_add_rings_mbx_out *) &cmd.rsp.arg[1];

	index = 0;
	/* status descriptor ring */
	for (i = 8; i < adapter->max_sds_rings; i++) {
		sds = &recv_ctx->sds_rings[i];
		sds->crb_sts_consumer = ahw->pci_base0 +
			le32_to_cpu(mbx_out->host_csmr[index]);
		if (adapter->flags & QLCNIC_MSIX_ENABLED)
			intr_mask = ahw->intr_tbl[i].src;
		else
			intr_mask = QLCRDX(ahw, QLCNIC_DEF_INT_MASK);
		sds->crb_intr_mask = ahw->pci_base0 + intr_mask;
		index++;
	}
out:
	qlcnic_free_mbx_args(&cmd);
	return err;
}

int qlcnic_83xx_create_rx_ctx(struct qlcnic_adapter *adapter)
{
	int i, err, index, sds_mbx_size, rds_mbx_size;
	u8 num_sds, num_rds;
	u32 *buf, intrpt_id, intr_mask, cap = 0;
	struct qlcnic_host_sds_ring *sds;
	struct qlcnic_host_rds_ring *rds;
	struct qlcnic_sds_mbx sds_mbx;
	struct qlcnic_rds_mbx rds_mbx;
	struct qlcnic_cmd_args cmd;
	struct qlcnic_rcv_mbx_out *mbx_out;
	struct qlcnic_recv_context *recv_ctx = adapter->recv_ctx;
	struct qlcnic_hardware_context *ahw = adapter->ahw;
	num_rds = adapter->max_rds_rings;

	if (adapter->max_sds_rings <= QLCNIC_MAX_RING_SETS)
		num_sds = adapter->max_sds_rings;
	else
		num_sds = QLCNIC_MAX_RING_SETS;

	sds_mbx_size = sizeof(struct qlcnic_sds_mbx);
	rds_mbx_size = sizeof(struct qlcnic_rds_mbx);
	cap = QLCNIC_CAP0_LEGACY_CONTEXT;

	if (adapter->flags & QLCNIC_FW_LRO_MSS_CAP)
		cap |= QLCNIC_FW_83XX_CAP_LRO_MSS;

	/* set mailbox hdr and capabilities */
	adapter->ahw->hw_ops->alloc_mbx_args(&cmd, adapter,
					QLCNIC_CMD_CREATE_RX_CTX);
	cmd.req.arg[1] = cpu_to_le32(cap);
	cmd.req.arg[5] = cpu_to_le32(1 | (num_rds << 5) | (num_sds << 8) |
				(QLCNIC_HOST_83XX_RDS_MODE_UNIQUE << 16));
	/* set up status rings, mbx 8-57/87 */
	index = QLCNIC_HOST_SDS_MBX_IDX;
	for (i = 0; i < num_sds; i++) {
		memset(&sds_mbx, 0, sds_mbx_size);
		sds = &recv_ctx->sds_rings[i];
		sds->consumer = 0;
		memset(sds->desc_head, 0, STATUS_DESC_RINGSIZE(sds));
		sds_mbx.phy_addr = cpu_to_le64(sds->phys_addr);
		sds_mbx.sds_ring_size = cpu_to_le16(sds->num_desc);
		if (adapter->flags & QLCNIC_MSIX_ENABLED)
			intrpt_id = ahw->intr_tbl[i].id;
		else
			intrpt_id = QLCRDX(ahw, QLCNIC_DEF_INT_ID);
		if (adapter->ahw->diag_test != QLCNIC_LOOPBACK_TEST)
			sds_mbx.intrpt_id = cpu_to_le32(intrpt_id);
		else
			sds_mbx.intrpt_id = 0xffff;
		sds_mbx.intrpt_val = 0;
		buf = &cmd.req.arg[index];
		memcpy(buf, &sds_mbx, sds_mbx_size);
		index += sds_mbx_size/sizeof(u32);
	}
	/* set up receive rings, mbx 88-111/135 */
	index = QLCNIC_HOST_RDS_MBX_IDX;
	rds = &recv_ctx->rds_rings[0];
	rds->producer = 0;
	memset(&rds_mbx, 0, rds_mbx_size);
	rds_mbx.phy_addr_reg = cpu_to_le64(rds->phys_addr);
	rds_mbx.reg_ring_sz = cpu_to_le16(rds->dma_size);
	rds_mbx.reg_ring_len = cpu_to_le16(rds->num_desc);
	/* Jumbo ring */
	rds = &recv_ctx->rds_rings[1];
	rds->producer = 0;
	rds_mbx.phy_addr_jmb = cpu_to_le64(rds->phys_addr);
	rds_mbx.jmb_ring_sz = cpu_to_le16(rds->dma_size);
	rds_mbx.jmb_ring_len = cpu_to_le16(rds->num_desc);
	buf = &cmd.req.arg[index];
	memcpy(buf, &rds_mbx, rds_mbx_size);

	/* send the mailbox command */
	err = ahw->hw_ops->mbx_cmd(adapter, &cmd);
	if (err) {
		dev_err(&adapter->pdev->dev,
			"Failed to create Rx ctx in firmware%d\n", err);
		goto out;
	}
	mbx_out = (struct qlcnic_rcv_mbx_out *) &cmd.rsp.arg[1];
	recv_ctx->context_id = le16_to_cpu(mbx_out->ctx_id);
	recv_ctx->state = le32_to_cpu(mbx_out->state);
	recv_ctx->virt_port = le16_to_cpu(mbx_out->vport_id);
	dev_info(&adapter->pdev->dev, "Rx Context[%d] Created, state:0x%x\n",
		recv_ctx->context_id, recv_ctx->state);
	/* Receive descriptor ring */
	/* Standard ring */
	rds = &recv_ctx->rds_rings[0];
	rds->crb_rcv_producer = ahw->pci_base0 +
			le32_to_cpu(mbx_out->host_prod[0].reg_buf);
	/* Jumbo ring */
	rds = &recv_ctx->rds_rings[1];
	rds->crb_rcv_producer = ahw->pci_base0 +
			le32_to_cpu(mbx_out->host_prod[0].jmb_buf);
	/* status descriptor ring */
	for (i = 0; i < num_sds; i++) {
		sds = &recv_ctx->sds_rings[i];
		sds->crb_sts_consumer = ahw->pci_base0 +
			le32_to_cpu(mbx_out->host_csmr[i]);
		if (adapter->flags & QLCNIC_MSIX_ENABLED)
			intr_mask = ahw->intr_tbl[i].src;
		else
			intr_mask = QLCRDX(ahw, QLCNIC_DEF_INT_MASK);
		sds->crb_intr_mask = ahw->pci_base0 + intr_mask;
	}

	if (adapter->max_sds_rings > QLCNIC_MAX_RING_SETS)
		err = qlcnic_83xx_add_rings(adapter);
out:
	qlcnic_free_mbx_args(&cmd);
	return err;
}

int qlcnic_83xx_create_tx_ctx(struct qlcnic_adapter *adapter,
		struct qlcnic_host_tx_ring *tx, int ring)
{
	int err;
	u16 msix_id;
	u32 *buf, intr_mask;
	struct qlcnic_cmd_args cmd;
	struct qlcnic_tx_mbx mbx;
	struct qlcnic_tx_mbx_out *mbx_out;
	struct qlcnic_hardware_context *ahw = adapter->ahw;

	/* Reset host resources */
	tx->producer = 0;
	tx->sw_consumer = 0;
	*(tx->hw_consumer) = 0;

	memset(&mbx, 0, sizeof(struct qlcnic_tx_mbx));

	/* setup mailbox inbox registerss */
	mbx.phys_addr = cpu_to_le64(tx->phys_addr);
	mbx.cnsmr_index = cpu_to_le64(tx->hw_cons_phys_addr);
	mbx.size = cpu_to_le16(tx->num_desc);
	if (adapter->flags & QLCNIC_MSIX_ENABLED)
		msix_id = ahw->intr_tbl[adapter->max_sds_rings + ring].id;
	else
		msix_id = QLCRDX(ahw, QLCNIC_DEF_INT_ID);
	if (adapter->ahw->diag_test != QLCNIC_LOOPBACK_TEST)
		mbx.intr_id = cpu_to_le16(msix_id);
	else
		mbx.intr_id = 0xffff;
	mbx.src = 0;

	adapter->ahw->hw_ops->alloc_mbx_args(&cmd, adapter,
					QLCNIC_CMD_CREATE_TX_CTX);
	cmd.req.arg[1] = cpu_to_le32(QLCNIC_CAP0_LEGACY_CONTEXT);
	cmd.req.arg[5] = cpu_to_le32(QLCNIC_MAX_TX_QUEUES);
	buf = &cmd.req.arg[6];
	memcpy(buf, &mbx, sizeof(struct qlcnic_tx_mbx));
	/* send the mailbox command*/
	err = ahw->hw_ops->mbx_cmd(adapter, &cmd);
	if (err) {
		dev_err(&adapter->pdev->dev,
			"Failed to create Tx ctx in firmware 0x%x\n", err);
		goto out;
	}
	mbx_out = (struct qlcnic_tx_mbx_out *) &cmd.rsp.arg[2];
	tx->crb_cmd_producer = ahw->pci_base0 + le32_to_cpu(mbx_out->host_prod);
	tx->ctx_id = le16_to_cpu(mbx_out->ctx_id);
	if (adapter->flags & QLCNIC_MSIX_ENABLED) {
		intr_mask = ahw->intr_tbl[adapter->max_sds_rings + ring].src;
		tx->crb_intr_mask = ahw->pci_base0 + intr_mask;
	}
	dev_info(&adapter->pdev->dev, "Tx Context[0x%x] Created, state:0x%x\n",
		tx->ctx_id, mbx_out->state);
out:
	qlcnic_free_mbx_args(&cmd);
	return err;
}

static int qlcnic_83xx_diag_alloc_res(struct net_device *netdev, int test)
{
	struct qlcnic_adapter *adapter = netdev_priv(netdev);
	struct qlcnic_host_sds_ring *sds_ring;
	struct qlcnic_host_rds_ring *rds_ring;
	u8 ring;
	int ret;

	netif_device_detach(netdev);

	if (netif_running(netdev))
		__qlcnic_down(adapter, netdev);

	qlcnic_detach(adapter);

	adapter->max_sds_rings = 1;
	adapter->ahw->diag_test = test;
	adapter->ahw->linkup = 0;

	ret = qlcnic_attach(adapter);
	if (ret) {
		netif_device_attach(netdev);
		return ret;
	}

	ret = qlcnic_fw_create_ctx(adapter);
	if (ret) {
		qlcnic_detach(adapter);
		netif_device_attach(netdev);
		return ret;
	}

	for (ring = 0; ring < adapter->max_rds_rings; ring++) {
		rds_ring = &adapter->recv_ctx->rds_rings[ring];
		qlcnic_post_rx_buffers(adapter, rds_ring, ring);
	}

	if (adapter->ahw->diag_test == QLCNIC_INTERRUPT_TEST) {
		for (ring = 0; ring < adapter->max_sds_rings; ring++) {
			sds_ring = &adapter->recv_ctx->sds_rings[ring];
			qlcnic_83xx_enable_intr(adapter, sds_ring);
		}
	}

	if (adapter->ahw->diag_test == QLCNIC_LOOPBACK_TEST) {
		/* disable and free mailbox interrupt */
		if (adapter->flags & QLCNIC_MSIX_ENABLED)
			qlcnic_83xx_config_intrpt(adapter, 0);
		qlcnic_83xx_free_mbx_intr(adapter);
		adapter->ahw->loopback_state = 0;
		adapter->ahw->hw_ops->setup_link_event(adapter, 1);
	}

	set_bit(__QLCNIC_DEV_UP, &adapter->state);
	return 0;
}

static void qlcnic_83xx_diag_free_res(struct net_device *netdev,
					int max_sds_rings)
{
	struct qlcnic_adapter *adapter = netdev_priv(netdev);
	struct qlcnic_host_sds_ring *sds_ring;
	int ring, err;

	clear_bit(__QLCNIC_DEV_UP, &adapter->state);
	if (adapter->ahw->diag_test == QLCNIC_INTERRUPT_TEST) {
		for (ring = 0; ring < adapter->max_sds_rings; ring++) {
			sds_ring = &adapter->recv_ctx->sds_rings[ring];
			writel(1, sds_ring->crb_intr_mask);
		}
	}

	qlcnic_fw_destroy_ctx(adapter);
	qlcnic_detach(adapter);

	if (adapter->ahw->diag_test == QLCNIC_LOOPBACK_TEST) {
		err = qlcnic_83xx_setup_mbx_intr(adapter);
		if (err) {
			netdev_err(netdev,
				"%s: failed to setup mbx interrupt\n",
				__func__);
			goto out;
		}
	}
	adapter->ahw->diag_test = 0;
	adapter->max_sds_rings = max_sds_rings;

	if (qlcnic_attach(adapter))
		goto out;

	if (netif_running(netdev))
		__qlcnic_up(adapter, netdev);
out:
	netif_device_attach(netdev);
}

int qlcnic_83xx_interrupt_test(struct net_device *netdev)
{
	struct qlcnic_adapter *adapter = netdev_priv(netdev);
	struct qlcnic_hardware_context *ahw = adapter->ahw;
	struct qlcnic_cmd_args cmd;
	u32 data;
	u16 intrpt_id, id;
	u8 val;
	int ret, max_sds_rings = adapter->max_sds_rings;

	if (test_and_set_bit(__QLCNIC_RESETTING, &adapter->state))
		return -EIO;

	ret = qlcnic_83xx_diag_alloc_res(netdev, QLCNIC_INTERRUPT_TEST);
	if (ret)
		goto fail_diag_irq;

	ahw->diag_cnt = 0;
	ahw->hw_ops->alloc_mbx_args(&cmd, adapter, QLCNIC_CMD_INTRPT_TEST);

	if (adapter->flags & QLCNIC_MSIX_ENABLED)
		intrpt_id = adapter->ahw->intr_tbl[0].id;
	else
		intrpt_id = QLCRDX(adapter->ahw, QLCNIC_DEF_INT_ID);

	cmd.req.arg[1] = cpu_to_le32(1);
	cmd.req.arg[2] = cpu_to_le32(intrpt_id);
	cmd.req.arg[3] = cpu_to_le32(BIT_0);

	ret = adapter->ahw->hw_ops->mbx_cmd(adapter, &cmd);
	data = le32_to_cpu(cmd.rsp.arg[2]);
	id = LSW(data);
	val = LSB(MSW(data));
	if (id != intrpt_id)
		netdev_info(adapter->netdev,
			"Interrupt generated: 0x%x, requested:0x%x\n",
			id, intrpt_id);
	if (val) {
		netdev_err(adapter->netdev,
			   "Interrupt test error: 0x%x\n", val);
	}
	if (ret)
		goto done;

	msleep(10);
	ret = !adapter->ahw->diag_cnt;

done:
	qlcnic_free_mbx_args(&cmd);
	qlcnic_83xx_diag_free_res(netdev, max_sds_rings);

fail_diag_irq:
	adapter->max_sds_rings = max_sds_rings;
	clear_bit(__QLCNIC_RESETTING, &adapter->state);
	return ret;
}

int
qlcnic_83xx_config_led(struct qlcnic_adapter *adapter, u32 state, u32 beacon)
{
	struct qlcnic_cmd_args cmd;
	u32 mbx_in;
	int i, status;

	if (state) {
		/* Get LED configuration */
		adapter->ahw->hw_ops->alloc_mbx_args(&cmd, adapter,
						QLCNIC_CMD_GET_LED_CONFIG);
		status = adapter->ahw->hw_ops->mbx_cmd(adapter, &cmd);
		if (status) {
			netdev_err(adapter->netdev,
					"Get led config failed.\n");
			goto mbx_err;
		} else {
			for (i = 0; i < 4; i++)
				adapter->ahw->mbox_reg[i] = cmd.rsp.arg[i+1];
		}
		qlcnic_free_mbx_args(&cmd);
		/* Set LED Configuration */
		mbx_in = (LSW(QLCNIC_83XX_LED_CONFIG) << 16) |
				LSW(QLCNIC_83XX_LED_CONFIG);
		adapter->ahw->hw_ops->alloc_mbx_args(&cmd, adapter,
						QLCNIC_CMD_SET_LED_CONFIG);
		cmd.req.arg[1] = cpu_to_le32(mbx_in);
		cmd.req.arg[2] = cpu_to_le32(mbx_in);
		cmd.req.arg[3] = cpu_to_le32(mbx_in);
		if (beacon)
			cmd.req.arg[4] = QLCNIC_83XX_ENABLE_BEACON;
		status = adapter->ahw->hw_ops->mbx_cmd(adapter, &cmd);
		if (status) {
			netdev_err(adapter->netdev,
					"Set led config failed.\n");
		}
mbx_err:
		qlcnic_free_mbx_args(&cmd);
		return status;
	} else {
		/* Restoring default LED configuration */
		adapter->ahw->hw_ops->alloc_mbx_args(&cmd, adapter,
						QLCNIC_CMD_SET_LED_CONFIG);
		cmd.req.arg[1] = adapter->ahw->mbox_reg[0];
		cmd.req.arg[2] = adapter->ahw->mbox_reg[1];
		cmd.req.arg[3] = adapter->ahw->mbox_reg[2];
		if (beacon)
			cmd.req.arg[4] = adapter->ahw->mbox_reg[3];
		status = adapter->ahw->hw_ops->mbx_cmd(adapter, &cmd);
		if (status)
			netdev_err(adapter->netdev,
					"Restoring led config failed.\n");
		qlcnic_free_mbx_args(&cmd);
		return status;
	}
}

void
qlcnic_83xx_register_nic_idc_func(struct qlcnic_adapter *adapter, int enable)
{
	struct qlcnic_cmd_args cmd;
	int status;

	if (enable) {
		adapter->ahw->hw_ops->alloc_mbx_args(&cmd, adapter,
						QLCNIC_CMD_INIT_NIC_FUNC);
		cmd.req.arg[1] = cpu_to_le32(1 | BIT_0 | BIT_31);
	} else {
		adapter->ahw->hw_ops->alloc_mbx_args(&cmd, adapter,
						QLCNIC_CMD_STOP_NIC_FUNC);
		cmd.req.arg[1] = cpu_to_le32(0 | BIT_0 | BIT_31);
	}
	status = adapter->ahw->hw_ops->mbx_cmd(adapter, &cmd);
	if (status) {
		netdev_err(adapter->netdev,
			"Failed to %s in NIC IDC function event.\n",
			(enable ? "register" : "unregistered"));
	}
	qlcnic_free_mbx_args(&cmd);
}

static int qlcnic_83xx_set_port_config(struct qlcnic_adapter *adapter)
{
	struct qlcnic_cmd_args cmd;
	int err;

	adapter->ahw->hw_ops->alloc_mbx_args(&cmd, adapter,
					QLCNIC_CMD_SET_PORT_CONFIG);
	cmd.req.arg[1] = cpu_to_le32(adapter->ahw->port_config);
	err = adapter->ahw->hw_ops->mbx_cmd(adapter, &cmd);
	if (err)
		netdev_err(adapter->netdev, "Set Port Config failed.\n");
	qlcnic_free_mbx_args(&cmd);
	return err;
}

static int qlcnic_83xx_get_port_config(struct qlcnic_adapter *adapter)
{
	struct qlcnic_cmd_args cmd;
	int err;

	adapter->ahw->hw_ops->alloc_mbx_args(&cmd, adapter,
					QLCNIC_CMD_GET_PORT_CONFIG);
	err = adapter->ahw->hw_ops->mbx_cmd(adapter, &cmd);
	if (err)
		netdev_err(adapter->netdev, "Get Port config failed\n");
	else
		adapter->ahw->port_config = le32_to_cpu(cmd.rsp.arg[1]);
	qlcnic_free_mbx_args(&cmd);
	return err;
}

int qlcnic_83xx_setup_link_event(struct qlcnic_adapter *adapter, int enable)
{
	int err;
	struct qlcnic_cmd_args cmd;

	adapter->ahw->hw_ops->alloc_mbx_args(&cmd, adapter,
					QLCNIC_CMD_GET_LINK_EVENT);
	cmd.req.arg[1] = cpu_to_le32((enable ? 1 : 0) | BIT_8 |
		((adapter->recv_ctx->context_id) << 16));
	err = adapter->ahw->hw_ops->mbx_cmd(adapter, &cmd);
	if (err)
		dev_info(&adapter->pdev->dev,
			"Setup linkevent mailbox failed\n");
	qlcnic_free_mbx_args(&cmd);
	return err;
}

int qlcnic_83xx_nic_set_promisc(struct qlcnic_adapter *adapter, u32 mode)
{
	int err;
	struct qlcnic_cmd_args cmd;

	if (adapter->recv_ctx->state == QLCNIC_HOST_CTX_STATE_FREED)
		return -EIO;

	adapter->ahw->hw_ops->alloc_mbx_args(&cmd, adapter,
					QLCNIC_CMD_CONFIGURE_MAC_RX_MODE);
	cmd.req.arg[1] = cpu_to_le32((mode ? 1 : 0) |
		(adapter->recv_ctx->context_id) << 16);
	err = adapter->ahw->hw_ops->mbx_cmd(adapter, &cmd);
	if (err)
		dev_info(&adapter->pdev->dev,
			"Promiscous mode config failed\n");
	qlcnic_free_mbx_args(&cmd);

	return err;
}

int qlcnic_83xx_loopback_test(struct net_device *netdev, u8 mode)
{
	struct qlcnic_adapter *adapter = netdev_priv(netdev);
	struct qlcnic_hardware_context *ahw = adapter->ahw;
	int ret = 0, loop = 0, max_sds_rings = adapter->max_sds_rings;

	QLCDB(adapter, DRV, "%s loopback test in progress\n",
		mode == QLCNIC_ILB_MODE ? "internal" : "external");
	if (ahw->op_mode == QLCNIC_NON_PRIV_FUNC) {
		netdev_warn(netdev, "Loopback test not supported for non "
			    "privilege function\n");
		return ret;
	}

	if (test_and_set_bit(__QLCNIC_RESETTING, &adapter->state))
		return -EBUSY;

	ret = qlcnic_83xx_diag_alloc_res(netdev, QLCNIC_LOOPBACK_TEST);
	if (ret)
		goto fail_diag_alloc;

	ret = qlcnic_83xx_set_lb_mode(adapter, mode);
	if (ret)
		goto free_diag_res;

	/* Poll for link up event before running traffic */
	do {
		msleep(500);
		qlcnic_83xx_process_aen(adapter);
		if (loop++ > QLCNIC_ILB_MAX_RCV_LOOP) {
			netdev_info(netdev, "Firmware didn't sent link up "
				    "event to loopback request\n");
			ret = -QLCNIC_FW_NOT_RESPOND;
			qlcnic_83xx_clear_lb_mode(adapter, mode);
			goto free_diag_res;
		}
	} while ((adapter->ahw->linkup && ahw->has_link_events) != 1);

	ret = qlcnic_do_lb_test(adapter, mode);

	qlcnic_83xx_clear_lb_mode(adapter, mode);

free_diag_res:
	qlcnic_83xx_diag_free_res(netdev, max_sds_rings);

fail_diag_alloc:
	adapter->max_sds_rings = max_sds_rings;
	clear_bit(__QLCNIC_RESETTING, &adapter->state);
	return ret;
}

int qlcnic_83xx_set_lb_mode(struct qlcnic_adapter *adapter, u8 mode)
{
	struct qlcnic_hardware_context *ahw = adapter->ahw;
	int status = 0, loop = 0;
	u32 config;

	status = qlcnic_83xx_get_port_config(adapter);
	if (status)
		return status;

	config = ahw->port_config;
	set_bit(QLC_83XX_IDC_COMP_AEN, &ahw->idc.status);

	if (mode == QLCNIC_ILB_MODE)
		ahw->port_config |= QLC_83XX_CFG_LOOPBACK_HSS;
	if (mode == QLCNIC_ELB_MODE)
		ahw->port_config |= QLC_83XX_CFG_LOOPBACK_EXT;

	status = qlcnic_83xx_set_port_config(adapter);
	if (status) {
		netdev_err(adapter->netdev,
			"Failed to Set Loopback Mode = 0x%x.\n",
			ahw->port_config);
		ahw->port_config = config;
		clear_bit(QLC_83XX_IDC_COMP_AEN, &ahw->idc.status);
		return status;
	}

	/* Poll for Link and IDC Completion AEN */
	do {
		msleep(300);
		qlcnic_83xx_process_aen(adapter);
		if (loop++ > QLCNIC_ILB_MAX_RCV_LOOP) {
			netdev_err(adapter->netdev,
				"Firmware didn't sent IDC completion AEN\n");
			clear_bit(QLC_83XX_IDC_COMP_AEN, &ahw->idc.status);
			qlcnic_83xx_clear_lb_mode(adapter, mode);
			return -EIO;
		}
	} while (test_bit(QLC_83XX_IDC_COMP_AEN, &ahw->idc.status));

	qlcnic_83xx_sre_macaddr_change(adapter, adapter->mac_addr, 0,
					QLCNIC_MAC_ADD);
	return status;
}

int qlcnic_83xx_clear_lb_mode(struct qlcnic_adapter *adapter, u8 mode)
{
	struct qlcnic_hardware_context *ahw = adapter->ahw;
	int status = 0, loop = 0;
	u32 config = ahw->port_config;

	set_bit(QLC_83XX_IDC_COMP_AEN, &ahw->idc.status);
	if (mode == QLCNIC_ILB_MODE)
		ahw->port_config &= ~QLC_83XX_CFG_LOOPBACK_HSS;
	if (mode == QLCNIC_ELB_MODE)
		ahw->port_config &= ~QLC_83XX_CFG_LOOPBACK_EXT;

	status = qlcnic_83xx_set_port_config(adapter);
	if (status) {
		netdev_err(adapter->netdev,
			"Failed to Clear Loopback Mode = 0x%x.\n",
			ahw->port_config);
		ahw->port_config = config;
		clear_bit(QLC_83XX_IDC_COMP_AEN, &ahw->idc.status);
		return status;
	}

	/* Poll for Link and IDC Completion AEN */
	do {
		msleep(300);
		qlcnic_83xx_process_aen(adapter);
		if (loop++ > QLCNIC_ILB_MAX_RCV_LOOP) {
			netdev_err(adapter->netdev,
				"Firmware didn't sent IDC completion AEN\n");
			clear_bit(QLC_83XX_IDC_COMP_AEN, &ahw->idc.status);
			return -EIO;
		}
	} while (test_bit(QLC_83XX_IDC_COMP_AEN, &ahw->idc.status));

	qlcnic_83xx_sre_macaddr_change(adapter, adapter->mac_addr, 0,
					QLCNIC_MAC_DEL);
	return status;
}

void qlcnic_83xx_config_ipaddr(struct qlcnic_adapter *adapter,
				 __be32 ip, int mode)
{
	int err;
	struct qlcnic_cmd_args cmd;

	adapter->ahw->hw_ops->alloc_mbx_args(&cmd, adapter,
					QLCNIC_CMD_CONFIGURE_IP_ADDR);
	if (mode == QLCNIC_IP_UP)
		cmd.req.arg[1] = cpu_to_le32(1 |
				adapter->recv_ctx->context_id << 16);
	else
		cmd.req.arg[1] = cpu_to_le32(2 |
				adapter->recv_ctx->context_id << 16);
	cmd.req.arg[2] = cpu_to_le32(ip);

	err = adapter->ahw->hw_ops->mbx_cmd(adapter, &cmd);
	if (err != QLCNIC_RCODE_SUCCESS)
		dev_err(&adapter->netdev->dev,
				"could not notify %s IP 0x%x request\n",
				(mode == QLCNIC_IP_UP) ? "Add" : "Remove", ip);
	qlcnic_free_mbx_args(&cmd);
}

int qlcnic_83xx_config_hw_lro(struct qlcnic_adapter *adapter, int mode)
{
	int err;
	struct qlcnic_cmd_args cmd;

	if (adapter->recv_ctx->state == QLCNIC_HOST_CTX_STATE_FREED)
		return 0;

	adapter->ahw->hw_ops->alloc_mbx_args(&cmd, adapter,
					QLCNIC_CMD_CONFIGURE_HW_LRO);
	cmd.req.arg[1] = cpu_to_le32((mode ? (BIT_0 | BIT_1 | BIT_3) : 0) |
			((adapter->recv_ctx->context_id) << 16));

	err = adapter->ahw->hw_ops->mbx_cmd(adapter, &cmd);
	if (err)
		dev_info(&adapter->pdev->dev,
			"LRO config failed\n");
	qlcnic_free_mbx_args(&cmd);

	return err;
}

int qlcnic_83xx_config_rss(struct qlcnic_adapter *adapter, int enable)
{
	int err;
	u32 word;
	struct qlcnic_cmd_args cmd;


	const u64 key[] = { 0xbeac01fa6a42b73bULL, 0x8030f20c77cb2da3ULL,
			0xae7b30b4d0ca2bcbULL, 0x43a38fb04167253dULL,
			0x255b0ec26d5a56daULL };

	adapter->ahw->hw_ops->alloc_mbx_args(&cmd, adapter,
						QLCNIC_CMD_CONFIGURE_RSS);

	/*
	 * RSS request:
	 * bits 3-0: Rsvd
	 *      5-4: hash_type_ipv4
	 *	7-6: hash_type_ipv6
	 *	  8: enable
	 *        9: use indirection table
	 *    16-31: indirection table mask
	 */
	word =  ((u32)(RSS_HASHTYPE_IP_TCP & 0x3) << 4) |
		((u32)(RSS_HASHTYPE_IP_TCP & 0x3) << 6) |
		((u32)(enable & 0x1) << 8) |
		((0x7ULL) << 16);
	cmd.req.arg[1] = (adapter->recv_ctx->context_id);
	cmd.req.arg[2] = cpu_to_le32(word);
	memcpy(&cmd.req.arg[4], key, sizeof(key));

	err = adapter->ahw->hw_ops->mbx_cmd(adapter, &cmd);

	if (err)
		dev_info(&adapter->pdev->dev,
			"RSS config failed\n");
	qlcnic_free_mbx_args(&cmd);

	return err;

}

int
qlcnic_83xx_get_regs_len(struct qlcnic_adapter *adapter)
{
	return (ARRAY_SIZE(qlcnic_83xx_ext_reg_tbl) *
		sizeof(adapter->ahw->ext_reg_tbl)) +
		(ARRAY_SIZE(qlcnic_83xx_reg_tbl) +
		sizeof(adapter->ahw->reg_tbl));
}

int
qlcnic_83xx_get_registers(struct qlcnic_adapter *adapter, u32 *regs_buff)
{
	int i, j = 0;

	for (i = QLCNIC_DEV_INFO_SIZE + 1; j < ARRAY_SIZE(qlcnic_83xx_reg_tbl); i++,j++)
		regs_buff[i] = QLCRD(adapter, j);

	for (j = 0; j < ARRAY_SIZE(qlcnic_83xx_ext_reg_tbl); j++)
		regs_buff[i++] = QLCRDX(adapter->ahw, j);
	return i;
}

int qlcnic_83xx_get_port_info(struct qlcnic_adapter *adapter)
{
	int status;

	status = qlcnic_83xx_get_port_config(adapter);
	if (status) {
		dev_info(&adapter->pdev->dev,
			"Get Port Info failed\n");
	} else {
		if (QLC_83XX_SFP_10G_CAPABLE(adapter->ahw->port_config))
			adapter->ahw->port_type = QLCNIC_XGBE;
		else
			adapter->ahw->port_type = QLCNIC_GBE;
		if (QLC_83XX_AUTONEG(adapter->ahw->port_config))
			adapter->ahw->link_autoneg = AUTONEG_ENABLE;
	}
	return status;
}

int qlcnic_83xx_test_link(struct qlcnic_adapter *adapter)
{
	int err;
	u32 config = 0, state;
	struct qlcnic_cmd_args cmd;
	struct qlcnic_hardware_context *ahw = adapter->ahw;

	state = readl(ahw->pci_base0 + QLC_83XX_LINK_STATE(ahw->pci_func));
	if (!QLC_83xx_FUNC_VAL(state, ahw->pci_func)){
		dev_info(&adapter->pdev->dev, "link state down\n");
		return config;
	}
	adapter->ahw->hw_ops->alloc_mbx_args(&cmd, adapter,
					QLCNIC_CMD_GET_LINK_STATUS);
	err = ahw->hw_ops->mbx_cmd(adapter, &cmd);
	if (err) {
		dev_info(&adapter->pdev->dev,
			"Get Link Status Command failed: 0x%x\n", err);
		goto out;
	} else {
		config = le32_to_cpu(cmd.rsp.arg[1]);
		switch(QLC_83XX_CURRENT_LINK_SPEED(config)) {
		case QLC_83XX_10M_LINK:
			ahw->link_speed = SPEED_10;
			break;
		case QLC_83XX_100M_LINK:
			ahw->link_speed = SPEED_100;
			break;
		case QLC_83XX_1G_LINK:
			ahw->link_speed = SPEED_1000;
			break;
		case QLC_83XX_10G_LINK:
			ahw->link_speed = SPEED_10000;
			break;
		default:
			ahw->link_speed = 0;
			break;
		}
		config = le32_to_cpu(cmd.rsp.arg[3]);
		if (config & 1)
			err = 1;
	}
out:
	qlcnic_free_mbx_args(&cmd);
	return config;
}

int qlcnic_83xx_get_settings(struct qlcnic_adapter *adapter)
{
	u32 config = 0;
	int status = 0;
	struct qlcnic_hardware_context *ahw = adapter->ahw;

	/* Get port configuration info */
	status = qlcnic_83xx_get_port_info(adapter);
	/* Get Link Status related info */
	config = qlcnic_83xx_test_link(adapter);
	ahw->module_type = QLC_83XX_SFP_MODULE_TYPE(config);
	/* hard code until there is a way to get it from flash/fw */
	ahw->board_type = QLCNIC_BRDTYPE_83XX_10G;
	return status;
}

int qlcnic_83xx_set_settings(struct qlcnic_adapter *adapter,
	struct ethtool_cmd *ecmd)
{
	int status = 0;
	u32 config = adapter->ahw->port_config;

	if (ecmd->autoneg)
		adapter->ahw->port_config |= BIT_15;

	switch(ethtool_cmd_speed(ecmd)) {
	case SPEED_10:
		adapter->ahw->port_config |= BIT_8;
		break;
	case SPEED_100:
		adapter->ahw->port_config |= BIT_9;
		break;
	case SPEED_1000:
		adapter->ahw->port_config |= BIT_10;
		break;
	case SPEED_10000:
		adapter->ahw->port_config |= BIT_11;
		break;
	default:
		return -EIO;
	}

	status = qlcnic_83xx_set_port_config(adapter);
	if (status) {
		dev_info(&adapter->pdev->dev,
				"Faild to Set Link Speed and autoneg.\n");
		adapter->ahw->port_config = config;
	}
	return status;
}

int qlcnic_83xx_reg_test(struct qlcnic_adapter *adapter)
{
	u32 major, minor, sub;

	major = QLCRD(adapter, QLCNIC_FW_VERSION_MAJOR);
	minor = QLCRD(adapter, QLCNIC_FW_VERSION_MINOR);
	sub = QLCRD(adapter, QLCNIC_FW_VERSION_SUB);

	if (adapter->fw_version != QLCNIC_VERSION_CODE(major, minor, sub)) {
		dev_info(&adapter->pdev->dev, "%s: Reg test failed.\n",
			 __func__);
		return 1;
	}
	return 0;
}

int qlcnic_83xx_eeprom_test(struct qlcnic_adapter *adapter)
{
	int status;

	status = qlcnic_83xx_read_flash_status_reg(adapter);
	if (status == -EIO) {
		dev_info(&adapter->pdev->dev, "%s: EEPROM test failed.\n",
			__func__);
		return 1;
	}
	return 0;
}

void qlcnic_83xx_get_pauseparam(struct qlcnic_adapter *adapter,
			struct ethtool_pauseparam *pause)
{
	struct qlcnic_hardware_context *ahw = adapter->ahw;
	int status = 0;
	u32 config;

	status = qlcnic_83xx_get_port_config(adapter);
	if (status) {
		netdev_err(adapter->netdev,
			"%s: Get Pause Config failed.\n", __func__);
		return;
	}
	config = ahw->port_config;
	if (config & QLC_83XX_CFG_STD_PAUSE) {
		if (config & QLC_83XX_CFG_STD_TX_PAUSE)
			pause->tx_pause = 1;
		if (config & QLC_83XX_CFG_STD_RX_PAUSE)
			pause->rx_pause = 1;
	}
	if (QLC_83XX_AUTONEG(config))
		pause->autoneg = 1;
}

int qlcnic_83xx_set_pauseparam(struct qlcnic_adapter *adapter,
			struct ethtool_pauseparam *pause)
{
	struct qlcnic_hardware_context *ahw = adapter->ahw;
	int status = 0;
	u32 config;

	status = qlcnic_83xx_get_port_config(adapter);
	if (status) {
		netdev_err(adapter->netdev,
			"%s: Get Pause Config failed.\n", __func__);
		return status;
	}
	config = ahw->port_config;

	if (ahw->port_type == QLCNIC_GBE) {
		if (pause->autoneg)
			ahw->port_config |= QLC_83XX_ENABLE_AUTONEG;
		if (!pause->autoneg)
			ahw->port_config &= ~QLC_83XX_ENABLE_AUTONEG;
	} else if ((ahw->port_type == QLCNIC_XGBE) && (pause->autoneg)) {
			return -EOPNOTSUPP;
	}

	if (!(config & QLC_83XX_CFG_STD_PAUSE))
		ahw->port_config |= QLC_83XX_CFG_STD_PAUSE;

	if (pause->rx_pause && pause->tx_pause) {
		ahw->port_config |= QLC_83XX_CFG_STD_TX_RX_PAUSE;
	} else if (pause->rx_pause && !pause->tx_pause) {
			ahw->port_config &= ~QLC_83XX_CFG_STD_TX_PAUSE;
			ahw->port_config |= QLC_83XX_CFG_STD_RX_PAUSE;
	} else if (pause->tx_pause && !pause->rx_pause) {
			ahw->port_config &= ~QLC_83XX_CFG_STD_RX_PAUSE;
			ahw->port_config |= QLC_83XX_CFG_STD_TX_PAUSE;
	} else if (!pause->rx_pause && !pause->tx_pause) {
			ahw->port_config &= ~QLC_83XX_CFG_STD_TX_RX_PAUSE;
	}
	status = qlcnic_83xx_set_port_config(adapter);
	if (status) {
		netdev_err(adapter->netdev,
			"%s: Set Pause Config failed.\n", __func__);
		ahw->port_config = config;
	}
	return status;
}

void qlcnic_83xx_enable_mbx_intrpt(struct qlcnic_adapter *adapter)
{
	u32 val;

	if (adapter->flags & QLCNIC_MSIX_ENABLED)
		val = BIT_2 | ((adapter->ahw->num_msix - 1) << 8);
	else
		val = BIT_2;
	QLCWRX(adapter->ahw, QLCNIC_MBX_INTR_ENBL, val);
}

void qlcnic_set_npar_data(struct qlcnic_adapter *adapter,
	const struct qlcnic_info *nic_info, struct qlcnic_info *npar_info)
{
	npar_info->pci_func = (le16_to_cpu(nic_info->pci_func)) & 0xF;
	npar_info->op_mode = le16_to_cpu(nic_info->op_mode);
	npar_info->phys_port = le16_to_cpu(nic_info->phys_port);
	npar_info->switch_mode = le16_to_cpu(nic_info->switch_mode);
	npar_info->max_tx_ques = le16_to_cpu(nic_info->max_tx_ques);
	npar_info->max_rx_ques = le16_to_cpu(nic_info->max_rx_ques);
	npar_info->min_tx_bw = le16_to_cpu(nic_info->min_tx_bw);
	npar_info->max_tx_bw = le16_to_cpu(nic_info->max_tx_bw);
	npar_info->capabilities = le32_to_cpu(nic_info->capabilities);
	npar_info->max_mtu = le16_to_cpu(nic_info->max_mtu);

	dev_info(&adapter->pdev->dev,
		"phy port: %d switch_mode: %d,\n"
		"\tmax_tx_q: %d max_rx_q: %d min_tx_bw: 0x%x,\n"
		"\tmax_tx_bw: 0x%x max_mtu:0x%x, capabilities: 0x%x\n",
		npar_info->phys_port, npar_info->switch_mode,
		npar_info->max_tx_ques, npar_info->max_rx_ques,
		npar_info->min_tx_bw, npar_info->max_tx_bw,
		npar_info->max_mtu, npar_info->capabilities);
}

int
qlcnic_83xx_sre_macaddr_change(struct qlcnic_adapter *adapter, u8 *addr,
				__le16 vlan_id, u8 op)
{
	int err;
	u32 *buf;
	struct qlcnic_cmd_args cmd;
	struct qlcnic_macvlan_mbx mv;

	if (adapter->recv_ctx->state == QLCNIC_HOST_CTX_STATE_FREED)
		return -EIO;

	err = adapter->ahw->hw_ops->alloc_mbx_args(&cmd, adapter,
						QLCNIC_CMD_CONFIG_MAC_VLAN);
	if (err)
		return err;
	cmd.req.arg[1] = cpu_to_le32(op | (1 << 8) |
			(adapter->recv_ctx->context_id << 16));

	mv.vlan = cpu_to_le16(vlan_id);
	memcpy(&mv.mac, addr, ETH_ALEN);
	buf = &cmd.req.arg[2];
	memcpy(buf, &mv, sizeof(struct qlcnic_macvlan_mbx));

	err = adapter->ahw->hw_ops->mbx_cmd(adapter, &cmd);
	if (err)
		netdev_err(adapter->netdev,
			"MAC-VLAN %s to CAM failed, err=%d.\n",
			((op == 1) ? "add " : "delete "), err);
	qlcnic_free_mbx_args(&cmd);
	return err;
}

void qlcnic_83xx_change_l2_filter(struct qlcnic_adapter *adapter, u64 *addr,
		__le16 vlan_id)
{
	u8 mac[ETH_ALEN];
	memcpy(&mac, addr, ETH_ALEN);
	qlcnic_83xx_sre_macaddr_change(adapter, mac, vlan_id, QLCNIC_MAC_ADD);
}

void qlcnic_83xx_configure_mac(struct qlcnic_adapter *adapter, u8 *mac,
	u8 type, struct qlcnic_cmd_args *cmd)
{
	switch (type) {
	case QLCNIC_SET_STATION_MAC:
	case QLCNIC_SET_FAC_DEF_MAC:
		memcpy(&cmd->req.arg[2], mac, sizeof(u32));
		memcpy(&cmd->req.arg[3], &mac[4], sizeof(u16));
		break;
	}
	cmd->req.arg[1] = cpu_to_le32(type);
}

/* Get MAC address of a NIC partition */
int qlcnic_83xx_get_mac_address(struct qlcnic_adapter *adapter, u8 *mac)
{
	int err, i;
	struct qlcnic_cmd_args cmd;
	u32 mac_low, mac_high;

	adapter->ahw->hw_ops->alloc_mbx_args(&cmd, adapter,
						QLCNIC_CMD_MAC_ADDRESS);
	qlcnic_83xx_configure_mac(adapter, mac, QLCNIC_GET_CURRENT_MAC, &cmd);
	err = adapter->ahw->hw_ops->mbx_cmd(adapter, &cmd);

	if (err == QLCNIC_RCODE_SUCCESS) {
		mac_low = cmd.rsp.arg[1];
		mac_high = cmd.rsp.arg[2];

		for (i = 0; i < 2; i++)
			mac[i] = (u8) (mac_high >> ((1 - i) * 8));
		for (i = 2; i < 6; i++)
			mac[i] = (u8) (mac_low >> ((5 - i) * 8));
	} else {
		dev_err(&adapter->pdev->dev,
			"Failed to get mac address%d\n", err);
		err = -EIO;
	}
	qlcnic_free_mbx_args(&cmd);
	return err;
}

void qlcnic_83xx_config_intr_coal(struct qlcnic_adapter *adapter)
{
	int err;
	struct qlcnic_cmd_args cmd;
	struct qlcnic_nic_intr_coalesce *coal = &adapter->ahw->coal;

	if (adapter->recv_ctx->state == QLCNIC_HOST_CTX_STATE_FREED)
		return;

	adapter->ahw->hw_ops->alloc_mbx_args(&cmd, adapter,
						QLCNIC_CMD_CONFIG_INTR_COAL);
	cmd.req.arg[1] = cpu_to_le32(1 | (adapter->recv_ctx->context_id << 16));
	cmd.req.arg[3] = cpu_to_le32(coal->flag);
	cmd.req.arg[2] = cpu_to_le32(coal->rx_packets |
		(coal->rx_time_us << 16));
	err = adapter->ahw->hw_ops->mbx_cmd(adapter, &cmd);
	if (err != QLCNIC_RCODE_SUCCESS)
		dev_info(&adapter->pdev->dev,
			"Can not send interrupt coalescence parameters\n");
	qlcnic_free_mbx_args(&cmd);
}

static void
qlcnic_83xx_handle_link_aen(struct qlcnic_adapter *adapter, u32 data[])
{
	u8 link_status, duplex;
	/* link speed */
	link_status = LSB(data[3]) & 1;
	adapter->ahw->link_speed = MSW(data[2]);
	adapter->ahw->link_autoneg = MSB(MSW(data[3]));
	adapter->ahw->module_type = MSB(LSW(data[3]));
	duplex = LSB(MSW(data[3]));
	if (duplex)
		adapter->ahw->link_duplex = DUPLEX_FULL;
	else
		adapter->ahw->link_duplex = DUPLEX_HALF;
	adapter->ahw->has_link_events = 1;
	qlcnic_advert_link_change(adapter, link_status);
}

irqreturn_t qlcnic_83xx_handle_aen(int irq, void *data)
{
	struct qlcnic_adapter *adapter = data;
	unsigned long flags;
	u32 mask, resp, event;

	spin_lock_irqsave(&adapter->ahw->mbx_lock, flags);
	resp = QLCRDX(adapter->ahw, QLCNIC_FW_MBX_CTRL);
	if (!(resp & QLCNIC_SET_OWNER))
		goto out;
	event = le32_to_cpu(readl(QLCNIC_MBX_FW(adapter->ahw, 0)));
	if (event &  QLCNIC_MBX_ASYNC_EVENT)
		qlcnic_83xx_process_aen(adapter);
out:
	mask = QLCRDX(adapter->ahw, QLCNIC_DEF_INT_MASK);
	writel(0, adapter->ahw->pci_base0 + mask);
	spin_unlock_irqrestore(&adapter->ahw->mbx_lock, flags);

	return IRQ_HANDLED;
}

int qlcnic_enable_eswitch(struct qlcnic_adapter *adapter, u8 port, u8 enable)
{
	int err = -EIO;
	struct qlcnic_cmd_args cmd;

	if (adapter->ahw->op_mode != QLCNIC_MGMT_FUNC) {
		dev_err(&adapter->pdev->dev,
			"%s: Error, invoked by non management func\n",
								__func__);
		return err;
	}

	adapter->ahw->hw_ops->alloc_mbx_args(&cmd, adapter,
						QLCNIC_CMD_TOGGLE_ESWITCH);

	cmd.req.arg[1] = (port & 0xf) | BIT_4;

	err = adapter->ahw->hw_ops->mbx_cmd(adapter, &cmd);

	if (err != QLCNIC_RCODE_SUCCESS) {
		dev_err(&adapter->pdev->dev,
			"Failed to enable eswitch%d\n", err);
		err = -EIO;
	}
	qlcnic_free_mbx_args(&cmd);

	return err;

}

/* Configure a NIC partition */
int qlcnic_83xx_set_nic_info(struct qlcnic_adapter *adapter,
					struct qlcnic_info *nic)
{
	int i, err = -EIO;
	struct qlcnic_cmd_args cmd;

	if (adapter->ahw->op_mode != QLCNIC_MGMT_FUNC) {
		dev_err(&adapter->pdev->dev,
			"%s: Error, invoked by non management func\n",
								__func__);
		return err;
	}

	adapter->ahw->hw_ops->alloc_mbx_args(&cmd, adapter,
						QLCNIC_CMD_SET_NIC_INFO);

	cmd.req.arg[1] = (nic->pci_func << 16);
	cmd.req.arg[2] = 0x1 << 16;
	cmd.req.arg[3] = nic->phys_port | (nic->switch_mode << 16);
	cmd.req.arg[4] = nic->capabilities;
	cmd.req.arg[5] = (nic->max_mac_filters & 0xFF) | ((nic->max_mtu) << 16);
	cmd.req.arg[6] = (nic->max_tx_ques) | ((nic->max_rx_ques) << 16);
	cmd.req.arg[7] = (nic->min_tx_bw) | ((nic->max_tx_bw) << 16);
	for (i = 8; i < 32; i++)
		cmd.req.arg[i] = 0;

	err = adapter->ahw->hw_ops->mbx_cmd(adapter, &cmd);

	if (err != QLCNIC_RCODE_SUCCESS) {
		dev_err(&adapter->pdev->dev,
			"Failed to set nic info%d\n", err);
		err = -EIO;
	}

	qlcnic_free_mbx_args(&cmd);

	return err;
}

int qlcnic_83xx_get_nic_info(struct qlcnic_adapter *adapter,
			struct qlcnic_info *npar_info, u8 func_id)
{
	int err;
	u8 op = 0;
	struct qlcnic_cmd_args cmd;

	adapter->ahw->hw_ops->alloc_mbx_args(&cmd, adapter, QLCNIC_CMD_GET_NIC_INFO);
	if (func_id != adapter->ahw->pci_func) {
		cmd.req.arg[1] = cpu_to_le32(op | BIT_31 |
			(func_id << 16));
	} else {
		cmd.req.arg[1] = cpu_to_le32(adapter->ahw->pci_func << 16);
	}
	err = adapter->ahw->hw_ops->mbx_cmd(adapter, &cmd);
	if (err) {
		dev_info(&adapter->pdev->dev,
			"Failed to get nic info %d\n", err);
		goto out;
	}

	npar_info->op_type = cmd.rsp.arg[1];
	npar_info->pci_func = cmd.rsp.arg[2] & 0xFFFF;
	npar_info->op_mode = (cmd.rsp.arg[2] & 0xFFFF0000) >> 16;
	npar_info->phys_port = cmd.rsp.arg[3] & 0xFFFF;
	npar_info->switch_mode = (cmd.rsp.arg[3] & 0xFFFF0000) >> 16;
	npar_info->capabilities = cmd.rsp.arg[4];
	npar_info->max_mac_filters = cmd.rsp.arg[5] & 0xFF;
	npar_info->max_mtu = (cmd.rsp.arg[5] & 0xFFFF0000) >> 16;
	npar_info->max_tx_ques =  cmd.rsp.arg[6] & 0xFFFF;
	npar_info->max_rx_ques = (cmd.rsp.arg[6] & 0xFFFF0000) >> 16;
	npar_info->min_tx_bw = cmd.rsp.arg[7] & 0xFFFF;
	npar_info->max_tx_bw = (cmd.rsp.arg[7] & 0xFFFF0000) >> 16;
	if (cmd.rsp.arg[8] & 0x1)
		npar_info->max_bw_reg_offset = (cmd.rsp.arg[8] & 0x7FFE) >> 1;
	if (cmd.rsp.arg[8] & 0x10000)
		npar_info->max_linkspeed_reg_offset =
				(cmd.rsp.arg[8] & 0x7FFE0000) >> 17;

	dev_info(&adapter->pdev->dev,
		"\n\top_type: %d, phy port: %d switch_mode: %d,\n"
		"\tmax_tx_q: %d max_rx_q: %d min_tx_bw: 0x%x, max_tx_bw: %d,\n"
		"\tmax_bw_offset: 0x%x max_link_speed_offset: 0x%x,\n"
		"\tmax_mtu:0x%x, capabilities: 0x%x\n",
		npar_info->op_type,
		npar_info->phys_port, npar_info->switch_mode,
		npar_info->max_tx_ques, npar_info->max_rx_ques,
		npar_info->min_tx_bw, npar_info->max_tx_bw,
		npar_info->max_bw_reg_offset,
		npar_info->max_linkspeed_reg_offset,
		npar_info->max_mtu, npar_info->capabilities);
out:
	qlcnic_free_mbx_args(&cmd);
	return err;
}

/* Get PCI Info of a partition */
int qlcnic_83xx_get_pci_info(struct qlcnic_adapter *adapter,
				struct qlcnic_pci_info *pci_info)
{
	int i, err = 0, j = 0;
	struct qlcnic_cmd_args cmd;

	adapter->ahw->hw_ops->alloc_mbx_args(&cmd, adapter,
						QLCNIC_CMD_GET_PCI_INFO);
	err = adapter->ahw->hw_ops->mbx_cmd(adapter, &cmd);

	adapter->ahw->act_pci_func = 0;
	if (err == QLCNIC_RCODE_SUCCESS) {
		pci_info->func_count = cmd.rsp.arg[1] & 0xFF;
		QLCDB(adapter, DRV, "%s: total functions = %d\n",
		      __func__, pci_info->func_count);
		for (i = 2, j = 0; j < QLCNIC_MAX_PCI_FUNC; j++, pci_info++) {
			pci_info->id = cmd.rsp.arg[i] & 0xFFFF;
			pci_info->active = (cmd.rsp.arg[i] & 0xFFFF0000) >> 16;
			i++;
			pci_info->type = cmd.rsp.arg[i] & 0xFFFF;
			if (pci_info->type == QLCNIC_TYPE_NIC)
				adapter->ahw->act_pci_func++;
			pci_info->default_port =
				(cmd.rsp.arg[i] & 0xFFFF0000) >> 16;
			i++;
			pci_info->tx_min_bw = cmd.rsp.arg[i] & 0xFFFF;
			pci_info->tx_max_bw =
				(cmd.rsp.arg[i] & 0xFFFF0000) >> 16;
			i = i + 2;
			memcpy(pci_info->mac, &cmd.rsp.arg[i], ETH_ALEN - 2);
			i++;
			memcpy(pci_info->mac + sizeof(u32), &cmd.rsp.arg[i], 2);
			i = i + 3;

			QLCDB(adapter, DRV, "%s:\n"
			      "\tid = %d active = %d type = %d\n"
			      "\tport = %d min bw = %d max bw = %d\n"
			      "\tmac_addr =  %pM\n", __func__,
			      pci_info->id, pci_info->active, pci_info->type,
			      pci_info->default_port, pci_info->tx_min_bw,
			      pci_info->tx_max_bw, pci_info->mac);
		}
	} else {
		dev_err(&adapter->pdev->dev,
			"Failed to get PCI Info%d\n", err);
		err = -EIO;
	}

	qlcnic_free_mbx_args(&cmd);

	return err;
}

int
qlcnic_83xx_ms_mem_write_128b(struct qlcnic_adapter *adapter,
					u64 addr, u32 *data, u32 count)
{
	int i, j, err, ret = 0;
	u32 temp;

	/* Only 128-bit aligned access */
	if (addr & 0xF)
		return -EIO;

	mutex_lock(&adapter->ahw->mem_lock);

	/* Write address */
	qlcnic_83xx_wrt_reg_indirect(adapter, QLCNIC_MS_ADDR_HI, 0);

	for (i = 0 ; i < count ; i++, addr += 16) {
		if (!((ADDR_IN_RANGE(addr, QLCNIC_ADDR_QDR_NET,
			QLCNIC_ADDR_QDR_NET_MAX)) ||
				(ADDR_IN_RANGE(addr, QLCNIC_ADDR_DDR_NET,
					QLCNIC_ADDR_DDR_NET_MAX)))){
			mutex_unlock(&adapter->ahw->mem_lock);
			return -EIO;
		}

		qlcnic_83xx_wrt_reg_indirect(adapter,
				QLCNIC_MS_ADDR_LO, addr);

		/* Write data */
		qlcnic_83xx_wrt_reg_indirect(adapter,
				QLCNIC_MS_WRTDATA_LO, *data++);
		qlcnic_83xx_wrt_reg_indirect(adapter,
				QLCNIC_MS_WRTDATA_HI, *data++);
		qlcnic_83xx_wrt_reg_indirect(adapter,
				QLCNIC_MS_WRTDATA_ULO, *data++);
		qlcnic_83xx_wrt_reg_indirect(adapter,
				QLCNIC_MS_WRTDATA_UHI, *data++);

		/* Check write status */
		qlcnic_83xx_wrt_reg_indirect(adapter, QLCNIC_MS_CTRL,
						QLC_TA_WRITE_ENABLE);
		qlcnic_83xx_wrt_reg_indirect(adapter, QLCNIC_MS_CTRL,
						QLC_TA_WRITE_START);

		for (j = 0; j < MAX_CTL_CHECK; j++) {
			temp = qlcnic_83xx_rd_reg_indirect(adapter,
						QLCNIC_MS_CTRL, &err);
			if (err == -EIO) {
				mutex_unlock(&adapter->ahw->mem_lock);
				return -EIO;
			}

			if ((temp & TA_CTL_BUSY) == 0)
				break;
		}

		/* Status check failed */
		if (j >= MAX_CTL_CHECK) {
			if (printk_ratelimit()) {
				dev_err(&adapter->pdev->dev,
					"MS memory write failed.\n");
				mutex_unlock(&adapter->ahw->mem_lock);
				return -EIO;
			}
		}
	}

	mutex_unlock(&adapter->ahw->mem_lock);

	return ret;
}

void
qlcnic_83xx_cancel_idc_work(struct qlcnic_adapter *adapter)
{
	int id;
	u32 val;

	while (test_and_set_bit(__QLCNIC_RESETTING, &adapter->state))
		msleep(10);

	id = QLCRDX(adapter->ahw, QLC_83XX_DRV_LOCK_ID);
	id = id & 0xFF;

	if (id == adapter->portnum) {
		dev_err(&adapter->pdev->dev,
			"%s: wait for lock recovery.. %d\n", __func__, id);
		msleep(20);
		id = QLCRDX(adapter->ahw, QLC_83XX_DRV_LOCK_ID);
		id = id & 0xFF;
	}

	/* Clear driver presence bit */
	val = QLCRDX(adapter->ahw, QLC_83XX_IDC_DRV_PRESENCE);
	val = val & ~(1 << adapter->portnum);
	QLCWRX(adapter->ahw, QLC_83XX_IDC_DRV_PRESENCE, val);

	clear_bit(QLC_83XX_MODULE_LOADED, &adapter->ahw->idc.status);
	clear_bit(__QLCNIC_RESETTING, &adapter->state);

	cancel_delayed_work_sync(&adapter->fw_work);
}

void
qlcnic_83xx_dev_request_reset(struct qlcnic_adapter *adapter, u32 key)
{
	u32 val;

	if (qlcnic_83xx_lock_driver(adapter)) {
		netdev_err(adapter->netdev,
			"%s:failed, please retry\n", __func__);
		return;
	}

	val = QLCRDX(adapter->ahw, QLC_83XX_IDC_CTRL);
	if ((val & QLC_83XX_IDC_DISABLE_FW_RESET_RECOVERY) || !auto_fw_reset) {
		netdev_err(adapter->netdev,
			"%s:failed, device in non reset mode\n", __func__);
		qlcnic_83xx_unlock_driver(adapter);
		return;
	}

	if (key == QLCNIC_FORCE_FW_RESET) {
		val = QLCRDX(adapter->ahw, QLC_83XX_IDC_CTRL);
		val = val | QLC_83XX_IDC_GRACEFULL_RESET;
		QLCWRX(adapter->ahw, QLC_83XX_IDC_CTRL, val);
	} else if (key == QLCNIC_FORCE_FW_DUMP_KEY) {
		adapter->ahw->idc.collect_dump = 1;
	}

	qlcnic_83xx_unlock_driver(adapter);
	return;
}

static int
qlcnic_sysfs_validate_bar(struct qlcnic_adapter *adapter, loff_t offset,
	size_t size)
{
	size_t bar = 4;

	if (!(adapter->flags & QLCNIC_DIAG_ENABLED))
		return -EIO;

	if (offset >= QLCNIC_83XX_BAR0_LENGTH || (offset & (bar - 1)) ||
		(size != bar))
		return -EINVAL;
	return 0;
}

static ssize_t
qlcnic_sysfs_read_bar(struct file *filp, struct kobject *kobj,
		struct bin_attribute *attr,
		char *buf, loff_t offset, size_t size)
{
	u32 data;
	int ret;
	struct device *dev = container_of(kobj, struct device, kobj);
	struct qlcnic_adapter *adapter = dev_get_drvdata(dev);

	ret = qlcnic_sysfs_validate_bar(adapter, offset, size);
	if (ret != 0)
		return ret;

	mutex_lock(&adapter->ahw->mem_lock);
	data = readl(adapter->ahw->pci_base0 + offset);
	mutex_unlock(&adapter->ahw->mem_lock);

	memcpy(buf, &data, size);
	return size;
}

static ssize_t
qlcnic_sysfs_write_bar(struct file *filp, struct kobject *kobj,
		struct bin_attribute *attr,
		char *buf, loff_t offset, size_t size)
{
	u32 data;
	int ret;
	struct device *dev = container_of(kobj, struct device, kobj);
	struct qlcnic_adapter *adapter = dev_get_drvdata(dev);

	ret = qlcnic_sysfs_validate_bar(adapter, offset, size);
	if (ret != 0)
		return ret;

	memcpy(&data, buf, size);
	mutex_lock(&adapter->ahw->mem_lock);
	writel(data, adapter->ahw->pci_base0 + offset);
	mutex_unlock(&adapter->ahw->mem_lock);

	return size;
}

static ssize_t
qlcnic_83xx_sysfs_flash_read_handler(struct file *filp, struct kobject *kobj,
		struct bin_attribute *attr,
		char *buf, loff_t offset, size_t size)
{
	unsigned char *p_read_buf;
	int  ret, u32_word_count;
	struct device *dev = container_of(kobj, struct device, kobj);
	struct qlcnic_adapter *adapter = dev_get_drvdata(dev);

	if (!size)
		return QL_STATUS_INVALID_PARAM;
	if (!buf)
		return QL_STATUS_INVALID_PARAM;

	u32_word_count = size/sizeof(u32);

	if (size%sizeof(u32))
		u32_word_count++;

	p_read_buf = kcalloc(size, sizeof(unsigned char), GFP_KERNEL);
	if (!p_read_buf)
		return -ENOMEM;
	if (qlcnic_83xx_lock_flash(adapter) != 0) {
		kfree(p_read_buf);
		return -EIO;
	}

	ret = qlcnic_83xx_lockless_flash_read_u32(adapter, offset,
					p_read_buf, u32_word_count);

	if (ret) {
		qlcnic_83xx_unlock_flash(adapter);
		kfree(p_read_buf);
		return ret;
	}

	qlcnic_83xx_unlock_flash(adapter);
	memcpy(buf, p_read_buf, size);
	kfree(p_read_buf);

	return size;
}

static int
qlcnic_83xx_sysfs_flash_bulk_write(struct qlcnic_adapter *adapter,
				char *buf, loff_t offset, size_t size)
{
	int  i, ret, u32_word_count;
	unsigned char *p_cache, *p_src;

	p_cache = kcalloc(size, sizeof(unsigned char), GFP_KERNEL);
	if (!p_cache)
		return -ENOMEM;

	memcpy(p_cache, buf, size);
	p_src = p_cache;
	u32_word_count = size/sizeof(u32);

	if (qlcnic_83xx_lock_flash(adapter) != 0) {
		kfree(p_cache);
		return -EIO;
	}

	if (adapter->ahw->flash_fdt.flash_manuf == adapter->flash_mfg_id) {
		ret = qlcnic_83xx_enable_flash_write_op(adapter);
		if (ret) {
			kfree(p_cache);
			qlcnic_83xx_unlock_flash(adapter);
			return -EIO;
		}
	}

	for (i = 0; i < u32_word_count/QLC_83XX_FLASH_BULK_WRITE_MAX; i++) {
		ret = qlcnic_83xx_flash_bulk_write(adapter, offset,
			(u32 *)p_src, QLC_83XX_FLASH_BULK_WRITE_MAX);

		if (ret) {
			if (adapter->ahw->flash_fdt.flash_manuf ==
			adapter->flash_mfg_id) {
				ret =
				qlcnic_83xx_disable_flash_write_op(adapter);
				if (ret) {
					kfree(p_cache);
					qlcnic_83xx_unlock_flash(adapter);
					return -EIO;
				}
			}
			kfree(p_cache);
			qlcnic_83xx_unlock_flash(adapter);
			return -EIO;
		}

		p_src = p_src + sizeof(u32)*QLC_83XX_FLASH_BULK_WRITE_MAX;
		offset = offset + sizeof(u32)*QLC_83XX_FLASH_BULK_WRITE_MAX;
	}

	if (adapter->ahw->flash_fdt.flash_manuf == adapter->flash_mfg_id) {
		ret = qlcnic_83xx_disable_flash_write_op(adapter);
		if (ret) {
			kfree(p_cache);
			qlcnic_83xx_unlock_flash(adapter);
			return -EIO;
		}
	}
	kfree(p_cache);
	qlcnic_83xx_unlock_flash(adapter);

	return 0;
}

static int
qlcnic_83xx_sysfs_flash_write(struct qlcnic_adapter *adapter,
				char *buf, loff_t offset, size_t size)
{
	int  i, ret, u32_word_count;
	unsigned char *p_cache, *p_src;

	p_cache = kcalloc(size, sizeof(unsigned char), GFP_KERNEL);
	if (!p_cache)
		return -ENOMEM;

	memcpy(p_cache, buf, size);
	p_src = p_cache;
	u32_word_count = size/sizeof(u32);

	if (qlcnic_83xx_lock_flash(adapter) != 0) {
		kfree(p_cache);
		return -EIO;
	}

	if (adapter->ahw->flash_fdt.flash_manuf == adapter->flash_mfg_id) {
		ret = qlcnic_83xx_enable_flash_write_op(adapter);
		if (ret) {
			kfree(p_cache);
			qlcnic_83xx_unlock_flash(adapter);
			return -EIO;
		}
	}

	for (i = 0; i < u32_word_count; i++) {
		ret = qlcnic_83xx_flash_write_u32(adapter,
					offset, (u32 *)p_src);
		if (ret) {
			if (adapter->ahw->flash_fdt.flash_manuf ==
				adapter->flash_mfg_id) {
				ret =
				qlcnic_83xx_disable_flash_write_op(adapter);
				if (ret) {
					kfree(p_cache);
					qlcnic_83xx_unlock_flash(adapter);
					return -EIO;
				}
			}
			kfree(p_cache);
			qlcnic_83xx_unlock_flash(adapter);
			return -EIO;
		}
		p_src = p_src + sizeof(u32);
		offset = offset + sizeof(u32);
	}

	if (adapter->ahw->flash_fdt.flash_manuf == adapter->flash_mfg_id) {
		ret = qlcnic_83xx_disable_flash_write_op(adapter);
		if (ret) {
			kfree(p_cache);
			qlcnic_83xx_unlock_flash(adapter);
			return -EIO;
		}
	}

	kfree(p_cache);
	qlcnic_83xx_unlock_flash(adapter);

	return 0;
}

static ssize_t
qlcnic_83xx_sysfs_flash_write_handler(struct file *filp, struct kobject *kobj,
		struct bin_attribute *attr,
		char *buf, loff_t offset, size_t size)
{
	int  ret;
	static int flash_mode;
	unsigned long data;
	struct device *dev = container_of(kobj, struct device, kobj);
	struct qlcnic_adapter *adapter = dev_get_drvdata(dev);

	if (!buf)
		return QL_STATUS_INVALID_PARAM;

	data = simple_strtoul(buf, NULL, 16);

	switch (data) {
	case QLC_83XX_FLASH_SECTOR_ERASE_CMD:
		flash_mode = QLC_83XX_ERASE_MODE;
		ret = qlcnic_83xx_erase_flash_sector(adapter, offset);
		if (ret) {
			dev_err(&adapter->pdev->dev,
				"%s failed at %d\n", __func__, __LINE__);
			return -EIO;
		}
		break;

	case QLC_83XX_FLASH_BULK_WRITE_CMD:
		flash_mode = QLC_83XX_BULK_WRITE_MODE;
		break;

	case QLC_83XX_FLASH_WRITE_CMD:
		flash_mode = QLC_83XX_WRITE_MODE;
		break;
	default:
		if (flash_mode == QLC_83XX_BULK_WRITE_MODE) {
			ret = qlcnic_83xx_sysfs_flash_bulk_write(adapter,
							buf, offset, size);
			if (ret) {
				dev_err(&adapter->pdev->dev,
				"%s failed at %d\n", __func__, __LINE__);
				return -EIO;
			}
		}

		if (flash_mode == QLC_83XX_WRITE_MODE) {
			ret = qlcnic_83xx_sysfs_flash_write(adapter,
						buf, offset, size);
			if (ret) {
				dev_err(&adapter->pdev->dev,
				"%s failed at %d\n", __func__, __LINE__);
				return -EIO;
			}
		}

	}

	return size;
}

static struct bin_attribute bin_attr_bar = {
	.attr = {.name = "membar", .mode = (S_IRUGO | S_IWUSR)},
	.size = 0,
	.read = qlcnic_sysfs_read_bar,
	.write = qlcnic_sysfs_write_bar,
};

static struct bin_attribute bin_attr_flash = {
	.attr = {.name = "flash", .mode = (S_IRUGO | S_IWUSR)},
	.size = 0,
	.read = qlcnic_83xx_sysfs_flash_read_handler,
	.write = qlcnic_83xx_sysfs_flash_write_handler,
};

/*Note: add new bin_attribute structures above this line */

void qlcnic_83xx_add_sysfs(struct qlcnic_adapter *adapter)
{
	struct device *dev = &adapter->pdev->dev;
	qlcnic_create_diag_entries(adapter);
	if (sysfs_create_bin_file(&dev->kobj, &bin_attr_bar))
		dev_info(dev, "failed to create mem bar sysfs entry\n");
	if (sysfs_create_bin_file(&dev->kobj, &bin_attr_flash))
		dev_info(dev, "failed to create flash sysfs entry\n");
}

void qlcnic_83xx_remove_sysfs(struct qlcnic_adapter *adapter)
{
	struct device *dev = &adapter->pdev->dev;
	qlcnic_remove_diag_entries(adapter);
	sysfs_remove_bin_file(&dev->kobj, &bin_attr_bar);
	sysfs_remove_bin_file(&dev->kobj, &bin_attr_flash);
}
