#include "qlcnic.h"
#include "qlcnic_hw.h"

int qlcnic_83xx_get_vnic_vport_info(struct qlcnic_adapter *adapter,
			struct qlcnic_info *npar_info, u8 vport_id)
{
	int err;
	u32 status;
	struct qlcnic_cmd_args cmd;

	adapter->ahw->hw_ops->alloc_mbx_args(&cmd, adapter,
					QLCNIC_CMD_GET_NIC_INFO);
	cmd.req.arg[1] = cpu_to_le32((vport_id << 16) | 0x1);
	err = adapter->ahw->hw_ops->mbx_cmd(adapter, &cmd);
	if (err) {
		dev_info(&adapter->pdev->dev,
			"Failed to get vport info %d\n", err);
		goto out;
	}

	status = cmd.rsp.arg[2] & 0xFFFF;
	if (status & BIT_0)
		npar_info->min_tx_bw = (cmd.rsp.arg[2] & 0xFFFF0000) >> 16;
	if (status & BIT_1)
		npar_info->max_tx_bw = (cmd.rsp.arg[3] & 0xFFFF);
	if (status & BIT_2)
		npar_info->max_tx_ques = (cmd.rsp.arg[3] & 0xFFFF0000) >> 16;
	if (status & BIT_3)
		npar_info->max_tx_mac_filters = (cmd.rsp.arg[4] & 0xFFFF);
	if (status & BIT_4)
		npar_info->max_rx_mcast_mac_filters =
					(cmd.rsp.arg[4] & 0xFFFF0000) >> 16;
	if (status & BIT_5)
		npar_info->max_rx_ucast_mac_filters = (cmd.rsp.arg[5] & 0xFFFF);
	if (status & BIT_6)
		npar_info->max_rx_ip_addr =
				(cmd.rsp.arg[5] & 0xFFFF0000) >> 16;
	if (status & BIT_7)
		npar_info->max_rx_lro_flow = (cmd.rsp.arg[6] & 0xFFFF);
	if (status & BIT_8)
		npar_info->max_rx_status_rings =
					(cmd.rsp.arg[6] & 0xFFFF0000) >> 16;
	if (status & BIT_9)
		npar_info->max_rx_buf_rings = (cmd.rsp.arg[7] & 0xFFFF);

	npar_info->max_rx_ques = (cmd.rsp.arg[7] & 0xFFFF0000) >> 16;
	npar_info->max_tx_vlan_keys = (cmd.rsp.arg[8] & 0xFFFF);

	dev_info(&adapter->pdev->dev,
		"\n\tmin_tx_bw: %d, max_tx_bw: %d max_tx_ques: %d,\n"
		"\tmax_tx_mac_filters: %d max_rx_mcast_mac_filters: %d,\n"
		"\tmax_rx_ucast_mac_filters: 0x%x, max_rx_ip_addr: %d,\n"
		"\tmax_rx_lro_flow: %d max_rx_status_rings: %d,\n"
		"\tmax_rx_buf_rings: %d, max_rx_ques: %d, max_tx_vlan_keys %d\n",
		npar_info->min_tx_bw,
		npar_info->max_tx_bw, npar_info->max_tx_ques,
		npar_info->max_tx_mac_filters, npar_info->max_rx_mcast_mac_filters,
		npar_info->max_rx_ucast_mac_filters, npar_info->max_rx_ip_addr,
		npar_info->max_rx_lro_flow, npar_info->max_rx_status_rings,
		npar_info->max_rx_buf_rings,
		npar_info->max_rx_ques, npar_info->max_tx_vlan_keys);
out:
	qlcnic_free_mbx_args(&cmd);
	return err;
}

int qlcnic_83xx_get_vnic_pf_info(struct qlcnic_adapter *adapter,
			struct qlcnic_info *npar_info)
{
	int err;
	struct qlcnic_cmd_args cmd;

	adapter->ahw->hw_ops->alloc_mbx_args(&cmd, adapter,
						QLCNIC_CMD_GET_NIC_INFO);
	cmd.req.arg[1] = cpu_to_le32(0x2);
	err = adapter->ahw->hw_ops->mbx_cmd(adapter, &cmd);
	if (err) {
		dev_info(&adapter->pdev->dev,
			"Failed to get vNIC PF info %d\n", err);
		goto out;
	}

	npar_info->total_pf = cmd.rsp.arg[2] & 0xFF;
	npar_info->total_rss_engines = (cmd.rsp.arg[2] & 0xFF00) >> 8;
	npar_info->max_vports = (cmd.rsp.arg[2] & 0xFFFF0000) >> 16;
	npar_info->max_tx_ques =  cmd.rsp.arg[3] & 0xFFFF;
	npar_info->max_tx_mac_filters = (cmd.rsp.arg[3] & 0xFFFF0000) >> 16;
	npar_info->max_rx_mcast_mac_filters = cmd.rsp.arg[4] & 0xFFFF;
	npar_info->max_rx_ucast_mac_filters =
				(cmd.rsp.arg[4] & 0xFFFF0000) >> 16;
	npar_info->max_rx_ip_addr = (cmd.rsp.arg[5] & 0xFFFF);
	npar_info->max_rx_lro_flow = (cmd.rsp.arg[5] & 0xFFFF0000) >> 16;
	npar_info->max_rx_status_rings = (cmd.rsp.arg[6] & 0xFFFF);
	npar_info->max_rx_buf_rings = (cmd.rsp.arg[6] & 0xFFFF0000) >> 16;
	npar_info->max_rx_ques = (cmd.rsp.arg[7] & 0xFFFF) >> 16;
	npar_info->max_tx_vlan_keys = (cmd.rsp.arg[7] & 0xFFFF0000) >> 16;

	dev_info(&adapter->pdev->dev,
		"\n\ttotal_pf: %d,\n"
		"\n\ttotal_rss_engines: %d max_vports: %d max_tx_ques %d,\n"
		"\tmax_tx_mac_filters: %d max_rx_mcast_mac_filters: %d,\n"
		"\tmax_rx_ucast_mac_filters: 0x%x, max_rx_ip_addr: %d,\n"
		"\tmax_rx_lro_flow: %d max_rx_status_rings: %d,\n"
		"\tmax_rx_buf_rings: %d, max_rx_ques: %d, max_tx_vlan_keys %d\n",
		npar_info->total_pf,
		npar_info->total_rss_engines, npar_info->max_vports,
		npar_info->max_tx_ques, npar_info->max_tx_mac_filters,
		npar_info->max_rx_mcast_mac_filters,
		npar_info->max_rx_ucast_mac_filters, npar_info->max_rx_ip_addr,
		npar_info->max_rx_lro_flow, npar_info->max_rx_status_rings,
		npar_info->max_rx_buf_rings,
		npar_info->max_rx_ques, npar_info->max_tx_vlan_keys);

out:
	qlcnic_free_mbx_args(&cmd);
	return err;
}

int
qlcnic_83xx_set_vnic_operational(struct qlcnic_adapter *adapter, int lock)
{
	if (lock) {
		if (qlcnic_83xx_lock_driver(adapter))
			return -EBUSY;
	}

	QLCWRX(adapter->ahw, QLC_83XX_VNIC_STATE, QLCNIC_DEV_NPAR_OPER);
	dev_info(&adapter->pdev->dev,
			"vNIC operational state set\n");

	if (lock)
		qlcnic_83xx_unlock_driver(adapter);

	return 0;
}

int
qlcnic_83xx_set_vnic_non_operational(struct qlcnic_adapter *adapter, int lock)
{
	struct qlcnic_hardware_context *ahw = adapter->ahw;

	if (lock) {
		if (qlcnic_83xx_lock_driver(adapter))
			return -EBUSY;
	}

	QLCWRX(adapter->ahw, QLC_83XX_VNIC_STATE, QLCNIC_DEV_NPAR_NON_OPER);
	ahw->idc.vnic_state = QLCNIC_DEV_NPAR_NON_OPER;
	dev_info(&adapter->pdev->dev,
			"vNIC non operational state set\n");

	if (lock)
		qlcnic_83xx_unlock_driver(adapter);

	return 0;
}

/**
 * qlcnic_83xx_set_vnic_opmode
 *
 * @adapter: adapter structure
 *
 * Returns:
 *
 **/
static int
qlcnic_83xx_set_vnic_opmode(struct qlcnic_adapter *adapter)
{
	u8 id;
	int i, ret = -EBUSY;
	u32 data = QLCNIC_MGMT_FUNC;
	struct qlcnic_hardware_context *ahw = adapter->ahw;

	if (qlcnic_83xx_lock_driver(adapter)) {
		return ret;
	}

	if (qlcnic_config_npars) {
		for (i = 0; i < ahw->act_pci_func; i++) {
			id = adapter->npars[i].pci_func;
			if (id == ahw->pci_func)
				continue;
			data |= (qlcnic_config_npars &
					QLC_83XX_SET_FUNC_OPMODE(0x3, id));
		}
	} else {
		data = QLCRDX(adapter->ahw, QLC_83XX_DRV_OP_MODE);
		data = (data & ~QLC_83XX_SET_FUNC_OPMODE(0x3, ahw->pci_func)) |
			(QLC_83XX_SET_FUNC_OPMODE(QLCNIC_MGMT_FUNC,
			ahw->pci_func));
	}
	QLCWRX(adapter->ahw, QLC_83XX_DRV_OP_MODE, data);

	qlcnic_83xx_unlock_driver(adapter);

	return 0;
}

/**
 * qlcnic_83xx_config_vnic_buff_descriptors
 *
 * @adapter: adapter structure
 *
 * Returns:
 *
 **/
static inline void
qlcnic_83xx_config_vnic_buff_descriptors(struct qlcnic_adapter *adapter)
{
	struct qlcnic_hardware_context *ahw = adapter->ahw;

	if (ahw->port_type == QLCNIC_XGBE) {
		adapter->num_rxd = DEFAULT_RCV_DESCRIPTORS_VF;
		adapter->max_rxd = MAX_RCV_DESCRIPTORS_VF;
		adapter->num_jumbo_rxd = MAX_JUMBO_RCV_DESCRIPTORS_10G;
		adapter->max_jumbo_rxd = MAX_JUMBO_RCV_DESCRIPTORS_10G;

	} else if (ahw->port_type == QLCNIC_GBE) {
		adapter->num_rxd = DEFAULT_RCV_DESCRIPTORS_1G;
		adapter->num_jumbo_rxd = MAX_JUMBO_RCV_DESCRIPTORS_1G;
		adapter->max_jumbo_rxd = MAX_JUMBO_RCV_DESCRIPTORS_1G;
		adapter->max_rxd = MAX_RCV_DESCRIPTORS_1G;
	}
	adapter->num_txd = MAX_CMD_DESCRIPTORS;
	adapter->max_rds_rings = MAX_RDS_RINGS;
}


/**
 * qlcnic_83xx_init_mgmt_vnic
 *
 * @adapter: adapter structure
 * Management vNIC sets the operational mode of other vNIC's and
 * configures embedded switch (ESWITCH).
 * Returns:
 *
 **/
static int
qlcnic_83xx_init_mgmt_vnic(struct qlcnic_adapter *adapter)
{
	int err = -EIO;

	qlcnic_83xx_get_minidump_template(adapter);
	if (!(adapter->flags & QLCNIC_ADAPTER_INITIALIZED)) {
		if (qlcnic_init_pci_info(adapter))
			return err;

		if (qlcnic_83xx_set_vnic_opmode(adapter))
			return err;

		if (qlcnic_set_default_offload_settings(adapter))
			return err;
	} else {
		if (qlcnic_reset_npar_config(adapter))
			return err;
	}

	if (qlcnic_83xx_get_port_info(adapter))
		return err;

	qlcnic_83xx_config_vnic_buff_descriptors(adapter);
	adapter->ahw->msix_supported = !!use_msi_x;
	adapter->flags |= QLCNIC_ADAPTER_INITIALIZED;
	qlcnic_83xx_set_vnic_operational(adapter, 1);

	dev_info(&adapter->pdev->dev, "HAL Version: %d, Management function\n",
			adapter->ahw->fw_hal_version);

	return 0;
}

/**
 * qlcnic_83xx_init_privileged_vnic
 *
 * @adapter: adapter structure
 *
 * Returns:
 *
 **/
static int
qlcnic_83xx_init_privileged_vnic(struct qlcnic_adapter *adapter)
{
	int err = -EIO;

	qlcnic_83xx_get_minidump_template(adapter);
	if (qlcnic_83xx_get_port_info(adapter))
		return err;

	qlcnic_83xx_config_vnic_buff_descriptors(adapter);
	adapter->ahw->msix_supported = !!use_msi_x;
	adapter->flags |= QLCNIC_ADAPTER_INITIALIZED;

	netdev_info(adapter->netdev, "HAL Version: %d, Privileged function\n",
			adapter->ahw->fw_hal_version);
	return 0;
}

/**
 * qlcnic_83xx_init_non_privileged_vnic
 *
 * @adapter: adapter structure
 *
 * Returns:
 *
 **/
static int
qlcnic_83xx_init_non_privileged_vnic(struct qlcnic_adapter *adapter)
{
	int err = -EIO;

	qlcnic_83xx_get_fw_version(adapter);
	if (qlcnic_set_eswitch_port_config(adapter))
		return err;

	if (qlcnic_83xx_get_port_info(adapter))
		return err;

	qlcnic_83xx_config_vnic_buff_descriptors(adapter);
	adapter->ahw->msix_supported = !!use_msi_x;
	adapter->flags |= QLCNIC_ADAPTER_INITIALIZED;

	dev_info(&adapter->pdev->dev, "HAL Version: %d, Virtual function\n",
				adapter->ahw->fw_hal_version);

	return 0;
}

/**
 * qlcnic_83xx_vnic_opmode
 *
 * @adapter: adapter structure
 * Identify virtual NIC operational modes.
 *
 * Returns:
 *
 **/
int
qlcnic_83xx_config_vnic_opmode(struct qlcnic_adapter *adapter)
{
	u32 op_mode, priv_level;
	struct pci_dev *pdev = adapter->pdev;
	struct qlcnic_hardware_context *ahw = adapter->ahw;

	ahw->hw_ops->get_func_no(adapter);

	op_mode = QLCRDX(adapter->ahw, QLC_83XX_DRV_OP_MODE);

	if (op_mode == QLC_83XX_DEFAULT_OPMODE)
		priv_level = QLCNIC_MGMT_FUNC;
	else
		priv_level = QLC_83XX_GET_FUNC_PRIVILEGE_LEVEL(op_mode,
							ahw->pci_func);

	if (priv_level == QLCNIC_NON_PRIV_FUNC) {
		ahw->op_mode = QLCNIC_NON_PRIV_FUNC;
		dev_info(&pdev->dev, "vNIC opmode %d\n", adapter->ahw->op_mode);
		adapter->ahw->idc.ready_state_entry_action =
			qlcnic_83xx_idc_ready_state_entry_action;
		adapter->nic_ops->init_driver =
				qlcnic_83xx_init_non_privileged_vnic;
	} else if (priv_level == QLCNIC_PRIV_FUNC) {
		ahw->op_mode = QLCNIC_PRIV_FUNC;
		dev_info(&pdev->dev, "vNIC opmode %d\n", adapter->ahw->op_mode);
		adapter->ahw->idc.ready_state_entry_action =
			qlcnic_83xx_idc_vnic_pf_ready_state_entry_action;
		adapter->nic_ops->init_driver =
				qlcnic_83xx_init_privileged_vnic;
	} else if (priv_level == QLCNIC_MGMT_FUNC) {
		ahw->op_mode = QLCNIC_MGMT_FUNC;
		dev_info(&pdev->dev, "vNIC opmode %d\n", adapter->ahw->op_mode);
		adapter->ahw->idc.ready_state_entry_action =
			qlcnic_83xx_idc_ready_state_entry_action;
		adapter->nic_ops->init_driver =
				qlcnic_83xx_init_mgmt_vnic;
	} else {
		return -EIO;
	}

	if (ahw->capabilities & BIT_23) {
		adapter->flags |= QLCNIC_ESWITCH_ENABLED;
		dev_info(&pdev->dev, "ESWITCH enabled %d\n",
						adapter->ahw->op_mode);
	} else {
		adapter->flags &= ~QLCNIC_ESWITCH_ENABLED;
	}

	adapter->ahw->idc.vnic_state = QLCNIC_DEV_NPAR_NON_OPER;
	adapter->ahw->idc.vnic_wait_limit = QLCNIC_DEV_NPAR_OPER_TIMEO;

	return 0;
}
