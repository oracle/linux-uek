/*
 * Copyright (c) 2004, 2005 Topspin Communications.  All rights reserved.
 * Copyright (c) 2005 Sun Microsystems, Inc. All rights reserved.
 * Copyright (c) 2005, 2006, 2007, 2008 Mellanox Technologies. All rights reserved.
 * Copyright (c) 2006, 2007 Cisco Systems, Inc. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/errno.h>
#include <linux/pci.h>
#include <linux/dma-mapping.h>
#include <linux/slab.h>
#include <linux/delay.h>
#include <asm/kmap_types.h>
#include <linux/io-mapping.h>

#include <linux/mlx4/device.h>
#include <linux/mlx4/doorbell.h>

#include "mlx4.h"
#include "fw.h"
#include "icm.h"

#include "fmr_master.h"
#include "fmr_slave.h"

MODULE_AUTHOR("Roland Dreier");
MODULE_DESCRIPTION("Mellanox ConnectX HCA low-level driver");
MODULE_LICENSE("Dual BSD/GPL");
MODULE_VERSION(DRV_VERSION);

struct workqueue_struct *mlx4_wq;

#ifdef CONFIG_MLX4_DEBUG

int mlx4_debug_level = 0;
module_param_named(debug_level, mlx4_debug_level, int, 0644);
MODULE_PARM_DESC(debug_level, "Enable debug tracing if > 0");

#endif /* CONFIG_MLX4_DEBUG */

int mlx4_blck_lb=1;
module_param_named(block_loopback, mlx4_blck_lb, int, 0644);
MODULE_PARM_DESC(block_loopback, "Block multicast loopback packets if > 0");

static int enable_qinq;
module_param(enable_qinq, bool, 0444);
MODULE_PARM_DESC(enable_qinq, "Set the device skips the first q-tag(vlan) in the packet and treat the secound vlan as the vlan tag."
			"(0/1 default: 0)");

#ifdef CONFIG_PCI_MSI

static int msi_x = 1;
module_param(msi_x, int, 0444);
MODULE_PARM_DESC(msi_x, "attempt to use MSI-X if nonzero");

#else /* CONFIG_PCI_MSI */

#define msi_x (0)

#endif /* CONFIG_PCI_MSI */

#ifdef CONFIG_PCI_IOV

static int sr_iov;
module_param(sr_iov, int, 0444);
MODULE_PARM_DESC(sr_iov, "enable #sr_iov functions if sr_iov > 0");

static int probe_vf;
module_param(probe_vf, int, 0444);
MODULE_PARM_DESC(probe_vf, "number of vfs to probe by pf driver (sr_iov > 0)");

int mlx4_log_num_mgm_entry_size = 10;
module_param_named(log_num_mgm_entry_size, mlx4_log_num_mgm_entry_size, int, 0444);
MODULE_PARM_DESC(log_num_mgm_entry_size, "log mgm size, that defines the num of qp per mcg,"
					 " for example: 10 gives 248."
					 "range: 9<= log_num_mgm_entry_size <= 12");

#else /* CONFIG_PCI_IOV */
static int sr_iov = 0;
#define probe_vf 0
int mlx4_log_num_mgm_entry_size = 9;
#endif /* CONFIG_PCI_IOV */

/* let the mlx4 generate entropy by default */

int enable_entropy = 1;
module_param(enable_entropy, int, 0444);
MODULE_PARM_DESC(enable_entropy, "Allow the mlx4 to seed the entropy pool (default = 1)");

static char mlx4_version[] __devinitdata =
	DRV_NAME ": Mellanox ConnectX core driver v"
	DRV_VERSION " (" DRV_RELDATE ")\n";

struct mutex drv_mutex;

static struct mlx4_profile default_profile = {
	.num_qp		= 1 << 18,
	.num_srq	= 1 << 16,
	.rdmarc_per_qp	= 1 << 4,
	.num_cq		= 1 << 16,
	.num_mcg	= 1 << 13,
	.num_mpt	= 1 << 20,
	.num_mtt	= 1 << 21
};

static int log_num_mac = 7;
module_param_named(log_num_mac, log_num_mac, int, 0444);
MODULE_PARM_DESC(log_num_mac, "Log2 max number of MACs per ETH port (1-7)");

static int use_prio;
module_param_named(use_prio, use_prio, bool, 0444);
MODULE_PARM_DESC(use_prio, "Enable steering by VLAN priority on ETH ports "
		  "(0/1, default 0)");

static struct mlx4_profile mod_param_profile = { 0 };

module_param_named(log_num_qp, mod_param_profile.num_qp, int, 0444);
MODULE_PARM_DESC(log_num_qp, "log maximum number of QPs per HCA");

module_param_named(log_num_srq, mod_param_profile.num_srq, int, 0444);
MODULE_PARM_DESC(log_num_srq, "log maximum number of SRQs per HCA");

module_param_named(log_rdmarc_per_qp, mod_param_profile.rdmarc_per_qp, int, 0444);
MODULE_PARM_DESC(log_rdmarc_per_qp, "log number of RDMARC buffers per QP");

module_param_named(log_num_cq, mod_param_profile.num_cq, int, 0444);
MODULE_PARM_DESC(log_num_cq, "log maximum number of CQs per HCA");

module_param_named(log_num_mcg, mod_param_profile.num_mcg, int, 0444);
MODULE_PARM_DESC(log_num_mcg, "log maximum number of multicast groups per HCA");

module_param_named(log_num_mpt, mod_param_profile.num_mpt, int, 0444);
MODULE_PARM_DESC(log_num_mpt,
		"log maximum number of memory protection table entries per HCA");

module_param_named(log_num_mtt, mod_param_profile.num_mtt, int, 0444);
MODULE_PARM_DESC(log_num_mtt,
		 "log maximum number of memory translation table segments per HCA");

static int log_mtts_per_seg = ilog2(MLX4_MTT_ENTRY_PER_SEG);
module_param_named(log_mtts_per_seg, log_mtts_per_seg, int, 0444);
MODULE_PARM_DESC(log_mtts_per_seg, "Log2 number of MTT entries per segment (1-7)");

static void process_mod_param_profile(void)
{
	default_profile.num_qp = (mod_param_profile.num_qp ?
				  1 << mod_param_profile.num_qp :
				  default_profile.num_qp);
	default_profile.num_srq = (mod_param_profile.num_srq ?
				  1 << mod_param_profile.num_srq :
				  default_profile.num_srq);
	default_profile.rdmarc_per_qp = (mod_param_profile.rdmarc_per_qp ?
				  1 << mod_param_profile.rdmarc_per_qp :
				  default_profile.rdmarc_per_qp);
	default_profile.num_cq = (mod_param_profile.num_cq ?
				  1 << mod_param_profile.num_cq :
				  default_profile.num_cq);
	default_profile.num_mcg = (mod_param_profile.num_mcg ?
				  1 << mod_param_profile.num_mcg :
				  default_profile.num_mcg);
	default_profile.num_mpt = (mod_param_profile.num_mpt ?
				  1 << mod_param_profile.num_mpt :
				  default_profile.num_mpt);
	default_profile.num_mtt = (mod_param_profile.num_mtt ?
				  1 << mod_param_profile.num_mtt :
				  default_profile.num_mtt);
}

struct mlx4_port_config
{
	struct list_head list;
	enum mlx4_port_type port_type[MLX4_MAX_PORTS + 1];
	struct pci_dev *pdev;
};
static LIST_HEAD(config_list);

static void mlx4_config_cleanup(void)
{
	struct mlx4_port_config *config, *tmp;

	list_for_each_entry_safe(config, tmp, &config_list, list) {
		list_del(&config->list);
		kfree(config);
	}
}

void *mlx4_get_prot_dev(struct mlx4_dev *dev, enum mlx4_prot proto, int port)
{
	return mlx4_find_get_prot_dev(dev, proto, port);
}
EXPORT_SYMBOL(mlx4_get_prot_dev);

void mlx4_set_iboe_counter(struct mlx4_dev *dev, int index, u8 port)
{
	struct mlx4_priv *priv = mlx4_priv(dev);

	priv->iboe_counter_index[port - 1] = index;
}
EXPORT_SYMBOL(mlx4_set_iboe_counter);

int mlx4_get_iboe_counter(struct mlx4_dev *dev, u8 port)
{
	struct mlx4_priv *priv = mlx4_priv(dev);

	return priv->iboe_counter_index[port - 1];
}
EXPORT_SYMBOL(mlx4_get_iboe_counter);

int mlx4_check_port_params(struct mlx4_dev *dev,
			   enum mlx4_port_type *port_type)
{
	int i;

	for (i = 0; i < dev->caps.num_ports - 1; i++) {
		if (port_type[i] != port_type[i + 1]) {
			if (!(dev->caps.flags & MLX4_DEV_CAP_FLAG_DPDP)) {
				mlx4_err(dev, "Only same port types supported "
					 "on this HCA, aborting.\n");
				return -EINVAL;
			}
			if (port_type[i] == MLX4_PORT_TYPE_ETH &&
			    port_type[i + 1] == MLX4_PORT_TYPE_IB)
				return -EINVAL;
		}
	}

	for (i = 0; i < dev->caps.num_ports; i++) {
		if (!(port_type[i] & dev->caps.supported_type[i+1])) {
			mlx4_err(dev, "Requested port type for port %d is not "
				      "supported on this HCA\n", i + 1);
			return -EINVAL;
		}
	}
	return 0;
}

void mlx4_set_port_mask(struct mlx4_dev *dev, struct mlx4_caps *caps, int function)
{
	int i;
	int active = (function & 1) + 1;

	for (i = 1; i <= caps->num_ports; ++i) {
		caps->port_mask[i] = caps->port_type[i];
		if (dev->caps.pf_num > 1 && i != active)
			caps->port_mask[i] = 0;
	}
}

static u8 get_counters_mode(u64 flags)
{
	switch (flags >> 48 & 3) {
	case 2:
	case 3:
	case 1:
		return MLX4_CUNTERS_BASIC;
	default:
		return MLX4_CUNTERS_DISABLED;
	}
}

static int mlx4_dev_cap(struct mlx4_dev *dev, struct mlx4_dev_cap *dev_cap)
{
	int err;
	int i;

	err = mlx4_QUERY_DEV_CAP(dev, dev_cap);
	if (err) {
		mlx4_err(dev, "QUERY_DEV_CAP command failed, aborting.\n");
		return err;
	}

	if (dev_cap->min_page_sz > PAGE_SIZE) {
		mlx4_err(dev, "HCA minimum page size of %d bigger than "
			 "kernel PAGE_SIZE of %ld, aborting.\n",
			 dev_cap->min_page_sz, PAGE_SIZE);
		return -ENODEV;
	}
	if (dev_cap->num_ports > MLX4_MAX_PORTS) {
		mlx4_err(dev, "HCA has %d ports, but we only support %d, "
			 "aborting.\n",
			 dev_cap->num_ports, MLX4_MAX_PORTS);
		return -ENODEV;
	}

	if (dev_cap->uar_size > pci_resource_len(dev->pdev, 2)) {
		mlx4_err(dev, "HCA reported UAR size of 0x%x bigger than "
			 "PCI resource 2 size of 0x%llx, aborting.\n",
			 dev_cap->uar_size,
			 (unsigned long long) pci_resource_len(dev->pdev, 2));
		return -ENODEV;
	}

	if (enable_qinq && !dev_cap->qinq) {
		mlx4_warn(dev, "Ignoring setting of QinQ"
				"No HW capability\n");
	}

	dev->caps.pf_num = dev_cap->pf_num;
	dev->caps.num_ports	     = dev_cap->num_ports;
	for (i = 1; i <= dev->caps.num_ports; ++i) {
		dev->caps.vl_cap[i]	    = dev_cap->max_vl[i];
		dev->caps.ib_mtu_cap[i]	    = dev_cap->ib_mtu[i];
		dev->caps.gid_table_len[i]  = dev_cap->max_gids[i];
		dev->caps.pkey_table_len[i] = dev_cap->max_pkeys[i];
		dev->caps.pkey_table_max_len[i] = dev_cap->max_pkeys[i];
		dev->caps.port_width_cap[i] = dev_cap->max_port_width[i];
		dev->caps.eth_mtu_cap[i]    = dev_cap->eth_mtu[i];
		dev->caps.def_mac[i]        = dev_cap->def_mac[i];
		dev->caps.supported_type[i] = dev_cap->supported_port_types[i];
		dev->caps.trans_type[i]	    = dev_cap->trans_type[i];
		dev->caps.vendor_oui[i]     = dev_cap->vendor_oui[i];
		dev->caps.wavelength[i]     = dev_cap->wavelength[i];
		dev->caps.trans_code[i]     = dev_cap->trans_code[i];
	}

	dev->caps.uar_page_size	     = PAGE_SIZE;
	dev->caps.num_uars	     = dev_cap->uar_size / PAGE_SIZE;
	dev->caps.local_ca_ack_delay = dev_cap->local_ca_ack_delay;
	dev->caps.bf_reg_size	     = dev_cap->bf_reg_size;
	dev->caps.bf_regs_per_page   = dev_cap->bf_regs_per_page;
	dev->caps.max_sq_sg	     = dev_cap->max_sq_sg;
	dev->caps.max_rq_sg	     = dev_cap->max_rq_sg;
	dev->caps.max_wqes	     = dev_cap->max_qp_sz;
	dev->caps.max_qp_init_rdma   = dev_cap->max_requester_per_qp;
	dev->caps.max_srq_wqes	     = dev_cap->max_srq_sz;
	dev->caps.max_srq_sge	     = dev_cap->max_rq_sg - 1;
	dev->caps.reserved_srqs	     = dev_cap->reserved_srqs;
	dev->caps.max_sq_desc_sz     = dev_cap->max_sq_desc_sz;
	dev->caps.max_rq_desc_sz     = dev_cap->max_rq_desc_sz;
	dev->caps.num_qp_per_mgm     =  mlx4_get_qp_per_mgm(dev);
	/*
	 * Subtract 1 from the limit because we need to allocate a
	 * spare CQE so the HCA HW can tell the difference between an
	 * empty CQ and a full CQ.
	 */
	dev->caps.max_cqes	     = dev_cap->max_cq_sz - 1;
	dev->caps.reserved_cqs	     = dev_cap->reserved_cqs;
	dev->caps.reserved_eqs	     = dev_cap->reserved_eqs;
	dev->caps.mtts_per_seg	     = 1 << log_mtts_per_seg;
	dev->caps.reserved_mtts	     = DIV_ROUND_UP(dev_cap->reserved_mtts,
						    dev->caps.mtts_per_seg);
	dev->caps.reserved_mrws	     = dev_cap->reserved_mrws;

	/* The first 128 UARs are used for EQ doorbells */
	dev->caps.reserved_uars	     = max_t(int, 128, dev_cap->reserved_uars);
	dev->caps.reserved_pds	     = dev_cap->reserved_pds;
	dev->caps.mtt_entry_sz	     = dev->caps.mtts_per_seg * dev_cap->mtt_entry_sz;
	dev->caps.dmpt_entry_sz	     = dev_cap->dmpt_entry_sz;
	dev->caps.max_msg_sz         = dev_cap->max_msg_sz;
	dev->caps.page_size_cap	     = ~(u32) (dev_cap->min_page_sz - 1);
	dev->caps.flags		     = dev_cap->flags;
	dev->caps.bmme_flags	     = dev_cap->bmme_flags;
	dev->caps.reserved_lkey	     = dev_cap->reserved_lkey;
	dev->caps.stat_rate_support  = dev_cap->stat_rate_support;
	dev->caps.udp_rss	     = dev_cap->udp_rss;
	dev->caps.loopback_support   = dev_cap->loopback_support;
	dev->caps.vep_uc_steering    = dev_cap->vep_uc_steering;
	dev->caps.vep_mc_steering    = dev_cap->vep_mc_steering;
	dev->caps.wol                = dev_cap->wol;
	dev->caps.max_gso_sz	     = dev_cap->max_gso_sz;
	dev->caps.reserved_xrcds     = (dev->caps.flags & MLX4_DEV_CAP_FLAG_XRC) ?
		dev_cap->reserved_xrcds : 0;
	dev->caps.max_xrcds	     = (dev->caps.flags & MLX4_DEV_CAP_FLAG_XRC) ?
		dev_cap->max_xrcds : 0;

	dev->caps.log_num_macs  = log_num_mac;
	dev->caps.log_num_prios = use_prio ? 3 : 0;
	dev->caps.qinq          = dev_cap->qinq && enable_qinq;
	for (i = 1; i <= dev->caps.num_ports; ++i) {
		dev->caps.port_type[i] = MLX4_PORT_TYPE_IB;
		if (dev->caps.supported_type[i]) {
			if (dev->caps.supported_type[i] == MLX4_PORT_TYPE_ETH)
				dev->caps.port_type[i] = MLX4_PORT_TYPE_ETH;
			else if (dev->caps.supported_type[i] ==
				 MLX4_PORT_TYPE_IB)
				dev->caps.port_type[i] = MLX4_PORT_TYPE_IB;
		}
		mlx4_priv(dev)->sense.sense_allowed[i] =
			dev->caps.supported_type[i] == MLX4_PORT_TYPE_AUTO;
		if (mlx4_priv(dev)->sense.sense_allowed[i])
			dev->caps.possible_type[i] = MLX4_PORT_TYPE_AUTO;
		else
			dev->caps.possible_type[i] = dev->caps.port_type[i];

		if (dev->caps.log_num_macs > dev_cap->log_max_macs[i]) {
			dev->caps.log_num_macs = dev_cap->log_max_macs[i];
			mlx4_warn(dev, "Requested number of MACs is too much "
				  "for port %d, reducing to %d.\n",
				  i, 1 << dev->caps.log_num_macs);
		}
		dev->caps.log_num_vlans = dev_cap->log_max_vlans[i];
	}

	dev->caps.counters_mode = get_counters_mode(dev_cap->flags);
        if (mlx4_CMD_SET_IF_STAT(dev, dev->caps.counters_mode))
		mlx4_warn(dev, "setting counters mode to %d failed\n",
			  dev->caps.counters_mode);

	dev->caps.max_basic_counters = 1 << ilog2(dev_cap->max_basic_counters);
	dev->caps.max_ext_counters = 1 << ilog2(dev_cap->max_ext_counters);
	mlx4_dbg(dev, "max_basic_counters %d, max_ext_counters %d\n",
		 dev->caps.max_basic_counters, dev->caps.max_ext_counters);

	dev->caps.reserved_qps_cnt[MLX4_QP_REGION_FW] = dev_cap->reserved_qps;
	dev->caps.reserved_qps_cnt[MLX4_QP_REGION_ETH_ADDR] =
		dev->caps.reserved_qps_cnt[MLX4_QP_REGION_FC_ADDR] =
		(1 << dev->caps.log_num_macs) *
		(1 << dev->caps.log_num_vlans) *
		(1 << dev->caps.log_num_prios) *
		dev->caps.num_ports;

	dev->caps.reserved_qps = dev->caps.reserved_qps_cnt[MLX4_QP_REGION_FW] +
		dev->caps.reserved_qps_cnt[MLX4_QP_REGION_ETH_ADDR] +
		dev->caps.reserved_qps_cnt[MLX4_QP_REGION_FC_ADDR];

	dev->caps.mad_demux = dev_cap->mad_demux;

	/* Master function demultiplexes mads */
	dev->caps.sqp_demux = (mlx4_is_master(dev)) ? MLX4_MAX_NUM_SLAVES : 0;
	dev->caps.clp_ver = dev_cap->clp_ver;
	return 0;
}
/*The function checks if there are live vf, return the num of them*/
static int mlx4_how_many_lives_vf(struct mlx4_dev *dev)
{
	struct mlx4_priv *priv = mlx4_priv(dev);
	struct mlx4_slave_state *s_state;
	int i;
	int ret = 0;

	for (i = 1/*the ppf is 0*/; i < dev->num_slaves; ++i) {
		s_state = &priv->mfunc.master.slave_state[i];
		if (s_state->active && s_state->last_cmd != MLX4_COMM_CMD_RESET) {
			mlx4_warn(dev, "%s: slave: %d is still active\n", __func__, i);
			ret++;
		}
	}
	return ret;
}

int mlx4_get_parav_qkey(struct mlx4_dev *dev, u32 qpn, u32 *qkey)
{
	u32 qk = MLX4_RESERVED_QKEY_BASE;
	if (qpn >= dev->caps.tunnel_qpn + 8 + 16 * MLX4_MFUNC_MAX ||
	    qpn < dev->caps.tunnel_qpn + 8)
		return -EINVAL;

	if (qpn >= dev->caps.tunnel_qpn + 8 * (MLX4_MFUNC_MAX + 1))
		/* tunnel qp */
		qk += qpn - (dev->caps.tunnel_qpn + 8 * (MLX4_MFUNC_MAX + 1));
	else
		qk += qpn - (dev->caps.tunnel_qpn + 8);
	*qkey = qk;
	return 0;
}
EXPORT_SYMBOL(mlx4_get_parav_qkey);

int mlx4_is_slave_active(struct mlx4_dev *dev, int slave)
{
	struct mlx4_priv *priv = mlx4_priv(dev);
	struct mlx4_slave_state *s_slave;

	if (!mlx4_is_mfunc(dev) || !mlx4_is_master(dev))
		return 0;

	s_slave = &priv->mfunc.master.slave_state[slave];
	return (!!s_slave->active);
}
EXPORT_SYMBOL(mlx4_is_slave_active);

int mlx4_slave_cap(struct mlx4_dev *dev)
{
	int err;
	u32 page_size;

	err = mlx4_QUERY_SLAVE_CAP(dev, &dev->caps);
	if (err)
		return err;

	page_size = ~dev->caps.page_size_cap + 1;
	mlx4_warn(dev, "HCA minimum page size:%d\n", page_size);
	if (page_size > PAGE_SIZE) {
		mlx4_err(dev, "HCA minimum page size of %d bigger than "
			 "kernel PAGE_SIZE of %ld, aborting.\n",
			 page_size, PAGE_SIZE);
		return -ENODEV;
	}

	/* TODO: relax this assumption */
	if (dev->caps.uar_page_size != PAGE_SIZE) {
		mlx4_err(dev, "UAR size:%d != kernel PAGE_SIZE of %ld\n",
			 dev->caps.uar_page_size, PAGE_SIZE);
		return -ENODEV;
	}

	if (dev->caps.num_ports > MLX4_MAX_PORTS) {
		mlx4_err(dev, "HCA has %d ports, but we only support %d, "
			 "aborting.\n", dev->caps.num_ports, MLX4_MAX_PORTS);
		return -ENODEV;
	}

	if (dev->caps.uar_page_size * (dev->caps.num_uars -
				       dev->caps.reserved_uars) >
				       pci_resource_len(dev->pdev, 2)) {
		mlx4_err(dev, "HCA reported UAR region size of 0x%x bigger than "
			 "PCI resource 2 size of 0x%llx, aborting.\n",
			 dev->caps.uar_page_size * dev->caps.num_uars,
			 (unsigned long long) pci_resource_len(dev->pdev, 2));
		return -ENODEV;
	}

	/* Adjust eq number */
	if (dev->caps.num_eqs - dev->caps.reserved_eqs > num_possible_cpus() + 1)
		dev->caps.num_eqs = dev->caps.reserved_eqs + num_possible_cpus() + 1;

	/* Calculate our sqp_start */
	dev->caps.sqp_start = dev->caps.tunnel_qpn + 8 * (dev->caps.function + 1);

	/* Calculate fmr dmpt index */
	dev->caps.fmr_dmpt_base_idx = (dev->caps.fmr_dmpt_base -
				       dev->caps.dmpt_base) /
				       dev->caps.dmpt_entry_sz;

#if 0
	mlx4_warn(dev, "sqp_demux:%d\n", dev->caps.sqp_demux);
	mlx4_warn(dev, "num_uars:%d reserved_uars:%d uar region:0x%x bar2:0x%llx\n",
					  dev->caps.num_uars, dev->caps.reserved_uars,
					  dev->caps.uar_page_size * dev->caps.num_uars,
					  pci_resource_len(dev->pdev, 2));
	mlx4_warn(dev, "num_eqs:%d reserved_eqs:%d\n", dev->caps.num_eqs,
						       dev->caps.reserved_eqs);
	mlx4_warn(dev, "num_pds:%d reserved_pds:%d slave_pd_shift:%d pd_base:%d\n",
							dev->caps.num_pds,
							dev->caps.reserved_pds,
							dev->caps.slave_pd_shift,
							dev->caps.pd_base);
#endif
	return 0;
}

static int mlx4_save_config(struct mlx4_dev *dev)
{
	struct mlx4_port_config *config;
	int i;

	list_for_each_entry(config, &config_list, list) {
		if (config->pdev == dev->pdev) {
			for (i = 1; i <= dev->caps.num_ports; i++)
				config->port_type[i] = dev->caps.possible_type[i];
			return 0;
		}
	}

	config = kmalloc(sizeof(struct mlx4_port_config), GFP_KERNEL);
	if (!config)
		return -ENOMEM;

	config->pdev = dev->pdev;
	for (i = 1; i <= dev->caps.num_ports; i++)
		config->port_type[i] = dev->caps.possible_type[i];

	list_add_tail(&config->list, &config_list);

	return 0;
}

/*
 * Change the port configuration of the device.
 * Every user of this function must hold the port mutex.
 */
int mlx4_change_port_types(struct mlx4_dev *dev,
			   enum mlx4_port_type *port_types)
{
	int err = 0;
	int change = 0;
	int port;

	for (port = 0; port <  dev->caps.num_ports; port++) {
		/* Change the port type only if the new type is different
		 * from the current, and not set to Auto */
		if (port_types[port] != dev->caps.port_type[port + 1]) {
			change = 1;
			dev->caps.port_type[port + 1] = port_types[port];
		}
	}
	if (change) {
		mlx4_unregister_device(dev);
		for (port = 1; port <= dev->caps.num_ports; port++) {
			mlx4_CLOSE_PORT(dev, port);
			err = mlx4_SET_PORT(dev, port, -1);
			if (err) {
				mlx4_err(dev, "Failed to set port %d, "
					      "aborting\n", port);
				goto out;
			}
		}
		mlx4_set_port_mask(dev, &dev->caps, dev->caps.function);
		mlx4_save_config(dev);
		err = mlx4_register_device(dev);
	}

out:
	return err;
}

static ssize_t show_port_type(struct device *dev,
			      struct device_attribute *attr,
			      char *buf)
{
	struct mlx4_port_info *info = container_of(attr, struct mlx4_port_info,
						   port_attr);
	struct mlx4_dev *mdev = info->dev;
	char type[16];

	if (mdev->caps.port_type[info->port] == MLX4_PORT_TYPE_IB)
		strcpy(type, "ib");
	else if (mdev->caps.port_type[info->port] == MLX4_PORT_TYPE_ETH)
		strcpy(type, "eth");
	else
		strcpy(type, "not detected");
	if (mdev->caps.possible_type[info->port] == MLX4_PORT_TYPE_AUTO)
		sprintf(buf, "auto (%s)\n", type);
	else
		sprintf(buf, "%s\n", type);

	return strlen(buf);
}

static ssize_t set_port_type(struct device *dev,
			     struct device_attribute *attr,
			     const char *buf, size_t count)
{
	struct mlx4_port_info *info = container_of(attr, struct mlx4_port_info,
						   port_attr);
	struct mlx4_dev *mdev = info->dev;
	struct mlx4_priv *priv = mlx4_priv(mdev);
	enum mlx4_port_type types[MLX4_MAX_PORTS];
	enum mlx4_port_type new_types[MLX4_MAX_PORTS];
	int i;
	int err = 0;

	if (!strcmp(buf, "ib\n"))
		info->tmp_type = MLX4_PORT_TYPE_IB;
	else if (!strcmp(buf, "eth\n"))
		info->tmp_type = MLX4_PORT_TYPE_ETH;
	else if (!strcmp(buf, "auto\n"))
		info->tmp_type = MLX4_PORT_TYPE_AUTO;
	else {
		mlx4_err(mdev, "%s is not supported port type\n", buf);
		return -EINVAL;
	}

	mlx4_stop_sense(mdev);
	mutex_lock(&priv->port_mutex);
	/* Possible type is always the one that was delivered */
	mdev->caps.possible_type[info->port] = info->tmp_type;

	for (i = 0; i < mdev->caps.num_ports; i++) {
		types[i] = priv->port[i+1].tmp_type ? priv->port[i+1].tmp_type :
					mdev->caps.possible_type[i+1];
		if (types[i] == MLX4_PORT_TYPE_AUTO)
			types[i] = mdev->caps.port_type[i+1];
	}

	if (priv->trig) {
		if (++priv->changed_ports < mdev->caps.num_ports)
			goto out;
		else
			priv->trig = priv->changed_ports = 0;
	}

	if (!(mdev->caps.flags & MLX4_DEV_CAP_FLAG_DPDP)) {
		for (i = 1; i <= mdev->caps.num_ports; i++) {
			if (mdev->caps.possible_type[i] == MLX4_PORT_TYPE_AUTO) {
				mdev->caps.possible_type[i] = mdev->caps.port_type[i];
				err = -EINVAL;
			}
		}
	}
	if (err) {
		mlx4_err(mdev, "Auto sensing is not supported on this HCA. "
			       "Set only 'eth' or 'ib' for both ports "
			       "(should be the same)\n");
		goto out;
	}

	mlx4_do_sense_ports(mdev, new_types, types);

	err = mlx4_check_port_params(mdev, new_types);
	if (err)
		goto out;

	/* We are about to apply the changes after the configuration
	 * was verified, no need to remember the temporary types
	 * any more */
	for (i = 0; i < mdev->caps.num_ports; i++)
		priv->port[i + 1].tmp_type = 0;

	err = mlx4_change_port_types(mdev, new_types);

out:
	mlx4_start_sense(mdev);
	mutex_unlock(&priv->port_mutex);
	return err ? err : count;
}

static ssize_t trigger_port(struct device *dev, struct device_attribute *attr,
			    const char *buf, size_t count)
{
	struct pci_dev *pdev = to_pci_dev(dev);
	struct mlx4_dev *mdev = pci_get_drvdata(pdev);
	struct mlx4_priv *priv = container_of(mdev, struct mlx4_priv, dev);

	if (!priv)
		return -ENODEV;

	mutex_lock(&priv->port_mutex);
	priv->trig = 1;
	mutex_unlock(&priv->port_mutex);
	return count;
}
DEVICE_ATTR(port_trigger, S_IWUGO, NULL, trigger_port);

static int mlx4_load_fw(struct mlx4_dev *dev)
{
	struct mlx4_priv *priv = mlx4_priv(dev);
	int err;

	priv->fw.fw_icm = mlx4_alloc_icm(dev, priv->fw.fw_pages,
					 GFP_HIGHUSER | __GFP_NOWARN, 0);
	if (!priv->fw.fw_icm) {
		mlx4_err(dev, "Couldn't allocate FW area, aborting.\n");
		return -ENOMEM;
	}

	err = mlx4_MAP_FA(dev, priv->fw.fw_icm);
	if (err) {
		mlx4_err(dev, "MAP_FA command failed, aborting.\n");
		goto err_free;
	}

	err = mlx4_RUN_FW(dev);
	if (err) {
		mlx4_err(dev, "RUN_FW command failed, aborting.\n");
		goto err_unmap_fa;
	}

	return 0;

err_unmap_fa:
	mlx4_UNMAP_FA(dev);

err_free:
	mlx4_free_icm(dev, priv->fw.fw_icm, 0, MLX4_MR_FLAG_NONE);
	return err;
}

static int mlx4_init_cmpt_table(struct mlx4_dev *dev, u64 cmpt_base,
				int cmpt_entry_sz)
{
	struct mlx4_priv *priv = mlx4_priv(dev);
	int err;
	int num_eqs;

	err = mlx4_init_icm_table(dev, &priv->qp_table.cmpt_table,
				  cmpt_base +
				  ((u64) (MLX4_CMPT_TYPE_QP *
					  cmpt_entry_sz) << MLX4_CMPT_SHIFT),
				  cmpt_entry_sz, dev->caps.num_qps,
				  dev->caps.reserved_qps_cnt[MLX4_QP_REGION_FW],
				  0, 0);
	if (err)
		goto err;

	err = mlx4_init_icm_table(dev, &priv->srq_table.cmpt_table,
				  cmpt_base +
				  ((u64) (MLX4_CMPT_TYPE_SRQ *
					  cmpt_entry_sz) << MLX4_CMPT_SHIFT),
				  cmpt_entry_sz, dev->caps.num_srqs,
				  dev->caps.reserved_srqs, 0, 0);
	if (err)
		goto err_qp;

	err = mlx4_init_icm_table(dev, &priv->cq_table.cmpt_table,
				  cmpt_base +
				  ((u64) (MLX4_CMPT_TYPE_CQ *
					  cmpt_entry_sz) << MLX4_CMPT_SHIFT),
				  cmpt_entry_sz, dev->caps.num_cqs,
				  dev->caps.reserved_cqs, 0, 0);
	if (err)
		goto err_srq;

	num_eqs = (mlx4_is_mfunc(dev) && mlx4_is_master(dev)) ?
		roundup_pow_of_two(mlx4_master_get_num_eqs(dev)) :
		dev->caps.num_eqs;
	err = mlx4_init_icm_table(dev, &priv->eq_table.cmpt_table,
				  cmpt_base +
				  ((u64) (MLX4_CMPT_TYPE_EQ *
					  cmpt_entry_sz) << MLX4_CMPT_SHIFT),
				  cmpt_entry_sz, num_eqs, num_eqs, 0, 0);
	if (err)
		goto err_cq;

	return 0;

err_cq:
	mlx4_cleanup_icm_table(dev, &priv->cq_table.cmpt_table,
			       MLX4_MR_FLAG_NONE);

err_srq:
	mlx4_cleanup_icm_table(dev, &priv->srq_table.cmpt_table,
			       MLX4_MR_FLAG_NONE);

err_qp:
	mlx4_cleanup_icm_table(dev, &priv->qp_table.cmpt_table,
			       MLX4_MR_FLAG_NONE);

err:
	return err;
}

static int mlx4_init_icm(struct mlx4_dev *dev, struct mlx4_dev_cap *dev_cap,
			 struct mlx4_init_hca_param *init_hca, u64 icm_size)
{
	struct mlx4_priv *priv = mlx4_priv(dev);
	u64 aux_pages;
	int num_eqs;
	u32 num_mpts;
	int err;

	err = mlx4_SET_ICM_SIZE(dev, icm_size, &aux_pages);
	if (err) {
		mlx4_err(dev, "SET_ICM_SIZE command failed, aborting.\n");
		return err;
	}

	mlx4_dbg(dev, "%lld KB of HCA context requires %lld KB aux memory.\n",
		 (unsigned long long) icm_size >> 10,
		 (unsigned long long) aux_pages << 2);

	priv->fw.aux_icm = mlx4_alloc_icm(dev, aux_pages,
					  GFP_HIGHUSER | __GFP_NOWARN, 0);
	if (!priv->fw.aux_icm) {
		mlx4_err(dev, "Couldn't allocate aux memory, aborting.\n");
		return -ENOMEM;
	}

	err = mlx4_MAP_ICM_AUX(dev, priv->fw.aux_icm);
	if (err) {
		mlx4_err(dev, "MAP_ICM_AUX command failed, aborting.\n");
		goto err_free_aux;
	}

	err = mlx4_init_cmpt_table(dev, init_hca->cmpt_base, dev_cap->cmpt_entry_sz);
	if (err) {
		mlx4_err(dev, "Failed to map cMPT context memory, aborting.\n");
		goto err_unmap_aux;
	}


	num_eqs = (mlx4_is_mfunc(dev) && mlx4_is_master(dev)) ?
		roundup_pow_of_two(mlx4_master_get_num_eqs(dev)) :
		dev->caps.num_eqs;
	err = mlx4_init_icm_table(dev, &priv->eq_table.table,
				  init_hca->eqc_base, dev_cap->eqc_entry_sz,
				  num_eqs, num_eqs, 0, 0);
	if (err) {
		mlx4_err(dev, "Failed to map EQ context memory, aborting.\n");
		goto err_unmap_cmpt;
	}

	/*
	 * Reserved MTT entries must be aligned up to a cacheline
	 * boundary, since the FW will write to them, while the driver
	 * writes to all other MTT entries. (The variable
	 * dev->caps.mtt_entry_sz below is really the MTT segment
	 * size, not the raw entry size)
	 */
	dev->caps.reserved_mtts =
		ALIGN(dev->caps.reserved_mtts * dev->caps.mtt_entry_sz,
		      dma_get_cache_alignment()) / dev->caps.mtt_entry_sz;

	err = mlx4_init_icm_table(dev, &priv->mr_table.mtt_table,
				  init_hca->mtt_base,
				  dev->caps.mtt_entry_sz,
				  dev->caps.num_mtt_segs,
				  dev->caps.reserved_mtts, 1, 0);
	if (err) {
		mlx4_err(dev, "Failed to map MTT context memory, aborting.\n");
		goto err_unmap_eq;
	}

	/* reserve mpts for fmr */
	num_mpts = dev->caps.num_mpts >> 1;

	if ((num_mpts * dev->caps.dmpt_entry_sz) & (PAGE_SIZE - 1)) {
		mlx4_err(dev, "MPT size is not page aligned, aborting.\n");
		return -EINVAL;
	}

	err = mlx4_init_icm_table(dev, &priv->mr_table.dmpt_table,
				  init_hca->dmpt_base,
				  dev_cap->dmpt_entry_sz,
				  num_mpts,
				  dev->caps.reserved_mrws, 1, 1);
	if (err) {
		mlx4_err(dev, "Failed to map dMPT context memory, aborting.\n");
		goto err_unmap_mtt;
	}

	err = mlx4_init_icm_table(dev, &priv->qp_table.qp_table,
				  init_hca->qpc_base,
				  dev_cap->qpc_entry_sz,
				  dev->caps.num_qps,
				  dev->caps.reserved_qps_cnt[MLX4_QP_REGION_FW],
				  0, 0);
	if (err) {
		mlx4_err(dev, "Failed to map QP context memory, aborting.\n");
		goto err_unmap_dmpt;
	}

	err = mlx4_init_icm_table(dev, &priv->qp_table.auxc_table,
				  init_hca->auxc_base,
				  dev_cap->aux_entry_sz,
				  dev->caps.num_qps,
				  dev->caps.reserved_qps_cnt[MLX4_QP_REGION_FW],
				  0, 0);
	if (err) {
		mlx4_err(dev, "Failed to map AUXC context memory, aborting.\n");
		goto err_unmap_qp;
	}

	err = mlx4_init_icm_table(dev, &priv->qp_table.altc_table,
				  init_hca->altc_base,
				  dev_cap->altc_entry_sz,
				  dev->caps.num_qps,
				  dev->caps.reserved_qps_cnt[MLX4_QP_REGION_FW],
				  0, 0);
	if (err) {
		mlx4_err(dev, "Failed to map ALTC context memory, aborting.\n");
		goto err_unmap_auxc;
	}

	err = mlx4_init_icm_table(dev, &priv->qp_table.rdmarc_table,
				  init_hca->rdmarc_base,
				  dev_cap->rdmarc_entry_sz << priv->qp_table.rdmarc_shift,
				  dev->caps.num_qps,
				  dev->caps.reserved_qps_cnt[MLX4_QP_REGION_FW],
				  0, 0);
	if (err) {
		mlx4_err(dev, "Failed to map RDMARC context memory, aborting\n");
		goto err_unmap_altc;
	}

	err = mlx4_init_icm_table(dev, &priv->cq_table.table,
				  init_hca->cqc_base,
				  dev_cap->cqc_entry_sz,
				  dev->caps.num_cqs,
				  dev->caps.reserved_cqs, 0, 0);
	if (err) {
		mlx4_err(dev, "Failed to map CQ context memory, aborting.\n");
		goto err_unmap_rdmarc;
	}

	err = mlx4_init_icm_table(dev, &priv->srq_table.table,
				  init_hca->srqc_base,
				  dev_cap->srq_entry_sz,
				  dev->caps.num_srqs,
				  dev->caps.reserved_srqs, 0, 0);
	if (err) {
		mlx4_err(dev, "Failed to map SRQ context memory, aborting.\n");
		goto err_unmap_cq;
	}

	/*
	 * It's not strictly required, but for simplicity just map the
	 * whole multicast group table now.  The table isn't very big
	 * and it's a lot easier than trying to track ref counts.
	 */
	err = mlx4_init_icm_table(dev, &priv->mcg_table.table,
				  init_hca->mc_base, mlx4_get_mgm_entry_size(dev),
				  dev->caps.num_mgms + dev->caps.num_amgms,
				  dev->caps.num_mgms + dev->caps.num_amgms,
				  0, 0);
	if (err) {
		mlx4_err(dev, "Failed to map MCG context memory, aborting.\n");
		goto err_unmap_srq;
	}

	return 0;

err_unmap_srq:
	mlx4_cleanup_icm_table(dev, &priv->srq_table.table,
			       MLX4_MR_FLAG_NONE);

err_unmap_cq:
	mlx4_cleanup_icm_table(dev, &priv->cq_table.table,
			       MLX4_MR_FLAG_NONE);

err_unmap_rdmarc:
	mlx4_cleanup_icm_table(dev, &priv->qp_table.rdmarc_table,
			       MLX4_MR_FLAG_NONE);

err_unmap_altc:
	mlx4_cleanup_icm_table(dev, &priv->qp_table.altc_table,
			       MLX4_MR_FLAG_NONE);

err_unmap_auxc:
	mlx4_cleanup_icm_table(dev, &priv->qp_table.auxc_table,
			       MLX4_MR_FLAG_NONE);

err_unmap_qp:
	mlx4_cleanup_icm_table(dev, &priv->qp_table.qp_table,
			       MLX4_MR_FLAG_NONE);

err_unmap_dmpt:
	mlx4_cleanup_icm_table(dev, &priv->mr_table.dmpt_table,
			       MLX4_MR_FLAG_NONE);

err_unmap_mtt:
	mlx4_cleanup_icm_table(dev, &priv->mr_table.mtt_table,
			       MLX4_MR_FLAG_NONE);

err_unmap_eq:
	mlx4_cleanup_icm_table(dev, &priv->eq_table.table,
			       MLX4_MR_FLAG_NONE);

err_unmap_cmpt:
	mlx4_cleanup_icm_table(dev, &priv->eq_table.cmpt_table,
			       MLX4_MR_FLAG_NONE);
	mlx4_cleanup_icm_table(dev, &priv->cq_table.cmpt_table,
			       MLX4_MR_FLAG_NONE);
	mlx4_cleanup_icm_table(dev, &priv->srq_table.cmpt_table,
			       MLX4_MR_FLAG_NONE);
	mlx4_cleanup_icm_table(dev, &priv->qp_table.cmpt_table,
			       MLX4_MR_FLAG_NONE);

err_unmap_aux:
	mlx4_UNMAP_ICM_AUX(dev);

err_free_aux:
	mlx4_free_icm(dev, priv->fw.aux_icm, 0, MLX4_MR_FLAG_NONE);

	return err;
}

static void mlx4_free_icms(struct mlx4_dev *dev)
{
	struct mlx4_priv *priv = mlx4_priv(dev);

	mlx4_cleanup_icm_table(dev, &priv->mcg_table.table,
			       MLX4_MR_FLAG_NONE);
	mlx4_cleanup_icm_table(dev, &priv->srq_table.table,
			       MLX4_MR_FLAG_NONE);
	mlx4_cleanup_icm_table(dev, &priv->cq_table.table,
			       MLX4_MR_FLAG_NONE);
	mlx4_cleanup_icm_table(dev, &priv->qp_table.rdmarc_table,
			       MLX4_MR_FLAG_NONE);
	mlx4_cleanup_icm_table(dev, &priv->qp_table.altc_table,
			       MLX4_MR_FLAG_NONE);
	mlx4_cleanup_icm_table(dev, &priv->qp_table.auxc_table,
			       MLX4_MR_FLAG_NONE);
	mlx4_cleanup_icm_table(dev, &priv->qp_table.qp_table,
			       MLX4_MR_FLAG_NONE);
	mlx4_cleanup_icm_table(dev, &priv->mr_table.dmpt_table,
			       MLX4_MR_FLAG_NONE);
	mlx4_cleanup_icm_table(dev, &priv->mr_table.mtt_table,
			       MLX4_MR_FLAG_NONE);
	mlx4_cleanup_icm_table(dev, &priv->eq_table.table,
			       MLX4_MR_FLAG_NONE);
	mlx4_cleanup_icm_table(dev, &priv->eq_table.cmpt_table,
			       MLX4_MR_FLAG_NONE);
	mlx4_cleanup_icm_table(dev, &priv->cq_table.cmpt_table,
			       MLX4_MR_FLAG_NONE);
	mlx4_cleanup_icm_table(dev, &priv->srq_table.cmpt_table,
			       MLX4_MR_FLAG_NONE);
	mlx4_cleanup_icm_table(dev, &priv->qp_table.cmpt_table,
			       MLX4_MR_FLAG_NONE);

	mlx4_UNMAP_ICM_AUX(dev);
	mlx4_free_icm(dev, priv->fw.aux_icm, 0, MLX4_MR_FLAG_NONE);
}

static void mlx4_slave_exit(struct mlx4_dev *dev)
{
	struct mlx4_priv *priv = mlx4_priv(dev);

	down(&priv->cmd.slave_sem);
	if (mlx4_comm_cmd(dev, MLX4_COMM_CMD_RESET, 0, MLX4_COMM_TIME))
		mlx4_warn(dev, "Failed to close slave function.\n");
	up(&priv->cmd.slave_sem);
}

static int map_bf_area(struct mlx4_dev *dev)
{
	struct mlx4_priv *priv = mlx4_priv(dev);
	resource_size_t bf_start;
	resource_size_t bf_len;
	int err = 0;

	bf_start = pci_resource_start(dev->pdev, 2) + (dev->caps.num_uars << PAGE_SHIFT);
	bf_len = pci_resource_len(dev->pdev, 2) - (dev->caps.num_uars << PAGE_SHIFT);
	priv->bf_mapping = io_mapping_create_wc(bf_start, bf_len);
	if (!priv->bf_mapping)
		err = -ENOMEM;

	return err;
}

static void unmap_bf_area(struct mlx4_dev *dev)
{
	if (mlx4_priv(dev)->bf_mapping)
		io_mapping_free(mlx4_priv(dev)->bf_mapping);
}

static void mlx4_close_hca(struct mlx4_dev *dev)
{
	unmap_bf_area(dev);

	if (mlx4_is_mfunc(dev) && !mlx4_is_master(dev))
		mlx4_slave_exit(dev);
	else {
		mlx4_CLOSE_HCA(dev, 0);
		mlx4_free_icms(dev);
		mlx4_UNMAP_FA(dev);
		mlx4_free_icm(dev, mlx4_priv(dev)->fw.fw_icm, 0,
			      MLX4_MR_FLAG_NONE);
	}
}

static int mlx4_init_slave(struct mlx4_dev *dev)
{
	struct mlx4_priv *priv = mlx4_priv(dev);
	u64 dma = (u64) priv->mfunc.vhcr_dma;
	int num_of_reset_retries = NUM_OF_RESET_RETRIES;
	int ret_from_reset = 0;
	u32 slave_read;
	u32 cmd_channel_ver;

	down(&priv->cmd.slave_sem);
	priv->cmd.max_cmds = 1;
	mlx4_warn(dev, "Sending reset\n");
	ret_from_reset = mlx4_comm_cmd(dev, MLX4_COMM_CMD_RESET, 0, MLX4_COMM_TIME);
	/*if we are in the middle of flr the slave will try NUM_OF_RESET_RETRIES times
	before leaving.*/
	if(ret_from_reset) {
		if (MLX4_DELAY_RESET_SLAVE == ret_from_reset ) {
			msleep(SLEEP_TIME_IN_RESET);
			while (ret_from_reset && num_of_reset_retries) {
				mlx4_warn(dev, "slave is currently in the middle of FLR. retrying...(try num:%d)\n",
					  (NUM_OF_RESET_RETRIES - num_of_reset_retries  + 1));
				ret_from_reset = mlx4_comm_cmd(dev, MLX4_COMM_CMD_RESET, 0, MLX4_COMM_TIME);
				num_of_reset_retries = num_of_reset_retries - 1;
			}
		} else
			goto err;
	}

	/* check the driver version - the slave I/F revision must match the master's */
	slave_read = swab32(readl(&priv->mfunc.comm->slave_read));
	cmd_channel_ver = mlx4_comm_get_version();

	if (MLX4_COMM_GET_IF_REV(cmd_channel_ver) != MLX4_COMM_GET_IF_REV(slave_read)) {
		mlx4_err(dev, "slave driver version is not supported by the master\n");
		goto err;
	}

	mlx4_warn(dev, "Sending vhcr0\n");
	if (mlx4_comm_cmd(dev, MLX4_COMM_CMD_VHCR0, dma >> 48,
						    MLX4_COMM_TIME))
		goto err;
	if (mlx4_comm_cmd(dev, MLX4_COMM_CMD_VHCR1, dma >> 32,
						    MLX4_COMM_TIME))
		goto err;
	if (mlx4_comm_cmd(dev, MLX4_COMM_CMD_VHCR2, dma >> 16,
						    MLX4_COMM_TIME))
		goto err;
	if (mlx4_comm_cmd(dev, MLX4_COMM_CMD_VHCR_EN, dma, MLX4_COMM_TIME))
		goto err;
	up(&priv->cmd.slave_sem);
	return 0;

err:
	mlx4_comm_cmd(dev, MLX4_COMM_CMD_RESET, 0, 0);
	up(&priv->cmd.slave_sem);
	return -EIO;
}

static void mlx4_dom0_fmr_cap(struct mlx4_dev *dev,
			      struct mlx4_init_hca_param *init_hca,
				  struct mlx4_dev_cap *dev_cap)
{
	int num_mpts, num_fmr_clients;

	/* fmr clients are the VFs and the PF. Does not support multiple PFs */
	num_fmr_clients = dev_cap->max_funix + 1;

	/* should be retrieved using QUERY DEV CAP cmd */
	dev->caps.fmr_num_mpts = rounddown_pow_of_two((dev->caps.num_mpts >> 1)
						      / num_fmr_clients);


	/* can be replaced by a dynamic mtt allocator */
	dev->caps.fmr_num_mtt_segs =
			rounddown_pow_of_two((dev->caps.num_mtt_segs >> 1) /
			num_fmr_clients);

	num_mpts = dev->caps.num_mpts >> 1;

	dev->caps.fmr_dmpt_base		= init_hca->dmpt_base + num_mpts
					  * dev->caps.dmpt_entry_sz;
	dev->caps.fmr_dmpt_base_idx	= num_mpts;

	/* save for fmr mtt tables virtual address computation */
	dev->caps.mtt_base		= init_hca->mtt_base;
	dev->caps.dmpt_base		= init_hca->dmpt_base;
}

static int mlx4_init_hca(struct mlx4_dev *dev)
{
	struct mlx4_priv	  *priv = mlx4_priv(dev);
	struct mlx4_adapter	   adapter;
	struct mlx4_dev_cap	   dev_cap;
	struct mlx4_mod_stat_cfg   mlx4_cfg;
	struct mlx4_profile	   profile;
	struct mlx4_init_hca_param init_hca;
	struct mlx4_port_config	  *config;
	u64 icm_size;
	int err;
	int i;

	if (!mlx4_is_mfunc(dev) || mlx4_is_master(dev)) {
		err = mlx4_QUERY_FW(dev);
		if (err) {
			if (err == -EACCES)
				mlx4_info(dev, "non-primary physical function, skipping.\n");
			else
				mlx4_err(dev, "QUERY_FW command failed, aborting.\n");
			goto out;
		}

		err = mlx4_load_fw(dev);
		if (err) {
			mlx4_err(dev, "Failed to start FW, aborting.\n");
			goto out;
		}

		mlx4_cfg.log_pg_sz_m = 1;
		mlx4_cfg.log_pg_sz = 0;
		err = mlx4_MOD_STAT_CFG(dev, &mlx4_cfg);
		if (err)
			mlx4_warn(dev, "Failed to override log_pg_sz parameter\n");

		err = mlx4_dev_cap(dev, &dev_cap);
		if (err) {
			mlx4_err(dev, "QUERY_DEV_CAP command failed, aborting.\n");
			goto err_stop_fw;
		}

		process_mod_param_profile();
		profile = default_profile;

		list_for_each_entry(config, &config_list, list) {
			if (config->pdev == dev->pdev) {
				for (i = 1; i <= dev->caps.num_ports; i++) {
					dev->caps.possible_type[i] = config->port_type[i];
					if (config->port_type[i] != MLX4_PORT_TYPE_AUTO)
						dev->caps.port_type[i] = config->port_type[i];
				}
			}
		}

		icm_size = mlx4_make_profile(dev, &profile, &dev_cap, &init_hca);
		if ((long long) icm_size < 0) {
			err = icm_size;
			goto err_stop_fw;
		}

		init_hca.log_uar_sz = ilog2(dev->caps.num_uars);

		mlx4_dom0_fmr_cap(dev, &init_hca, &dev_cap);

		err = mlx4_init_icm(dev, &dev_cap, &init_hca, icm_size);
		if (err)
			goto err_stop_fw;

		err = mlx4_INIT_HCA(dev, &init_hca);
		if (err) {
			mlx4_err(dev, "INIT_HCA command failed, aborting.\n");
			goto err_free_icm;
		}
	} else {
		err = mlx4_init_slave(dev);
		if (err) {
			mlx4_err(dev, "Failed to initialize slave\n");
			goto out;
		}

		err = mlx4_slave_cap(dev);
		if (err) {
			mlx4_err(dev, "Failed to obtain slave caps\n");
			goto err_close_hca;
		}
	}

        if (map_bf_area(dev))
		mlx4_dbg(dev, "Kernel support for blue flame is not available "
			 "for kernels < 2.6.28\n");

	/*Only the master set the ports, all the rest got it from it.*/
	if (!mlx4_is_mfunc(dev) || mlx4_is_master(dev)) {
		mlx4_set_port_mask(dev, &dev->caps, dev->caps.function);
	}

	err = mlx4_QUERY_ADAPTER(dev, &adapter);
	if (err) {
		mlx4_err(dev, "QUERY_ADAPTER command failed, aborting.\n");
		goto unmap_bf;
	}

	priv->eq_table.inta_pin = adapter.inta_pin;
	memcpy(dev->board_id, adapter.board_id, sizeof dev->board_id);

	return 0;

unmap_bf:
	unmap_bf_area(dev);

err_close_hca:
	mlx4_close_hca(dev);
	goto out;

err_free_icm:
	if (!mlx4_is_mfunc(dev) || mlx4_is_master(dev))
		mlx4_free_icms(dev);

err_stop_fw:
	if (!mlx4_is_mfunc(dev) || mlx4_is_master(dev)) {
		mlx4_UNMAP_FA(dev);
		mlx4_free_icm(dev, priv->fw.fw_icm, 0, MLX4_MR_FLAG_NONE);
	}

out:
	return err;
}

static int mlx4_init_counters_table(struct mlx4_dev *dev)
{
	struct mlx4_priv *priv = mlx4_priv(dev);
	int err;
	int nent;

	switch (dev->caps.counters_mode) {
	case MLX4_CUNTERS_BASIC:
		nent = dev->caps.max_basic_counters;
		break;
	case MLX4_CUNTERS_EXT:
		nent = dev->caps.max_ext_counters;
		break;
	default:
		return -ENOENT;
	}
	err = mlx4_bitmap_init(&priv->counters_bitmap, nent, nent - 1, 0, 0);
	if (err)
		return err;

	return 0;
}

static void mlx4_cleanup_counters_table(struct mlx4_dev *dev)
{
	switch (dev->caps.counters_mode) {
	case MLX4_CUNTERS_BASIC:
	case MLX4_CUNTERS_EXT:
		mlx4_bitmap_cleanup(&mlx4_priv(dev)->counters_bitmap);
		break;
	default:
		break;
	}
}

int __mlx4_counter_alloc(struct mlx4_dev *dev, u32 *idx)
{
	struct mlx4_priv *priv = mlx4_priv(dev);

	switch (dev->caps.counters_mode) {
	case MLX4_CUNTERS_BASIC:
	case MLX4_CUNTERS_EXT:
		*idx = mlx4_bitmap_alloc(&priv->counters_bitmap);
		if (*idx == -1)
			return -ENOMEM;
		return 0;
	default:
		return -ENOMEM;
	}
}

int mlx4_counter_alloc(struct mlx4_dev *dev, u32 *idx)
{
	u64 out_param;
	int err;

	if (mlx4_is_mfunc(dev)) {
		err = mlx4_cmd_imm(dev, 0, &out_param, RES_COUNTER, RES_OP_RESERVE,
				   MLX4_CMD_ALLOC_RES, MLX4_CMD_TIME_CLASS_A, 0);
		if (!err)
			*idx = get_param_l(&out_param);

		return err;
	}
	return __mlx4_counter_alloc(dev, idx);
}
EXPORT_SYMBOL_GPL(mlx4_counter_alloc);

void __mlx4_counter_free(struct mlx4_dev *dev, u32 idx)
{
	switch (dev->caps.counters_mode) {
	case MLX4_CUNTERS_BASIC:
	case MLX4_CUNTERS_EXT:
		mlx4_bitmap_free(&mlx4_priv(dev)->counters_bitmap, idx);
		return;
	default:
		return;
	}
}

void mlx4_counter_free(struct mlx4_dev *dev, u32 idx)
{
	u64 in_param;

	if (mlx4_is_mfunc(dev)) {
		set_param_l(&in_param, idx);
		if (mlx4_cmd(dev, in_param, RES_COUNTER, RES_OP_RESERVE,
			     MLX4_CMD_FREE_RES, MLX4_CMD_TIME_CLASS_A, 0))
			mlx4_warn(dev, "Failed freeing counter: %d\n", idx);
		return;
	}
	__mlx4_counter_free(dev, idx);
}
EXPORT_SYMBOL_GPL(mlx4_counter_free);

void mlx4_slave_handle_guid(struct mlx4_dev *dev, int slave_id, u8 port_num, __be64 cur_ag)
{
	enum slave_port_state new_state;
	enum slave_port_gen_event gen_event;

	mlx4_gen_guid_change_eqe(dev, slave_id, port_num);

	mlx4_dbg(dev, "%s: update slave number:%d, port %d, GUID: 0x%llx\n", __func__,
		 slave_id, port_num, cur_ag);

	if (MLX4_NOT_SET_GUID != cur_ag) { /* valid GUID */
		new_state = set_and_calc_slave_port_state(dev, slave_id,
							  port_num,
							  MLX4_PORT_STATE_IB_PORT_STATE_EVENT_GID_VALID,
							  &gen_event);
		mlx4_dbg(dev, "%s: slave: %d, port:%d , new_port_state: %d, gen_event :%d\n",
			 __func__, slave_id, port_num, new_state, gen_event);

		if (SLAVE_PORT_GEN_EVENT_UP == gen_event) {
			mlx4_dbg(dev, "%s: sending PORT_UP event to slave: %d, port:%d\n",
				 __func__, slave_id, port_num);

			mlx4_gen_port_state_change_eqe(dev, slave_id, port_num,
						       MLX4_PORT_CHANGE_SUBTYPE_ACTIVE);
		} else
			mlx4_dbg(dev, "%s: GOT: %d event to slave: %d, port:%d\n",
				 __func__, gen_event, slave_id, port_num);

	} else { /*Invalidate GUID*/
		set_and_calc_slave_port_state(dev,
                                              slave_id,
                                              port_num,
                                              MLX4_PORT_STATE_IB_EVENT_GID_INVALID,
                                              &gen_event);
		mlx4_dbg(dev, "%s: sending MLX4_PORT_STATE_IB_EVENT_GID_INVALID"
			 " event to slave: %d, port:%d [got gen_event: %d]\n",
			 __func__, slave_id, port_num, gen_event);
		mlx4_gen_port_state_change_eqe(dev, slave_id, port_num, MLX4_PORT_CHANGE_SUBTYPE_DOWN);
	}
}
EXPORT_SYMBOL(mlx4_slave_handle_guid);

static int mlx4_config_mad_demux(struct mlx4_dev *dev)
{
	struct mlx4_cmd_mailbox *mailbox;
	int err = 0;

	/* Check if mad_demux is supported */
	if (!(dev->caps.mad_demux & 0x01))
		return 0;

        mailbox = mlx4_alloc_cmd_mailbox(dev);
        if (IS_ERR(mailbox)) {
		mlx4_warn(dev, "Failed to allocate mailbox for cmd MAD_IFC");
                return 1;
	}

	/* Query mad_demux to find out which events can
	   be generated by the FW */
	err = mlx4_cmd_box(dev, 0, mailbox->dma, 0x01 /* subn class */,
			   MLX4_CMD_MAD_DEMUX_QUERY_REST, MLX4_CMD_MAD_DEMUX,
			   MLX4_CMD_TIME_CLASS_B, 1);
	if (err) {
		mlx4_warn(dev, "Failed in mlx4_cmd_box of MLX4_CMD_MAD_DEMUX, "
			  "query restrictions");
                goto out;
	}

	/* Config mad_demux */
	err = mlx4_cmd(dev, mailbox->dma, 0x01 /* subn class */,
		       MLX4_CMD_MAD_DEMUX_CONFIG, MLX4_CMD_MAD_DEMUX,
		       MLX4_CMD_TIME_CLASS_B, 1);
	if (err) {
		mlx4_warn(dev, "Failed in mlx4_cmd_box of MLX4_CMD_MAD_DEMUX, "
			  "configure");
		goto out;
	}
	dev->is_internal_sma = 1;

out:	
	mlx4_free_cmd_mailbox(dev, mailbox);
	return err;
}

static int mlx4_setup_hca(struct mlx4_dev *dev)
{
	struct mlx4_priv *priv = mlx4_priv(dev);
	int err;
	int port;
	__be32 ib_port_default_caps;

	err = mlx4_init_uar_table(dev);
	if (err) {
		mlx4_err(dev, "Failed to initialize "
			 "user access region table, aborting.\n");
		return err;
	}

	err = mlx4_uar_alloc(dev, &priv->driver_uar);
	if (err) {
		mlx4_err(dev, "Failed to allocate driver access region, "
			 "aborting.\n");
		goto err_uar_table_free;
	}

	priv->kar = ioremap(priv->driver_uar.pfn << PAGE_SHIFT, PAGE_SIZE);
	if (!priv->kar) {
		mlx4_err(dev, "Couldn't map kernel access region, "
			 "aborting.\n");
		err = -ENOMEM;
		goto err_uar_free;
	}

	err = mlx4_init_pd_table(dev);
	if (err) {
		mlx4_err(dev, "Failed to initialize "
			 "protection domain table, aborting.\n");
		goto err_kar_unmap;
	}

	err = mlx4_init_xrcd_table(dev);
	if (err) {
		mlx4_err(dev, "Failed to initialize extended "
			 "reliably connected domain table, aborting.\n");
		goto err_pd_table_free;
	}

	err = mlx4_init_mr_table(dev);
	if (err) {
		mlx4_err(dev, "Failed to initialize "
			 "memory region table, aborting.\n");
		goto err_xrcd_table_free;
	}

	if (!mlx4_is_mfunc(dev) || mlx4_is_master(dev)) {
		err = mlx4_config_mad_demux(dev);
		if (err) {
			mlx4_err(dev, "Failed in config_mad_demux\n");
			goto err_mr_table_free;
		}
	}

	err = mlx4_init_eq_table(dev);
	if (err) {
		mlx4_err(dev, "Failed to initialize "
			 "event queue table, aborting.\n");
		goto err_mr_table_free;
	}

	err = mlx4_cmd_use_events(dev);
	if (err) {
		mlx4_err(dev, "Failed to switch to event-driven "
			      "firmware commands, aborting.\n");
		goto err_eq_table_free;
	}

	err = mlx4_NOP(dev);
	if (err) {
		if (dev->flags & MLX4_FLAG_MSI_X) {
			mlx4_warn(dev, "NOP command failed to generate MSI-X "
				  "interrupt IRQ %d).\n",
				  priv->eq_table.eq[dev->caps.num_comp_vectors].irq);
			mlx4_warn(dev, "Trying again without MSI-X.\n");
		} else {
			mlx4_err(dev, "NOP command failed to generate interrupt "
				 "(IRQ %d), aborting.\n",
				 priv->eq_table.eq[dev->caps.num_comp_vectors].irq);
			mlx4_err(dev, "BIOS or ACPI interrupt routing problem?\n");
		}

		goto err_cmd_poll;
	}

	mlx4_dbg(dev, "NOP command IRQ test passed\n");

	err = mlx4_init_cq_table(dev);
	if (err) {
		mlx4_err(dev, "Failed to initialize "
			 "completion queue table, aborting.\n");
		goto err_cmd_poll;
	}

	err = mlx4_init_srq_table(dev);
	if (err) {
		mlx4_err(dev, "Failed to initialize "
			 "shared receive queue table, aborting.\n");
		goto err_cq_table_free;
	}

	err = mlx4_init_qp_table(dev);
	if (err) {
		mlx4_err(dev, "Failed to initialize "
			 "queue pair table, aborting.\n");
		goto err_srq_table_free;
	}

	err = mlx4_init_mcg_table(dev);
	if (err) {
		mlx4_err(dev, "Failed to initialize "
			 "multicast group table, aborting.\n");
		goto err_qp_table_free;
	}

	err = mlx4_init_counters_table(dev);
	if (err && err != -ENOENT) {
		mlx4_err(dev, "Failed to initialize counters table, aborting.\n");
		goto err_mcg_table_free;
	}

	if (!mlx4_is_mfunc(dev) || mlx4_is_master(dev)) {
		int pkey_tbl_size;
		for (port = 1; port <= dev->caps.num_ports; port++) {
			ib_port_default_caps = 0;
			pkey_tbl_size = -1;
			err = mlx4_get_port_ib_caps(dev, port, &ib_port_default_caps);
			if (err)
				mlx4_warn(dev, "failed to get port %d default "
					  "ib capabilities (%d). Continuing with "
					  "caps = 0\n", port, err);
			dev->caps.ib_port_def_cap[port] = ib_port_default_caps;
			if (mlx4_is_master(dev)) {
				int i;
				for (i = 0; i < dev->num_slaves; i++)
					if (i != dev->caps.function)
						priv->mfunc.master.slave_state[i].ib_cap_mask[port] =
							ib_port_default_caps;
				pkey_tbl_size = dev->caps.pkey_table_len[port] - 1;
			}
			err = mlx4_SET_PORT(dev, port, pkey_tbl_size);
			if (err) {
				mlx4_err(dev, "Failed to set port %d, aborting\n",
					port);
				goto err_counters_table_free;
			}
		}
	}

	return 0;

err_counters_table_free:
	mlx4_cleanup_counters_table(dev);

err_mcg_table_free:
	mlx4_cleanup_mcg_table(dev);

err_qp_table_free:
	mlx4_cleanup_qp_table(dev);

err_srq_table_free:
	mlx4_cleanup_srq_table(dev);

err_cq_table_free:
	mlx4_cleanup_cq_table(dev);

err_cmd_poll:
	mlx4_cmd_use_polling(dev);

err_eq_table_free:
	mlx4_cleanup_eq_table(dev);

err_mr_table_free:
	mlx4_cleanup_mr_table(dev);

err_xrcd_table_free:
	mlx4_cleanup_xrcd_table(dev);

err_pd_table_free:
	mlx4_cleanup_pd_table(dev);

err_kar_unmap:
	iounmap(priv->kar);

err_uar_free:
	mlx4_uar_free(dev, &priv->driver_uar);

err_uar_table_free:
	mlx4_cleanup_uar_table(dev);
	return err;
}

static void mlx4_enable_msi_x(struct mlx4_dev *dev)
{
	struct mlx4_priv *priv = mlx4_priv(dev);
	struct msix_entry *entries;
	int nreq;
	int err;
	int i;
	dev->caps.poolsz           = 0;
	if (msi_x) {
		nreq = min_t(int, dev->caps.num_eqs - dev->caps.reserved_eqs,
				     num_online_cpus() + 1);
		entries = kcalloc(nreq, sizeof *entries, GFP_KERNEL);
		if (!entries)
			goto no_msi;

		for (i = 0; i < nreq; ++i)
			entries[i].entry = i;

	retry:
		err = pci_enable_msix(dev->pdev, entries, nreq);
		if (err) {
			/* Try again if at least 2 vectors are available */
			if (err > 1) {
				mlx4_info(dev, "Requested %d vectors, "
					  "but only %d MSI-X vectors available, "
					  "trying again\n", nreq, err);
				nreq = err;
				goto retry;
			}
			kfree(entries);
			goto no_msi;
		}

		dev->caps.num_comp_vectors = nreq - 1;
		for (i = 0; i < nreq; ++i)
			priv->eq_table.eq[i].irq = entries[i].vector;

		dev->flags |= MLX4_FLAG_MSI_X;

		kfree(entries);
		return;
	}

no_msi:
	dev->caps.num_comp_vectors = 1;

	for (i = 0; i < 2; ++i)
		priv->eq_table.eq[i].irq = dev->pdev->irq;
}

static int mlx4_init_port_info(struct mlx4_dev *dev, int port)
{
	struct mlx4_port_info *info = &mlx4_priv(dev)->port[port];
	int err = 0;

	info->dev = dev;
	info->port = port;
	if (!mlx4_is_mfunc(dev) || mlx4_is_master(dev)) {
		INIT_RADIX_TREE(&info->mac_tree, GFP_KERNEL);
		mlx4_init_mac_table(dev, &info->mac_table);
		mlx4_init_vlan_table(dev, &info->vlan_table);
		info->base_qpn = dev->caps.reserved_qps_base[MLX4_QP_REGION_ETH_ADDR] +
			(port - 1) * (1 << log_num_mac);
	}
	sprintf(info->dev_name, "mlx4_port%d", port);
	info->port_attr.attr.name = info->dev_name;
	info->port_attr.attr.mode = S_IRUGO | S_IWUSR;
	info->port_attr.show      = show_port_type;
	info->port_attr.store     = set_port_type;

	err = device_create_file(&dev->pdev->dev, &info->port_attr);
	if (err) {
		mlx4_err(dev, "Failed to create file for port %d\n", port);
		info->port = -1;
	}

	return err;
}

static void mlx4_cleanup_port_info(struct mlx4_port_info *info)
{
	if (info->port < 0)
		return;

	device_remove_file(&info->dev->pdev->dev, &info->port_attr);
}

static int mlx4_init_trigger(struct mlx4_priv *priv)
{
	memcpy(&priv->trigger_attr, &dev_attr_port_trigger,
	       sizeof(struct device_attribute));
        return device_create_file(&priv->dev.pdev->dev, &priv->trigger_attr);
}

static int mlx4_init_steering(struct mlx4_dev *dev)
{
	struct mlx4_priv *priv = mlx4_priv(dev);
	int num_entries = max(dev->caps.num_ports, dev->caps.pf_num);
	int i, j;

	priv->steer = kzalloc(sizeof(struct mlx4_steer) * num_entries, GFP_KERNEL);
	if (!priv->steer)
		return -ENOMEM;

	for (i = 0; i < num_entries; i++) {
		for (j = 0; j < MLX4_NUM_STEERS; j++) {
			INIT_LIST_HEAD(&priv->steer[i].promisc_qps[j]);
			INIT_LIST_HEAD(&priv->steer[i].steer_entries[j]);
		}
	}
	return 0;
}

static void mlx4_clear_steering(struct mlx4_dev *dev)
{
	struct mlx4_priv *priv = mlx4_priv(dev);
	struct mlx4_steer_index *entry, *tmp_entry;
	struct mlx4_promisc_qp *pqp, *tmp_pqp;
	int num_entries = max(dev->caps.num_ports, dev->caps.pf_num);
	int i, j;

	for (i = 0; i < num_entries; i++) {
		for (j = 0; j < MLX4_NUM_STEERS; j++) {
			list_for_each_entry_safe(pqp, tmp_pqp,
						 &priv->steer[i].promisc_qps[j],
						 list) {
				list_del(&pqp->list);
				kfree(pqp);
			}
			list_for_each_entry_safe(entry, tmp_entry,
						 &priv->steer[i].steer_entries[j],
						 list) {
				list_del(&entry->list);
				list_for_each_entry_safe(pqp, tmp_pqp,
							 &entry->duplicates,
							 list) {
					list_del(&pqp->list);
					kfree(pqp);
				}
				kfree(entry);
			}
		}
	}
	kfree(priv->steer);
}

static int extended_func_num(struct pci_dev *pdev)
{
	return PCI_SLOT(pdev->devfn) * 8 + PCI_FUNC(pdev->devfn);
}

static int __mlx4_init_one(struct pci_dev *pdev, const struct pci_device_id *id)
{
	struct mlx4_priv *priv;
	struct mlx4_dev *dev;
	int err, i;
	int port;
	int mfunc_cleaned_up = 0;

	printk(KERN_INFO PFX "Initializing %s\n",
	       pci_name(pdev));

	err = pci_enable_device(pdev);
	if (err) {
		dev_err(&pdev->dev, "Cannot enable PCI device, "
			"aborting.\n");
		return err;
	}

	/* Since we give to each VF two GUIDs, we can't support more than 63 VFs */
	if (sr_iov > MLX4_MAX_NUM_VF - 1) {
		printk(KERN_ERR "There are more VF's(%d) than allowed(%d)\n",sr_iov, MLX4_MAX_NUM_VF - 1);
		return -EINVAL;
	}
	/*
	 * Check for BARs.
	 */
	if (((id == NULL) || !(id->driver_data & MLX4_VF)) &&
	    !(pci_resource_flags(pdev, 0) & IORESOURCE_MEM)) {
		dev_err(&pdev->dev, "Missing DCS, aborting.(id == 0X%p, id->driver_data: 0x%lx,"
				    " pci_resource_flags(pdev, 0):0x%lx)\n",
				     id, id ? id->driver_data : 0, pci_resource_flags(pdev, 0));
		err = -ENODEV;
		goto err_disable_pdev;
	}
	if (!(pci_resource_flags(pdev, 2) & IORESOURCE_MEM)) {
		dev_err(&pdev->dev, "Missing UAR, aborting.\n");
		err = -ENODEV;
		goto err_disable_pdev;
	}

	err = pci_request_region(pdev, 0, DRV_NAME);
	if (err) {
		dev_err(&pdev->dev, "Cannot request control region (err:0X%x), aborting.\n", err);
		goto err_disable_pdev;
	}

	err = pci_request_region(pdev, 2, DRV_NAME);
	if (err) {
		dev_err(&pdev->dev, "Cannot request UAR region (err:0X%x), aborting.\n", err);
		goto err_release_bar0;
	}

	pci_set_master(pdev);

	err = pci_set_dma_mask(pdev, DMA_BIT_MASK(64));
	if (err) {
		dev_warn(&pdev->dev, "Warning: couldn't set 64-bit PCI DMA mask.\n");
		err = pci_set_dma_mask(pdev, DMA_BIT_MASK(32));
		if (err) {
			dev_err(&pdev->dev, "Can't set PCI DMA mask, aborting.\n");
			goto err_release_bar2;
		}
	}
	err = pci_set_consistent_dma_mask(pdev, DMA_BIT_MASK(64));
	if (err) {
		dev_warn(&pdev->dev, "Warning: couldn't set 64-bit "
			 "consistent PCI DMA mask.\n");
		err = pci_set_consistent_dma_mask(pdev, DMA_BIT_MASK(32));
		if (err) {
			dev_err(&pdev->dev, "Can't set consistent PCI DMA mask, "
				"aborting.\n");
			goto err_release_bar2;
		}
	}

	priv = kzalloc(sizeof *priv, GFP_KERNEL);
	if (!priv) {
		dev_err(&pdev->dev, "Device struct alloc failed, "
			"aborting.\n");
		err = -ENOMEM;
		goto err_release_bar2;
	}

	dev       = &priv->dev;
	dev->pdev = pdev;
	INIT_LIST_HEAD(&priv->ctx_list);
	spin_lock_init(&priv->ctx_lock);

	mutex_init(&priv->port_mutex);
	mutex_init(&priv->port_ops_mutex);

	INIT_LIST_HEAD(&priv->pgdir_list);
	mutex_init(&priv->pgdir_mutex);

	for (i = 0; i < MLX4_MAX_PORTS; ++i)
		priv->iboe_counter_index[i] = -1;

	INIT_LIST_HEAD(&priv->bf_list);
	mutex_init(&priv->bf_mutex);

	/* Detect if this device is a virtual function */
	if (id && id->driver_data & MLX4_VF) {
		/* When acting as pf, we normally skip vfs unless explicitly
		 * requested to probe them. */
		if (sr_iov && extended_func_num(pdev) > probe_vf) {
			mlx4_warn(dev, "Skipping virtual function:%d\n",
						extended_func_num(pdev));
			err = -ENODEV;
			goto err_free_dev;
		}
		mlx4_warn(dev, "Detected virtual function - running in slave mode\n");
		dev->flags |= MLX4_FLAG_MFUNC;
	}

	/* We reset the device and enable SRIOV only for physical devices */
	if (!mlx4_is_mfunc(dev) || mlx4_is_master(dev)) {
		/* Claim ownership on the device,
		 * if already taken, act as slave*/
		err = mlx4_get_ownership(dev);
		if (err) {
			if (err < 0)
				goto err_free_dev;
			else {
				err = 0;
				dev->flags |= MLX4_FLAG_MFUNC;
				dev->flags &= ~MLX4_FLAG_MASTER;
				goto slave_start;
			}
		}

		if (sr_iov) {
			mlx4_warn(dev, "Enabling sriov with:%d vfs\n", sr_iov);
			if (pci_enable_sriov(pdev, sr_iov)) {
				mlx4_err(dev, "Failed to enable sriov, aborting.\n");
				goto err_rel_own;
			}
			mlx4_warn(dev, "Running in master mode\n");
			dev->flags |= MLX4_FLAG_SRIOV | MLX4_FLAG_MASTER;
			dev->sr_iov = sr_iov;
		}

		/*
		 * Now reset the HCA before we touch the PCI capabilities or
		 * attempt a firmware command, since a boot ROM may have left
		 * the HCA in an undefined state.
		 */
		err = mlx4_reset(dev);
		if (err) {
			mlx4_err(dev, "Failed to reset HCA, aborting.\n");
			goto err_sriov;
		}
	}

slave_start:
	if (mlx4_cmd_init(dev)) {
		mlx4_err(dev, "Failed to init command interface, aborting.\n");
		goto err_sriov;
	}

	/* In slave functions, the communication channel must be initialized before
	 * posting commands. Also, init num_slaves before calling mlx4_init_hca */
	if (mlx4_is_mfunc(dev)) {
		if(mlx4_is_master(dev))
			dev->num_slaves = MLX4_MAX_NUM_SLAVES;
		else {
			dev->num_slaves = 0;
			if (mlx4_multi_func_init(dev)) {
				mlx4_err(dev, "Failed to init slave mfunc"
					 " interface, aborting.\n");
				goto err_cmd;
			}
		}
	}

	err = mlx4_init_hca(dev);
	if (err) {
		if (err == -EACCES) {
			/* Not primary Physical function
			 * Running in slave mode */
			mlx4_cmd_cleanup(dev);
			dev->flags |= MLX4_FLAG_MFUNC;
			dev->flags &= ~MLX4_FLAG_MASTER;
			goto slave_start;
		} else
			goto err_mfunc;
	}

	/* In master functions, the communication channel must be initialized after obtaining
	 * its address from fw */
	if (mlx4_is_mfunc(dev) && mlx4_is_master(dev)) {
		if (mlx4_multi_func_init(dev)) {
			mlx4_err(dev, "Failed to init master mfunc interface, aborting.\n");
			goto err_close;
		}
	}

	err = mlx4_alloc_eq_table(dev);
	if (err)
		goto err_master_mfunc;

	mlx4_enable_msi_x(dev);
	if ((mlx4_is_mfunc(dev) && !mlx4_is_master(dev)) &&
	    !(dev->flags & MLX4_FLAG_MSI_X)) {
		mlx4_err(dev, "INTx is not supported in slave mode, aborting.\n");
		goto err_free_eq;
	}

	if (!mlx4_is_mfunc(dev) || mlx4_is_master(dev)) {
		err = mlx4_init_steering(dev);
		if (err)
			goto err_free_eq;
	}

	err = mlx4_setup_hca(dev);
	if (err == -EBUSY && (dev->flags & MLX4_FLAG_MSI_X) &&
	    (!mlx4_is_mfunc(dev) || mlx4_is_master(dev))) {
		dev->flags &= ~MLX4_FLAG_MSI_X;
		pci_disable_msix(pdev);
		err = mlx4_setup_hca(dev);
	}

	if (err)
		goto err_steer;

	for (port = 1; port <= dev->caps.num_ports; port++) {
		err = mlx4_init_port_info(dev, port);
		if (err)
			goto err_port;
	}

	err = mlx4_register_device(dev);
	if (err)
		goto err_port;

	err = mlx4_init_trigger(priv);
	if (err)
		goto err_register;

	err = mlx4_sense_init(dev);
	if (err)
		goto err_trigger;

	mlx4_start_sense(dev);

	pci_set_drvdata(pdev, dev);

	err = mlx4_rtt_init(dev);
	if (err)
		goto err_sense;

	return 0;

err_sense:
	mlx4_sense_cleanup(dev);
err_trigger:
	device_remove_file(&dev->pdev->dev, &priv->trigger_attr);
err_register:
	mlx4_unregister_device(dev);
err_port:
	for (--port; port >= 1; --port)
		mlx4_cleanup_port_info(&priv->port[port]);

	mlx4_cleanup_counters_table(dev);
	mlx4_cleanup_mcg_table(dev);
	mlx4_cleanup_qp_table(dev);
	mlx4_cleanup_srq_table(dev);
	mlx4_cleanup_cq_table(dev);
	mlx4_cmd_use_polling(dev);
	mlx4_cleanup_eq_table(dev);
	mlx4_cleanup_mr_table(dev);
	mlx4_cleanup_xrcd_table(dev);
	mlx4_cleanup_pd_table(dev);
	mlx4_cleanup_uar_table(dev);

err_steer:
	if (!mlx4_is_mfunc(dev) || mlx4_is_master(dev))
		mlx4_clear_steering(dev);

err_free_eq:
	mlx4_free_eq_table(dev);

err_master_mfunc:
	if (mlx4_is_mfunc(dev) && mlx4_is_master(dev))
		mlx4_multi_func_cleanup(dev);

	mfunc_cleaned_up = 1;

err_close:
	if (dev->flags & MLX4_FLAG_MSI_X)
		pci_disable_msix(pdev);

	mlx4_close_hca(dev);

err_mfunc:
	if (!mfunc_cleaned_up && mlx4_is_mfunc(dev) && !mlx4_is_master(dev))
		mlx4_multi_func_cleanup(dev);

err_cmd:
	mlx4_cmd_cleanup(dev);

err_sriov:
	if (sr_iov && (dev->flags & MLX4_FLAG_SRIOV))
		pci_disable_sriov(pdev);

err_rel_own:
	if (!mlx4_is_mfunc(dev) || mlx4_is_master(dev))
		mlx4_free_ownership(dev);

err_free_dev:
	kfree(priv);

err_release_bar2:
	pci_release_region(pdev, 2);

err_release_bar0:
	pci_release_region(pdev, 0);

err_disable_pdev:
	pci_disable_device(pdev);
	pci_set_drvdata(pdev, NULL);
	return err;
}

static int __devinit mlx4_init_one(struct pci_dev *pdev,
				   const struct pci_device_id *id)
{
	static int mlx4_version_printed;

	if (!mlx4_version_printed) {
		printk(KERN_INFO "%s", mlx4_version);
		++mlx4_version_printed;
	}

	return __mlx4_init_one(pdev, id);
}

static void mlx4_remove_one(struct pci_dev *pdev)
{
	struct mlx4_dev  *dev  = pci_get_drvdata(pdev);
	struct mlx4_priv *priv = mlx4_priv(dev);
	int p;

	if (dev) {
		/*in SRIOV it is not allowed to unload the ppf's driver when there is alive vf's*/
		if (mlx4_is_mfunc(dev) && mlx4_is_master(dev)) {
			if (mlx4_how_many_lives_vf(dev))
				printk(KERN_ERR "Removing PPF when there are assinged VF's !!!\n");
		}
		mlx4_rtt_cleanup(dev);
		mlx4_sense_cleanup(dev);
		mlx4_unregister_device(dev);
		device_remove_file(&dev->pdev->dev, &priv->trigger_attr);

		for (p = 1; p <= dev->caps.num_ports; p++) {
			mlx4_cleanup_port_info(&priv->port[p]);
			mlx4_CLOSE_PORT(dev, p);
		}

                mlx4_cleanup_counters_table(dev);
		mlx4_cleanup_mcg_table(dev);
		mlx4_cleanup_qp_table(dev);
		mlx4_cleanup_srq_table(dev);
		mlx4_cleanup_cq_table(dev);
		mlx4_cmd_use_polling(dev);
		mlx4_cleanup_eq_table(dev);
		mlx4_cleanup_mr_table(dev);
		mlx4_cleanup_xrcd_table(dev);
		mlx4_cleanup_pd_table(dev);

		if (mlx4_is_mfunc(dev) && mlx4_is_master(dev)) {
			mlx4_free_resource_tracker(dev);
		}

		if (mlx4_is_mfunc(dev) && !mlx4_is_master(dev))
			mlx4_fmr_slave_context_term(dev);

		iounmap(priv->kar);
		mlx4_uar_free(dev, &priv->driver_uar);
		mlx4_cleanup_uar_table(dev);
		if (!mlx4_is_mfunc(dev) || mlx4_is_master(dev))
			mlx4_clear_steering(dev);
		mlx4_free_eq_table(dev);
		if (mlx4_is_mfunc(dev) && mlx4_is_master(dev))
			mlx4_multi_func_cleanup(dev);
		mlx4_close_hca(dev);
		if (mlx4_is_mfunc(dev) && !mlx4_is_master(dev))
			mlx4_multi_func_cleanup(dev);
		mlx4_cmd_cleanup(dev);

		if (dev->flags & MLX4_FLAG_MSI_X)
			pci_disable_msix(pdev);
		if (sr_iov && (dev->flags & MLX4_FLAG_SRIOV)) {
			mlx4_warn(dev, "Disabling sriov\n");
			pci_disable_sriov(pdev);
		}

		if (!mlx4_is_mfunc(dev) || mlx4_is_master(dev))
			mlx4_free_ownership(dev);
		kfree(priv);
		pci_release_region(pdev, 2);
		pci_release_region(pdev, 0);
		pci_disable_device(pdev);
		pci_set_drvdata(pdev, NULL);
	}
}

int mlx4_restart_one(struct pci_dev *pdev)
{
	mlx4_remove_one(pdev);
	return __mlx4_init_one(pdev, NULL);
}

int mlx4_gid_idx_to_slave(struct mlx4_dev *dev, int gid_index)
{
	return gid_index % (dev->sr_iov + 1);
}
EXPORT_SYMBOL_GPL(mlx4_gid_idx_to_slave);

static struct pci_device_id mlx4_pci_table[] = {
	{ MLX4_VDEVICE(MELLANOX, 0x6340, 0) }, /* MT25408 "Hermon" SDR */
	{ MLX4_VDEVICE(MELLANOX, 0x6341, MLX4_VF) }, /* MT25408 "Hermon" SDR VF */
	{ MLX4_VDEVICE(MELLANOX, 0x634a, 0) }, /* MT25408 "Hermon" DDR */
	{ MLX4_VDEVICE(MELLANOX, 0x634b, MLX4_VF) }, /* MT25408 "Hermon" DDR VF */
	{ MLX4_VDEVICE(MELLANOX, 0x6354, 0) }, /* MT25408 "Hermon" QDR */
	{ MLX4_VDEVICE(MELLANOX, 0x6732, 0) }, /* MT25408 "Hermon" DDR PCIe gen2 */
	{ MLX4_VDEVICE(MELLANOX, 0x6733, MLX4_VF) }, /* MT25408 "Hermon" DDR PCIe gen2 VF */
	{ MLX4_VDEVICE(MELLANOX, 0x673c, 0) }, /* MT25408 "Hermon" QDR PCIe gen2 */
	{ MLX4_VDEVICE(MELLANOX, 0x673d, MLX4_VF) }, /* MT25408 "Hermon" QDR PCIe gen2 VF */
	{ MLX4_VDEVICE(MELLANOX, 0x6368, 0) }, /* MT25408 "Hermon" EN 10GigE */
	{ MLX4_VDEVICE(MELLANOX, 0x6369, MLX4_VF) }, /* MT25408 "Hermon" EN 10GigE VF */
	{ MLX4_VDEVICE(MELLANOX, 0x6750, 0) }, /* MT25408 "Hermon" EN 10GigE PCIe gen2 */
	{ MLX4_VDEVICE(MELLANOX, 0x6751, MLX4_VF) }, /* MT25408 "Hermon" EN 10GigE PCIe gen2 VF */
	{ MLX4_VDEVICE(MELLANOX, 0x6372, 0) }, /* MT25458 ConnectX EN 10GBASE-T 10GigE */
	{ MLX4_VDEVICE(MELLANOX, 0x6373, MLX4_VF) }, /* MT25458 ConnectX EN 10GBASE-T 10GigE */
	{ MLX4_VDEVICE(MELLANOX, 0x675a, 0) }, /* MT25458 ConnectX EN 10GBASE-T+Gen2 10GigE */
	{ MLX4_VDEVICE(MELLANOX, 0x675b, MLX4_VF) }, /* MT25458 ConnectX EN 10GBASE-T+Gen2 10GigE */
	{ MLX4_VDEVICE(MELLANOX, 0x6764, 0) }, /* MT26468 ConnectX EN 10GigE PCIe gen2*/
	{ MLX4_VDEVICE(MELLANOX, 0x6765, MLX4_VF) }, /* MT26468 ConnectX EN 10GigE PCIe gen2 VF*/
	{ MLX4_VDEVICE(MELLANOX, 0x6746, 0) }, /* MT26438 ConnectX VPI PCIe 2.0 5GT/s - IB QDR / 10GigE Virt+ */
	{ MLX4_VDEVICE(MELLANOX, 0x6747, MLX4_VF) }, /* MT26438 ConnectX VPI PCIe 2.0 5GT/s - IB QDR / 10GigE Virt+ VF*/
	{ MLX4_VDEVICE(MELLANOX, 0x676e, 0) }, /* MT26478 ConnectX EN 40GigE PCIe 2.0 5GT/s */
	{ MLX4_VDEVICE(MELLANOX, 0x676f, MLX4_VF) }, /* MT26478 ConnectX EN 40GigE PCIe 2.0 5GT/s VF*/
	{ MLX4_VDEVICE(MELLANOX, 0x6778, 0) }, /* MT26488 ConnectX VPI PCIe 2.0 5GT/s - IB DDR / 10GigE Virt+ */
	{ MLX4_VDEVICE(MELLANOX, 0x6779, MLX4_VF) }, /* MT26488 ConnectX VPI PCIe 2.0 5GT/s - IB DDR / 10GigE Virt+ VF*/
	{ MLX4_VDEVICE(MELLANOX, 0x1002, MLX4_VF) }, /* ConnectX-2 Virtual Function */
	{ MLX4_VDEVICE(MELLANOX, 0x1003, 0) }, /* ConnectX-3 */
	{ MLX4_VDEVICE(MELLANOX, 0x1004, MLX4_VF) }, /* ConnectX-3 Virtual Function */
	{ MLX4_VDEVICE(MELLANOX, 0x1005, 0) },
	{ MLX4_VDEVICE(MELLANOX, 0x1006, 0) },
	{ MLX4_VDEVICE(MELLANOX, 0x1007, 0) },
	{ MLX4_VDEVICE(MELLANOX, 0x1008, 0) },
	{ MLX4_VDEVICE(MELLANOX, 0x1009, 0) },
	{ MLX4_VDEVICE(MELLANOX, 0x100a, 0) },
	{ MLX4_VDEVICE(MELLANOX, 0x100b, 0) },
	{ MLX4_VDEVICE(MELLANOX, 0x100c, 0) },
	{ MLX4_VDEVICE(MELLANOX, 0x100d, 0) },
	{ MLX4_VDEVICE(MELLANOX, 0x100e, 0) },
	{ MLX4_VDEVICE(MELLANOX, 0x100f, 0) },
	{ 0, }
};

MODULE_DEVICE_TABLE(pci, mlx4_pci_table);

static struct pci_driver mlx4_driver = {
	.name		= DRV_NAME,
	.id_table	= mlx4_pci_table,
	.probe		= mlx4_init_one,
	.remove		= __devexit_p(mlx4_remove_one)
};

static int __init mlx4_verify_params(void)
{
	if ((log_num_mac < 0) || (log_num_mac > 7)) {
		printk(KERN_WARNING "mlx4_core: bad num_mac: %d\n", log_num_mac);
		return -1;
	}

	if ((log_mtts_per_seg < 1) || (log_mtts_per_seg > 7)) {
		printk(KERN_WARNING "mlx4_core: bad log_mtts_per_seg: %d\n", log_mtts_per_seg);
		return -1;
	}

	return 0;
}
static int __init mlx4_init(void)
{
	int ret;

	mutex_init(&drv_mutex);

	if (mlx4_verify_params())
		return -EINVAL;

	mlx4_catas_init();
	mlx4_fmr_master_init();
	mlx4_fmr_slave_init();

	mlx4_wq = create_singlethread_workqueue("mlx4");
	if (!mlx4_wq)
		return -ENOMEM;

	ret = pci_register_driver(&mlx4_driver);
	return ret < 0 ? ret : 0;
}

static void __exit mlx4_cleanup(void)
{
	mutex_lock(&drv_mutex);
	mlx4_config_cleanup();
	pci_unregister_driver(&mlx4_driver);
	mutex_unlock(&drv_mutex);
	destroy_workqueue(mlx4_wq);
}

module_init(mlx4_init);
module_exit(mlx4_cleanup);

