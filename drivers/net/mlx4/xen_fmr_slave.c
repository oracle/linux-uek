/*
 * Copyright (c) 2012 Oracle.  All rights reserved.
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
 *
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/autoconf.h>

#include <xen/grant_table.h>
#include <xen/xen.h>
#include <xen/page.h>
#include <xen/xenbus.h>

#include "fmr_api.h"
#include "xen_fmr.h"

MODULE_AUTHOR("Yuval Shaia <yuval.shaia@oracle.com>");
MODULE_DESCRIPTION("XEN FMR API - Frontend");
MODULE_LICENSE("Dual BSD/GPL");
MODULE_VERSION(DRV_VERSION);

/* Indicates if we are running in dom0 or domU */
bool			m_running_on_dom_u;
/* Save running domain ID */
domid_t			m_my_dom_id;
/* Indicate no xenbus operation until registration completed */
int			m_registered_to_xenbus;
/* Will be use to make sure all shared pages were unshared */
struct ref_count	m_shr_ref_count;
/* Will be use to make sure all VFs were cleaned */
struct ref_count	m_vf_ref_count;

/**
 * Slave Context, initiated in share(), used and destroyed in
 * unshare()
 */
struct xen_slave_vpm_ctx {
	addr_ref_t	gref;
} xen_slave_vpm_ctx;

/**
 * Called by each FV on load
 */
int mlx_xen_fmr_icm_slave_init(struct pci_dev *vf,
			       u8 vpm_info_size,
			       u8 fmr_info_size,
			       u8 *fmr_info,
			       void **vf_ctx)
{
	DPRINTK("xen_fmr_slave: FMR-ICM Slave Initializing for device %d\n",
		vf->devfn);

	/* Integration check */
	if (unlikely(vpm_info_size != XEN_VPM_SZ)) {
		printk(KERN_ERR "xen_fmr_slave: Invalid vpm_info_size\n");
		return -EINVAL;
	}

	/* Caller trust init when context is not NULL so we malloc
	   dummy buffer */
	*vf_ctx = kmalloc(sizeof(int), GFP_KERNEL);

	ref_count_inc(&m_vf_ref_count);

	printk(KERN_INFO "xen_fmr_slave: FMR-ICM Slave"
	       " Initialized for device %d\n", vf->devfn);

	return 0;
}

/**
 * Share pages using info from vpm and returns ctx handle
 */
int mlx_xen_fmr_icm_slave_share(void *vf_ctx,
				void *virt_addr,
				struct vpm *vpm_page,
				void **vpm_ctx)
{
	struct xen_slave_vpm_ctx	*my_vpm_ctx;
	struct xen_vpm			*xen_vpm;
	addr_ref_t			addr_ref;
	int				res = 0;

	DPRINTK("xen_fmr_slave: Sharing page 0x%lx\n", virt_addr);

	/* Validate VPM Page */
	if (unlikely(vpm_page == 0)) {
		printk(KERN_ERR "xen_fmr_slave: Error,"
		       " Got empty VPM address in share\n");
		return -EFAULT;
	}
	xen_vpm = (struct xen_vpm *)(vpm_page);

	if (m_running_on_dom_u) {
		/* Make sure we set dom_id */
		if (unlikely(m_my_dom_id == 0)) {
			printk("xen_fmr_slave: Domain ID is not set\n");
			return -EINVAL;
		}

		/* Grant access to dom0 */
		res = gnttab_grant_foreign_access(0, virt_to_mfn(virt_addr), 0);
		if (res < 0) {
			printk(KERN_ERR "xen_fmr_slave: Fail to share\n");
			return res;
		}
		addr_ref = (addr_ref_t)res;

		xen_vpm->dom_id = cpu_to_be16(m_my_dom_id);
	} else {
		addr_ref = (addr_ref_t)virt_addr;
		xen_vpm->dom_id = 0;
	}
	xen_vpm->addr_ref = cpu_to_be_addr_ref(addr_ref);

	/* Save context to be used in unshare */
	my_vpm_ctx = kzalloc(sizeof(xen_slave_vpm_ctx), GFP_KERNEL);
	my_vpm_ctx->gref = addr_ref;
	*vpm_ctx = my_vpm_ctx;

	DPRINTK("xen_fmr_slave: Page shared '%d %ld (0x%llx)'\n",
		m_my_dom_id, addr_ref, addr_ref);

	ref_count_inc(&m_shr_ref_count);

	return 0;
}

/**
 * Release pages based on ctx handle
 */
int mlx_xen_fmr_icm_slave_unshare(void *vpm_ctx)
{
	struct xen_slave_vpm_ctx	*my_vpm_ctx;
	int				err = 0;

	/* Validate PPF context */
	if (unlikely(vpm_ctx == 0)) {
		printk(KERN_ERR "xen_fmr_slave: Error,"
		       " Got empty VPM context in unshare\n");
		return -EFAULT;
	}
	my_vpm_ctx = (struct xen_slave_vpm_ctx *)vpm_ctx;

	if (m_running_on_dom_u) {
		/* Unshare the page */
		DPRINTK("xen_fmr_slave: Unsharing gref %d\n", my_vpm_ctx->gref);

		if (gnttab_query_foreign_access((grant_ref_t)my_vpm_ctx->gref)) {
			DPRINTK("xen_fmr_slave: Can't release grant, ref leak!\n");
			err = -EINVAL;
			/*todo: fix grant table leak */
		} else
			gnttab_end_foreign_access((grant_ref_t)my_vpm_ctx->gref, 0, 0);
	}

	/* Destroy context */
	kfree(vpm_ctx);

	DPRINTK("xen_fmr_slave: Shareing ended for %ld\n", my_vpm_ctx->gref);

	ref_count_dec(&m_shr_ref_count);

	return err;
}

/**
 * Called by each VF before unload
 */
void mlx_xen_fmr_icm_slave_term(void *vf_ctx)
{
	kfree(vf_ctx);

	ref_count_dec(&m_vf_ref_count);
	printk(KERN_INFO "xen_fmr_slave: FMR-ICM Slave"
	       " Terminated for device\n");
}

/**
 * ICM Slave interface
 */
static struct mlx4_icm_slave icm_slave = {
	.protocol	  = FMR_PROTOCOL_XEN,
	.init		  = mlx_xen_fmr_icm_slave_init,
	.share		  = mlx_xen_fmr_icm_slave_share,
	.unshare	  = mlx_xen_fmr_icm_slave_unshare,
	.term		  = mlx_xen_fmr_icm_slave_term
};

/**
 * xenbus "probe" event handler
 */
static int mlx4_xen_fmr_front_probe(struct xenbus_device *dev,
				    const struct xenbus_device_id *id)
{
	if (xenbus_scanf(XBT_NIL, dev->otherend, "dom-id", "%d",
			 (int *)&m_my_dom_id)) {
		DPRINTK("xen_fmr_slave: My domain ID is %d\n",
			(int)m_my_dom_id);
	}

	if (!m_registered_to_xenbus)
		return 0;

	mlx4_xen_fmr_switch_state(dev, XenbusStateInitialising);

	return 0;
}

/**
 * xenbus "backend change state" event handler
 */
static void mlx4_xen_fmr_backend_changed(struct xenbus_device *dev,
					 enum xenbus_state backend_state)
{
	if (!m_registered_to_xenbus)
		return;

	DPRINTK("xen_fmr_slave: Domain %d change state to %s\n",
		dev->otherend_id,
		xenbus_strstate(backend_state));
	DPRINTK("xen_fmr_slave: My state is %s\n",
		xenbus_strstate(dev->state));
	DPRINTK("xen_fmr_slave: dev->nodename=%s\n", dev->nodename);

	if (xenbus_scanf(XBT_NIL, dev->otherend, "dom-id", "%d",
			(int *)&m_my_dom_id)) {
		DPRINTK("xen_fmr_slave: My domain ID is %d\n",
			(int)m_my_dom_id);
	}
	mlx4_xen_fmr_switch_state(dev, XenbusStateInitialised);

	return;
}

/**
 * xenbus "un-probe" event handler
 */
static int mlx4_xen_fmr_front_remove(struct xenbus_device *dev)
{
	if (!m_registered_to_xenbus)
		return 0;

	return 0;
}

/**
 *
 */
static const struct xenbus_device_id mlx4_xen_fmr_front_ids[] = {
	{ XENBUS_DEVID },
	{ "" }
};
static DEFINE_XENBUS_DRIVER(mlx4_xen_fmr_front, ,
	.probe			= mlx4_xen_fmr_front_probe,
	.remove			= mlx4_xen_fmr_front_remove,
	.otherend_changed	= mlx4_xen_fmr_backend_changed
);

/**
 * Initialize module
 */
static int __init xen_fmr_slave_init(void)
{
	m_my_dom_id = 0;

	m_running_on_dom_u = (!xen_initial_domain());

	if (!m_running_on_dom_u)
		DPRINTK(KERN_ERR "xen_fmr_slave: Running on Dom0\n");
	else
		DPRINTK(KERN_ERR "xen_fmr_slave: Running on DomU\n");

	m_registered_to_xenbus = 0;
	if (m_running_on_dom_u) {
		DPRINTK(KERN_INFO "xen_fmr_slave: Registering to XENBUS\n");
		if (xenbus_register_frontend(&mlx4_xen_fmr_front_driver)) {
			printk(KERN_ERR "xen_fmr_slave: Fail to register to XENBUS\n");
			return -EFAULT;
		}
		m_registered_to_xenbus = 1;
	}

	ref_count_init(&m_vf_ref_count);
	ref_count_init(&m_shr_ref_count);

	DPRINTK(KERN_INFO "xen_fmr_slave: Registering to ICM\n");
	if (mlx4_reg_icm_slave(&icm_slave) != 0) {
		printk(KERN_ERR "xen_fmr_slave: Fail to register to ICM\n");
		xenbus_unregister_driver(&mlx4_xen_fmr_front_driver);
		return -EFAULT;
	}

	/* Let backend know we are up */
	if (m_running_on_dom_u)
		xenbus_printf(XBT_NIL, "device/fmr/0", "ready", "%d", 1);

	printk(KERN_INFO "xen_fmr_slave: Initialized\n");
	return 0;
}

/**
 * Terminate module
 */
static void __exit xen_fmr_slave_exit(void)
{
	DPRINTK(KERN_INFO "xen_fmr_slave: Going down\n");

	/* Let backend know we are down */
	if (m_running_on_dom_u)
		xenbus_printf(XBT_NIL, "device/fmr/0", "ready", "%d", 0);

	DPRINTK(KERN_INFO "xen_fmr_slave: Unregistering from ICM\n");
	mlx4_unreg_icm_slave(&icm_slave);

	DPRINTK(KERN_INFO "xen_fmr_slave: Verify sharings\n");
	ref_count_wait_for_zero(&m_shr_ref_count);
	DPRINTK(KERN_INFO "xen_fmr_slave: Verify VFs\n");
	ref_count_wait_for_zero(&m_vf_ref_count);

	if (m_running_on_dom_u) {
		DPRINTK(KERN_INFO "xen_fmr_slave: Unregistering from XENBUS\n");
		xenbus_unregister_driver(&mlx4_xen_fmr_front_driver);
	}

	printk(KERN_INFO "xen_fmr_slave: Terminated\n");
}

module_init(xen_fmr_slave_init);
module_exit(xen_fmr_slave_exit);
