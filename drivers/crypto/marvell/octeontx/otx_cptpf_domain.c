// SPDX-License-Identifier: GPL-2.0
/* Marvell OcteonTX CPT driver
 *
 * Copyright (C) 2018 Marvell International Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include "otx_cptpf.h"
#include "otx_cpt_common.h"
#include "cpt.h"

extern struct mutex octeontx_cpt_devices_lock;
extern struct list_head octeontx_cpt_devices;

static void identify(struct cptpf_vf *vf, u16 domain_id, u16 subdomain_id)
{
	u64 reg = (((u64)subdomain_id << 16) | (domain_id)) << 8;

	writeq(reg, vf->domain.reg_base + OTX_CPT_VQX_SADDR(0));
}

static void cpt_config_gmctl(struct otx_cpt_device *cpt, uint8_t vq,
			     uint8_t strm, uint16_t gmid)
{
	union otx_cptx_pf_qx_gmctl gmctl = {0};

	gmctl.s.strm = strm;
	gmctl.s.gmid = gmid;
	writeq(gmctl.u, cpt->reg_base + OTX_CPT_PF_QX_GMCTL(vq));

}

static int cpt_pf_remove_domain(u32 node, u16 domain_id, struct kobject *kobj)
{
	struct otx_cpt_device *cpt = NULL;
	struct otx_cpt_device *curr;
	struct pci_dev *virtfn;
	struct cptpf_vf *vf;
	int i, vf_idx = 0;

	mutex_lock(&octeontx_cpt_devices_lock);
	list_for_each_entry(curr, &octeontx_cpt_devices, list) {
		if (curr->pf_type == OTX_CPT_SE) {
			cpt = curr;
			break;
		}
	}

	if (!cpt) {
		mutex_unlock(&octeontx_cpt_devices_lock);
		return -ENODEV;
	}

	for (i = 0; i < cpt->vfs_enabled; i++) {
		vf = &cpt->vf[i];
		if (vf->domain.in_use &&
		    vf->domain.domain_id == domain_id) {
			virtfn = pci_get_domain_bus_and_slot(
				     pci_domain_nr(cpt->pdev->bus),
				     pci_iov_virtfn_bus(cpt->pdev, i),
				     pci_iov_virtfn_devfn(cpt->pdev, i));

			if (virtfn && kobj)
				sysfs_remove_link(kobj, virtfn->dev.kobj.name);
			put_device(&virtfn->dev);

			/* Release the VF to PF */
			cpt_config_gmctl(cpt, i, 0, 0);
			identify(vf, 0x0, 0x0);
			dev_info(&cpt->pdev->dev, "Free vf[%d] from domain_id:%d subdomain_id:%d\n",
				 i, vf->domain.domain_id, vf_idx);
			iounmap(vf->domain.reg_base);
			vf->domain.in_use = false;
			memset(vf, 0, sizeof(struct cptpf_vf));
			vf_idx++;
		}
	}

	cpt->vfs_in_use -= vf_idx;
	mutex_unlock(&octeontx_cpt_devices_lock);
	return 0;
}

static u64 cpt_pf_create_domain(u32 node, u16 domain_id,
				u32 num_vfs, struct kobject *kobj)
{
	struct otx_cpt_device *cpt = NULL;
	struct otx_cpt_device *curr;
	struct pci_dev *virtfn;
	struct cptpf_vf *vf;
	resource_size_t vf_start;
	int vf_idx = 0, ret = 0;
	int i;
	unsigned long cpt_mask = 0;

	if (!kobj)
		return 0;

	mutex_lock(&octeontx_cpt_devices_lock);
	list_for_each_entry(curr, &octeontx_cpt_devices, list) {
		if (curr->pf_type == OTX_CPT_SE) {
			cpt = curr;
			break;
		}
	}

	if (!cpt)
		goto err_unlock;

	for (i = 0; i < cpt->vfs_enabled; i++) {
		vf = &cpt->vf[i];
		if (vf->domain.in_use)
			continue;

		virtfn = pci_get_domain_bus_and_slot(
					pci_domain_nr(cpt->pdev->bus),
					pci_iov_virtfn_bus(cpt->pdev, i),
					pci_iov_virtfn_devfn(cpt->pdev, i));
		if (!virtfn)
			break;

		ret = sysfs_create_link(kobj, &virtfn->dev.kobj,
					virtfn->dev.kobj.name);
		if (ret < 0)
			goto err_unlock;
		put_device(&virtfn->dev);

		vf_start = pci_resource_start(cpt->pdev,
					      OTX_CPT_PF_PCI_CFG_BAR);
		vf_start += OTX_CPT_BAR_E_CPTX_VFX_BAR0_OFFSET(node, i);
		vf->domain.reg_base = ioremap(vf_start,
					      OTX_CPT_BAR_E_CPTX_VFX_BAR0_SIZE);
		if (!vf->domain.reg_base) {
			ret = -ENOMEM;
			goto err_unlock;
		}
		vf->domain.domain_id = domain_id;
		vf->domain.subdomain_id = vf_idx;
		vf->domain.gmid = get_gmid(domain_id);
		vf->domain.in_use = true;

		cpt_config_gmctl(cpt, i, i + 1, vf->domain.gmid);
		identify(vf, domain_id, vf_idx);

		set_bit(i, &cpt_mask);
		vf_idx++;
		if (vf_idx == num_vfs) {
			cpt->vfs_in_use += num_vfs;
			break;
		}
	}

	if (vf_idx != num_vfs)
		goto err_unlock;

	mutex_unlock(&octeontx_cpt_devices_lock);
	return cpt_mask;

err_unlock:
	mutex_unlock(&octeontx_cpt_devices_lock);
	cpt_pf_remove_domain(node, domain_id, kobj);
	return 0;
}

static int cpt_reset_domain(u32 node, u16 domain_id)
{
	struct otx_cpt_device *cpt = NULL;
	struct otx_cpt_device *curr;
	struct cptpf_vf *vf;
	u64 inflight = 0;
	int i, ret;

	mutex_lock(&octeontx_cpt_devices_lock);
	list_for_each_entry(curr, &octeontx_cpt_devices, list) {
		if (curr->pf_type == OTX_CPT_SE) {
			cpt = curr;
			break;
		}
	}

	if (!cpt) {
		ret = -ENODEV;
		goto err_unlock;
	}

	for (i = 0; i < cpt->vfs_enabled; i++) {
		vf = &cpt->vf[i];
		if (vf->domain.in_use &&
		    vf->domain.domain_id == domain_id) {

			/* Wait till the VQ is empty */
			inflight = readq(vf->domain.reg_base +
					 OTX_CPT_VQX_INPROG(0));

			while (inflight != 0) {
				inflight = readq(vf->domain.reg_base +
						 OTX_CPT_VQX_INPROG(0));
			}

			identify(vf, domain_id, vf->domain.subdomain_id);
		}
	}

	mutex_unlock(&octeontx_cpt_devices_lock);
	return 0;

err_unlock:
	mutex_unlock(&octeontx_cpt_devices_lock);
	return ret;
}

struct cptpf_com_s cptpf_com = {
	.create_domain = cpt_pf_create_domain,
	.destroy_domain = cpt_pf_remove_domain,
	.reset_domain = cpt_reset_domain
};
EXPORT_SYMBOL(cptpf_com);
