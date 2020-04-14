// SPDX-License-Identifier: GPL-2.0
/* OcteonTX2 RVU Resource Manager driver
 *
 * Copyright (C) 2018 Marvell International Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#include <linux/sysfs.h>
#include "domain_sysfs.h"
#include "otx2_rm.h"
#include "dpi.h"

#define DOMAIN_NAME_LEN	32
#define PCI_SCAN_FMT	"%04x:%02x:%02x.%02x"

/* The format of DP is: DP(_name, _param_type, _scanf_fmt) */
#define DOM_PARAM_SPEC	\
DP(ssow, int, "%d")	\
DP(sso, int, "%d")	\
DP(npa, int, "%d")	\
DP(tim, int, "%d")	\
DP(dpi, int, "%d")

struct domain_params {
	const char *name;
#define DP(_name, _type, _1) \
	_type _name;
DOM_PARAM_SPEC
#undef DP
	const char *ports[RM_MAX_PORTS];
	const char *cpt[RM_MAX_CPT_VFS];
	u16 port_cnt;
	u16  cpt_count;
};

struct rvu_cpt {
	/* handle in global list of ports associated to all domains */
	struct list_head	list;
	struct pci_dev		*pdev;
	struct domain		*domain;
};

struct domain {
	char			name[DOMAIN_NAME_LEN];
	struct kobj_attribute	domain_id;
	struct kobj_attribute	domain_in_use;
	/* List of all ports attached to the domain */
	struct rvu_port		*ports;
	struct rvu_cpt		*cpt;
	struct kobject		*kobj;
	struct rvu_vf		*rvf;
	int			port_count;
	bool			in_use;
	bool			cpt_count;
};

struct rvu_port {
	/* handle in global list of ports associated to all domains */
	struct list_head	list;
	struct pci_dev		*pdev;
	struct domain		*domain;
};

struct dpi_vf {
	struct pci_dev		*pdev;
	/* pointer to the kobject which owns this vf */
	struct kobject		*domain_kobj;
	int			vf_id;
	bool			in_use;
};

struct dpi_info {
	/* Total number of vfs available */
	uint8_t num_vfs;
	/* Free vfs */
	uint8_t vfs_free;
	/* Pointer to the vfs available */
	struct dpi_vf *dpi_vf;
};

struct domain_sysfs {
	struct list_head	list;
	struct kobj_attribute	create_domain;
	struct kobj_attribute	destroy_domain;
	struct kobj_attribute	pmccntr_el0;
	/* List of all ports added to all domains. Used for validating if new
	 * domain creation doesn't want to take an already taken port.
	 */
	struct list_head	ports;
	struct list_head	cpt;
	struct rm_dev		*rdev;
	struct kobject		*parent;
	struct domain		*domains;
	size_t			domains_len;
	struct dpi_info		dpi_info;
};

static DEFINE_MUTEX(domain_sysfs_lock);
static LIST_HEAD(domain_sysfs_list);

static ssize_t
domain_id_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	struct domain *dom = container_of(attr, struct domain, domain_id);

	return snprintf(buf, PAGE_SIZE, "%s\n", dom->name);
}

static ssize_t
domain_in_use_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	struct domain *dom = container_of(attr, struct domain, domain_in_use);

	return snprintf(buf, PAGE_SIZE, "%d\n", dom->rvf->in_use);
}

static int do_destroy_domain(struct domain_sysfs *lsfs, struct domain *domain)
{
	struct device *dev = &lsfs->rdev->pdev->dev;
	int i;

	if (domain->rvf->in_use) {
		dev_err(dev, "Domain %s is in use.\n", domain->name);
		return -EBUSY;
	}

	sysfs_remove_file(domain->kobj, &domain->domain_id.attr);
	domain->domain_id.attr.mode = 0;
	sysfs_remove_file(domain->kobj, &domain->domain_in_use.attr);
	domain->domain_in_use.attr.mode = 0;
	for (i = 0; i < domain->port_count; i++) {
		sysfs_remove_link(domain->kobj,
				  pci_name(domain->ports[i].pdev));
	}

	for (i = 0; i < domain->cpt_count; i++) {
		sysfs_remove_link(domain->kobj,
				  pci_name(domain->cpt[i].pdev));
	}

	for (i = 0; i < lsfs->dpi_info.num_vfs; i++) {
		struct dpi_vf *dpivf_ptr = NULL;

		dpivf_ptr = &lsfs->dpi_info.dpi_vf[i];
		/* Identify the devices belongs to this domain */
		if (dpivf_ptr->in_use &&
		    dpivf_ptr->domain_kobj == domain->kobj) {
			sysfs_remove_link(domain->kobj,
					  pci_name(dpivf_ptr->pdev));
			dpivf_ptr->in_use = false;
			dpivf_ptr->domain_kobj = NULL;
			lsfs->dpi_info.vfs_free++;
		}
	}

	sysfs_remove_link(domain->kobj, pci_name(domain->rvf->pdev));
	kobject_del(domain->kobj);
	mutex_lock(&lsfs->rdev->lock);
	// restore limits
	lsfs->rdev->vf_limits.sso->a[domain->rvf->vf_id].val = 0;
	lsfs->rdev->vf_limits.ssow->a[domain->rvf->vf_id].val = 0;
	lsfs->rdev->vf_limits.npa->a[domain->rvf->vf_id].val = 0;
	lsfs->rdev->vf_limits.tim->a[domain->rvf->vf_id].val = 0;
	mutex_unlock(&lsfs->rdev->lock);

	mutex_lock(&domain_sysfs_lock);
	// FREE ALL allocated ports
	for (i = 0; i < domain->port_count; i++) {
		list_del(&domain->ports[i].list);
		pci_dev_put(domain->ports[i].pdev);
	}

	for (i = 0; i < domain->cpt_count; i++) {
		list_del(&domain->cpt[i].list);
		pci_dev_put(domain->cpt[i].pdev);
	}
	domain->cpt_count = 0;
	kfree(domain->ports);
	domain->ports = NULL;
	domain->port_count = 0;
	domain->in_use = false;
	domain->name[0] = '\0';
	mutex_unlock(&domain_sysfs_lock);

	return 0;
}

static int
do_create_domain(struct domain_sysfs *lsfs, struct domain_params *dparams)
{
	struct device *dev = &lsfs->rdev->pdev->dev;
	struct domain *domain = NULL;
	struct rvu_port *ports = NULL, *cur;
	struct rvu_cpt *cpt = NULL;
	u32 dom, bus, slot, fn;
	int old_sso, old_ssow, old_npa, old_tim, device;
	int res = 0, i, domain_index;

	/* Validate parameters */
	if (dparams == NULL)
		return -EINVAL;
	if (strnlen(dparams->name, DOMAIN_NAME_LEN) >= DOMAIN_NAME_LEN) {
		dev_err(dev, "Domain name too long, max %d characters.\n",
			DOMAIN_NAME_LEN);
		return -EINVAL;
	}
	if (dparams->npa != 1) {
		dev_err(dev, "Exactly 1 NPA resource required.\n");
		return -EINVAL;
	}
	if (dparams->ssow < 1) {
		dev_err(dev, "At least 1 SSOW resource required.\n");
		return -EINVAL;
	}
	mutex_lock(&domain_sysfs_lock);
	/* Find a free domain device */
	for (i = 0; i < lsfs->domains_len; i++) {
		if (!strncmp(lsfs->domains[i].name, dparams->name,
			     DOMAIN_NAME_LEN)) {
			dev_err(dev, "Domain %s exists already.\n",
				dparams->name);
			res = -EINVAL;
			goto err_dom;
		}
		if (lsfs->domains[i].in_use == false &&
		    lsfs->domains[i].rvf->in_use == false) {
			if (domain == NULL) {
				domain = &lsfs->domains[i];
				domain_index = i;
			}
		}
	}
	if (domain == NULL) {
		dev_err(dev, "No free device to create new domain.\n");
		res = -ENODEV;
		goto err_dom;
	}
	strncpy(domain->name, dparams->name, DOMAIN_NAME_LEN - 1);
	domain->in_use = true;
	/* Verify ports are valid and supported. */
	if (dparams->port_cnt == 0)
		goto skip_ports;
	ports = kcalloc(dparams->port_cnt, sizeof(struct rvu_port), GFP_KERNEL);
	if (ports == NULL) {
		dev_err(dev, "Not enough memory.\n");
		res = -ENOMEM;
		goto err_ports;
	}

	for (i = 0; i < dparams->port_cnt; i++) {
		if (sscanf(dparams->ports[i], PCI_SCAN_FMT, &dom, &bus, &slot,
		    &fn) != 4) {
			dev_err(dev, "Invalid port: %s.\n", dparams->ports[i]);
			res = -EINVAL;
			goto err_ports;
		}
		ports[i].pdev =
			pci_get_domain_bus_and_slot(dom, bus,
						    PCI_DEVFN(slot, fn));
		if (ports[i].pdev == NULL) {
			dev_err(dev, "Unknown port: %s.\n", dparams->ports[i]);
			res = -ENODEV;
			goto err_ports;
		}
		device = ports[i].pdev->device;
		if (ports[i].pdev->vendor != PCI_VENDOR_ID_CAVIUM ||
		    (device != PCI_DEVID_OCTEONTX2_RVU_PF &&
		     device != PCI_DEVID_OCTEONTX2_PASS1_RVU_PF &&
		     device != PCI_DEVID_OCTEONTX2_RVU_AFVF &&
		     device != PCI_DEVID_OCTEONTX2_PASS1_RVU_AFVF &&
		     device != PCI_DEVID_OCTEONTX2_RVU_VF &&
		     device != PCI_DEVID_OCTEONTX2_PASS1_RVU_VF)) {
			dev_err(dev, "Unsupported port: %s.\n",
				dparams->ports[i]);
			res = -EINVAL;
			goto err_ports;
		}
		list_for_each_entry(cur, &lsfs->ports, list) {
			if (cur->pdev != ports[i].pdev)
				continue;
			dev_err(dev,
				"Port %s already assigned to domain %s.\n",
				dparams->ports[i], cur->domain->name);
			res = -EBUSY;
			goto err_ports;
		}
	}
	for (i = 0; i < dparams->port_cnt; i++) {
		ports[i].domain = domain;
		list_add(&ports[i].list, &lsfs->ports);
	}
	domain->ports = ports;
	domain->port_count = dparams->port_cnt;
skip_ports:
	if (dparams->cpt_count == 0)
		goto skip_cpt;
	cpt = kcalloc(dparams->cpt_count, sizeof(struct rvu_cpt), GFP_KERNEL);
	for (i = 0; i < dparams->cpt_count; i++) {
		if (sscanf(dparams->cpt[i], PCI_SCAN_FMT, &dom, &bus, &slot,
			    &fn) != 4) {
			dev_err(dev, "Invalid cpt device: %s.\n",
				dparams->cpt[i]);
			res = -EINVAL;
			goto err_ports;
		}
		cpt[i].pdev =
			pci_get_domain_bus_and_slot(dom, bus,
					    PCI_DEVFN(slot, fn));
		if (cpt[i].pdev == NULL) {
			dev_err(dev, "Unknown cpt device: %s.\n",
				dparams->cpt[i]);
			res = -ENODEV;
			goto err_cpt;
		}
		device = cpt[i].pdev->device;
		list_for_each_entry(cur, &lsfs->cpt, list) {
			if (cur->pdev != cpt[i].pdev)
				continue;
			dev_err(dev,
				"cpt %s already assigned to domain %s.\n",
				dparams->cpt[i], cur->domain->name);
			res = -EBUSY;
			goto err_cpt;
		}
	}
	for (i = 0; i < dparams->cpt_count; i++) {
		cpt[i].domain = domain;
		list_add(&cpt[i].list, &lsfs->cpt);
	}
	domain->cpt = cpt;
	domain->cpt_count = dparams->cpt_count;
skip_cpt:
	mutex_unlock(&domain_sysfs_lock);
	/* Check domain spec against limits for the parent RVU. */
	mutex_lock(&lsfs->rdev->lock);
	old_sso = lsfs->rdev->vf_limits.sso->a[domain->rvf->vf_id].val;
	old_ssow = lsfs->rdev->vf_limits.ssow->a[domain->rvf->vf_id].val;
	old_npa = lsfs->rdev->vf_limits.npa->a[domain->rvf->vf_id].val;
	old_tim = lsfs->rdev->vf_limits.tim->a[domain->rvf->vf_id].val;
#define CHECK_LIMITS(_ls, _val, _n, _idx) do {				    \
	if (quotas_get_sum(_ls) + _val - _ls->a[_idx].val > _ls->max_sum) { \
		dev_err(dev,						    \
			"Not enough "_n" LFs, currently used: %lld/%lld\n", \
			quotas_get_sum(_ls), _ls->max_sum);		    \
		res = -ENODEV;						    \
		goto err_limits;					    \
	}								    \
} while (0)
	CHECK_LIMITS(lsfs->rdev->vf_limits.sso, dparams->sso, "SSO",
		     domain->rvf->vf_id);
	CHECK_LIMITS(lsfs->rdev->vf_limits.ssow, dparams->ssow, "SSOW",
		     domain->rvf->vf_id);
	CHECK_LIMITS(lsfs->rdev->vf_limits.npa, dparams->npa, "NPA",
		     domain->rvf->vf_id);
	CHECK_LIMITS(lsfs->rdev->vf_limits.tim, dparams->tim, "TIM",
		     domain->rvf->vf_id);
	if (dparams->dpi > lsfs->dpi_info.vfs_free) {
		dev_err(dev,
			"Not enough DPI VFS, currently used:%d/%d\n",
			lsfs->dpi_info.num_vfs -
			lsfs->dpi_info.vfs_free,
			lsfs->dpi_info.num_vfs);
		res = -ENODEV;
		goto err_limits;
	}

	/* Now that checks are done, update the limits */
	lsfs->rdev->vf_limits.sso->a[domain->rvf->vf_id].val = dparams->sso;
	lsfs->rdev->vf_limits.ssow->a[domain->rvf->vf_id].val = dparams->ssow;
	lsfs->rdev->vf_limits.npa->a[domain->rvf->vf_id].val = dparams->npa;
	lsfs->rdev->vf_limits.tim->a[domain->rvf->vf_id].val = dparams->tim;
	lsfs->dpi_info.vfs_free -= dparams->dpi;
	mutex_unlock(&lsfs->rdev->lock);

	/* Set it up according to user spec */
	domain->kobj = kobject_create_and_add(dparams->name, lsfs->parent);
	if (domain->kobj == NULL) {
		dev_err(dev, "Failed to create domain directory.\n");
		res = -ENOMEM;
		goto err_kobject_create;
	}
	res = sysfs_create_link(domain->kobj, &domain->rvf->pdev->dev.kobj,
				pci_name(domain->rvf->pdev));
	if (res < 0) {
		dev_err(dev, "Failed to create dev links for domain %s.\n",
			domain->name);
		res = -ENOMEM;
		goto err_dom_dev_symlink;
	}
	for (i = 0; i < dparams->port_cnt; i++) {
		res = sysfs_create_link(domain->kobj, &ports[i].pdev->dev.kobj,
					pci_name(ports[i].pdev));
		if (res < 0) {
			dev_err(dev,
				"Failed to create dev links for domain %s.\n",
				domain->name);
			res = -ENOMEM;
			goto err_dom_port_symlink;
		}
	}
	for (i = 0; i < dparams->cpt_count; i++) {
		res = sysfs_create_link(domain->kobj, &cpt[i].pdev->dev.kobj,
						pci_name(cpt[i].pdev));
		if (res < 0) {
			dev_err(dev,
				"Failed to create dev links for domain %s.\n",
				domain->name);
			res = -ENOMEM;
			goto err_dom_cpt_symlink;
		}
	}
	/* Create symlinks for dpi vfs in domain */
	for (i = 0; i < dparams->dpi; i++) {
		struct dpi_vf *dpivf_ptr = NULL;
		int vf_idx;

		for (vf_idx = 0; vf_idx < lsfs->dpi_info.num_vfs;
		     vf_idx++) {
			/* Find available dpi vfs and create symlinks */
			dpivf_ptr = &lsfs->dpi_info.dpi_vf[vf_idx];
			if (dpivf_ptr->in_use)
				continue;
			else
				break;
		}
		res = sysfs_create_link(domain->kobj,
					&dpivf_ptr->pdev->dev.kobj,
					pci_name(dpivf_ptr->pdev));
		if (res < 0) {
			dev_err(dev,
				"Failed to create DPI dev links for domain %s\n",
				domain->name);
			res = -ENOMEM;
			goto err_dpi_symlink;
		}
		dpivf_ptr->domain_kobj = domain->kobj;
		dpivf_ptr->in_use = true;
	}

	domain->domain_in_use.attr.mode = 0444;
	domain->domain_in_use.attr.name = "domain_in_use";
	domain->domain_in_use.show = domain_in_use_show;
	res = sysfs_create_file(domain->kobj, &domain->domain_in_use.attr);
	if (res < 0) {
		dev_err(dev,
			"Failed to create domain_in_use file for domain %s.\n",
			domain->name);
		res = -ENOMEM;
		goto err_dom_in_use;
	}

	domain->domain_id.attr.mode = 0444;
	domain->domain_id.attr.name = "domain_id";
	domain->domain_id.show = domain_id_show;
	res = sysfs_create_file(domain->kobj, &domain->domain_id.attr);
	if (res < 0) {
		dev_err(dev, "Failed to create domain_id file for domain %s.\n",
			domain->name);
		res = -ENOMEM;
		goto err_dom_id;
	}

	return res;

err_dom_id:
	domain->domain_id.attr.mode = 0;
	sysfs_remove_file(domain->kobj, &domain->domain_in_use.attr);
err_dom_in_use:
	domain->domain_in_use.attr.mode = 0;
err_dpi_symlink:
	for (i = 0; i < lsfs->dpi_info.num_vfs; i++) {
		struct dpi_vf *dpivf_ptr = NULL;

		dpivf_ptr = &lsfs->dpi_info.dpi_vf[i];
		/* Identify the devices belongs to this domain */
		if (dpivf_ptr->in_use &&
		    dpivf_ptr->domain_kobj == domain->kobj) {
			sysfs_remove_link(domain->kobj,
					  pci_name(dpivf_ptr->pdev));
			dpivf_ptr->in_use = false;
			dpivf_ptr->domain_kobj = NULL;
		}
	}
err_dom_cpt_symlink:
	for (i = 0; i < dparams->cpt_count; i++)
		sysfs_remove_link(domain->kobj, pci_name(cpt[i].pdev));
	sysfs_remove_link(domain->kobj, pci_name(domain->rvf->pdev));
err_dom_port_symlink:
	for (i = 0; i < dparams->port_cnt; i++)
		sysfs_remove_link(domain->kobj, pci_name(ports[i].pdev));
	sysfs_remove_link(domain->kobj, pci_name(domain->rvf->pdev));
err_dom_dev_symlink:
	kobject_del(domain->kobj);
err_kobject_create:
	mutex_lock(&lsfs->rdev->lock);
err_limits:
	// restore limits
	lsfs->rdev->vf_limits.sso->a[domain->rvf->vf_id].val = old_sso;
	lsfs->rdev->vf_limits.ssow->a[domain->rvf->vf_id].val = old_ssow;
	lsfs->rdev->vf_limits.npa->a[domain->rvf->vf_id].val = old_npa;
	lsfs->rdev->vf_limits.tim->a[domain->rvf->vf_id].val = old_tim;
	lsfs->dpi_info.vfs_free += dparams->dpi;
	mutex_unlock(&lsfs->rdev->lock);
	mutex_lock(&domain_sysfs_lock);
err_cpt:
	for (i = 0; i < dparams->cpt_count; i++) {
		if (cpt[i].pdev == NULL)
			break;
		if (cpt[i].domain != NULL)
			list_del(&cpt[i].list);
		pci_dev_put(cpt[i].pdev);
	}
err_ports:
	// FREE ALL allocated ports
	for (i = 0; i < dparams->port_cnt; i++) {
		if (ports[i].pdev == NULL)
			break;
		if (ports[i].domain != NULL)
			list_del(&ports[i].list);
		pci_dev_put(ports[i].pdev);
	}
	kfree(ports);
	domain->ports = NULL;
	domain->port_count = 0;
	domain->in_use = false;
	domain->name[0] = '\0';
err_dom:
	mutex_unlock(&domain_sysfs_lock);
	return res;
}

static ssize_t
destroy_domain_store(struct kobject *kobj, struct kobj_attribute *attr,
		    const char *buf, size_t count)
{
	struct domain_sysfs *lsfs =
		container_of(attr, struct domain_sysfs, destroy_domain);
	struct device *dev = &lsfs->rdev->pdev->dev;
	struct domain *domain = NULL;
	char name[DOMAIN_NAME_LEN], *name_ptr;
	int i, res;

	strncpy(name, buf, DOMAIN_NAME_LEN - 1);
	name_ptr = strim(name);
	if (strlen(name_ptr) == 0) {
		dev_err(dev, "Empty domain name.\n");
		return -EINVAL;
	}

	mutex_lock(&domain_sysfs_lock);
	/* Find a free domain device */
	for (i = 0; i < lsfs->domains_len; i++) {
		if (!strncmp(lsfs->domains[i].name, name_ptr,
		    DOMAIN_NAME_LEN)) {
			domain = &lsfs->domains[i];
			break;
		}
	}
	if (domain == NULL) {
		dev_err(dev, "Domain '%s' doesn't exist.\n", name);
		res = -EINVAL;
		goto err_dom;
	}
	mutex_unlock(&domain_sysfs_lock);

	res = do_destroy_domain(lsfs, domain);
	if (res == 0)
		res = count;
err_dom:
	mutex_unlock(&domain_sysfs_lock);
	return res;
}

static ssize_t
create_domain_store(struct kobject *kobj, struct kobj_attribute *attr,
		    const char *buf, size_t count)
{
	struct domain_params *dparams = NULL;
	struct domain_sysfs *lsfs =
		container_of(attr, struct domain_sysfs, create_domain);
	struct device *dev = &lsfs->rdev->pdev->dev;
	int res = 0;
	char *start;
	char *end;
	char *ptr = NULL;
	const char *name;
	char *errmsg = "Invalid domain specification format.";

	if (strlen(buf) == 0) {
		dev_err(dev, "Empty domain spec.\n");
		return -EINVAL;
	}

	dparams = kzalloc(sizeof(*dparams), GFP_KERNEL);
	if (dparams == NULL) {
		errmsg = "Not enough memory";
		res = -ENOMEM;
		goto error;
	}

	end = kzalloc(PAGE_SIZE, GFP_KERNEL);
	if (end == NULL) {
		errmsg = "Not enough memory";
		res = -ENOMEM;
		goto error;
	}

	ptr = end;
	memcpy(end, buf, count);

	name = strsep(&end, ";");
	if (end == NULL) {
		res = -EINVAL;
		goto error;
	}

	dparams->name = name;

	for (;;) {
		start = strsep(&end, ";");
		if (start == NULL)
			break;
		start = strim(start);
		if (!*start)
			continue;

		if (!strncmp(strim(start), "port", sizeof("port") - 1)) {
			strsep(&start, ":");
			if (dparams->port_cnt >= RM_MAX_PORTS)
				goto error;
			dparams->ports[dparams->port_cnt++] = strim(start);
		}
		#define DP(_name, _1, _fmt)				\
		else if (!strncmp(strim(start), #_name,			\
				  sizeof(#_name) - 1)) {		\
			strsep(&start, ":");				\
			start = strim(start);				\
			res = sscanf(start, _fmt, &dparams->_name);	\
			if (res != 1)					\
				goto error;				\
			continue;					\
		}
		DOM_PARAM_SPEC
		#undef DP
		else if (!strncmp(strim(start), "cpt", sizeof("cpt") - 1)) {
			strsep(&start, ":");
			if (dparams->cpt_count > RM_MAX_CPT_VFS)
				goto error;
			dparams->cpt[dparams->cpt_count++] = strim(start);
		} else {
			res = -EINVAL;
			goto error;
		}
	}
	res = do_create_domain(lsfs, dparams);
	if (res < 0) {
		errmsg = "Failed to create application domain.";
		goto error;
	} else
		res = count;
error:
	if (res < 0)
		dev_err(dev, "%s\n", errmsg);
	kfree(ptr);
	kfree(dparams);
	return res;
}

static int dpivf_sysfs_create(struct domain_sysfs *lsfs)
{
	struct dpi_info *dpi_info = &lsfs->dpi_info;
	struct dpi_vf *dpivf_ptr = NULL;
	struct pci_dev *pdev = lsfs->rdev->pdev;
	struct pci_dev *vdev = NULL;
	uint8_t vf_idx = 0;

	dpi_info->dpi_vf = kcalloc(DPI_MAX_VFS,
				   sizeof(struct dpi_vf), GFP_KERNEL);
	if (dpi_info->dpi_vf == NULL)
		return -ENOMEM;

	/* Get available DPI vfs */
	while ((vdev = pci_get_device(pdev->vendor,
				      PCI_DEVID_OCTEONTX2_DPI_VF, vdev))) {
		if (!vdev->is_virtfn)
			continue;
		else {
			dpivf_ptr = &dpi_info->dpi_vf[vf_idx];
			dpivf_ptr->pdev = vdev;
			dpivf_ptr->vf_id = vf_idx;
			dpivf_ptr->in_use = false;
			vf_idx++;
		}
	}
	dpi_info->num_vfs = vf_idx;
	dpi_info->vfs_free = vf_idx;
	return 0;
}

static void dpivf_sysfs_destroy(struct domain_sysfs *lsfs)
{
	struct dpi_info *dpi_info = &lsfs->dpi_info;
	struct dpi_vf *dpivf_ptr = NULL;
	uint8_t vf_idx = 0;

	if (dpi_info->num_vfs == 0)
		goto free_mem;
	else {
		for (vf_idx = 0; vf_idx < dpi_info->num_vfs; vf_idx++) {
			dpivf_ptr = &dpi_info->dpi_vf[vf_idx];
			pci_dev_put(dpivf_ptr->pdev);
			dpivf_ptr->pdev = NULL;
			vf_idx++;
		}
	}
	dpi_info->num_vfs = 0;

free_mem:
	kfree(dpi_info->dpi_vf);
	dpi_info->dpi_vf = NULL;
}


static void enable_pmccntr_el0(void *data)
{
	u64 val;
	/* Disable cycle counter overflow interrupt */
	asm volatile("mrs %0, pmintenset_el1" : "=r" (val));
	val &= ~BIT_ULL(31);
	asm volatile("msr pmintenset_el1, %0" : : "r" (val));
	/* Enable cycle counter */
	asm volatile("mrs %0, pmcntenset_el0" : "=r" (val));
	val |= BIT_ULL(31);
	asm volatile("msr pmcntenset_el0, %0" :: "r" (val));
	/* Enable user-mode access to cycle counters. */
	asm volatile("mrs %0, pmuserenr_el0" : "=r" (val));
	val |= BIT(2) | BIT(0);
	asm volatile("msr pmuserenr_el0, %0" : : "r"(val));
	/* Start cycle counter */
	asm volatile("mrs %0, pmcr_el0" : "=r" (val));
	val |= BIT(0);
	isb();
	asm volatile("msr pmcr_el0, %0" : : "r" (val));
	asm volatile("mrs %0, pmccfiltr_el0" : "=r" (val));
	val |= BIT(27);
	asm volatile("msr pmccfiltr_el0, %0" : : "r" (val));
}

static void disable_pmccntr_el0(void *data)
{
	u64 val;
	/* Disable cycle counter */
	asm volatile("mrs %0, pmcntenset_el0" : "=r" (val));
	val &= ~BIT_ULL(31);
	asm volatile("msr pmcntenset_el0, %0" :: "r" (val));
	/* Disable user-mode access to counters. */
	asm volatile("mrs %0, pmuserenr_el0" : "=r" (val));
	val &= ~(BIT(2) | BIT(0));
	asm volatile("msr pmuserenr_el0, %0" : : "r"(val));
}

static ssize_t
enadis_pmccntr_el0_store(struct kobject *kobj, struct kobj_attribute *attr,
			 const char *buf, size_t count)
{
	struct domain_sysfs *lsfs = container_of(attr, struct domain_sysfs,
						 pmccntr_el0);
	struct device *dev = &lsfs->rdev->pdev->dev;
	char tmp_buf[64];
	long enable = 0;
	char *tmp_ptr;

	strlcpy(tmp_buf, buf, 64);
	tmp_ptr = strim(tmp_buf);
	if (kstrtol(tmp_ptr, 0, &enable)) {
		dev_err(dev, "Invalid value, expected 1/0\n");
		return -EIO;
	}

	if (enable)
		on_each_cpu(enable_pmccntr_el0, NULL, 1);
	else
		on_each_cpu(disable_pmccntr_el0, NULL, 1);

	return count;
}

static void check_pmccntr_el0(void *data)
{
	int *out = data;
	u64 val;

	asm volatile("mrs %0, pmuserenr_el0" : "=r" (val));
	*out = *out & !!(val & (BIT(2) | BIT(0)));
}

static ssize_t
enadis_pmccntr_el0_show(struct kobject *kobj, struct kobj_attribute *attr,
			char *buf)
{
	int out = 1;

	on_each_cpu(check_pmccntr_el0, &out, 1);

	return snprintf(buf, PAGE_SIZE, "%d\n", out);
}

int domain_sysfs_create(struct rm_dev *rm)
{
	struct domain_sysfs *lsfs;
	int res = 0, i;

	if (rm == NULL || rm->num_vfs == 0)
		return -EINVAL;

	lsfs = kzalloc(sizeof(*lsfs), GFP_KERNEL);
	if (lsfs == NULL) {
		res = -ENOMEM;
		goto err_lsfs_alloc;
	}

	INIT_LIST_HEAD(&lsfs->ports);
	INIT_LIST_HEAD(&lsfs->cpt);
	lsfs->rdev = rm;
	lsfs->domains_len = rm->num_vfs;
	lsfs->domains =
		kcalloc(lsfs->domains_len, sizeof(struct domain), GFP_KERNEL);
	if (lsfs->domains == NULL)
		goto err_domains_alloc;
	for (i = 0; i < lsfs->domains_len; i++)
		lsfs->domains[i].rvf = &rm->vf_info[i];

	lsfs->create_domain.attr.name = "create_domain";
	lsfs->create_domain.attr.mode = 0200;
	lsfs->create_domain.store = create_domain_store;
	res = sysfs_create_file(&rm->pdev->dev.kobj, &lsfs->create_domain.attr);
	if (res)
		goto err_create_domain;

	lsfs->destroy_domain.attr.name = "destroy_domain";
	lsfs->destroy_domain.attr.mode = 0200;
	lsfs->destroy_domain.store = destroy_domain_store;
	res = sysfs_create_file(&rm->pdev->dev.kobj,
				&lsfs->destroy_domain.attr);
	if (res)
		goto err_destroy_domain;

	lsfs->pmccntr_el0.attr.name = "pmccntr_el0";
	lsfs->pmccntr_el0.attr.mode = 0644;
	lsfs->pmccntr_el0.show = enadis_pmccntr_el0_show;
	lsfs->pmccntr_el0.store = enadis_pmccntr_el0_store;
	res = sysfs_create_file(&rm->pdev->dev.kobj, &lsfs->pmccntr_el0.attr);
	if (res)
		goto err_pmccntr_el0;

	lsfs->parent = &rm->pdev->dev.kobj;

	res = dpivf_sysfs_create(lsfs);
	if (res)
		goto err_dpivf_sysfs_create;

	mutex_lock(&domain_sysfs_lock);
	list_add_tail(&lsfs->list, &domain_sysfs_list);
	mutex_unlock(&domain_sysfs_lock);

	return 0;

err_dpivf_sysfs_create:
	sysfs_remove_file(&rm->pdev->dev.kobj, &lsfs->pmccntr_el0.attr);
err_pmccntr_el0:
	sysfs_remove_file(&rm->pdev->dev.kobj, &lsfs->destroy_domain.attr);
err_destroy_domain:
	sysfs_remove_file(&rm->pdev->dev.kobj, &lsfs->create_domain.attr);
err_create_domain:
	kfree(lsfs->domains);
err_domains_alloc:
	kfree(lsfs);
err_lsfs_alloc:
	return res;
}

void domain_sysfs_destroy(struct rm_dev *rm)
{
	struct list_head *pos, *n;
	struct domain_sysfs *lsfs;

	if (rm == NULL)
		return;

	mutex_lock(&domain_sysfs_lock);
	list_for_each_safe(pos, n, &domain_sysfs_list) {
		lsfs = container_of(pos, struct domain_sysfs, list);
		if (lsfs->rdev == rm) {
			list_del(pos);
			break;
		}
		lsfs = NULL;
	}
	mutex_unlock(&domain_sysfs_lock);

	if (lsfs == NULL)
		return;

	dpivf_sysfs_destroy(lsfs);

	if (lsfs->pmccntr_el0.attr.mode != 0)
		sysfs_remove_file(lsfs->parent, &lsfs->pmccntr_el0.attr);
	if (lsfs->destroy_domain.attr.mode != 0)
		sysfs_remove_file(lsfs->parent, &lsfs->destroy_domain.attr);
	if (lsfs->create_domain.attr.mode != 0)
		sysfs_remove_file(lsfs->parent, &lsfs->create_domain.attr);

	kfree(lsfs->domains);
	kfree(lsfs);
}
