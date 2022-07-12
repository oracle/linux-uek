// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2022 Marvell.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/of_address.h>
#include <linux/arm_sdei.h>
#include <acpi/acpi_io.h>
#include <acpi/apei.h>
#include <linux/arm-smccc.h>
#include "edac_mc.h"
#include "edac_device.h"
#include "octeontx_edac.h"

#define DRIVER_NAME	"octeontx-edac-ghes"

#define otx_printk(level, fmt, arg...) edac_printk(level, DRIVER_NAME, fmt, ##arg)

static const struct of_device_id octeontx_edac_ghes_of_match[] = {
	{ .compatible = "marvell,sdei-ghes", },
	{ },
};
MODULE_DEVICE_TABLE(of, octeontx_edac_ghes_of_match);

#ifdef CONFIG_ACPI
static const struct acpi_device_id octeontx_edac_ghes_acpi_match[] = {
	{ "MRVLECC1", 0 },
	{ },
};
MODULE_DEVICE_TABLE(acpi, octeontx_edac_ghes_acpi_match);
#endif

static const struct pci_device_id octeontx_edac_ghes_pci_tbl[] = {
	{ PCI_DEVICE(PCI_VENDOR_ID_CAVIUM, PCI_DEVICE_ID_OCTEONTX2_LMC) },
	{ PCI_DEVICE(PCI_VENDOR_ID_CAVIUM, PCI_DEVICE_ID_OCTEONTX2_MCC) },
	{ PCI_DEVICE(PCI_VENDOR_ID_CAVIUM, PCI_DEVICE_ID_OCTEONTX2_MDC) },
	{ 0, },
};

static const u64 otx2_einj_test_val = 0x5555555555555555;
static u64 otx2_einj_test_fn(void)
{
	return otx2_einj_test_val;
}

static void octeontx_edac_mc_inject(struct mem_ctl_info *mci)
{
	struct arm_smccc_res res;
	unsigned long arg[8] = {0};
	struct octeontx_edac_pvt *pvt = mci->pvt_info;
	bool test_read = false;
	bool test_call = false;
	u64 ecc_test_target_data = otx2_einj_test_val;

	if (pvt->inject != 1) {
		pvt->inject = 0;
		return;
	}

	pvt->inject = 0;

	if (MIDR_PARTNUM(read_cpuid_id()) == CN10K_CPU_MODEL) {
		arg[0] = OCTEON10_EDAC_INJECT;
		arg[1] = 0xd;
		arg[2] = pvt->address;
		arg[3] = (pvt->error_type >> 8) & 1;
		arg[4] = pvt->error_type & 0xFF;
		otx_printk(KERN_DEBUG, "%s %lx %lx %lx %lx %lx %lx %lx %lx\n", __func__,
				arg[0], arg[1], arg[2], arg[3], arg[4], arg[5], arg[6], arg[7]);
		arm_smccc_smc(arg[0], arg[1], arg[2], arg[3], arg[4], arg[5], arg[6], arg[7], &res);
	} else {
		arg[0] = OCTEONTX2_EDAC_INJECT;
		arg[1] = 0x3;
		arg[2] = pvt->address;
		arg[3] = pvt->error_type;

		arg[3] &= ~OCTEONTX_EDAC_F_REREAD;
		switch (arg[2]) {
		case 1 ... 2:	/* EL0..EL2 D-space target */
			arg[2] = (u64)&ecc_test_target_data;
			test_read = true;
			break;	/* EL0..EL2 I-space target */
		case 5 ... 6:
			arg[2] = (u64)otx2_einj_test_fn;
			test_call = true;
			break;
		case 3:	/* EL3 targets */
		case 7:
			arg[3] |= OCTEONTX_EDAC_F_REREAD;
			break;
		}

		otx_printk(KERN_DEBUG, "%s %lx %lx %lx %lx %lx %lx %lx %lx\n", __func__,
				arg[0], arg[1], arg[2], arg[3], arg[4], arg[5], arg[6], arg[7]);
		arm_smccc_smc(arg[0], arg[1], arg[2], arg[3], arg[4], arg[5], arg[6], arg[7], &res);

		if (test_read && ecc_test_target_data != otx2_einj_test_val)
			otx_printk(KERN_DEBUG, "%s test_read mismatch\n", __func__);

		if (test_call && otx2_einj_test_fn() != otx2_einj_test_val)
			otx_printk(KERN_DEBUG, "%s test_call mismatch\n", __func__);
	}

	otx_printk(KERN_DEBUG, "%s: (%lx, %lx, %lx, %lx) -> e?%ld\n",
			__func__, arg[0], arg[1], arg[2], arg[3], res.a0);
}

#define to_mci(k) container_of(k, struct mem_ctl_info, dev)

#define TEMPLATE_SHOW(reg)					\
static ssize_t reg##_show(struct device *dev,			\
		struct device_attribute *attr,			\
		char *data)					\
{								\
	struct mem_ctl_info *mci = to_mci(dev);			\
	struct octeontx_edac_pvt *pvt = mci->pvt_info;		\
	return sprintf(data, "0x%016llx\n", (u64)pvt->reg);	\
}

#define TEMPLATE_STORE(reg)					\
static ssize_t reg##_store(struct device *dev,			\
		struct device_attribute *attr,			\
		const char *data, size_t count)			\
{								\
	struct mem_ctl_info *mci = to_mci(dev);			\
	struct octeontx_edac_pvt *pvt = mci->pvt_info;		\
	if (isdigit(*data)) {					\
		if (!kstrtoul(data, 0, &pvt->reg))		\
			return count;				\
	}							\
	return 0;						\
}

static ssize_t inject_store(struct device *dev,
		struct device_attribute *attr,
		const char *data, size_t count)
{
	struct mem_ctl_info *mci = to_mci(dev);
	struct octeontx_edac_pvt *pvt = mci->pvt_info;

	if (isdigit(*data)) {
		if (!kstrtoul(data, 0, &pvt->inject))
			octeontx_edac_mc_inject(mci);
	}
	return count;
}

TEMPLATE_SHOW(address);
TEMPLATE_STORE(address);
TEMPLATE_SHOW(error_type);
TEMPLATE_STORE(error_type);

static DEVICE_ATTR_WO(inject);
static DEVICE_ATTR_RW(error_type);
static DEVICE_ATTR_RW(address);

static struct attribute *octeontx_dev_attrs[] = {
	&dev_attr_inject.attr,
	&dev_attr_error_type.attr,
	&dev_attr_address.attr,
	NULL
};

ATTRIBUTE_GROUPS(octeontx_dev);

static int octeontx_mc_sdei_callback(u32 event_id, struct pt_regs *regs, void *arg)
{
	struct octeontx_edac_ghes *gsrc;

	if (!arg) {
		otx_printk(KERN_DEBUG, "%s null ghes", __func__);
		return -EINVAL;
	}

	gsrc = arg;
	schedule_work(&gsrc->mc_work);

	return 0;
}

extern void cper_estatus_print(const char *pfx,
		const struct acpi_hest_generic_status *estatus);

static void octeontx_edac_mc_sdei_wq(struct work_struct *work)
{
	struct octeontx_edac_ghes_ring_record *ring;
	struct octeontx_edac_mc_record rec;
	enum hw_event_mc_err_type type;
	struct mem_ctl_info *mci;
	static DEFINE_RAW_SPINLOCK(edac_lock_sdei);
	struct octeontx_edac_ghes *gsrc =
			container_of(work, struct octeontx_edac_ghes, mc_work);
	u32 head, tail;

	raw_spin_lock(&edac_lock_sdei);
	head = gsrc->ring->head;
	tail = gsrc->ring->tail;

	otx_printk(KERN_DEBUG, "%s:[%08x] %llx, tail=%d, head=%d, size=%d, sign=%x\n",
			gsrc->name, gsrc->id, (long long)gsrc->esb_va, tail, head,
			gsrc->ring->size, gsrc->ring->sig);

	/*Ensure that head updated*/
	rmb();

	if (head == tail) {
		raw_spin_unlock(&edac_lock_sdei);
		return;
	}

	ring = &gsrc->ring->records[tail];
	mci = gsrc->mci;

	gsrc->esb_va->estatus.error_severity = ring->error_severity;
	gsrc->esb_va->estatus.block_status = 1;
	gsrc->esb_va->gdata.error_severity = ring->error_severity;
	memcpy_fromio(&rec, gsrc->esb_va,
			(gsrc->id <= OCTEONTX_RAS_TAD_SDEI_EVENT) ?
					sizeof(rec) - sizeof(rec.cper.mem) :
					sizeof(rec) - sizeof(rec.cper.core));
	memcpy_fromio(&rec.gdata.fru_text, ring->fru_text, sizeof(rec.gdata.fru_text));
	memcpy_fromio(&rec.cper.mem, &ring->u,
			(gsrc->id <= OCTEONTX_RAS_TAD_SDEI_EVENT) ?
					sizeof(rec.cper.mem) :
					sizeof(rec.cper.core));

	switch (ring->error_severity) {
	case CPER_SEV_CORRECTED:
		type = HW_EVENT_ERR_CORRECTED;
		break;
	case CPER_SEV_RECOVERABLE:
		type = HW_EVENT_ERR_UNCORRECTED;
		break;
	case CPER_SEV_FATAL:
		type = HW_EVENT_ERR_FATAL;
		break;
	default:
		type = HW_EVENT_ERR_INFO;
	}

	if (gsrc->id <= OCTEONTX_RAS_TAD_SDEI_EVENT)
		edac_mc_handle_error(type, mci, 1, PHYS_PFN(rec.cper.mem.physical_addr),
			offset_in_page(rec.cper.mem.physical_addr),
			0, -1, -1, -1, ring->fru_text, mci->ctl_name);

	if (acpi_disabled && IS_ENABLED(CONFIG_ACPI)) {
		cper_estatus_print(HW_ERR, &rec.estatus);
	} else {
		memcpy_toio(gsrc->esb_va->gdata.fru_text, rec.gdata.fru_text,
				sizeof(rec.gdata.fru_text));
		memcpy_toio(&gsrc->esb_va->cper.mem, &rec.cper.mem,
				(gsrc->id <= OCTEONTX_RAS_TAD_SDEI_EVENT) ?
						sizeof(rec.cper.mem) :
						sizeof(rec.cper.core));
	}

	if (++tail >= gsrc->ring->size)
		tail = 0;
	gsrc->ring->tail = tail;

	/*Ensure that head updated*/
	wmb();

	raw_spin_unlock(&edac_lock_sdei);

	if (head != tail)
		schedule_work(&gsrc->mc_work);

}

static void octeontx_edac_enable_msix(struct pci_dev *pdev)
{
	u16 ctrl;

	if ((pdev->msi_enabled) || (pdev->msix_enabled)) {
		dev_err(&pdev->dev, "MSI(%d) or MSIX(%d) already enabled\n",
			pdev->msi_enabled, pdev->msix_enabled);
		return;
	}

	pdev->msix_cap = pci_find_capability(pdev, PCI_CAP_ID_MSIX);
	if (pdev->msix_cap) {
		pci_read_config_word(pdev, pdev->msix_cap + PCI_MSIX_FLAGS, &ctrl);
		ctrl |= PCI_MSIX_FLAGS_ENABLE;
		pci_write_config_word(pdev, pdev->msix_cap + PCI_MSIX_FLAGS, ctrl);

		otx_printk(KERN_DEBUG, "Set MSI-X Enable for PCI dev %04d:%02d.%d\n",
			pdev->bus->number, PCI_SLOT(pdev->devfn), PCI_FUNC(pdev->devfn));
	} else {
		dev_err(&pdev->dev, "PCI dev %04d:%02d.%d missing MSIX capabilities\n",
			pdev->bus->number, PCI_SLOT(pdev->devfn), PCI_FUNC(pdev->devfn));
	}
}

static void octeontx_edac_msix_init(void)
{
	const struct pci_device_id *pdevid;
	struct pci_dev *pdev;
	size_t i;

	if (MIDR_PARTNUM(read_cpuid_id()) == CN10K_CPU_MODEL)
		return;

	for (i = 0; i < ARRAY_SIZE(octeontx_edac_ghes_pci_tbl); i++) {
		pdevid = &octeontx_edac_ghes_pci_tbl[i];
		pdev = NULL;
		while ((pdev = pci_get_device(pdevid->vendor, pdevid->device, pdev)))
			octeontx_edac_enable_msix(pdev);
	}
}

static void octeontx_edac_ghes_driver_init(struct platform_device *pdev)
{
	struct octeontx_edac_driver *ghes_drv;
	struct octeontx_edac_ghes *gsrc;
	struct device *dev = &pdev->dev;
	size_t i = 0;
	int ret = 0;

	ghes_drv = platform_get_drvdata(pdev);

	for (i = 0; i < ghes_drv->source_count; i++) {
		gsrc = &ghes_drv->source_list[i];

		ret = sdei_event_register(gsrc->id, octeontx_mc_sdei_callback, gsrc);
		if (ret < 0) {
			dev_err(dev, "Error %d registering ghes 0x%x (%s)\n",
				ret, gsrc->id, gsrc->name);
			continue;
		}

		ret = sdei_event_enable(gsrc->id);
		if (ret < 0) {
			dev_err(dev, "Error %d enabling ghes 0x%x (%s)\n",
				ret, gsrc->id, gsrc->name);
			continue;
		}
		gsrc->ring->reg = OCTEONTX_GHES_ERR_RING_SIG;

		otx_printk(KERN_DEBUG, "Register 0x%x (%s) reg [%llx, %llx, %llx]\n", gsrc->id, gsrc->name,
			(long long)gsrc->esa_va, (long long)gsrc->esb_va, (long long)gsrc->ring);
	}
}

static int octentx_edac_ghes_driver_deinit(struct platform_device *pdev)
{
	struct octeontx_edac_driver *ghes_drv;
	struct device *dev = &pdev->dev;
	struct octeontx_edac_ghes *gsrc;
	int ret, i;

	ghes_drv = platform_get_drvdata(pdev);

	for (i = 0; i < ghes_drv->source_count; i++) {
		gsrc = &ghes_drv->source_list[i];

		gsrc->ring->reg = 0;

		ret = sdei_event_disable(gsrc->id);
		if (ret < 0)
			dev_err(dev, "Error %d disabling SDEI gsrc 0x%x (%s)\n",
				ret, gsrc->id, gsrc->name);

		ret = sdei_event_unregister(gsrc->id);
		if (ret < 0)
			dev_err(dev, "Error %d unregistering SDEI gsrc 0x%x (%s)\n",
				ret, gsrc->id, gsrc->name);

		if (gsrc->mci) {
			edac_mc_del_mc(&gsrc->dev);
			edac_mc_free(gsrc->mci);
			put_device(&gsrc->dev);
		}
	}

	return 0;
}

static int __init octeontx_edac_ghes_of_match_resource(struct platform_device *pdev)
{
	struct device_node *of_node;
	struct device_node *child_node;
	struct octeontx_edac_driver *ghes_drv;
	struct octeontx_edac_ghes *gsrc;
	struct device *dev;
	const __be32 *res;
	u64 size;
	u64 base;
	const u32 *id;
	int i = 0;

	dev = &pdev->dev;
	ghes_drv = platform_get_drvdata(pdev);
	of_node = of_find_matching_node(NULL, octeontx_edac_ghes_of_match);
	if (!of_node)
		return -ENODEV;

	for_each_available_child_of_node(of_node, child_node) {
		gsrc = &ghes_drv->source_list[i++];

		strncpy(gsrc->name, child_node->name, sizeof(gsrc->name) - 1);

		res = of_get_address(child_node, 0, NULL, NULL);
		base = of_translate_address(child_node, res);
		if (base == OF_BAD_ADDR) {
			dev_err(dev, "ghes cannot map esa addr\n");
			return -EINVAL;
		}
		gsrc->esa_pa = (phys_addr_t)base;

		res = of_get_address(child_node, 1, &size, NULL);
		base = of_translate_address(child_node, res);
		if (base == OF_BAD_ADDR) {
			dev_err(dev, "ghes cannot map esb addr\n");
			return -EINVAL;
		}
		gsrc->esb_pa = (phys_addr_t)base;
		gsrc->esb_sz = (size_t)size;

		res = of_get_address(child_node, 2, &size, NULL);
		base = of_translate_address(child_node, res);
		if (base == OF_BAD_ADDR) {
			dev_err(dev, "ghes cannot map ring addr\n");
			return -EINVAL;
		}
		gsrc->ring_pa = (phys_addr_t)base;
		gsrc->ring_sz = (size_t)size;

		id = of_get_property(child_node, "event-id", NULL);
		if (!id) {
			dev_err(dev, "ghes cannot get sdei event\n");
			return -EINVAL;
		}
		gsrc->id = be32_to_cpu(*id);

		otx_printk(KERN_DEBUG, "%s 0x%llx/0x%llx/0x%llx, ID:0x%x)\n", gsrc->name,
				gsrc->esa_pa, gsrc->esb_pa, gsrc->ring_pa, gsrc->id);
	}

	return 0;
}

static int __init hest_estatus_address(struct acpi_hest_header *hest_hdr, void *data)
{
	struct acpi_hest_generic *generic = (struct acpi_hest_generic *)hest_hdr;
	u64 *esrc = data;
	static int i;

	esrc[i] = generic->error_status_address.address;
	i++;

	return 0;
}

static phys_addr_t __init octeontx_edac_ghes_get_address(struct octeontx_edac_driver *ghes_drv)
{
	int i = 0;
	u64 *esrc = NULL;
	phys_addr_t ret = ~0ULL;

	esrc = kcalloc(ghes_drv->source_count, sizeof(u64 *), GFP_KERNEL);
	if (!esrc)
		return 0;

	apei_hest_parse(hest_estatus_address, esrc);

	for (i = 0; i < ghes_drv->source_count; i++)
		ret = ret > esrc[i] ? esrc[i] : ret;

	kfree(esrc);

	return ret;
}

static int __init hest_get_vector(struct acpi_hest_header *hest_hdr, void *data)
{
	struct acpi_hest_generic *generic = (struct acpi_hest_generic *)hest_hdr;

	u32 *vec = data;
	static int v;

	vec[v++] = generic->notify.vector;

	return 0;
}

static void __init octeontx_edac_ghes_get_vector(struct octeontx_edac_driver *ghes_drv)
{
	struct octeontx_edac_ghes *gsrc;
	int i = 0;
	u32 *vec = NULL;
	bool cn10k = (MIDR_PARTNUM(read_cpuid_id()) == CN10K_CPU_MODEL);
	unsigned int core = 0;

	vec = kcalloc(ghes_drv->source_count, sizeof(u32 *), GFP_KERNEL);
	if (!vec)
		return;

	apei_hest_parse(hest_get_vector, vec);

	for (i = 0; i < ghes_drv->source_count; i++) {
		gsrc = &ghes_drv->source_list[i];
		gsrc->id = vec[i];

		if (gsrc->id == OCTEONTX_RAS_MDC_SDEI_EVENT)
			sprintf(gsrc->name, OCTEONTX_MDC);
		else if (gsrc->id == OCTEONTX_RAS_MCC_SDEI_EVENT)
			sprintf(gsrc->name, cn10k ? OCTEONTX_DSS : OCTEONTX_MCC);
		else if (gsrc->id == OCTEONTX_RAS_LMC_SDEI_EVENT)
			sprintf(gsrc->name, cn10k ? OCTEONTX_TAD : OCTEONTX_LMC);
		else if (gsrc->id > OCTEONTX_RAS_LMC_SDEI_EVENT)
			sprintf(gsrc->name, "core%d", core++);
	}

	kfree(vec);
}

static int __init octeontx_edac_ghes_acpi_match_resource(struct platform_device *pdev)
{
	struct octeontx_edac_driver *ghes_drv;
	struct octeontx_edac_ghes *gsrc;
	struct resource *res;
	struct device *dev;
	size_t i = 0;
	size_t idx = 0;
	phys_addr_t base = 0;

	dev = &pdev->dev;
	ghes_drv = platform_get_drvdata(pdev);

	base = octeontx_edac_ghes_get_address(ghes_drv);
	if (!base)
		return -EINVAL;

	for (i = 0; i < ghes_drv->source_count; i++) {
		gsrc = &ghes_drv->source_list[i];

		res = platform_get_resource(pdev, IORESOURCE_MEM, idx++);
		if (!res) {
			dev_err(dev, "ghes cannot map esa addr\n");
			return -ENODEV;
		}
		gsrc->esa_pa = res->start + base;

		res = platform_get_resource(pdev, IORESOURCE_MEM, idx++);
		if (!res) {
			dev_err(dev, "ghes cannot map esb addr\n");
			return -ENODEV;
		}
		gsrc->esb_pa = res->start + base;
		gsrc->esb_sz = resource_size(res);

		res = platform_get_resource(pdev, IORESOURCE_MEM, idx++);
		if (!res) {
			dev_err(dev, "ghes cannot map ring addr\n");
			return -ENODEV;
		}
		gsrc->ring_pa = res->start + base;
		gsrc->ring_sz = resource_size(res);

		otx_printk(KERN_DEBUG, "%s[0x%x] 0x%llx 0x%llx 0x%llx)\n",
				gsrc->name, gsrc->id, gsrc->esa_pa, gsrc->esb_pa, gsrc->ring_pa);
	}

	return 0;
}

static int octeontx_edac_ghes_setup_resource(struct octeontx_edac_driver *ghes_drv)
{
	struct octeontx_edac_ghes *gsrc;
	struct device *dev = ghes_drv->dev;
	size_t i = 0;

	for (i = 0; i < ghes_drv->source_count; i++) {
		gsrc = &ghes_drv->source_list[i];

		if (!devm_request_mem_region(dev, gsrc->esa_pa, sizeof(gsrc->esa_va), gsrc->name))
			return -EBUSY;
		gsrc->esa_va = devm_ioremap(dev, gsrc->esa_pa, sizeof(gsrc->esa_va));
		if (!gsrc->esa_va)
			return -ENOMEM;

		if (has_acpi_companion(dev)) {
			*gsrc->esa_va = gsrc->esb_pa;
			devm_iounmap(ghes_drv->dev, gsrc->esa_va);
			devm_release_mem_region(ghes_drv->dev, gsrc->esa_pa, sizeof(gsrc->esa_va));
			acpi_os_map_iomem(gsrc->esa_pa, sizeof(gsrc->esa_pa));
		}

		if (!devm_request_mem_region(dev, gsrc->esb_pa, gsrc->esb_sz, gsrc->name))
			return -EBUSY;
		gsrc->esb_va = devm_ioremap(dev, gsrc->esb_pa, gsrc->esb_sz);
		if (!gsrc->esb_va)
			return -ENOMEM;

		if (!devm_request_mem_region(dev, gsrc->ring_pa, gsrc->ring_sz, gsrc->name))
			return -EBUSY;
		gsrc->ring = devm_ioremap(dev, gsrc->ring_pa, gsrc->ring_sz);
		if (!gsrc->ring)
			return -ENOMEM;

		otx_printk(KERN_DEBUG, "%s: %x %llx/%llx/%llx\n", gsrc->name, gsrc->id,
			(long long)gsrc->esa_va, (long long)gsrc->esb_va, (long long)gsrc->ring);
	}

	return 0;
}

static int hest_count_ghes(struct acpi_hest_header *hest_hdr, void *data)
{
	int *count = data;

	if (hest_hdr->type == ACPI_HEST_TYPE_GENERIC_ERROR ||
		hest_hdr->type == ACPI_HEST_TYPE_GENERIC_ERROR_V2)
		(*count)++;

	return 0;
}

static size_t octeontx_edac_ghes_count(struct octeontx_edac_driver *ghes_drv)
{
	size_t count;
	struct device_node *of_node;
	struct device_node *child_node;
	struct device *dev = ghes_drv->dev;

	count = 0;
	of_node = of_find_matching_node(NULL, octeontx_edac_ghes_of_match);

	if (of_node) {
		for_each_available_child_of_node(of_node, child_node)
			count++;
	} else if (has_acpi_companion(dev)) {
		count = 0;
		apei_hest_parse(hest_count_ghes, &count);
	}

	return count;
}

static int octeontx_edac_ghes_register_mc(struct octeontx_edac_driver *ghes_drv)
{
	struct mem_ctl_info *mci;
	struct edac_mc_layer layers[1];
	struct octeontx_edac_ghes *gsrc;
	int idx = 0;
	int i = 0;
	int ret = 0;

	for (i = 0; i < ghes_drv->source_count; i++) {
		gsrc = &ghes_drv->source_list[i];
		INIT_WORK(&gsrc->mc_work, octeontx_edac_mc_sdei_wq);

		if (IS_NOT_MC_SDEI_EVENT(gsrc->id))
			continue;

		idx = edac_device_alloc_index();

		device_initialize(&gsrc->dev);
		dev_set_name(&gsrc->dev, "edac-%s", gsrc->name);
		ret = device_add(&gsrc->dev);
		if (ret < 0) {
			dev_err(&gsrc->dev, "add device %s\n", dev_name(&gsrc->dev));
			put_device(&gsrc->dev);
			return ret;
		}

		layers[0].type = EDAC_MC_LAYER_ALL_MEM;
		layers[0].size = 1;
		layers[0].is_virt_csrow = false;

		mci = edac_mc_alloc(idx, ARRAY_SIZE(layers), layers,
				sizeof(struct octeontx_edac_pvt));
		if (!mci)
			return -ENOMEM;

		mci->pdev = &gsrc->dev;
		mci->dev_name = dev_name(&gsrc->dev);
		mci->edac_ctl_cap = EDAC_FLAG_SECDED;
		mci->mod_name = DRIVER_NAME;
		mci->ctl_name = gsrc->name;
		mci->edac_check = NULL;
		mci->pvt_info = gsrc;

		if ((strncmp(mci->ctl_name, OCTEONTX_MDC, 3) == 0) ||
				(strncmp(mci->ctl_name, OCTEONTX_MCC, 3) == 0) ||
				(strncmp(mci->ctl_name, OCTEONTX_DSS, 3) == 0))
			ret = edac_mc_add_mc_with_groups(mci, octeontx_dev_groups);
		else
			ret = edac_mc_add_mc_with_groups(mci, NULL);

		if (ret) {
			edac_mc_del_mc(&gsrc->dev);
			put_device(&gsrc->dev);
			return ret;
		}

		gsrc->mci = mci;
	}

	return 0;
}

static int __init octeontx_edac_ghes_probe(struct platform_device *pdev)
{
	struct octeontx_edac_driver *ghes_drv = NULL;
	struct device *dev = &pdev->dev;
	int ret = -ENODEV;

	ghes_drv = devm_kzalloc(dev, sizeof(struct octeontx_edac_driver), GFP_KERNEL);
	if (!ghes_drv)
		return -ENOMEM;

	ghes_drv->dev = dev;

	ghes_drv->source_count = octeontx_edac_ghes_count(ghes_drv);
	if (!ghes_drv->source_count) {
		dev_err(dev, "Not available ghes.\n");
		return -EINVAL;
	}
	otx_printk(KERN_DEBUG, "%s source count %ld\n", __func__, ghes_drv->source_count);

	ghes_drv->source_list = devm_kcalloc(dev, ghes_drv->source_count,
			sizeof(struct octeontx_edac_ghes), GFP_KERNEL);
	if (!ghes_drv->source_list)
		return -ENOMEM;

	platform_set_drvdata(pdev, ghes_drv);

	if (has_acpi_companion(dev)) {
		otx_printk(KERN_DEBUG, "%s ACPI\n", __func__);
		acpi_match_device(dev->driver->acpi_match_table, dev);
		octeontx_edac_ghes_get_vector(ghes_drv);
		ret = octeontx_edac_ghes_acpi_match_resource(pdev);
	} else {
		otx_printk(KERN_DEBUG, "%s DeviceTree\n", __func__);
		if (IS_ENABLED(CONFIG_ACPI))
			acpi_permanent_mmap = true;
		set_bit(EFI_MEMMAP, &efi.flags);
		ret = octeontx_edac_ghes_of_match_resource(pdev);
	}
	if (ret < 0) {
		dev_err(dev, "Failed match resources\n");
		goto exit0;
	}

	ret = octeontx_edac_ghes_setup_resource(ghes_drv);
	if (ret)
		goto exit0;

	octeontx_edac_msix_init();

	octeontx_edac_ghes_driver_init(pdev);

	ret = octeontx_edac_ghes_register_mc(ghes_drv);
	if (ret)
		goto exit0;

	return 0;

exit0:
	dev_err(dev, "Error edac probe\n");

	return ret;
}

static int octeontx_edac_ghes_remove(struct platform_device *pdev)
{
	octentx_edac_ghes_driver_deinit(pdev);

	return 0;
}

static const struct platform_device_id octeontx_edac_ghes_pdev_match[] = {
	{ .name = DRIVER_NAME, },
	{},
};
MODULE_DEVICE_TABLE(platform, octeontx_edac_ghes_pdev_match);

static struct platform_driver octeontx_edac_ghes_drv_probe = {
	.driver = {
		.name             = DRIVER_NAME,
		.of_match_table   = of_match_ptr(octeontx_edac_ghes_of_match),
		.acpi_match_table = ACPI_PTR(octeontx_edac_ghes_acpi_match),
	},
	.probe    = octeontx_edac_ghes_probe,
	.remove   = octeontx_edac_ghes_remove,
	.id_table = octeontx_edac_ghes_pdev_match,
};
module_platform_driver(octeontx_edac_ghes_drv_probe);

MODULE_AUTHOR("Marvell International Ltd.");
MODULE_DESCRIPTION("OcteonTX2 / CN10K EDAC driver");
MODULE_LICENSE("GPL");
