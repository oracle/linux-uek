// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2022 Marvell.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/io.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_device.h>
#include <linux/platform_device.h>
#include <linux/of_address.h>
#include <linux/arm_sdei.h>
#include <linux/uuid.h>
#include <linux/acpi.h>
#include <acpi/apei.h>
#include <linux/pci.h>
#include <linux/crash_dump.h>
#include <asm/cputype.h>
#include <linux/edac.h>
#include <soc/marvell/octeontx/octeontx_smc.h>
#include "octeontx_edac.h"
#include "edac_mc.h"

#define DRV_NAME       "sdei-ghes"

#define initerrmsg(fmt, ...) pr_err(DRV_NAME ":" fmt, __VA_ARGS__)
#ifdef CONFIG_EDAC_DEBUG
#  define initdbgmsg(fmt, ...) pr_info(DRV_NAME ":" fmt, __VA_ARGS__)
#  define dbgmsg(dev, ...) dev_info((dev), __VA_ARGS__)
#else
#  define initdbgmsg(fmt, ...) (void)(fmt)
#  define dbgmsg(dev, ...) (void)(dev)
#endif // CONFIG_EDAC_DEBUG

#define OTX2_HEST_OEM_ID	"MRVL  "
#define HEST_TBL_OEM_ID		"OTX2    "

static const struct of_device_id sdei_ghes_of_match[] = {
	{ .compatible = "marvell,sdei-ghes", },
	{},
};
MODULE_DEVICE_TABLE(of, sdei_ghes_of_match);

#ifdef CONFIG_ACPI
static const struct acpi_device_id sdei_ghes_acpi_match[] = {
	{ "GHES0001", 0 },
	{ },
};
MODULE_DEVICE_TABLE(acpi, sdei_ghes_acpi_match);
#endif

#define PCI_VENDOR_ID_CAVIUM            0x177d
#define PCI_DEVICE_ID_OCTEONTX2_LMC     0xa022
#define PCI_DEVICE_ID_OCTEONTX2_MCC     0xa070
#define PCI_DEVICE_ID_OCTEONTX2_MDC     0xa073

static const struct pci_device_id sdei_ghes_mrvl_pci_tbl[] = {
	{ PCI_DEVICE(PCI_VENDOR_ID_CAVIUM, PCI_DEVICE_ID_OCTEONTX2_LMC) },
	{ PCI_DEVICE(PCI_VENDOR_ID_CAVIUM, PCI_DEVICE_ID_OCTEONTX2_MCC) },
	{ PCI_DEVICE(PCI_VENDOR_ID_CAVIUM, PCI_DEVICE_ID_OCTEONTX2_MDC) },
	{ 0, },
};

#define to_mci(k) container_of(k, struct mem_ctl_info, dev)

#define TEMPLATE_SHOW(reg)					\
static ssize_t reg##_show(struct device *dev,	\
			       struct device_attribute *attr,	\
			       char *data)			\
{								\
	struct mem_ctl_info *mci = to_mci(dev);			\
	struct octeontx_edac_pvt *pvt = mci->pvt_info;		\
	return sprintf(data, "%016llu\n", (u64)pvt->reg);	\
}

#define TEMPLATE_STORE(reg)					\
static ssize_t reg##_store(struct device *dev,	\
			       struct device_attribute *attr,	\
			       const char *data, size_t count)	\
{								\
	struct mem_ctl_info *mci = to_mci(dev);			\
	struct octeontx_edac_pvt *pvt = mci->pvt_info;		\
	if (isdigit(*data)) {					\
		if (!kstrtoul(data, 0, &pvt->reg))		\
			return count;				\
	}							\
	return 0;						\
}

TEMPLATE_SHOW(inject);
TEMPLATE_STORE(inject);
TEMPLATE_SHOW(address);
TEMPLATE_STORE(address);
TEMPLATE_SHOW(error_type);
TEMPLATE_STORE(error_type);

static DEVICE_ATTR_RW(inject);
static DEVICE_ATTR_RW(error_type);
static DEVICE_ATTR_RW(address);

static struct attribute *octeontx_dev_attrs[] = {
	&dev_attr_inject.attr,
	&dev_attr_error_type.attr,
	&dev_attr_address.attr,
	NULL
};

ATTRIBUTE_GROUPS(octeontx_dev);

static bool cn10kx_model;
static u8 tmp[256];

static int sdei_ghes_callback(u32 event_id, struct pt_regs *regs, void *arg)
{
	struct acpi_hest_generic_status *estatus;
	struct acpi_hest_generic_data *gdata;
	void *esb_err;
	struct otx2_ghes_err_record *ring_rec;
	struct mrvl_ghes_source *gsrc;
	u32 head, tail;

	if (!arg)
		return -1;

	gsrc = arg;

	head = gsrc->ring->head;
	tail = gsrc->ring->tail;

	initerrmsg("%s to %llx, head=%d (%llx), tail=%d (%llx), size=%d, sign=%x\n", __func__,
			(long long)gsrc->esb_va, head,
			(long long)&gsrc->ring->head, tail, (long long)&gsrc->ring->tail,
			gsrc->ring->size, *(int *)((&gsrc->ring->size) + 1));

	/*Ensure that head updated*/
	rmb();

	if (head == tail) {
		initerrmsg("event 0x%x ring is empty, head=%d, size=%d\n",
				event_id, head, gsrc->ring->size);
		return -1;
	}

	ring_rec = &gsrc->ring->records[tail];

	estatus = (struct acpi_hest_generic_status *)tmp;
	gdata = (struct acpi_hest_generic_data *)(estatus + 1);
	esb_err = (gdata + 1);

	//This simply needs the entry count to be non-zero.
	//Set entry count to one (see ACPI_HEST_ERROR_ENTRY_COUNT).
	estatus->block_status = (1 << 4); // i.e. one entry
	estatus->raw_data_offset = sizeof(*estatus) + sizeof(*gdata);
	estatus->raw_data_length = 0;
	estatus->data_length = gsrc->esb_sz - sizeof(*estatus);
	estatus->error_severity = ring_rec->severity;
	gdata->revision = 0x201; // ACPI 4.x
	if (ring_rec->fru_text[0]) {
		gdata->validation_bits = ACPI_HEST_GEN_VALID_FRU_STRING;
		memcpy_fromio(gdata->fru_text, ring_rec->fru_text, sizeof(gdata->fru_text));
		memcpy_fromio(((struct mrvl_mem_error_raport *)(tmp))->fru_text,
				ring_rec->fru_text, sizeof(ring_rec->fru_text));
	}
	gdata->error_severity = estatus->error_severity;

	guid_copy((guid_t *)gdata->section_type, &CPER_SEC_PLATFORM_MEM);
	initdbgmsg("%s CPER_SEC_PLATFORM_MEM\n", __func__);

	gdata->error_data_length = gsrc->esb_sz -
			(sizeof(*estatus) + sizeof(*gdata));

	memcpy_fromio(esb_err, &ring_rec->u.mcc, gdata->error_data_length);
	initdbgmsg("%s err_sev=%x,\n", __func__, ring_rec->severity);
	memcpy_toio(gsrc->esb_va, tmp, gsrc->esb_sz);

	/*Ensure that error status is committed to memory prior to set block_status*/
	wmb();

	if (++tail >= gsrc->ring->size)
		tail = 0;
	gsrc->ring->tail = tail;

	return 0;
}

static void octeontx_edac_check(struct mem_ctl_info *mci)
{
	struct mrvl_ghes_source *gsrc;
	enum hw_event_mc_err_type type;
	struct acpi_hest_generic_status *estatus;
	unsigned long address;
	struct mrvl_mem_error_raport *rec;

	gsrc = mci->pvt_info;
	estatus = gsrc->esb_va;

	if (!estatus->error_severity)
		return;

	type = (estatus->error_severity == CPER_SEV_CORRECTED) ?
			HW_EVENT_ERR_CORRECTED : HW_EVENT_ERR_FATAL;
	rec = (struct mrvl_mem_error_raport *)tmp;
	address = rec->cper.physical_addr;
	edac_mc_handle_error(type, mci, 1, address >> PAGE_SHIFT, address & ~(PAGE_MASK),
			0, -1, -1, -1, rec->fru_text, mci->ctl_name);

	estatus->error_severity = 0;
}

static int sdei_ras_core_callback(uint32_t event_id, struct pt_regs *regs, void *arg)
{
	struct mrvl_ghes_source *core = NULL;
	struct mrvl_core_error_raport *raport = NULL;
	struct acpi_hest_generic_status *estatus = NULL;
	struct acpi_hest_generic_data *gdata = NULL;
	struct otx2_ghes_err_record *rec = NULL;
	uint32_t head = 0;
	uint32_t tail = 0;

	if (!arg) {
		initdbgmsg("%s %s failed argument\n", DRV_NAME, __func__);
		return -EINVAL;
	}

	core = arg;

	head = core->ring->head;
	tail = core->ring->tail;
	pr_notice("%s event id 0x%x\n", __func__, event_id);

	/*Ensure that head updated*/
	rmb();

	if (head == tail) {
		initdbgmsg("%s event 0x%x ring is empty, head=%d, size=%d\n", DRV_NAME,
				event_id, head, core->ring->size);
		return -EINVAL;
	}

	memset(tmp, 0, sizeof(tmp));
	rec = &core->ring->records[tail];

	raport = (struct mrvl_core_error_raport *)tmp;
	estatus = &raport->estatus;
	gdata = &raport->gdata;

	estatus->block_status = (1 << 4);
	estatus->raw_data_offset = sizeof(struct acpi_hest_generic_status) +
			sizeof(struct acpi_hest_generic_data);
	estatus->raw_data_length = 0;
	estatus->data_length = core->esb_sz - sizeof(struct acpi_hest_generic_status);
	estatus->error_severity = rec->severity;

	gdata->revision = 0x201; // ACPI 4.x
	if (rec->fru_text[0]) {
		gdata->validation_bits = ACPI_HEST_GEN_VALID_FRU_STRING;
		memcpy(gdata->fru_text, rec->fru_text, sizeof(gdata->fru_text));
	}

	gdata->error_severity = estatus->error_severity;
	guid_copy((guid_t *)gdata->section_type, &CPER_SEC_PROC_ARM);
	gdata->error_data_length = core->esb_sz -
			(sizeof(struct acpi_hest_generic_status) +
					sizeof(struct acpi_hest_generic_data));

	initdbgmsg("%s event 0x%x error severity=%x,\n", DRV_NAME, core->id,
			rec->severity);

	memcpy_fromio(&raport->desc, &rec->u.core.desc, gdata->error_data_length);
	memcpy_fromio(&raport->info, &rec->u.core.info, sizeof(rec->u.core.info));

	memcpy_toio(core->esb_core_va, tmp, core->esb_sz);

	/*Ensure that error status is committed to memory prior to set status*/
	wmb();

	if (++tail >= core->ring->size)
		tail = 0;
	core->ring->tail = tail;

	return 0;
}

/*
 * Enable MSIX at the device level (MSIX_CAPABILITIES Header).
 *
 * NOTE: We SHOULD be able to use PCCPVF_XXX_VSEC_SCTL[MSIX_SEC_EN]
 * to enable our SECURE IRQs, but for errata PCC-34263...
 */
static void dev_enable_msix_t9x(struct pci_dev *pdev)
{
	u16 ctrl;

	initdbgmsg("%s: entry\n", __func__);

	if ((pdev->msi_enabled) || (pdev->msix_enabled)) {
		initerrmsg("MSI(%d) or MSIX(%d) already enabled\n",
				pdev->msi_enabled, pdev->msix_enabled);
		return;
	}

	/* enable MSIX delivery for this device; we handle [secure] MSIX ints */
	pdev->msix_cap = pci_find_capability(pdev, PCI_CAP_ID_MSIX);
	if (pdev->msix_cap) {
		pci_read_config_word(pdev, pdev->msix_cap + PCI_MSIX_FLAGS, &ctrl);
		ctrl |= PCI_MSIX_FLAGS_ENABLE;
		pci_write_config_word(pdev, pdev->msix_cap + PCI_MSIX_FLAGS, ctrl);

		initdbgmsg("Set MSI-X Enable for PCI dev %04d:%02d.%d\n",
			   pdev->bus->number, PCI_SLOT(pdev->devfn), PCI_FUNC(pdev->devfn));
	} else {
		initerrmsg("PCI dev %04d:%02d.%d missing MSIX capabilities\n",
			   pdev->bus->number, PCI_SLOT(pdev->devfn), PCI_FUNC(pdev->devfn));
	}
}

/* Enable MSIX for devices whose [secure] IRQ's we control.
 * These IRQs have been initialized by ATF.
 * This is required due to an errata against
 * PCCPVF_XXX_VSEC_SCTL[MSIX_SEC_EN].
 */
static void sdei_ghes_msix_init_t9x(void)
{
	const struct pci_device_id *pdevid;
	struct pci_dev *pdev;
	size_t i;

	initdbgmsg("%s: entry\n", __func__);

	for (i = 0; i < ARRAY_SIZE(sdei_ghes_mrvl_pci_tbl); i++) {
		pdevid = &sdei_ghes_mrvl_pci_tbl[i];
		pdev = NULL;

		while ((pdev = pci_get_device(pdevid->vendor, pdevid->device, pdev)))
			dev_enable_msix_t9x(pdev);
	}
}

/* Main initialization function for ghes_drv device instance. */
static int sdei_ghes_driver_init(struct platform_device *pdev)
{
	struct mrvl_sdei_ghes_drv *ghes_drv;
	struct device *dev = &pdev->dev;
	struct mrvl_ghes_source *gsrc;
	size_t i;
	int ret = 0;

	initdbgmsg("%s: entry\n", __func__);

	ghes_drv = platform_get_drvdata(pdev);

	for (i = 0; i < ghes_drv->source_count; i++) {
		gsrc = &ghes_drv->source_list[i];

		if (gsrc->id < OCTEONTX_SDEI_RAS_AP0_EVENT)
			ret = sdei_event_register(gsrc->id, sdei_ghes_callback, gsrc);
		else
			ret = sdei_event_register(gsrc->id, sdei_ras_core_callback, gsrc);

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
		gsrc->ring->reg = OTX2_GHES_ERR_RING_SIG;

		initdbgmsg("Register GHES 0x%x (%s) %s [%llx, %llx, %llx]\n",
				gsrc->id, gsrc->name, "reg",
				(long long)gsrc->esa_va,
				(long long)gsrc->esb_va, (long long)gsrc->ring);
	}

	if (i != ghes_drv->source_count)
		dev_err(dev, "Error cannot register all ghes\n");
	else
		dev_info(dev, "Registered & enabled %ld GHES\n", ghes_drv->source_count);

	return 0;
}

/* Main de-initialization function for ghes_drv device instance. */
static int sdei_ghes_driver_deinit(struct platform_device *pdev)
{
	struct mrvl_sdei_ghes_drv *ghes_drv;
	struct device *dev = &pdev->dev;
	struct mrvl_ghes_source *gsrc;
	int ret, i;

	initdbgmsg("%s: entry\n", __func__);

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
			edac_mc_free(gsrc->mci);
			put_device(&gsrc->dev);
		}
	}

	return 0;
}

static int __init sdei_ghes_of_match_resource(struct platform_device *pdev)
{
	struct device_node *of_node;
	struct device_node *child_node;
	struct mrvl_sdei_ghes_drv *ghes_drv;
	struct mrvl_ghes_source *gsrc;
	struct device *dev;
	const __be32 *res;
	u64 size;
	u64 base;
	const u32 *id;
	size_t i = 0;

	initdbgmsg("%s: entry\n", __func__);

	dev = &pdev->dev;
	ghes_drv = platform_get_drvdata(pdev);
	of_node = of_find_matching_node(NULL, sdei_ghes_of_match);

	if (!of_node) {
		dev_err(dev, "ghes no matching node.\n");
		return -ENODEV;
	}

	for_each_available_child_of_node(of_node, child_node) {
		if (i >= ghes_drv->source_count) {
			dev_err(dev, "ghes resource allocation overflow %ld.\n", i);
			return -EFAULT;
		}

		gsrc = &ghes_drv->source_list[i];

		strncpy(gsrc->name, child_node->name, sizeof(gsrc->name) - 1);

		// Error Status Address
		res = of_get_address(child_node, 0, NULL, NULL);
		if (!res) {
			dev_err(dev, "ghes cannot get esa addr %ld.\n", i);
			return -EINVAL;
		}
		base = of_translate_address(child_node, res);
		if (base == OF_BAD_ADDR) {
			dev_err(dev, "ghes cannot map esa addr %ld.\n", i);
			return -EINVAL;
		}
		gsrc->esa_pa = (phys_addr_t)base;

		// Error Status Block
		res = of_get_address(child_node, 1, &size, NULL);
		if (!res) {
			dev_err(dev, "ghes cannot get esb addr %ld.\n", i);
			return -EINVAL;
		}
		base = of_translate_address(child_node, res);
		if (base == OF_BAD_ADDR) {
			dev_err(dev, "ghes cannot map esb addr %ld.\n", i);
			return -EINVAL;
		}
		gsrc->esb_pa = (phys_addr_t)base;
		gsrc->esb_sz = (size_t)size;

		// Error Ring
		res = of_get_address(child_node, 2, &size, NULL);
		if (!res) {
			dev_err(dev, "ghes cannot get ring addr %ld.\n", i);
			return -EINVAL;
		}
		base = of_translate_address(child_node, res);
		if (base == OF_BAD_ADDR) {
			dev_err(dev, "ghes cannot map ring addr %ld.", i);
			return -EINVAL;
		}
		gsrc->ring_pa = (phys_addr_t)base;
		gsrc->ring_sz = (size_t)size;

		// Event ID
		id = of_get_property(child_node, "event-id", NULL);
		if (!id) {
			dev_err(dev, "ghes cannot map event id %ld.", i);
			return -EINVAL;
		}
		gsrc->id = be32_to_cpu(*id);

		initdbgmsg("GHES: %s 0x%llx/0x%llx/0x%llx, ID:0x%x)\n", gsrc->name,
				gsrc->esa_pa, gsrc->esb_pa, gsrc->ring_pa, gsrc->id);

		i++;
	}

	return 0;
}

static int __init sdei_ghes_get_esa(struct acpi_hest_header *hest_hdr, void *data)
{
	struct acpi_hest_generic *generic = (struct acpi_hest_generic *)hest_hdr;
	u64 *esrc = data;
	static int i;

	initdbgmsg("%s 0x%llx: 0x%llx\n", __func__,
			(long long)&generic->error_status_address.address,
			(long long)generic->error_status_address.address);
	esrc[i] = generic->error_status_address.address;
	i++;

	return 0;
}

static phys_addr_t __init sdei_ghes_get_error_source_address(struct mrvl_sdei_ghes_drv *ghes_drv)
{
	int i = 0;
	u64 *esrc = NULL;
	phys_addr_t ret = ~0ULL;

	esrc = kcalloc(ghes_drv->source_count, sizeof(u64 *), GFP_KERNEL);
	if (!esrc) {
		initdbgmsg("%s Failed to allocate esrc\n", __func__);
		return 0;
	}

	apei_hest_parse(sdei_ghes_get_esa, esrc);

	for (i = 0; i < ghes_drv->source_count; i++)
		ret = ret > esrc[i] ? esrc[i] : ret;

	kfree(esrc);
	return ret;
}

static int __init sdei_ghes_acpi_match_resource(struct platform_device *pdev)
{
	struct mrvl_sdei_ghes_drv *ghes_drv;
	struct mrvl_ghes_source *gsrc;
	struct resource *res;
	struct device *dev;
	size_t i = 0;
	size_t idx = 0;
	phys_addr_t base = 0;
	u32 core = 0;

	dev = &pdev->dev;
	ghes_drv = platform_get_drvdata(pdev);

	base = sdei_ghes_get_error_source_address(ghes_drv);

	for (i = 0; i < ghes_drv->source_count; i++) {
		gsrc = &ghes_drv->source_list[i];

		// Error Status Address
		res = platform_get_resource(pdev, IORESOURCE_MEM, idx);
		if (!res) {
			dev_err(dev, "%s ACPI warn get gsrc=%ld idx=%ld\n", __func__, i, idx);
			return -ENOENT;
		}
		initdbgmsg("%s Status Address %s [%llx - %llx, %lx, %lx]\n", __func__,
				res->name, res->start, res->end, res->flags, res->desc);
		/*
		 * HEST define BASE address 'error status address' block
		 * DSDT define offset from BASE for error address status/block/ring
		 * driver make valid addresses base + offset
		 * and next patch HEST with validated addresses
		 */
		gsrc->esa_pa = res->start + base;
		idx++;

		// Error Status Block Buffer
		res = platform_get_resource(pdev, IORESOURCE_MEM, idx);
		if (!res) {
			dev_err(dev, "%s ACPI warn get gsrc=%ld idx=%ld\n", __func__, i, idx);
			return -ENOENT;
		}
		initdbgmsg("%s Status Block %s [%llx - %llx / %llx, %lx, %lx]\n", __func__,
				res->name, res->start, res->end, resource_size(res),
				res->flags, res->desc);
		gsrc->esb_pa = res->start + base;
		gsrc->esb_sz = resource_size(res);
		idx++;

		// Error Blocks Ring
		res = platform_get_resource(pdev, IORESOURCE_MEM, idx);
		if (!res) {
			dev_err(dev, "%s ACPI warn get gsrc=%ld idx=%ld\n", __func__, i, idx);
			return -ENOENT;
		}
		initdbgmsg("%s Status Ring %s [%llx - %llx, %lx, %lx]\n", __func__,
				res->name, res->start, res->end, res->flags, res->desc);
		gsrc->ring_pa = res->start + base;
		gsrc->ring_sz = resource_size(res);
		idx++;

		// Event ID
		res = platform_get_resource(pdev, IORESOURCE_MEM, idx);
		if (!res) {
			dev_err(dev, "%s ACPI warn get gsrc=%ld idx=%ld\n", __func__, i, idx);
			return -ENOENT;
		}
		initdbgmsg("%s Event ID %s [%llx - %llx, %lx, %lx]\n", __func__,
				res->name, res->start, res->end, res->flags, res->desc);
		gsrc->id = res->start;
		idx++;

		initdbgmsg("GHES: 0x%llx / 0x%llx / 0x%llx, ID:0x%x)\n",
				gsrc->esa_pa, gsrc->esb_pa, gsrc->ring_pa, gsrc->id);
	}

	for (i = 0; i < ghes_drv->source_count; i++) {
		gsrc = &ghes_drv->source_list[i];
		if (gsrc->id >= OCTEONTX_SDEI_RAS_AP0_EVENT)
			sprintf(gsrc->name, "core%d", core++);
		else if (gsrc->id == OCTEONTX_SDEI_RAS_MDC_EVENT)
			sprintf(gsrc->name, "mdc");
		else if (gsrc->id == OCTEONTX_SDEI_RAS_MCC_EVENT)
			sprintf(gsrc->name, cn10kx_model ? "dss" : "mcc");
		else if (gsrc->id == OCTEONTX_SDEI_RAS_LMC_EVENT)
			sprintf(gsrc->name, cn10kx_model ? "tad" : "lmc");
		initdbgmsg("%s %s\n", __func__, gsrc->name);
	}

	return 0;
}

static int  sdei_ghes_setup_resource(struct mrvl_sdei_ghes_drv *ghes_drv)
{
	struct mrvl_ghes_source *gsrc;
	size_t i = 0;
	struct device *dev = ghes_drv->dev;

	initdbgmsg("%s: entry\n", __func__);

	for (i = 0; i < ghes_drv->source_count; i++) {
		gsrc = &ghes_drv->source_list[i];

		if (pfn_valid(PHYS_PFN(gsrc->esa_pa)))
			gsrc->esa_va = phys_to_virt(gsrc->esa_pa);
		else {
			if (!devm_request_mem_region(dev, gsrc->esa_pa,
						     sizeof(gsrc->esa_va), gsrc->name))
				return -EFAULT;
			gsrc->esa_va = devm_ioremap(dev, gsrc->esa_pa, sizeof(gsrc->esa_va));
			if (!gsrc->esa_va) {
				dev_err(dev, "estatus unable map phys addr");
				return -EFAULT;
			}
		}

		if (pfn_valid(PHYS_PFN(gsrc->esb_pa)))
			gsrc->esb_va = phys_to_virt(gsrc->esb_pa);
		else {
			if (!devm_request_mem_region(dev, gsrc->esb_pa, gsrc->esb_sz, gsrc->name))
				return -EFAULT;
			gsrc->esb_va = devm_ioremap(dev, gsrc->esb_pa, gsrc->esb_sz);
			if (!gsrc->esb_va) {
				dev_err(dev, "gdata unable map phys addr");
				return -EFAULT;
			}
		}

		if (pfn_valid(PHYS_PFN(gsrc->ring_pa))) {
			gsrc->ring = phys_to_virt(gsrc->ring_pa);
			initdbgmsg("%s ring buffer direct map\n", __func__);
		} else {
			if (!devm_request_mem_region(dev, gsrc->ring_pa, gsrc->ring_sz, gsrc->name))
				return -EFAULT;
			gsrc->ring = devm_ioremap(dev, gsrc->ring_pa, gsrc->ring_sz);
			if (!gsrc->ring) {
				dev_err(dev, "ring unable map phys addr");
				return -EFAULT;
			}
		}

		initdbgmsg("%s %s 0x%llx/0x%llx/0x%llx\n", __func__, gsrc->name,
				(unsigned long long)gsrc->esa_va,
				(unsigned long long)gsrc->esb_va,
				(unsigned long long)gsrc->ring);
	}

	return 0;
}

static void sdei_ghes_init_source(struct mrvl_sdei_ghes_drv *ghes_drv)
{
	struct mrvl_ghes_source *gsrc;
	size_t i;

	for (i = 0; i < ghes_drv->source_count; i++) {
		gsrc = &ghes_drv->source_list[i];

		gsrc->esb_va->block_status = 0;

		*gsrc->esa_va = gsrc->esb_pa;

		initdbgmsg("%s poll address 0x%llx: 0x%llx\n", __func__,
				gsrc->esa_pa, gsrc->esb_pa);

		devm_iounmap(ghes_drv->dev, gsrc->esa_va);
		devm_release_mem_region(ghes_drv->dev, gsrc->esa_pa, sizeof(gsrc->esa_va));
		acpi_os_map_iomem(gsrc->esa_pa, 8);
	}
}

static int sdei_ghes_count(struct acpi_hest_header *hest_hdr, void *data)
{
	int *count = data;

	if (hest_hdr->type == ACPI_HEST_TYPE_GENERIC_ERROR ||
		hest_hdr->type == ACPI_HEST_TYPE_GENERIC_ERROR_V2)
		(*count)++;

	return 0;
}

static size_t sdei_ghes_count_source(struct mrvl_sdei_ghes_drv *ghes_drv)
{
	size_t count;
	struct device_node *of_node;
	struct device_node *child_node;

	count = 0;
	of_node = of_find_matching_node(NULL, sdei_ghes_of_match);

	if (of_node) {
		for_each_available_child_of_node(of_node, child_node) {
			initdbgmsg("%s %s\n", __func__, child_node->name);
			count++;
		}
	} else {
		count = 0;
		apei_hest_parse(sdei_ghes_count, &count);
	}
	initdbgmsg("%s %zu\n", __func__, count);

	return count;
}

static int sdei_ghes_alloc_source(struct device *dev,
		struct mrvl_sdei_ghes_drv *ghes_drv)
{
	size_t size = 0;

	initdbgmsg("%s\n", __func__);

	size = ghes_drv->source_count * sizeof(struct mrvl_ghes_source);

	ghes_drv->source_list = devm_kzalloc(dev, size, GFP_KERNEL);
	if (!ghes_drv->source_list)
		return -ENOMEM;

	return 0;
}

static int __init sdei_ghes_of_alloc_hest(struct mrvl_sdei_ghes_drv *ghes_drv)
{
	struct mrvl_ghes_source *gsrc;
	unsigned int size;
	struct acpi_table_hest *hest;
	struct acpi_table_header *hdr;
	struct acpi_hest_generic *generic;
	size_t i;
	u8 *p;
	u8 sum = 0;
	struct device *dev = ghes_drv->dev;

	initdbgmsg("%s: entry\n", __func__);

	size = sizeof(struct acpi_table_hest) +
			ghes_drv->source_count * sizeof(struct acpi_hest_generic);

	hest = devm_kzalloc(dev, size, GFP_KERNEL);
	if (!hest)
		return -ENOMEM;

	generic = (struct acpi_hest_generic *)(hest + 1);

	hdr = &hest->header;

	strcpy(hdr->signature, ACPI_SIG_HEST);
	hdr->length = size;
	hdr->revision = 1;
	strcpy(hdr->oem_id, OTX2_HEST_OEM_ID);
	strcpy(hdr->oem_table_id, HEST_TBL_OEM_ID);
	hdr->oem_revision = 1;
	strcpy(hdr->asl_compiler_id, OTX2_HEST_OEM_ID);
	hdr->asl_compiler_revision = 1;
	p = (u8 *)hdr;
	while (p < (u8 *)(hdr + 1))
		sum += *p, p++;
	hdr->checksum -= sum;
	hest->error_source_count = ghes_drv->source_count;

	for (i = 0; i < hest->error_source_count; i++, generic++) {
		gsrc = &ghes_drv->source_list[i];

		generic->header.type = ACPI_HEST_TYPE_GENERIC_ERROR;
		generic->header.source_id = i;
		generic->related_source_id = i;
		generic->reserved = 0;
		generic->enabled = 1;
		generic->records_to_preallocate = 1;
		generic->max_sections_per_record = 1;
		generic->max_raw_data_length = 0;

		generic->error_status_address.space_id = ACPI_ADR_SPACE_SYSTEM_MEMORY;
		generic->error_status_address.bit_width = 64;
		generic->error_status_address.bit_offset = 0;
		generic->error_status_address.access_width = 4;
		generic->error_status_address.address = gsrc->esa_pa;

		generic->notify.type = ACPI_HEST_NOTIFY_POLLED;
		generic->notify.length = sizeof(struct acpi_hest_notify);
		generic->notify.config_write_enable = 0;
		generic->notify.poll_interval = 1000; /* i.e. 1 sec */
		generic->notify.vector = gsrc->id;
		generic->notify.error_threshold_value = 1;
		generic->notify.error_threshold_window = 1;

		generic->error_block_length = gsrc->esb_sz;

		initdbgmsg("%s %s [%x] estatus=%llx, poll=%d, block_sz=%x\n", __func__,
				gsrc->name, gsrc->id,
				(unsigned long long)generic->error_status_address.address,
				generic->notify.poll_interval,
				generic->error_block_length);
	}

	hest_table_set(hest);

	acpi_hest_init();
	initdbgmsg("%s registering HEST\n", __func__);

	return 0;
}

static int octeontx_edac_mc_create(struct mrvl_sdei_ghes_drv *ghes_drv)
{
	struct mem_ctl_info *mci;
	struct edac_mc_layer layer;
	struct mrvl_ghes_source *gsrc;
	int mc = 0;
	int i = 0;
	int err = 0;

	opstate_init();

	for (i = 0; i < ghes_drv->source_count; i++) {
		gsrc = &ghes_drv->source_list[i];

		gsrc->mci = NULL;
		if (gsrc->id >= OCTEONTX_SDEI_RAS_AP0_EVENT)
			continue;

		memset(tmp, 0, sizeof(tmp));
		memcpy_toio(gsrc->esb_va, tmp, gsrc->esb_sz);

		device_initialize(&gsrc->dev);
		dev_set_name(&gsrc->dev, gsrc->name);
		err = device_add(&gsrc->dev);
		if (err < 0) {
			dev_err(&gsrc->dev, "failure: create device %s\n", dev_name(&gsrc->dev));
			put_device(&gsrc->dev);
			return err;
		}

		layer.type = EDAC_MC_LAYER_CHIP_SELECT;
		layer.size = 1;
		layer.is_virt_csrow = false;

		mci = edac_mc_alloc(mc++, 1, &layer, sizeof(struct octeontx_edac_pvt));
		if (!mci)
			return -ENXIO;

		mci->pdev = &gsrc->dev;
		mci->dev_name = dev_name(&gsrc->dev);
		dev_set_name(&mci->dev, "mrvl_mdc");

		mci->mod_name = "octeontx-edac";
		mci->ctl_name = gsrc->name;
		mci->edac_check = octeontx_edac_check;
		mci->ctl_page_to_phys = NULL;
		mci->pvt_info = gsrc;
		mci->error_desc.grain = 0;

		if (edac_mc_add_mc_with_groups(mci, octeontx_dev_groups)) {
			dev_err(&gsrc->dev, "edac_mc_add_mc() failed\n");
			edac_mc_free(mci);
			return -ENXIO;
		}

		gsrc->mci = mci;
	}

	return 0;
}

static int __init edac_ghes_mrvl_probe(struct platform_device *pdev)
{
	struct mrvl_sdei_ghes_drv *ghes_drv = NULL;
	struct device *dev = &pdev->dev;
	int ret = -ENODEV;
	int i;

	cn10kx_model = is_soc_cn10kx();

#ifdef CONFIG_CRASH_DUMP
	if (is_kdump_kernel())
#else
	#pragma message "CONFIG_CRASH_DUMP setting is required for this module"
	if (true)
#endif
		return ret;

	initdbgmsg("%s\n", __func__);

	ghes_drv = devm_kzalloc(dev, sizeof(struct mrvl_sdei_ghes_drv), GFP_KERNEL);
	if (!ghes_drv)
		return -ENOMEM;

	ghes_drv->dev = dev;

	ghes_drv->source_count = sdei_ghes_count_source(ghes_drv);
	if (!ghes_drv->source_count) {
		dev_err(dev, "Not available resource.\n");
		return -EINVAL;
	}
	initdbgmsg("%s source count %ld\n", __func__, ghes_drv->source_count);

	ret = sdei_ghes_alloc_source(dev, ghes_drv);
	if (ret)
		return ret;

	platform_set_drvdata(pdev, ghes_drv);

	if (has_acpi_companion(dev)) {
		initdbgmsg("%s ACPI\n", __func__);
		acpi_match_device(dev->driver->acpi_match_table, dev);
		ret = sdei_ghes_acpi_match_resource(pdev);
	} else {
		initdbgmsg("%s DeviceTree\n", __func__);
		acpi_permanent_mmap = true;
		set_bit(EFI_MEMMAP, &efi.flags);
		ret = sdei_ghes_of_match_resource(pdev);
	}
	if (ret < 0) {
		dev_err(dev, "Failed parse match resources\n");
		return ret;
	}

	ret = sdei_ghes_setup_resource(ghes_drv);
	if (ret)
		goto exit0;

	sdei_ghes_init_source(ghes_drv);

	if (!has_acpi_companion(dev)) {
		ret = sdei_ghes_of_alloc_hest(ghes_drv);
		if (ret) {
			dev_err(dev, "Unable allocate HEST.\n");
			goto exit0;
		}
	}

	if (!cn10kx_model)
		sdei_ghes_msix_init_t9x();

	ret = octeontx_edac_mc_create(ghes_drv);
	if (ret)
		goto exit1;

	ret = sdei_ghes_driver_init(pdev);
	if (ret) {
		dev_err(dev, "Error initializing SDEI GHES support.\n");
		sdei_ghes_driver_deinit(pdev);
		goto exit0;
	}

	return 0;

exit1:
	for (i = 0; i < ghes_drv->source_count; i++)
		if (ghes_drv->source_list[i].mci) {
			edac_mc_free(ghes_drv->source_list[i].mci);
			put_device(&ghes_drv->source_list[i].dev);
		}

exit0:
	dev_err(dev, "Error probe GHES.\n");
	return ret;
}

static int edac_ghes_mrvl_remove(struct platform_device *pdev)
{
	initdbgmsg("%s: entry\n", __func__);

	sdei_ghes_driver_deinit(pdev);

	return 0;
}

static const struct platform_device_id sdei_ghes_pdev_match[] = {
	{ .name = DRV_NAME, },
	{},
};
MODULE_DEVICE_TABLE(platform, sdei_ghes_pdev_match);

static struct platform_driver sdei_ghes_drv_probe = {
	.driver = {
		.name             = DRV_NAME,
		.of_match_table   = sdei_ghes_of_match,
		.acpi_match_table = ACPI_PTR(sdei_ghes_acpi_match),
	},
	.probe    = edac_ghes_mrvl_probe,
	.remove   = edac_ghes_mrvl_remove,
	.id_table = sdei_ghes_pdev_match,
};
module_platform_driver(sdei_ghes_drv_probe);

MODULE_AUTHOR("Marvell International Ltd.");
MODULE_DESCRIPTION("Marvell EDAC memory driver");
MODULE_LICENSE("GPL v2");
