/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Marvell CN10K Generic Hardware Error Source[s] (GHES)
 * GHES ACPI HEST & DT
 *
 * Copyright (C) 2021 Marvell.
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
#include "otx2-sdei-ghes.h"

#define DRV_NAME       "sdei-ghes"

#define initerrmsg(fmt, ...) pr_err(DRV_NAME ":" fmt, __VA_ARGS__)
#ifdef CONFIG_OCTEONTX2_SDEI_GHES_DEBUG
#  define initdbgmsg(fmt, ...) pr_info(DRV_NAME ":" fmt, __VA_ARGS__)
#  define dbgmsg(dev, ...) dev_info((dev), __VA_ARGS__)
#else
#  define initdbgmsg(fmt, ...) (void)(fmt)
#  define dbgmsg(dev, ...) (void)(dev)
#endif // CONFIG_OCTEONTX2_SDEI_GHES_DEBUG

#define MRVL_HEST_OEM_ID "MRVL  "
#define HEST_TBL_OEM_ID	"OTX2    "


#ifdef CONFIG_OF
static const struct of_device_id sdei_ghes_of_match[] = {
	{ .compatible = "marvell,sdei-ghes", },
	{},
};
MODULE_DEVICE_TABLE(of, sdei_ghes_of_match);
#endif

#ifdef CONFIG_ACPI
static const struct acpi_device_id sdei_ghes_acpi_match[] = {
	{ "GHES0001", 0 },
	{ },
};
MODULE_DEVICE_TABLE(acpi, sdei_ghes_acpi_match);
#endif

static const char * const sdei_ghes_mrvl[] = {"mdc", "mcc", "lmc"};

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

/* SDEI event notification callback. */
static int sdei_ghes_callback(u32 event_id, struct pt_regs *regs, void *arg)
{
	struct acpi_hest_generic_status *esb;
	struct acpi_hest_generic_data *esb_data;
	struct cper_sec_mem_err_old *esb_err;
	struct mrvl_ghes_err_record *ring_rec;
	struct mrvl_sdei_ghes_drv *ghes_drv;
	struct mrvl_ghes_source *gsrc;
	u32 head, tail;
	size_t i;

	initdbgmsg("%s event id 0x%x\n", __func__, event_id);

	ghes_drv = arg;

	for (i = 0; i < ghes_drv->source_count; i++) {
		gsrc = &ghes_drv->source_list[i];

		if (gsrc->esa_va && *gsrc->esa_va != gsrc->esb_pa) {
			initdbgmsg("%s ACPI ESB address 0x%llx 0x%llx\n",
					__func__, *gsrc->esa_va, gsrc->esb_pa);
			*gsrc->esa_va = gsrc->esb_pa;
		} else
			initdbgmsg("%s no need patch address\n", __func__);

		initdbgmsg("%s is match event id 0x%x\n", __func__, gsrc->id);

		if (gsrc->id != event_id)
			continue;

		initdbgmsg("%s matching event id 0x%x\n", __func__, gsrc->id);

		head = gsrc->ring->head;
		tail = gsrc->ring->tail;

		/*Ensure that head updated*/
		rmb();

		if (head == tail) {
			initerrmsg("ghes 0x%x ring is empty, head=%d, size=%d\n",
					event_id, head, gsrc->ring->size);
			break;
		}

		/*
		 * Error Records Ring an array of records
		 */
		ring_rec = &gsrc->ring->records[tail];

		/*
		 * Error Status Block memory layout:
		 * [1] acpi_hest_generic_status
		 * [2] acpi_hest_generic_data
		 * [3] cper_sec_mem_er_old
		 */
		esb = gsrc->esb_va;
		esb_data = (struct acpi_hest_generic_data *)(esb + 1);
		esb_err = (struct cper_sec_mem_err_old *)(esb_data + 1);

		initdbgmsg("%s esb=%p, esb_data=%p, esb_err=%p\n", __func__,
				esb, esb_data, esb_err);

		// Error Status
		esb->raw_data_length = 0;
		esb->data_length =
				sizeof(*esb_data) +
				sizeof(struct cper_sec_mem_err_old);
		esb->error_severity = ring_rec->severity;

		// Error Generic Data
		memset(esb_data, 0, sizeof(*esb_data));
		esb_data->revision = 0x201; /* ACPI 4.x */
		if (ring_rec->fru_text[0]) {
			esb_data->validation_bits = ACPI_HEST_GEN_VALID_FRU_STRING;
			strncpy(esb_data->fru_text, ring_rec->fru_text,
				sizeof(esb_data->fru_text));
		}
		esb_data->error_severity = esb->error_severity;
		guid_copy((guid_t *)esb_data->section_type, &CPER_SEC_PLATFORM_MEM);
		esb_data->error_data_length = sizeof(struct cper_sec_mem_err_old);

		initdbgmsg("%s err_sev=%x,\n", __func__,
				ring_rec->severity);

		// Error Record
		memcpy(esb_err, &ring_rec->u.mcc, sizeof(*esb_err));

		/* Ensure that error status (esb) is committed to memory prior to
		 * setting block_status.
		 */
		wmb();

		/*
		 * This simply needs the entry count to be non-zero.
		 * Set entry count to one (see ACPI_HEST_ERROR_ENTRY_COUNT).
		 */
		esb->block_status = (1 << 4); /* i.e. one entry */

		if (++tail >= gsrc->ring->size)
			tail = 0;
		gsrc->ring->tail = tail;
		break;
	}

	if (i == ghes_drv->source_count)
		initerrmsg("%s no source event id match\n", __func__);

	return 0;
}


/*
 * Enable MSIX at the device level (MSIX_CAPABILITIES Header).
 *
 * NOTE: We SHOULD be able to use PCCPVF_XXX_VSEC_SCTL[MSIX_SEC_EN]
 * to enable our SECURE IRQs, but for errata PCC-34263...
 */
static void dev_enable_msix(struct pci_dev *pdev)
{
	u16 ctrl;

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
static void sdei_ghes_msix_init(void)
{
	const struct pci_device_id *pdevid;
	struct pci_dev *pdev;
	size_t i;

	initdbgmsg("%s: entry\n", __func__);

	for (i = 0; i < ARRAY_SIZE(sdei_ghes_mrvl_pci_tbl); i++) {
		pdevid = &sdei_ghes_mrvl_pci_tbl[i];
		pdev = NULL;

		while ((pdev = pci_get_device(pdevid->vendor, pdevid->device, pdev)))
			dev_enable_msix(pdev);
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

		ret = sdei_event_register(gsrc->id, sdei_ghes_callback, ghes_drv);
		if (ret < 0) {
			dev_err(dev, "Error %d registering gsrc 0x%x (%s)\n",
				ret, gsrc->id, gsrc->name);
			break;
		}

		ret = sdei_event_enable(gsrc->id);
		if (ret < 0) {
			dev_err(dev, "Error %d enabling gsrc 0x%x (%s)\n",
				ret, gsrc->id, gsrc->name);
			break;
		}

		initdbgmsg("Register GHES 0x%x (%s) [%llx, %llx, %llx, %llx]\n",
				gsrc->id, gsrc->name, (long long)gsrc->esa_pa,
				(long long)gsrc->esa_va,
				(long long)gsrc->esb_va, (long long)gsrc->ring);
	}

	if (i != ghes_drv->source_count)
		return -ENODEV;

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

	ghes_drv = platform_get_drvdata(pdev);

	for (i = 0; i < ghes_drv->source_count; i++) {
		gsrc = &ghes_drv->source_list[i];

		ret = sdei_event_disable(gsrc->id);
		if (ret < 0)
			dev_err(dev, "Error %d disabling SDEI gsrc 0x%x (%s)\n",
				ret, gsrc->id, gsrc->name);

		ret = sdei_event_unregister(gsrc->id);
		if (ret < 0)
			dev_err(dev, "Error %d unregistering SDEI gsrc 0x%x (%s)\n",
				ret, gsrc->id, gsrc->name);
	}

	return 0;
}

/*
 * For ACPI, the Error Status address must be present in the
 * memory map.  If not present, ACPI can generate an exception
 * when trying to map it (see apei_read/acpi_os_read_memory()).
 * For this reason, if the Error Status Address is NOT present
 * we allocate one here (the firmware doesn't actually write
 * to this block; THIS driver does so, in response to SDEI
 * notifications).
 */
static int sdei_ghes_adjust_error_status_block(struct page **pg,
		struct mrvl_sdei_ghes_drv *ghes_drv)
{
	struct mrvl_ghes_source *gsrc;
	phys_addr_t pg_pa;
	void *pg_va;
	int i;

	initdbgmsg("%s: entry\n", __func__);

	if (!pg)
		return -EFAULT;

	gsrc = &ghes_drv->source_list[0];

	if (pfn_valid(PHYS_PFN(gsrc->esa_pa)))
		return 0;

	*pg = alloc_page(GFP_KERNEL);
	if (!*pg) {
		pr_err("Unable to allocate error status block\n");
		return -ENOMEM;
	}

	pg_pa = PFN_PHYS(page_to_pfn(*pg));
	pg_va = page_address(*pg);

	initdbgmsg("! Allocated Error Status Address %p (%llx)\n",
			pg_va, (unsigned long long)pg_pa);

	for (i = 0; i < ghes_drv->source_count; i++) {
		gsrc = &ghes_drv->source_list[i];

		gsrc->esa_pa  = pg_pa + (gsrc->esa_pa & ~PAGE_MASK);
		gsrc->esb_pa  = pg_pa + (gsrc->esb_pa & ~PAGE_MASK);
		gsrc->ring_pa = pg_pa + (gsrc->ring_pa & ~PAGE_MASK);
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

		// Name
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

static int __init sdei_ghes_acpi_match_resource(struct platform_device *pdev)
{
	struct mrvl_sdei_ghes_drv *ghes_drv;
	struct mrvl_ghes_source *gsrc;
	struct resource *res;
	struct device *dev;
	size_t i = 0;
	size_t idx = 0;

	dev = &pdev->dev;
	ghes_drv = platform_get_drvdata(pdev);

	initdbgmsg("%s: entry\n", __func__);

	for (i = 0; i < ghes_drv->source_count; i++) {
		gsrc = &ghes_drv->source_list[i];

		strncpy(gsrc->name, sdei_ghes_mrvl[i], strlen(sdei_ghes_mrvl[i]));

		// Error Status Address
		res = platform_get_resource(pdev, IORESOURCE_MEM, idx);
		if (!res) {
			dev_err(dev, "%s ACPI warn get gsrc=%ld idx=%ld\n", __func__, i, idx);
			return -ENOENT;
		}
		initdbgmsg("%s Status Address %s [%llx - %llx, %lx, %lx]\n", __func__,
				res->name, res->start, res->end, res->flags, res->desc);
		gsrc->esa_pa = res->start;
		idx++;

		// Error Status Block Buffer
		res = platform_get_resource(pdev, IORESOURCE_MEM, idx);
		if (!res) {
			dev_err(dev, "%s ACPI warn get gsrc=%ld idx=%ld\n", __func__, i, idx);
			return -ENOENT;
		}
		initdbgmsg("%s Status Block %s [%llx - %llx, %lx, %lx]\n", __func__,
				res->name, res->start, res->end, res->flags, res->desc);
		gsrc->esb_pa = res->start;
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
		gsrc->ring_pa = res->start;
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

		initdbgmsg("GHES: %s 0x%llx/0x%llx/0x%llx, ID:0x%x)\n", gsrc->name,
				gsrc->esa_pa, gsrc->esb_pa, gsrc->ring_pa, gsrc->id);
	}

	return 0;
}

static int  sdei_ghes_map_resource(struct mrvl_sdei_ghes_drv *ghes_drv)
{
	struct mrvl_ghes_source *gsrc;
	size_t i;

	initdbgmsg("%s: entry\n", __func__);

	for (i = 0; i < ghes_drv->source_count; i++) {
		gsrc = &ghes_drv->source_list[i];

		if (pfn_valid(PHYS_PFN(gsrc->esa_pa)))
			gsrc->esa_va = phys_to_virt(gsrc->esa_pa);

		if (pfn_valid(PHYS_PFN(gsrc->esb_pa)))
			gsrc->esb_va = phys_to_virt(gsrc->esb_pa);

		if (pfn_valid(PHYS_PFN(gsrc->ring_pa)))
			gsrc->ring = phys_to_virt(gsrc->ring_pa);

		initdbgmsg("0x%p/0x%p/0x%p\n", gsrc->esa_va, gsrc->esb_va, gsrc->ring);

		if (gsrc->esa_va && gsrc->esb_va && gsrc->ring)
			continue;

		if (!gsrc->esa_va)
			gsrc->esa_va = ioremap(gsrc->esa_pa, sizeof(gsrc->esa_va));

		if (!gsrc->esb_va)
			gsrc->esb_va = ioremap(gsrc->esb_pa, gsrc->esb_sz);

		if (!gsrc->ring)
			gsrc->ring = ioremap(gsrc->ring_pa, gsrc->ring_sz);

		initdbgmsg("0x%p/0x%p/0x%p\n", gsrc->esa_va, gsrc->esb_va, gsrc->ring);

		if (!gsrc->esa_va || !gsrc->esb_va || !gsrc->ring)
			goto err;
	}

	return 0;

err:
	initerrmsg("%s Unable to map error block.\n", __func__);
	while (i >= 0) {
		gsrc = &ghes_drv->source_list[i];
		iounmap(gsrc->esa_va);
		iounmap(gsrc->esb_va);
		iounmap(gsrc->ring);
		i--;
	}

	return -EFAULT;
}

static void  sdei_ghes_init_source(struct mrvl_sdei_ghes_drv *ghes_drv)
{
	struct mrvl_ghes_source *gsrc;
	size_t i;

	for (i = 0; i < ghes_drv->source_count; i++) {
		gsrc = &ghes_drv->source_list[i];

		gsrc->esb_va->block_status = 0;

		*gsrc->esa_va = gsrc->esb_pa;
	}
}

static void  sdei_ghes_count_source(struct mrvl_sdei_ghes_drv *ghes_drv)
{
	size_t count;

	count = ARRAY_SIZE(sdei_ghes_mrvl_pci_tbl) - 1;
	ghes_drv->source_count = count;
	initdbgmsg("%s: %ld\n", __func__, count);
}

static int  sdei_ghes_alloc_source(struct device *dev,
		struct mrvl_sdei_ghes_drv *ghes_drv)
{
	size_t size = 0;

	initdbgmsg("%s()\n", __func__);

	size = ghes_drv->source_count * sizeof(struct mrvl_ghes_source);

	ghes_drv->source_list = devm_kzalloc(dev, size, GFP_KERNEL);
	if (!ghes_drv->source_list)
		return -ENOMEM;

	return 0;
}

static void * __init sdei_ghes_of_alloc_hest(struct device *dev,
		struct mrvl_sdei_ghes_drv *ghes_drv)
{
	struct mrvl_ghes_source *gsrc;
	unsigned int size;
	struct acpi_table_hest *hest;
	struct acpi_table_header *hdr;
	struct acpi_hest_generic *hest_gen;
	size_t i;
	u8 *p;
	u8 sum = 0;

	initdbgmsg("%s: entry\n", __func__);

	size = sizeof(struct acpi_table_hest) +
			ghes_drv->source_count * sizeof(struct acpi_hest_generic);

	hest = kzalloc(size, GFP_KERNEL);
	if (!hest)
		return NULL;

	hest_gen = (struct acpi_hest_generic *)(hest + 1);

	hdr = &hest->header;
	strncpy(hdr->signature, ACPI_SIG_HEST, sizeof(hdr->signature));
	hdr->length = size;
	hdr->revision = 1;
	strncpy(hdr->oem_id, MRVL_HEST_OEM_ID, sizeof(hdr->oem_id));
	strncpy(hdr->oem_table_id, HEST_TBL_OEM_ID, sizeof(hdr->oem_table_id));
	hdr->oem_revision = 1;
	strncpy(hdr->asl_compiler_id, MRVL_HEST_OEM_ID, sizeof(hdr->asl_compiler_id));
	hdr->asl_compiler_revision = 1;
	p = (u8 *)hdr;
	while (p < (u8 *)(hdr + 1))
		sum += *p, p++;
	hdr->checksum -= sum;
	hest->error_source_count = ghes_drv->source_count;

	for (i = 0; i < hest->error_source_count; i++, hest_gen++) {
		gsrc = &ghes_drv->source_list[i];

		hest_gen->header.type = ACPI_HEST_TYPE_GENERIC_ERROR;
		hest_gen->header.source_id = i;
		hest_gen->related_source_id = i;
		hest_gen->reserved = 0;
		hest_gen->enabled = 1;
		hest_gen->records_to_preallocate = 1;
		hest_gen->max_sections_per_record = 1;
		hest_gen->max_raw_data_length = 0;

		hest_gen->error_status_address.space_id = ACPI_ADR_SPACE_SYSTEM_MEMORY;
		hest_gen->error_status_address.bit_width = 64;
		hest_gen->error_status_address.bit_offset = 0;
		hest_gen->error_status_address.access_width = 4;
		hest_gen->error_status_address.address = gsrc->esa_pa;
		hest_gen->notify.type = ACPI_HEST_NOTIFY_POLLED;
		hest_gen->notify.length = sizeof(struct acpi_hest_notify);
		hest_gen->notify.config_write_enable = 0;
		hest_gen->notify.poll_interval = 1000; /* i.e. 1 sec */
		hest_gen->notify.vector = gsrc->id;
		hest_gen->notify.error_threshold_value = 1;
		hest_gen->notify.error_threshold_window = 1;
		hest_gen->error_block_length =
				sizeof(struct acpi_hest_generic_status) +
				sizeof(struct acpi_hest_generic_data) +
				sizeof(struct cper_sec_mem_err_old);
	}

	hest_table_set(hest);

	acpi_hest_init();
	dbgmsg(dev, "%s: registering HEST\n", __func__);

	return hest;
}

static int __init sdei_ghes_probe(struct platform_device *pdev)
{
	struct mrvl_sdei_ghes_drv *ghes_drv = NULL;
	struct device *dev = &pdev->dev;
	struct page *pg = NULL;
	struct acpi_table_hest *hest = NULL;
	const struct acpi_device_id *acpi_id = NULL;
	int ret = -ENODEV;

#ifdef CONFIG_CRASH_DUMP
	if (is_kdump_kernel())
#else
	#pragma message "CONFIG_CRASH_DUMP setting is required for this module"
	if (true)
#endif
		return ret;

	initdbgmsg("%s: entry\n", __func__);

	ghes_drv = devm_kzalloc(dev, sizeof(struct mrvl_sdei_ghes_drv), GFP_KERNEL);
	if (!ghes_drv)
		return -ENOMEM;

	sdei_ghes_count_source(ghes_drv);

	ret = sdei_ghes_alloc_source(dev, ghes_drv);
	if (ret)
		goto exit0;

	platform_set_drvdata(pdev, ghes_drv);

	if (has_acpi_companion(dev)) {
		dbgmsg(dev, "%s ACPI\n", __func__);
		acpi_id = acpi_match_device(dev->driver->acpi_match_table, dev);
		ret = sdei_ghes_acpi_match_resource(pdev);
	} else {
		dbgmsg(dev, "%s DeviceTree\n", __func__);
		ret = sdei_ghes_of_match_resource(pdev);
	}
	if (ret)
		goto exit1;

	ret = sdei_ghes_adjust_error_status_block(&pg, ghes_drv);
	if (ret) {
		dev_err(dev, "Unable adjust status block.\n");
		goto exit1;
	}

	ret = sdei_ghes_map_resource(ghes_drv);
	if (ret) {
		dev_err(dev, "Unable map resource.\n");
		goto exit2;
	}

	sdei_ghes_init_source(ghes_drv);

	if (!has_acpi_companion(dev)) {
		hest = sdei_ghes_of_alloc_hest(dev, ghes_drv);
		if (!hest) {
			dev_err(dev, "Unable allocate HEST.\n");
			goto exit2;
		}
	}

	sdei_ghes_msix_init();

	ret = sdei_ghes_driver_init(pdev);
	if (ret)
		goto exit3;

	return 0;

exit3:
	dev_err(dev, "Error initializing SDEI GHES support.\n");
	sdei_ghes_driver_deinit(pdev);
	kfree(hest);
exit2:
	if (pg)
		__free_page(pg);
exit1:
	devm_kfree(dev, ghes_drv->source_list);
exit0:
	devm_kfree(dev, ghes_drv);

	return -ENODEV;
}

static int sdei_ghes_remove(struct platform_device *pdev)
{
	struct mrvl_sdei_ghes_drv *ghes_drv;
	struct device *dev = &pdev->dev;

	ghes_drv = platform_get_drvdata(pdev);

	dbgmsg(dev, "%s: entry\n", __func__);

	sdei_ghes_driver_deinit(pdev);

	devm_kfree(dev, ghes_drv->source_list);

	devm_kfree(dev, ghes_drv);

	return 0;
}

static void sdei_ghes_shutdown(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;

	dbgmsg(dev, "%s: entry\n", __func__);
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
	.probe    = sdei_ghes_probe,
	.remove   = sdei_ghes_remove,
	.shutdown = sdei_ghes_shutdown,
	.id_table = sdei_ghes_pdev_match,
};
module_platform_driver(sdei_ghes_drv_probe);

MODULE_DESCRIPTION("OcteonTX2 SDEI GHES Driver");
