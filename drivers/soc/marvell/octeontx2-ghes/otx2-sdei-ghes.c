// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2020 Marvell International Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Supports OcteonTX2 Generic Hardware Error Source[s] (GHES).
 *
 */

#include <linux/io.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_device.h>
#include <linux/platform_device.h>
#include <linux/of_address.h>
#include <linux/uuid.h>
#include <linux/acpi.h>
#include <linux/workqueue.h>
#include <acpi/apei.h>
#include <acpi/acpi_io.h>
#include <linux/pci.h>
#include "otx2-sdei-ghes.h"

#define DRV_NAME       "sdei-ghes"

/* The initialization function does not have a device ptr; use 'pr_xxx' */
#define initerrmsg(fmt, ...) pr_err(DRV_NAME ":" fmt, __VA_ARGS__)

#ifdef CONFIG_OCTEONTX2_SDEI_GHES_DEBUG
#  define initdbgmsg(fmt, ...) pr_info(DRV_NAME ":" fmt, __VA_ARGS__)
#  define dbgmsg(dev, ...) dev_info((dev), __VA_ARGS__)
#else
#  define initdbgmsg(fmt, ...) (void)(fmt)
#  define dbgmsg(dev, ...) (void)(dev)
#endif // CONFIG_OCTEONTX2_SDEI_GHES_DEBUG

static struct acpi_table_hest *hest;
/* A list of all GHES producers, allocated during module initialization. */
static struct otx2_ghes_source *ghes_source_list;

#ifdef CONFIG_EDAC_DEBUG
extern int edac_debug_level;
#else
static const int edac_debug_level;
#endif

#define PCI_VENDOR_ID_CAVIUM            0x177d
#define PCI_DEVICE_ID_OCTEONTX2_LMC     0xa022
#define PCI_DEVICE_ID_OCTEONTX2_MCC     0xa070
#define PCI_DEVICE_ID_OCTEONTX2_MDC     0xa073
static const struct pci_device_id sdei_ghes_otx2_pci_tbl[] = {
	{ PCI_DEVICE(PCI_VENDOR_ID_CAVIUM, PCI_DEVICE_ID_OCTEONTX2_LMC) },
	{ PCI_DEVICE(PCI_VENDOR_ID_CAVIUM, PCI_DEVICE_ID_OCTEONTX2_MCC) },
	{ PCI_DEVICE(PCI_VENDOR_ID_CAVIUM, PCI_DEVICE_ID_OCTEONTX2_MDC) },
	{ 0, },
};

/* periodic event poll */
enum { POLL_HZ = 1 * HZ };

static void poll_worker(struct work_struct *work)
{
	struct acpi_hest_generic_data *hest_gen_data;
	struct acpi_hest_generic_status *estatus;
	struct otx2_ghes_err_record *err_rec;
	struct cper_sec_mem_err_old *mem_err;
	struct otx2_sdei_ghes_drv *ghes_drv;
	struct otx2_ghes_source *event;
	struct delayed_work *dwork;
	u32 head, tail;
	size_t idx;

	dwork = to_delayed_work(work);
	ghes_drv = container_of(dwork, struct otx2_sdei_ghes_drv, dwork);

	for (idx = 0; idx < ghes_drv->source_count; idx++) {
		static u32 ostatus;

		event = &ghes_drv->source_list[idx];
		head = event->ring->head;
		tail = event->ring->tail;

		/* if ring is empty, check next event source */
		if (head == tail)
			continue;

		err_rec = &event->ring->records[tail];

		if (edac_debug_level >= 2)
			pr_info_ratelimited(
				"head %d, tail %d, rec %p\n",
				event->ring->head, tail, err_rec);

		estatus = event->estatus;

		if (edac_debug_level >= 2 &&
				ostatus != estatus->block_status)
			pr_err_ratelimited("%s: cpu%d estat:%x\n",
				__func__, smp_processor_id(),
				estatus->block_status);
		ostatus = estatus->block_status;

		estatus->raw_data_length = 0;
		/* Implementation note: 'data_length' must equal
		 * 'hest_gen_entry->error_block_length' MINUS
		 * sizeof(struct acpi_hest_generic_status).
		 * See 'sdei_ghes_init()'.
		 */

		/* Initialize 'data_length'; trimmed below. */
		estatus->data_length = sizeof(*hest_gen_data);
		estatus->error_severity = err_rec->severity;

		/* generic data follows header */
		hest_gen_data = (struct acpi_hest_generic_data *)(estatus + 1);
		memset(hest_gen_data, 0, sizeof(*hest_gen_data));

		hest_gen_data->revision = 0x201; /* ACPI 4.x */
		if (err_rec->fru_text[0]) {
			hest_gen_data->validation_bits =
				ACPI_HEST_GEN_VALID_FRU_STRING;
			strncpy(hest_gen_data->fru_text, err_rec->fru_text,
				sizeof(hest_gen_data->fru_text));
		}
		/* copy severity from generic status */
		hest_gen_data->error_severity = estatus->error_severity;
		guid_copy((guid_t *)hest_gen_data->section_type,
			  &CPER_SEC_PLATFORM_MEM);

		hest_gen_data->error_data_length =
			sizeof(struct cper_sec_mem_err_old);
		estatus->data_length += sizeof(struct cper_sec_mem_err_old);
		/* memory error follows generic data */
		mem_err = (struct cper_sec_mem_err_old *)(hest_gen_data + 1);
		/* copy error record from ring */
		memcpy(mem_err, &err_rec->u.mcc, sizeof(*mem_err));

		/* Ensure that estatus is committed to memory prior to
		 * setting block_status.
		 */
		wmb();

		/*
		 * This simply needs the entry count to be non-zero.
		 * Set entry count to one (see ACPI_HEST_ERROR_ENTRY_COUNT).
		 */
		estatus->block_status = (1 << 4); /* i.e. one entry */

		if (++tail >= event->ring->size)
			tail = 0;
		event->ring->tail = tail;
	}

	schedule_delayed_work(dwork, POLL_HZ);
}

/*
 * Main initialization function for ghes_drv device instance.
 *
 * returns:
 *   0 if no error
 *   -ENODEV if error occurred initializing device
 *   ENODEV if device should not be used (not an error per se)
 */
static int sdei_ghes_init(struct platform_device *pdev)
{
	struct otx2_sdei_ghes_drv *ghes_drv;

	ghes_drv = platform_get_drvdata(pdev);

	/* Allocated during initialization (see sdei_ghes_driver_init) */
	ghes_drv->source_list = ghes_source_list;
	ghes_drv->source_count = hest->error_source_count;

	INIT_DEFERRABLE_WORK(&ghes_drv->dwork, poll_worker);
	schedule_delayed_work(&ghes_drv->dwork, 0);

	return 0;
}

/* Main de-initialization function for ghes_drv device instance. */
static int sdei_ghes_de_init(struct platform_device *pdev)
{
	struct otx2_sdei_ghes_drv *ghes_drv;
	struct device *dev = &pdev->dev;

	dbgmsg(dev, "%s: entry\n", __func__);

	ghes_drv = platform_get_drvdata(pdev);
	cancel_delayed_work_sync(&ghes_drv->dwork);

	return 0;
}

/* Linux driver framework probe function. */
static int sdei_ghes_probe(struct platform_device *pdev)
{
	struct otx2_sdei_ghes_drv *ghes_drv;
	struct device *dev = &pdev->dev;
	int ret;

	dbgmsg(dev, "%s: entry\n", __func__);

	ret = -ENODEV;

	/* allocate device structure */
	ghes_drv = devm_kzalloc(dev, sizeof(*ghes_drv), GFP_KERNEL);

	if (ghes_drv == NULL) {
		ret = -ENOMEM;
		dev_err(dev, "Unable to allocate drv context.\n");
		goto exit;
	}

	platform_set_drvdata(pdev, ghes_drv);

	ret = sdei_ghes_init(pdev);

	/* a negative value indicates an error */
	if (ret < 0)
		dev_err(dev, "Error initializing SDEI GHES support.\n");

exit:
	if (ret) {
		sdei_ghes_de_init(pdev);

		if (ghes_drv != NULL)
			devm_kfree(dev, ghes_drv);
	}

	return ret ? -ENODEV : 0;
}

static void sdei_ghes_shutdown(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;

	dbgmsg(dev, "%s: entry\n", __func__);
}

static int sdei_ghes_remove(struct platform_device *pdev)
{
	struct otx2_sdei_ghes_drv *ghes_drv;
	struct device *dev = &pdev->dev;

	ghes_drv = platform_get_drvdata(pdev);

	dbgmsg(dev, "%s: entry\n", __func__);

	sdei_ghes_de_init(pdev);

	devm_kfree(dev, ghes_drv);

	return 0;
}

static const struct of_device_id sdei_ghes_of_match[] = {
	{ .compatible = "marvell,sdei-ghes", },
	{},
};
MODULE_DEVICE_TABLE(of, sdei_ghes_of_match);

static const struct platform_device_id sdei_ghes_pdev_match[] = {
	{ .name = DRV_NAME, },
	{},
};
MODULE_DEVICE_TABLE(platform, sdei_ghes_pdev_match);

static struct platform_driver sdei_ghes_drv = {
	.driver = {
		.name = DRV_NAME,
		.of_match_table = sdei_ghes_of_match,
	},
	.probe = sdei_ghes_probe,
	.remove = sdei_ghes_remove,
	.shutdown = sdei_ghes_shutdown,
	.id_table = sdei_ghes_pdev_match,
};

/*
 * Allocates and initializes Hardware Error Source Table (HEST), then
 * registers it with kernel.
 */
static int __init sdei_ghes_hest_init(struct device_node *of_node)
{
	const __be32 *of_base0, *of_base1, *of_base2;
	struct acpi_hest_generic *hest_gen_entry;
	struct device_node *child_node;
	struct otx2_ghes_source *event;
	size_t event_cnt, size, idx;
	const u32 *evt_id_prop;
	int ret, prop_sz;
	void *memblock;
	u8 sum;
	u8 *p;

	initdbgmsg("%s: entry\n", __func__);

	ret = -ENODEV;

	/* enumerate [GHES] producers available for subscription */
	event_cnt = 0;
	for_each_available_child_of_node(of_node, child_node) {
		of_base0 = of_get_address(child_node, 0, NULL, NULL);
		if ((of_base0 == NULL) ||
		    (of_translate_address(child_node, of_base0) == OF_BAD_ADDR))
			continue;
		of_base1 = of_get_address(child_node, 1, NULL, NULL);
		if ((of_base1 == NULL) ||
		    (of_translate_address(child_node, of_base1) == OF_BAD_ADDR))
			continue;
		of_base2 = of_get_address(child_node, 2, NULL, NULL);
		if ((of_base2 == NULL) ||
		    (of_translate_address(child_node, of_base2) == OF_BAD_ADDR))
			continue;
		evt_id_prop = of_get_property(child_node, "event-id", &prop_sz);
		if (!evt_id_prop && (prop_sz != sizeof(*evt_id_prop)))
			continue;

		event_cnt++;
		initdbgmsg("Found child %s/%s 0x%llx/0x%llx/0x%llx, ID:0x%x)\n",
		       child_node->name, child_node->full_name,
		       (long long)of_translate_address(child_node, of_base0),
		       (long long)of_translate_address(child_node, of_base1),
		       (long long)of_translate_address(child_node, of_base2),
		       be32_to_cpu(*evt_id_prop));
	}

	/* allocate room for HEST */
	size = sizeof(struct acpi_table_hest);
	/* each error source is of type ACPI_HEST_TYPE_GENERIC_ERROR */
	size += event_cnt * sizeof(struct acpi_hest_generic);
	/* align event list on 8-byte boundary */
	size = roundup(size, 8);

	/* allocate room for list of available events */
	size += event_cnt * sizeof(struct otx2_ghes_source);

	/* allocate everything in one block, ordered as:
	 *   HEST table
	 *   event list
	 */
	memblock = kzalloc(size, GFP_KERNEL);
	if (memblock == NULL) {
		initerrmsg("Unable to allocate HEST & event memory (0x%lx B)\n",
			   size);
		ret = -ENOMEM;
		goto exit;
	}

	/* HEST is at start of allocated block */
	hest = memblock;

	/* event table is after HEST */
	size = sizeof(struct acpi_table_hest);
	size += event_cnt * sizeof(struct acpi_hest_generic);
	/* align event list on 8-byte boundary (see allocation above) */
	size = roundup(size, 8);
	ghes_source_list = memblock + size;

	/* populate HEST header */
	strncpy(hest->header.signature, ACPI_SIG_HEST,
		sizeof(hest->header.signature));
	hest->header.length =
		sizeof(struct acpi_table_hest) +
		       (event_cnt * sizeof(struct acpi_hest_generic));
	hest->header.revision = 1;
#define OTX2_HEST_OEM_ID "MRVL  "
	strncpy(hest->header.oem_id, OTX2_HEST_OEM_ID,
		sizeof(hest->header.oem_id));
	strncpy(hest->header.oem_table_id, "OTX2    ",
		sizeof(hest->header.oem_table_id));
	hest->header.oem_revision = 1;
	strncpy(hest->header.asl_compiler_id, OTX2_HEST_OEM_ID,
		sizeof(hest->header.asl_compiler_id));
	hest->header.asl_compiler_revision = 1;

	sum = 0;
	for (p = (u8 *) &hest->header; p < (u8 *) (1 + &hest->header); p++)
		sum += *p;
	hest->header.checksum -= sum;

	hest->error_source_count = event_cnt;

	/* retrieve/init event IDs from DeviceTree & populate HEST entries */
	idx = 0;
	hest_gen_entry = (struct acpi_hest_generic *)(hest + 1);
	for_each_available_child_of_node(of_node, child_node) {
		of_base0 = of_get_address(child_node, 0, NULL, NULL);
		if ((of_base0 == NULL) ||
		    (of_translate_address(child_node, of_base0) == OF_BAD_ADDR))
			continue;
		of_base1 = of_get_address(child_node, 1, NULL, NULL);
		if ((of_base1 == NULL) ||
		    (of_translate_address(child_node, of_base1) == OF_BAD_ADDR))
			continue;
		of_base2 = of_get_address(child_node, 2, NULL, NULL);
		if ((of_base2 == NULL) ||
		    (of_translate_address(child_node, of_base2) == OF_BAD_ADDR))
			continue;
		evt_id_prop = of_get_property(child_node, "event-id", &prop_sz);
		if (!evt_id_prop && (prop_sz != sizeof(*evt_id_prop)))
			continue;

		event = &ghes_source_list[idx];

		/* name is already terminated by 'kzalloc' */
		strncpy(event->name, child_node->name,
			sizeof(event->name) - 1);
		event->id = be32_to_cpu(*evt_id_prop);

		hest_gen_entry->header.type = ACPI_HEST_TYPE_GENERIC_ERROR;
		hest_gen_entry->header.source_id = idx;
		hest_gen_entry->related_source_id =
			hest_gen_entry->header.source_id;
		hest_gen_entry->reserved = 0;
		hest_gen_entry->enabled = 1;
		hest_gen_entry->records_to_preallocate = 1;
		hest_gen_entry->max_sections_per_record = 1;
		hest_gen_entry->max_raw_data_length = 0;

		hest_gen_entry->error_status_address.space_id =
			ACPI_ADR_SPACE_SYSTEM_MEMORY;
		hest_gen_entry->error_status_address.bit_width = 64;
		hest_gen_entry->error_status_address.bit_offset = 0;
		hest_gen_entry->error_status_address.access_width = 4;
		hest_gen_entry->error_status_address.address =
			of_translate_address(child_node, of_base0);

		hest_gen_entry->notify.type = ACPI_HEST_NOTIFY_POLLED;
		hest_gen_entry->notify.length = sizeof(hest_gen_entry->notify);
		hest_gen_entry->notify.config_write_enable = 0;
		hest_gen_entry->notify.poll_interval = 1000; /* i.e. 1 sec */
		hest_gen_entry->notify.vector = event->id;
		hest_gen_entry->notify.error_threshold_value = 1;
		hest_gen_entry->notify.error_threshold_window = 1;

		hest_gen_entry->error_block_length =
			sizeof(struct acpi_hest_generic_status) +
			sizeof(struct acpi_hest_generic_data) +
			sizeof(struct cper_sec_mem_err_old);

		event->estatus_address = phys_to_virt(
				hest_gen_entry->error_status_address.address);
		if (event->estatus_address == NULL) {
			initerrmsg("Unable to access estatus_address 0x%llx\n",
				   hest_gen_entry->error_status_address.address)
				   ;
			goto exit;
		}

		event->estatus_pa = of_translate_address(child_node, of_base1);
		event->estatus = phys_to_virt(event->estatus_pa);
		if (event->estatus == NULL) {
			initerrmsg("Unable to access estatus block 0x%llx\n",
				   of_translate_address(child_node, of_base1));
			goto exit;
		}

		/* Event ring buffer in memory */
		event->ring = phys_to_virt(of_translate_address(child_node,
								of_base2));
		if (event->ring == NULL) {
			initerrmsg("Unable to access event 0x%x ring buffer\n",
				   event->id);
			goto exit;
		}

		/* clear status */
		event->estatus->block_status = 0;

		/* set event status address */
		*event->estatus_address = event->estatus_pa;

		idx++;
		hest_gen_entry++;
	}

	if (idx != event_cnt) {
		ret = -ENODEV;
		goto exit;
	}

	initdbgmsg("%s: registering HEST\n", __func__);
	hest_table_set(hest);
	acpi_hest_init();

	ret = 0;

exit:
	return ret;
}

/*
 * Enable MSIX at the device level (MSIX_CAPABILITIES Header).
 *
 * NOTE: We SHOULD be able to use PCCPV_XXX_VSEC_SCTL[MSIX_SEC_EN]
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
		pci_read_config_word(pdev, pdev->msix_cap + PCI_MSIX_FLAGS,
				     &ctrl);
		ctrl |= PCI_MSIX_FLAGS_ENABLE;
		pci_write_config_word(pdev, pdev->msix_cap + PCI_MSIX_FLAGS,
				      ctrl);
		initdbgmsg("Set MSI-X Enable for PCI dev %04d:%02d.%d\n",
			   pdev->bus->number, PCI_SLOT(pdev->devfn),
			   PCI_FUNC(pdev->devfn));
	} else {
		initerrmsg("PCI dev %04d:%02d.%d missing MSIX capabilities\n",
			   pdev->bus->number, PCI_SLOT(pdev->devfn),
			   PCI_FUNC(pdev->devfn));
	}
}

/* Driver entry point */
static int __init sdei_ghes_driver_init(void)
{
	const struct pci_device_id *pdevid;
	struct device_node *of_node;
	struct pci_dev *pdev;
	int i, rc;

	initdbgmsg("%s: edac_debug_level:%d\n", __func__, edac_debug_level);

	rc = -ENODEV;

	of_node = of_find_matching_node_and_match(NULL, sdei_ghes_of_match,
						  NULL);
	if (!of_node)
		return rc;

	/* Initialize Hardware Error Source Table (HEST) */
	rc = sdei_ghes_hest_init(of_node);
	if (rc) {
		initerrmsg("HEST initialization error %d\n", rc);
		return rc;
	}

	platform_driver_register(&sdei_ghes_drv);

	/* Enable MSIX for devices whose [secure] IRQ's we control.
	 * These IRQs have been initialized by ATF.
	 * This is required due to an errata against
	 * PCCPV_XXX_VSEC_SCTL[MSIX_SEC_EN].
	 */
	for (i = 0; i < ARRAY_SIZE(sdei_ghes_otx2_pci_tbl); i++) {
		pdevid = &sdei_ghes_otx2_pci_tbl[i];
		pdev = NULL;
		while ((pdev = pci_get_device(pdevid->vendor, pdevid->device,
			pdev)))
			dev_enable_msix(pdev);
	}

	return rc;
}

device_initcall(sdei_ghes_driver_init);

MODULE_DESCRIPTION("OcteonTX2 SDEI GHES Driver");
MODULE_LICENSE("GPL v2");
